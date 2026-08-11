package main

import (
	"time"

	"sync"

	"github.com/lwlcom/cisco_exporter/connector"
	"github.com/lwlcom/cisco_exporter/rpc"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const prefix = "cisco_"

var (
	scrapeCollectorDurationDesc *prometheus.Desc
	scrapeDurationDesc          *prometheus.Desc
	upDesc                      *prometheus.Desc
)

func init() {
	upDesc = prometheus.NewDesc(prefix+"up", "Scrape of target was successful", []string{"target"}, nil)
	scrapeDurationDesc = prometheus.NewDesc(prefix+"collector_duration_seconds", "Duration of a collector scrape for one target", []string{"target"}, nil)
	scrapeCollectorDurationDesc = prometheus.NewDesc(prefix+"collect_duration_seconds", "Duration of a scrape by collector and target", []string{"target", "collector"}, nil)
}

type ciscoCollector struct {
	devices    []*connector.Device
	collectors *collectors

	mu       sync.Mutex
	sessions map[string]*deviceSession
}

// deviceSession holds the SSH connection to one device between scrapes. The
// device is driven through a single interactive shell, so the mutex is held for
// the whole of a collection to keep two concurrent scrapes from interleaving
// commands on it.
type deviceSession struct {
	mu         sync.Mutex
	conn       *connector.SSHConnection
	client     *rpc.Client
	identified bool
}

func newCiscoCollector(devices []*connector.Device) *ciscoCollector {
	return &ciscoCollector{
		devices:    devices,
		collectors: collectorsForDevices(devices, cfg),
		sessions:   make(map[string]*deviceSession),
	}
}

func (c *ciscoCollector) sessionFor(host string) *deviceSession {
	c.mu.Lock()
	defer c.mu.Unlock()

	s, ok := c.sessions[host]
	if !ok {
		s = &deviceSession{}
		c.sessions[host] = s
	}
	return s
}

// usable reports whether the stored connection can carry another command.
func (s *deviceSession) usable() bool {
	return s.conn != nil && !s.conn.Broken()
}

// connect reuses the stored connection when it is still usable and dials a new
// one otherwise.
func (s *deviceSession) connect(device *connector.Device) (*rpc.Client, error) {
	if s.usable() {
		return s.client, nil
	}
	s.close()

	conn, err := connector.NewSSSHConnection(device, cfg)
	if err != nil {
		return nil, err
	}

	s.conn = conn
	s.client = rpc.NewClient(conn, cfg.Debug)
	s.identified = false
	return s.client, nil
}

// identify determines the device OS once per connection. It cannot change while
// the session lasts, so there is no reason to ask again on every scrape.
func (s *deviceSession) identify() error {
	if s.identified {
		return nil
	}
	if err := s.client.Identify(); err != nil {
		s.close()
		return err
	}
	s.identified = true
	return nil
}

func (s *deviceSession) close() {
	if s.conn != nil {
		s.conn.Close()
	}
	s.conn = nil
	s.client = nil
	s.identified = false
}

func (s *deviceSession) closeIfBroken() {
	if s.conn != nil && s.conn.Broken() {
		s.close()
	}
}

// Describe implements prometheus.Collector interface
func (c *ciscoCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- upDesc
	ch <- scrapeDurationDesc
	ch <- scrapeCollectorDurationDesc

	for _, col := range c.collectors.allEnabledCollectors() {
		col.Describe(ch)
	}
}

// Collect implements prometheus.Collector interface
func (c *ciscoCollector) Collect(ch chan<- prometheus.Metric) {
	wg := &sync.WaitGroup{}

	wg.Add(len(c.devices))
	for _, d := range c.devices {
		go c.collectForHost(d, ch, wg)
	}

	wg.Wait()
}

func (c *ciscoCollector) collectForHost(device *connector.Device, ch chan<- prometheus.Metric, wg *sync.WaitGroup) {
	defer wg.Done()

	l := []string{device.Host}

	t := time.Now()
	defer func() {
		ch <- prometheus.MustNewConstMetric(scrapeDurationDesc, prometheus.GaugeValue, time.Since(t).Seconds(), l...)
	}()

	s := c.sessionFor(device.Host)
	s.mu.Lock()
	defer s.mu.Unlock()

	for attempt := 0; ; attempt++ {
		reused := s.usable()

		client, err := s.connect(device)
		if err != nil {
			log.Errorln(err)
			ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 0, l...)
			return
		}

		if err := s.identify(); err != nil {
			log.Errorln(device.Host + ": " + err.Error())
			ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 1, l...)
			return
		}

		metrics := c.runCollectors(device, client, l)

		// A session carried over from an earlier scrape may have been closed by
		// the device since it was last used, and that only becomes visible when
		// a command fails. Give it one more try on a fresh connection, throwing
		// away what the dead one produced so nothing is reported twice.
		if reused && attempt == 0 && !s.usable() {
			s.close()
			continue
		}

		ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 1, l...)
		for _, m := range metrics {
			ch <- m
		}
		s.closeIfBroken()
		return
	}
}

// runCollectors gathers the metrics for one device into a slice rather than
// emitting them directly, so a collection that turns out to have run over a
// dead connection can be discarded and repeated.
func (c *ciscoCollector) runCollectors(device *connector.Device, client *rpc.Client, l []string) []prometheus.Metric {
	var metrics []prometheus.Metric

	out := make(chan prometheus.Metric, 256)
	done := make(chan struct{})
	go func() {
		for m := range out {
			metrics = append(metrics, m)
		}
		close(done)
	}()

	for _, col := range c.collectors.collectorsForDevice(device) {
		ct := time.Now()
		err := col.Collect(client, out, l)

		if err != nil && err.Error() != "EOF" {
			log.Errorln(col.Name() + ": " + err.Error())
		}

		out <- prometheus.MustNewConstMetric(scrapeCollectorDurationDesc, prometheus.GaugeValue, time.Since(ct).Seconds(), append(l, col.Name())...)
	}

	close(out)
	<-done
	return metrics
}
