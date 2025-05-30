package mactable

import (
	"strconv"

	"github.com/lwlcom/cisco_exporter/rpc"

	"github.com/lwlcom/cisco_exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
)

const prefix string = "cisco_mactable_"

var (
	countDesc       *prometheus.Desc
	VLANDesc      *prometheus.Desc
)

func init() {
	l := []string{"target", "vlan"}
	countDesc = prometheus.NewDesc(prefix+"count", "Count of MAC addresses", l, nil)
}

type mactableCollector struct {
}

// NewCollector creates a new collector
func NewCollector() collector.RPCCollector {
	return &mactableCollector{}
}

// Name returns the name of the collector
func (*mactableCollector) Name() string {
	return "Mactable"
}

// Describe describes the metrics
func (*mactableCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- countDesc
}

// Collect collects metrics from Cisco
func (c *mactableCollector) Collect(client *rpc.Client, ch chan<- prometheus.Metric, labelValues []string) error {
	out, err := client.RunCommand("show vlan brief | include active | no-more")
	if err != nil {
		return err
	}
	vlans, err := c.ParseVlans(client.OSType, out)
	if err != nil {
		return err
	}

    items := make([]Mactableentry, 0)
	for _, vlan := range vlans {
		out, err := client.RunCommand("show mac address-table count dynamic vlan " + strconv.Itoa(vlan))
		if err != nil {
			return err
		}
		count, err := c.Parse(client.OSType, out)
		if err != nil {
			return err
		}
		items = append(items, Mactableentry{
			VLAN: vlan,
			Count: count,
		})
	}

	for _, item := range items {
		l := append(labelValues, strconv.Itoa(item.VLAN))
		ch <- prometheus.MustNewConstMetric(countDesc, prometheus.GaugeValue, float64(item.Count), l...)
	}

	return nil
}
