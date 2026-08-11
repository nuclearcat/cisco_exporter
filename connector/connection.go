package connector

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"sync"

	"time"

	"github.com/lwlcom/cisco_exporter/config"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// NewSSSHConnection connects to device
func NewSSSHConnection(device *Device, cfg *config.Config) (*SSHConnection, error) {
	deviceConfig := device.DeviceConfig

	legacyCiphers := cfg.LegacyCiphers
	if deviceConfig.LegacyCiphers != nil {
		legacyCiphers = *deviceConfig.LegacyCiphers
	}

	batchSize := cfg.BatchSize
	if deviceConfig.BatchSize != nil {
		batchSize = *deviceConfig.BatchSize
	}

	timeout := cfg.Timeout
	if deviceConfig.Timeout != nil {
		timeout = *deviceConfig.Timeout
	}

	sshConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
	}
	if legacyCiphers {
		sshConfig.SetDefaults()
		sshConfig.Ciphers = append(sshConfig.Ciphers, "aes128-cbc", "3des-cbc")
	}

	device.Auth(sshConfig)

	c := &SSHConnection{
		Host:         device.Host + ":" + device.Port,
		batchSize:    batchSize,
		clientConfig: sshConfig,
	}

	err := c.Connect()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// SSHConnection encapsulates the connection to the device
type SSHConnection struct {
	client       *ssh.Client
	Host         string
	stdin        io.WriteCloser
	stdout       io.Reader
	session      *ssh.Session
	batchSize    int
	clientConfig *ssh.ClientConfig
	outCh        chan string // delivers one response per command

	mu     sync.Mutex
	broken bool // set once the command stream can no longer be trusted
}

// markBroken records that the response stream is out of sync with the commands
// being issued, so the connection must not be used for anything else.
func (c *SSHConnection) markBroken() {
	c.mu.Lock()
	c.broken = true
	c.mu.Unlock()
}

// Broken reports whether the connection has been abandoned mid-command and has
// to be torn down instead of reused.
func (c *SSHConnection) Broken() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.broken
}

func (c *SSHConnection) readLoop() {
	rdr := bufio.NewReader(c.stdout)
	for {
		line, err := rdr.ReadString('\n')
		if err != nil {
			close(c.outCh)
			return
		}
		c.outCh <- strings.TrimPrefix(line, "\r") // drop solitary CR
	}
}

// Connect connects to the device
func (c *SSHConnection) Connect() error {
	var err error
	c.client, err = ssh.Dial("tcp", c.Host, c.clientConfig)
	if err != nil {
		return err
	}

	session, err := c.client.NewSession()
	if err != nil {
		c.client.Conn.Close()
		return err
	}
	c.stdin, _ = session.StdinPipe()
	c.stdout, _ = session.StdoutPipe()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.OCRNL:         0,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	session.RequestPty("vt100", 80, 2000, modes)
	session.Shell()

	// single reader goroutine
	c.outCh = make(chan string, 4) // buffered channel to avoid blocking

	go c.readLoop()                      // ONLY reader touching StdoutPipe
	_, _ = io.WriteString(c.stdin, "\n") // wake NX‑OS and maybe IOS devices

	select {
	case _, ok := <-c.outCh: // discard, just unblocks reader
		if !ok {
			return fmt.Errorf("session closed before a prompt appeared")
		}
	case <-time.After(c.clientConfig.Timeout):
		return fmt.Errorf("device never presented a prompt")
	}

	c.session = session

	//c.RunCommand("")
	c.RunCommand("terminal length 0")

	return nil
}

func (c *SSHConnection) RunCommand(cmd string) (string, error) {
	// Once a command has been abandoned its unread output is still queued, so
	// anything issued afterwards would be answered with the previous command's
	// tail. Refuse instead of returning data that belongs to another command.
	if c.Broken() {
		return "", errors.New("connection is out of sync after an aborted command")
	}

	tag := fmt.Sprintf("__END_%d__", time.Now().UnixNano())

	// real command + sentinel comment (needs no privilege)
	if _, err := fmt.Fprintf(c.stdin, "%s\n!%s\n", cmd, tag); err != nil {
		return "", err
	}

	var buf strings.Builder

	// The timeout is an idle timeout, not a budget for the whole response: a
	// large "show interface" on a busy chassis streams for far longer than any
	// sane per-command limit, but it never goes quiet for long. Reset the timer
	// on every line so we only give up when the device actually stops talking.
	idle := time.NewTimer(c.clientConfig.Timeout)
	defer idle.Stop()

	for {
		select {
		case line, ok := <-c.outCh:
			if !ok {
				// readLoop closes the channel when the session ends; without
				// this the receive would succeed instantly forever and spin
				// the CPU until the idle timeout expired.
				c.markBroken()
				return "", errors.New("connection closed")
			}
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(c.clientConfig.Timeout)

			clean := strings.TrimSpace(line)

			switch {
			// 1. line is the sentinel comment → finished (don’t copy it)
			case strings.HasSuffix(clean, "!"+tag):
				allstr := buf.String()
				// if it is empty, keep going, we are not done yet (and dont append to buf)
				// On NX-OS, it will echo tag at the beginning of the output
				if allstr == "" {
					continue
				}
				//log.Printf("Command{%s}: %s\n", c.Host, allstr)
				return strings.ReplaceAll(allstr, "\r", "\n"), nil

			// 2. line is the command echo → ignore it
			case strings.HasSuffix(clean, cmd):
				continue

			// 3. normal payload
			default:
				buf.WriteString(line)
			}

		case <-idle.C:
			// The sentinel for this command was never seen, so its remaining
			// output stays in the stream and would be misread as the answer to
			// whatever runs next.
			c.markBroken()
			return "", errors.New("timeout reached")
		}
	}
}

// Close closes connection
func (c *SSHConnection) Close() {
	if c.client == nil || c.client.Conn == nil {
		return
	}
	c.client.Conn.Close()
	if c.session != nil {
		c.session.Close()
	}
}

func loadPrivateKey(r io.Reader) (ssh.AuthMethod, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "could not read from reader")
	}

	key, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse private key")
	}

	return ssh.PublicKeys(key), nil
}
