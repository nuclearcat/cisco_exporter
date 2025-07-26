package connector

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

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
		sshConfig.KeyExchanges = append(sshConfig.KeyExchanges, "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1")
		sshConfig.HostKeyAlgorithms = append(sshConfig.HostKeyAlgorithms, ssh.KeyAlgoRSA, ssh.KeyAlgoDSA)
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
	case <-c.outCh: // discard, just unblocks reader
	case <-time.After(c.clientConfig.Timeout):
		return fmt.Errorf("device never presented a prompt")
	}

	c.session = session

	//c.RunCommand("")
	c.RunCommand("terminal length 0")

	return nil
}

func (c *SSHConnection) RunCommand(cmd string) (string, error) {
	tag := fmt.Sprintf("__END_%d__", time.Now().UnixNano())

	// real command + sentinel comment (needs no privilege)
	if _, err := fmt.Fprintf(c.stdin, "%s\n!%s\n", cmd, tag); err != nil {
		return "", err
	}

	var (
		buf      strings.Builder
		deadline = time.After(c.clientConfig.Timeout)
	)

	for {
		select {
		case line := <-c.outCh:
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

		case <-deadline:
			return "", errors.New("timeout reached")
		}
	}
}

// Close closes connection
func (c *SSHConnection) Close() {
	if c.client.Conn == nil {
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
