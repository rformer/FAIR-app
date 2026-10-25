package audit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// SyslogSink writes RFC 5424 messages over TCP, TLS (RFC 5425, octet-counting
// framing) or UDP (RFC 5426). The standard library's log/syslog only speaks
// the legacy BSD format, so the formatter lives here.
type SyslogSink struct {
	network  string // "tcp", "tls" or "udp"
	addr     string
	tlsCfg   *tls.Config
	appName  string
	hostname string
	timeout  time.Duration

	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

// SyslogConfig configures the sink.
type SyslogConfig struct {
	Network string // tcp | tls | udp
	Addr    string // host:port
	TLS     *tls.Config
	AppName string
	Timeout time.Duration
}

// NewSyslogSink builds the sink. The connection is opened lazily and
// re-dialled once after a write error.
func NewSyslogSink(cfg SyslogConfig) (*SyslogSink, error) {
	switch cfg.Network {
	case "tcp", "tls", "udp":
	default:
		return nil, fmt.Errorf("audit syslog: unsupported network %q", cfg.Network)
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}
	t := cfg.TLS
	if t == nil {
		t = &tls.Config{}
	}
	t = t.Clone()
	if t.MinVersion < tls.VersionTLS12 {
		t.MinVersion = tls.VersionTLS12
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	app := cfg.AppName
	if app == "" {
		app = "fair"
	}
	return &SyslogSink{network: cfg.Network, addr: cfg.Addr, tlsCfg: t, appName: app, hostname: host, timeout: cfg.Timeout}, nil
}

// facility 10 = authpriv (security/authorization messages).
const syslogFacility = 10

func syslogSeverity(s Severity) int {
	switch s {
	case SeverityCritical:
		return 2
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 4
	case SeverityLow:
		return 5
	default:
		return 6
	}
}

// sdEscape escapes an SD-PARAM value per RFC 5424 §6.3.3.
func sdEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return r.Replace(s)
}

// FormatRFC5424 renders an event as a syslog message (without transport framing).
// MSG is the event JSON; key fields are repeated as structured data so SIEMs
// can index them without parsing the body.
func FormatRFC5424(e Event, appName, hostname string) ([]byte, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	pri := syslogFacility*8 + syslogSeverity(e.Severity)
	sd := fmt.Sprintf(`[fair@32473 id="%s" type="%s" severity="%s" outcome="%s" actor="%s" target="%s"]`,
		sdEscape(e.ID), sdEscape(e.Type), sdEscape(string(e.Severity)), sdEscape(string(e.Outcome)),
		sdEscape(e.Actor.ID), sdEscape(e.Target.Kind+":"+e.Target.ID))
	msg := fmt.Sprintf("<%d>1 %s %s %s - %s %s %s",
		pri, e.Time.UTC().Format(time.RFC3339Nano), hostname, appName, e.Type, sd, body)
	return []byte(msg), nil
}

func (s *SyslogSink) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: s.timeout}
	if s.network == "tls" {
		td := &tls.Dialer{NetDialer: d, Config: s.tlsCfg}
		return td.DialContext(ctx, "tcp", s.addr)
	}
	return d.DialContext(ctx, s.network, s.addr)
}

func (s *SyslogSink) write(msg []byte) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	if s.network == "udp" {
		_, err := s.conn.Write(msg)
		return err
	}
	// Octet-counting framing (RFC 6587 §3.4.1 / RFC 5425 §4.3).
	_, err := fmt.Fprintf(s.conn, "%d %s", len(msg), msg)
	return err
}

// Emit implements Emitter.
func (s *SyslogSink) Emit(ctx context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	msg, err := FormatRFC5424(e, s.appName, s.hostname)
	if err != nil {
		return fmt.Errorf("audit syslog: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for attempt := 0; attempt < 2; attempt++ {
		if s.conn == nil {
			c, err := s.dial(ctx)
			if err != nil {
				return fmt.Errorf("audit syslog: dial: %w", err)
			}
			s.conn = c
		}
		if err = s.write(msg); err == nil {
			return nil
		}
		_ = s.conn.Close()
		s.conn = nil
	}
	return fmt.Errorf("audit syslog: write: %w", err)
}

// Close implements Emitter.
func (s *SyslogSink) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
