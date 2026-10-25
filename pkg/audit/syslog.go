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

// Syslog sends events as RFC 5424 messages with RFC 6587 octet-counting framing
// over TCP, optionally wrapped in TLS (RFC 5425). The structured event is the
// JSON message body, which SIEMs parse directly.
type Syslog struct {
	mu       sync.Mutex
	addr     string
	tlsConf  *tls.Config
	appName  string
	hostname string
	conn     net.Conn
	dial     func(ctx context.Context) (net.Conn, error)
	now      func() time.Time
}

// NewSyslog creates a syslog sink. When tlsConf is nil the connection is plain
// TCP, which is only acceptable to a local relay; production profiles require TLS.
func NewSyslog(addr, appName string, tlsConf *tls.Config) *Syslog {
	host, _ := os.Hostname()
	s := &Syslog{addr: addr, tlsConf: tlsConf, appName: appName, hostname: host, now: time.Now}
	s.dial = func(ctx context.Context) (net.Conn, error) {
		d := &net.Dialer{Timeout: 5 * time.Second}
		if s.tlsConf != nil {
			td := &tls.Dialer{NetDialer: d, Config: s.tlsConf}
			return td.DialContext(ctx, "tcp", s.addr)
		}
		return d.DialContext(ctx, "tcp", s.addr)
	}
	return s
}

// Emit implements Emitter.
func (s *Syslog) Emit(ctx context.Context, e Event) error {
	e, err := Normalize(e, s.now())
	if err != nil {
		return err
	}
	msg, err := FormatRFC5424(e, s.hostname, s.appName)
	if err != nil {
		return err
	}
	frame := fmt.Sprintf("%d %s", len(msg), msg)

	s.mu.Lock()
	defer s.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if s.conn == nil {
			c, derr := s.dial(ctx)
			if derr != nil {
				return fmt.Errorf("audit syslog dial: %w", derr)
			}
			s.conn = c
		}
		_ = s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, werr := s.conn.Write([]byte(frame)); werr == nil {
			return nil
		} else {
			_ = s.conn.Close()
			s.conn = nil
			err = werr
		}
	}
	return fmt.Errorf("audit syslog write: %w", err)
}

// Close closes the underlying connection.
func (s *Syslog) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// FormatRFC5424 renders an event as an RFC 5424 message (facility: security/auth = 10).
func FormatRFC5424(e Event, hostname, appName string) (string, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	const facility = 10
	pri := facility*8 + syslogSeverity(e.Severity)
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s",
		pri,
		e.Time.UTC().Format(time.RFC3339Nano),
		nilvalue(hostname),
		nilvalue(appName),
		nilvalue(sanitizeMsgID(e.Type)),
		body,
	), nil
}

func syslogSeverity(s Severity) int {
	switch s {
	case SeverityCritical:
		return 2 // critical
	case SeverityHigh:
		return 4 // warning
	case SeverityLow:
		return 5 // notice
	default:
		return 6 // informational
	}
}

func nilvalue(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// MSGID is limited to 32 printable US-ASCII characters without spaces.
func sanitizeMsgID(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return -1
		}
		return r
	}, s)
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}
