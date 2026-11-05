package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	events "github.com/rformer/fair-app/pkg/audit"
)

// SyslogPEN is the private enterprise number of the structured-data ID
// fair@<PEN>: the documentation number of RFC 5612 until one is registered
// with IANA (design §15; decision of 2026-11-05).
const SyslogPEN = 32473

// SyslogSDID is the structured-data element each forwarded record carries.
var SyslogSDID = "fair@" + strconv.Itoa(SyslogPEN)

// Destination names (rows of audit.destination; the settings
// audit.syslog_destination and audit.otlp_destination).
const (
	SyslogDestination = "syslog"
	OTLPDestination   = "otlp"
)

// ForwardEvery is how often the leader forwards when it has caught up.
const ForwardEvery = 5 * time.Second

const forwardBatch = 1000

// SyslogTLS is the syslog forwarder's TLS configuration from the
// environment (F-002 T-16; these variables moved from every service to the
// audit service): TLS 1.2 or later, the destination's CA from
// FAIR_AUDIT_SYSLOG_CA_FILE (else the system roots). Plain TCP
// (FAIR_AUDIT_SYSLOG_PLAINTEXT=true, a local relay; nil config) is refused
// outside development.
func SyslogTLS(env string, getenv func(string) string) (*tls.Config, error) {
	return forwardTLS("FAIR_AUDIT_SYSLOG", "syslog", env, getenv)
}

// OTLPTLS is the OTLP forwarder's (T-17): FAIR_AUDIT_OTLP_CA_FILE and
// FAIR_AUDIT_OTLP_PLAINTEXT, with the same rules.
func OTLPTLS(env string, getenv func(string) string) (*tls.Config, error) {
	return forwardTLS("FAIR_AUDIT_OTLP", "OTLP", env, getenv)
}

func forwardTLS(prefix, what, env string, getenv func(string) string) (*tls.Config, error) {
	if getenv(prefix+"_PLAINTEXT") == "true" {
		if env != "development" {
			return nil, fmt.Errorf("%s_PLAINTEXT: plaintext %s is for development only; the destination needs TLS", prefix, what)
		}
		return nil, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if f := getenv(prefix + "_CA_FILE"); f != "" {
		pem, err := os.ReadFile(f) // #nosec G304 -- operator-supplied CA file
		if err != nil {
			return nil, fmt.Errorf("%s_CA_FILE: %w", prefix, err)
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s_CA_FILE holds no certificate", prefix)
		}
	}
	return tc, nil
}

// ForwardRecord is one record as the trail holds it.
type ForwardRecord struct {
	Seq     int64
	Segment int64
	Body    []byte
	Leaf    []byte
	Chain   []byte
}

// Transport delivers records to one kind of destination.
type Transport interface {
	// Kind is the destination kind (audit.destination.kind).
	Kind() string
	// Send delivers recs, in order, to addr. It returns nil only when the
	// batch may count as delivered; otherwise all of it is sent again.
	Send(ctx context.Context, addr string, recs []ForwardRecord) error
	// Close drops any connection.
	Close()
}

// Forwarder sends the trail to one SIEM destination (F-002 T-16, T-17;
// AC-22, AC-23; design §6.4): every record in sequence order through its
// Transport. The cursor advances only after the transport delivered a
// batch, so an outage queues records and delivery resumes in order, at
// least once and never lost. The backlog alert is raised and cleared once
// per crossing. Run it on the leader.
type Forwarder struct {
	DB        *pgxpool.Pool // app_audit
	Audit     events.Emitter
	Name      string // SyslogDestination or OTLPDestination
	Transport Transport
	// Address is the destination (its setting, host:port; "" for none).
	Address func() (string, error)
	// Thresholds are audit.forward_backlog_records and _age.
	Thresholds func() (int, time.Duration)
	// Check refuses a destination before anything is sent (air-gapped:
	// internal addresses only).
	Check func(ctx context.Context, addr string) error
	Batch int
	Now   func() time.Time

	mu sync.Mutex
}

func (f *Forwarder) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Forwarder) batch() int {
	if f.Batch <= 0 {
		return forwardBatch
	}
	return f.Batch
}

// Step sends the next batch of records after the cursor and returns how
// many were sent.
func (f *Forwarder) Step(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	addr, err := f.Address()
	if err != nil {
		return 0, fmt.Errorf("audit forward: %s destination: %w", f.Name, err)
	}
	if addr == "" {
		f.Transport.Close()
		_, err := f.DB.Exec(ctx, "SELECT audit.forward_clear($1)", f.Name)
		return 0, err
	}
	var cursor int64
	if err := f.DB.QueryRow(ctx, "SELECT audit.forward_destination($1, $2, $3)", f.Name, f.Transport.Kind(), addr).Scan(&cursor); err != nil {
		return 0, fmt.Errorf("audit forward: %w", err)
	}
	if err := f.alert(ctx, addr, ""); err != nil {
		return 0, err
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return 0, f.failed(ctx, addr, fmt.Errorf("destination %q is not host:port", addr))
	}
	if f.Check != nil {
		if err := f.Check(ctx, addr); err != nil {
			return 0, f.failed(ctx, addr, err)
		}
	}
	rows, err := f.DB.Query(ctx, "SELECT seq, segment, body, leaf_hash, chain_hash FROM audit.verify_records($1, $2, $3)",
		cursor+1, int64(math.MaxInt64), f.batch())
	if err != nil {
		return 0, fmt.Errorf("audit forward: read: %w", err)
	}
	recs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ForwardRecord])
	if err != nil {
		return 0, fmt.Errorf("audit forward: read: %w", err)
	}
	if len(recs) == 0 {
		return 0, nil
	}
	if err := f.Transport.Send(ctx, addr, recs); err != nil {
		return 0, f.failed(ctx, addr, err)
	}
	if _, err := f.DB.Exec(ctx, "SELECT audit.forward_advance($1, $2)", f.Name, recs[len(recs)-1].Seq); err != nil {
		return 0, fmt.Errorf("audit forward: advance: %w", err)
	}
	return len(recs), f.alert(ctx, addr, "")
}

// failed records a sending failure on the destination (and the backlog
// alert it may raise) and returns it.
func (f *Forwarder) failed(ctx context.Context, addr string, cause error) error {
	err := fmt.Errorf("audit forward to %s: %w", addr, cause)
	if _, rerr := f.DB.Exec(ctx, "SELECT audit.forward_error($1, $2)", f.Name, cause.Error()); rerr != nil {
		return errors.Join(err, rerr)
	}
	if aerr := f.alert(ctx, addr, cause.Error()); aerr != nil {
		return errors.Join(err, aerr)
	}
	return err
}

// alert raises the backlog alert when the backlog crosses either threshold
// and clears it when it is back under both, recording the crossing once
// (audit.forward_backlog, high; audit.forward_recovered, info).
func (f *Forwarder) alert(ctx context.Context, addr, lastErr string) error {
	var waiting int64
	var oldest *time.Time
	var alerted bool
	var recorded *string
	if err := f.DB.QueryRow(ctx, "SELECT waiting, oldest_at, alerted, last_error FROM audit.forward_backlog($1)", f.Name).
		Scan(&waiting, &oldest, &alerted, &recorded); err != nil {
		return fmt.Errorf("audit forward: backlog: %w", err)
	}
	if lastErr == "" && recorded != nil {
		lastErr = *recorded
	}
	records, age := 10_000, 15*time.Minute
	if f.Thresholds != nil {
		records, age = f.Thresholds()
	}
	over := waiting > int64(records) || (oldest != nil && f.now().Sub(*oldest) > age)
	if over == alerted {
		return nil
	}
	return pgx.BeginFunc(ctx, f.DB, func(tx pgx.Tx) error {
		var changed bool
		if err := tx.QueryRow(ctx, "SELECT audit.forward_set_alert($1, $2)", f.Name, over).Scan(&changed); err != nil || !changed {
			return err
		}
		ev := events.Event{Type: "audit.forward_recovered", Severity: events.SeverityInfo, Actor: "system:audit",
			Target: "audit:destination:" + f.Name, Attributes: map[string]string{
				"destination": f.Name, "kind": f.Transport.Kind(), "address": addr, "waiting": strconv.FormatInt(waiting, 10)}}
		if over {
			ev.Type, ev.Severity = "audit.forward_backlog", events.SeverityHigh
			ev.Attributes["threshold_records"] = strconv.Itoa(records)
			ev.Attributes["threshold_age"] = age.String()
			if oldest != nil {
				ev.Attributes["oldest_waiting_at"] = oldest.UTC().Format(time.RFC3339)
			}
			if lastErr != "" {
				ev.Attributes["last_error"] = truncate(lastErr, 500)
			}
		}
		return f.Audit.Emit(events.WithTx(ctx, tx), ev)
	})
}

// Run forwards until ctx ends: batch after batch while there is a backlog,
// then every interval (ForwardEvery when zero). Errors go to onErr.
func (f *Forwarder) Run(ctx context.Context, every time.Duration, onErr func(error)) error {
	if every <= 0 {
		every = ForwardEvery
	}
	defer func() {
		f.mu.Lock()
		f.Transport.Close()
		f.mu.Unlock()
	}()
	for {
		n, err := f.Step(ctx)
		if err != nil && onErr != nil && ctx.Err() == nil {
			onErr(err)
		}
		if err == nil && n == f.batch() {
			continue // more waiting
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}

// SyslogTransport sends records as RFC 5424 messages over TLS (RFC 5425,
// octet-counting framing; T-16): the body exactly as recorded and the
// record's position and integrity data as structured data
// [fair@32473 seq= chain= segment=]. Syslog has no acknowledgement, and a
// write onto a connection the receiver has closed can still succeed: a
// stale connection is replaced before each batch, and a batch counts as
// delivered only when the connection is still up after it.
type SyslogTransport struct {
	TLS      *tls.Config // nil: plain TCP (SyslogTLS allows it in development only)
	Hostname string
	// ProbeWait is how long to wait for a reset after a batch (100 ms when
	// zero).
	ProbeWait time.Duration

	conn     net.Conn
	connAddr string
}

// Kind implements Transport.
func (s *SyslogTransport) Kind() string { return "syslog" }

// Send implements Transport.
func (s *SyslogTransport) Send(ctx context.Context, addr string, recs []ForwardRecord) error {
	var buf []byte
	for _, r := range recs {
		frame, err := SyslogFrame(r.Seq, r.Segment, r.Chain, r.Body, s.Hostname)
		if err != nil {
			return err
		}
		buf = append(buf, frame...)
	}
	// A connection the destination has closed is replaced before sending: a
	// write onto it could still succeed and lose the batch.
	if s.conn != nil && (s.connAddr != addr || !s.alive()) {
		s.Close()
	}
	if s.conn == nil {
		c, err := s.dial(ctx, addr)
		if err != nil {
			return err
		}
		s.conn, s.connAddr = c, addr
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, werr := s.conn.Write(buf)
	// The batch counts as sent only when the write succeeded and the
	// connection is still up afterwards (a peer that went away answers the
	// write with a reset).
	if werr == nil && !s.alive() {
		werr = errors.New("the destination closed the connection")
	}
	if werr != nil {
		s.Close()
	}
	return werr
}

// alive reports whether the connection is still open: a syslog receiver
// never writes, so a read that does not time out within ProbeWait means
// the peer closed or reset it.
func (s *SyslogTransport) alive() bool {
	wait := s.ProbeWait
	if wait <= 0 {
		wait = 100 * time.Millisecond
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(wait))
	var one [1]byte
	_, err := s.conn.Read(one[:])
	_ = s.conn.SetReadDeadline(time.Time{})
	var ne net.Error
	return err == nil || (errors.As(err, &ne) && ne.Timeout())
}

func (s *SyslogTransport) dial(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if s.TLS == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	td := &tls.Dialer{NetDialer: d, Config: s.TLS}
	return td.DialContext(ctx, "tcp", addr)
}

// Close implements Transport.
func (s *SyslogTransport) Close() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

// SyslogFrame is one record as an RFC 5424 message with RFC 6587
// octet-counting framing: facility security/authorization (10), the
// severity, time and type from the body, APP-NAME fair-audit, the
// structured data [fair@32473 seq="" chain="" segment=""] and the body
// exactly as recorded as MSG.
func SyslogFrame(seq, segment int64, chain, body []byte, hostname string) ([]byte, error) {
	ev, err := recordHeader(seq, body)
	if err != nil {
		return nil, err
	}
	ts := "-"
	if !ev.time.IsZero() {
		ts = ev.time.UTC().Format("2006-01-02T15:04:05.000000Z")
	}
	msg := fmt.Sprintf("<%d>1 %s %s fair-audit - %s [%s seq=\"%d\" chain=\"%s\" segment=\"%d\"] %s",
		10*8+syslogSeverity(ev.Severity), ts, header(hostname, 255), header(ev.Type, 32), SyslogSDID, seq, hex.EncodeToString(chain), segment, body)
	return []byte(strconv.Itoa(len(msg)) + " " + msg), nil
}

type recordFields struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Time     string `json:"time"`
	time     time.Time
}

// recordHeader reads a body's type, severity and time; a body is one line
// of JSON.
func recordHeader(seq int64, body []byte) (recordFields, error) {
	var ev recordFields
	if err := json.Unmarshal(body, &ev); err != nil {
		return ev, fmt.Errorf("record %d: the body is not JSON: %w", seq, err)
	}
	if strings.ContainsAny(string(body), "\r\n") {
		return ev, fmt.Errorf("record %d: the body is not one line", seq)
	}
	if t, err := time.Parse(time.RFC3339Nano, ev.Time); err == nil {
		ev.time = t
	}
	return ev, nil
}

func syslogSeverity(s string) int {
	switch s {
	case "critical":
		return 2
	case "high":
		return 4
	case "low":
		return 5
	default:
		return 6
	}
}

// header keeps an RFC 5424 header field to printable US-ASCII without
// spaces, at most n characters ("-" when empty).
func header(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	if s == "" {
		return "-"
	}
	return s
}
