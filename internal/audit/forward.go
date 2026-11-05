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

// SyslogDestination is the syslog destination's name (its row in
// audit.destination; the setting audit.syslog_destination).
const SyslogDestination = "syslog"

// ForwardEvery is how often the leader forwards when it has caught up.
const ForwardEvery = 5 * time.Second

const forwardBatch = 1000

// SyslogTLS is the forwarder's TLS configuration from the environment
// (F-002 T-16; these variables moved from every service to the audit
// service): TLS 1.2 or later, the destination's CA from
// FAIR_AUDIT_SYSLOG_CA_FILE (else the system roots). Plain TCP
// (FAIR_AUDIT_SYSLOG_PLAINTEXT=true, a local relay; nil config) is refused
// outside development.
func SyslogTLS(env string, getenv func(string) string) (*tls.Config, error) {
	if getenv("FAIR_AUDIT_SYSLOG_PLAINTEXT") == "true" {
		if env != "development" {
			return nil, errors.New("FAIR_AUDIT_SYSLOG_PLAINTEXT: plain TCP syslog is for development only; the destination needs a TLS listener")
		}
		return nil, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if f := getenv("FAIR_AUDIT_SYSLOG_CA_FILE"); f != "" {
		pem, err := os.ReadFile(f) // #nosec G304 -- operator-supplied CA file
		if err != nil {
			return nil, fmt.Errorf("FAIR_AUDIT_SYSLOG_CA_FILE: %w", err)
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("FAIR_AUDIT_SYSLOG_CA_FILE holds no certificate")
		}
	}
	return tc, nil
}

// SyslogForwarder sends the trail to the syslog destination (F-002 T-16,
// AC-22, AC-23; design §6.4): every record in sequence order as an RFC 5424
// message over TLS (RFC 5425, octet-counting framing), its body exactly as
// recorded and its position and integrity data as structured data
// [fair@32473 seq= chain= segment=]. The cursor advances only after the
// records were written, so an outage queues them and delivery resumes in
// order (at least once: syslog has no acknowledgement, so a batch counts
// as sent only when the connection is still up after it). The
// backlog alert is raised and cleared once per crossing. Run it on the
// leader.
type SyslogForwarder struct {
	DB    *pgxpool.Pool // app_audit
	Audit events.Emitter
	// Address is the destination (the setting audit.syslog_destination,
	// host:port; "" for none).
	Address func() (string, error)
	// Thresholds are audit.forward_backlog_records and _age.
	Thresholds func() (int, time.Duration)
	TLS        *tls.Config // nil: plain TCP (SyslogTLS allows it in development only)
	// Check refuses a destination before anything is sent (air-gapped:
	// internal addresses only).
	Check    func(ctx context.Context, addr string) error
	Hostname string
	Batch    int
	Now      func() time.Time
	// ProbeWait is how long to wait for a reset after a batch (100 ms when
	// zero).
	ProbeWait time.Duration

	mu       sync.Mutex
	conn     net.Conn
	connAddr string
}

func (f *SyslogForwarder) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

type forwardRecord struct {
	Seq     int64
	Segment int64
	Body    []byte
	Leaf    []byte
	Chain   []byte
}

// Step sends the next batch of records after the cursor and returns how
// many were sent.
func (f *SyslogForwarder) Step(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	addr, err := f.Address()
	if err != nil {
		return 0, fmt.Errorf("audit forward: destination: %w", err)
	}
	if addr == "" {
		f.closeConn()
		_, err := f.DB.Exec(ctx, "SELECT audit.forward_clear($1)", SyslogDestination)
		return 0, err
	}
	var cursor int64
	if err := f.DB.QueryRow(ctx, "SELECT audit.forward_destination($1, 'syslog', $2)", SyslogDestination, addr).Scan(&cursor); err != nil {
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
	batch := f.Batch
	if batch <= 0 {
		batch = forwardBatch
	}
	rows, err := f.DB.Query(ctx, "SELECT seq, segment, body, leaf_hash, chain_hash FROM audit.verify_records($1, $2, $3)",
		cursor+1, int64(math.MaxInt64), batch)
	if err != nil {
		return 0, fmt.Errorf("audit forward: read: %w", err)
	}
	recs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[forwardRecord])
	if err != nil {
		return 0, fmt.Errorf("audit forward: read: %w", err)
	}
	if len(recs) == 0 {
		return 0, nil
	}
	var buf []byte
	for _, r := range recs {
		frame, err := SyslogFrame(r.Seq, r.Segment, r.Chain, r.Body, f.Hostname)
		if err != nil {
			return 0, f.failed(ctx, addr, err)
		}
		buf = append(buf, frame...)
	}
	// A connection the destination has closed is replaced before sending: a
	// write onto it could still succeed and lose the batch.
	if f.conn != nil && (f.connAddr != addr || !f.alive()) {
		f.closeConn()
	}
	if f.conn == nil {
		c, err := f.dial(ctx, addr)
		if err != nil {
			return 0, f.failed(ctx, addr, err)
		}
		f.conn, f.connAddr = c, addr
	}
	_ = f.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, werr := f.conn.Write(buf)
	// Syslog has no acknowledgement: the batch counts as sent only when the
	// write succeeded and the connection is still up afterwards (a peer
	// that went away answers the write with a reset). Otherwise the whole
	// batch is sent again later, so delivery is at least once, never lost.
	if werr == nil && !f.alive() {
		werr = errors.New("the destination closed the connection")
	}
	if werr != nil {
		f.closeConn()
		return 0, f.failed(ctx, addr, werr)
	}
	if _, err := f.DB.Exec(ctx, "SELECT audit.forward_advance($1, $2)", SyslogDestination, recs[len(recs)-1].Seq); err != nil {
		return 0, fmt.Errorf("audit forward: advance: %w", err)
	}
	return len(recs), f.alert(ctx, addr, "")
}

// alive reports whether the connection is still open: a syslog receiver
// never writes, so a read that does not time out within ProbeWait means
// the peer closed or reset it.
func (f *SyslogForwarder) alive() bool {
	wait := f.ProbeWait
	if wait <= 0 {
		wait = 100 * time.Millisecond
	}
	_ = f.conn.SetReadDeadline(time.Now().Add(wait))
	var one [1]byte
	_, err := f.conn.Read(one[:])
	_ = f.conn.SetReadDeadline(time.Time{})
	var ne net.Error
	return err == nil || (errors.As(err, &ne) && ne.Timeout())
}

func (f *SyslogForwarder) dial(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if f.TLS == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	td := &tls.Dialer{NetDialer: d, Config: f.TLS}
	return td.DialContext(ctx, "tcp", addr)
}

func (f *SyslogForwarder) closeConn() {
	if f.conn != nil {
		_ = f.conn.Close()
		f.conn = nil
	}
}

// failed records a sending failure on the destination (and the backlog
// alert it may raise) and returns it.
func (f *SyslogForwarder) failed(ctx context.Context, addr string, cause error) error {
	err := fmt.Errorf("audit forward to %s: %w", addr, cause)
	if _, rerr := f.DB.Exec(ctx, "SELECT audit.forward_error($1, $2)", SyslogDestination, cause.Error()); rerr != nil {
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
func (f *SyslogForwarder) alert(ctx context.Context, addr, lastErr string) error {
	var waiting int64
	var oldest *time.Time
	var alerted bool
	var recorded *string
	if err := f.DB.QueryRow(ctx, "SELECT waiting, oldest_at, alerted, last_error FROM audit.forward_backlog($1)", SyslogDestination).
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
		if err := tx.QueryRow(ctx, "SELECT audit.forward_set_alert($1, $2)", SyslogDestination, over).Scan(&changed); err != nil || !changed {
			return err
		}
		ev := events.Event{Type: "audit.forward_recovered", Severity: events.SeverityInfo, Actor: "system:audit",
			Target: "audit:destination:" + SyslogDestination, Attributes: map[string]string{
				"destination": SyslogDestination, "kind": "syslog", "address": addr, "waiting": strconv.FormatInt(waiting, 10)}}
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
func (f *SyslogForwarder) Run(ctx context.Context, every time.Duration, onErr func(error)) error {
	if every <= 0 {
		every = ForwardEvery
	}
	defer func() {
		f.mu.Lock()
		f.closeConn()
		f.mu.Unlock()
	}()
	batch := f.Batch
	if batch <= 0 {
		batch = forwardBatch
	}
	for {
		n, err := f.Step(ctx)
		if err != nil && onErr != nil && ctx.Err() == nil {
			onErr(err)
		}
		if err == nil && n == batch {
			continue // more waiting
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}

// SyslogFrame is one record as an RFC 5424 message with RFC 6587
// octet-counting framing: facility security/authorization (10), the
// severity, time and type from the body, APP-NAME fair-audit, the
// structured data [fair@32473 seq="" chain="" segment=""] and the body
// exactly as recorded as MSG.
func SyslogFrame(seq, segment int64, chain, body []byte, hostname string) ([]byte, error) {
	var ev struct {
		Type     string `json:"type"`
		Severity string `json:"severity"`
		Time     string `json:"time"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, fmt.Errorf("record %d: the body is not JSON: %w", seq, err)
	}
	if strings.ContainsAny(string(body), "\r\n") {
		return nil, fmt.Errorf("record %d: the body is not one line", seq)
	}
	ts := "-"
	if t, err := time.Parse(time.RFC3339Nano, ev.Time); err == nil {
		ts = t.UTC().Format("2006-01-02T15:04:05.000000Z")
	}
	msg := fmt.Sprintf("<%d>1 %s %s fair-audit - %s [%s seq=\"%d\" chain=\"%s\" segment=\"%d\"] %s",
		10*8+syslogSeverity(ev.Severity), ts, header(hostname, 255), header(ev.Type, 32), SyslogSDID, seq, hex.EncodeToString(chain), segment, body)
	return []byte(strconv.Itoa(len(msg)) + " " + msg), nil
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
