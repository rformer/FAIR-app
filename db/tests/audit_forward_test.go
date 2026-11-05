package tests

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/approvals"
	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-002 T-16 (F-002-AC-22, AC-23, AC-24; design §6.4): forwarding the trail
// to a syslog destination over TLS.

// syslogServer is a syslog-over-TLS receiver (RFC 5425 octet counting) that
// can go down and come back on the same address.
type syslogServer struct {
	t      *testing.T
	addr   string
	conf   *tls.Config
	mu     sync.Mutex
	ln     net.Listener
	conns  []net.Conn
	frames []string
	// drop makes the receiver complete the handshake, then close each new
	// connection after this long without reading (a crash after accepting).
	drop time.Duration
}

func newSyslogServer(t *testing.T, maxVersion uint16) (*syslogServer, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siem.test"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	s := &syslogServer{t: t, conf: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion: tls.VersionTLS10, MaxVersion: maxVersion}} // #nosec G402 -- a test server offering old versions to prove the client refuses them
	s.start()
	t.Cleanup(s.stop)
	return s, roots
}

// sibling is another receiver with the same certificate, on a new address.
func (s *syslogServer) sibling(t *testing.T) *syslogServer {
	t.Helper()
	o := &syslogServer{t: t, conf: s.conf}
	o.start()
	t.Cleanup(o.stop)
	return o
}

func (s *syslogServer) start() {
	s.t.Helper()
	addr := s.addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := tls.Listen("tcp", addr, s.conf)
	if err != nil {
		s.t.Fatal(err)
	}
	s.mu.Lock()
	s.ln, s.addr = ln, ln.Addr().String()
	s.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			drop := s.drop
			s.mu.Unlock()
			if drop > 0 {
				go func() {
					_ = c.(*tls.Conn).HandshakeContext(context.Background())
					time.Sleep(drop)
					_ = c.Close() // unread data: the peer sees a reset
				}()
				continue
			}
			go s.read(c)
		}
	}()
}

func (s *syslogServer) read(c net.Conn) {
	r := bufio.NewReader(c)
	for {
		n, err := r.ReadString(' ')
		if err != nil {
			return
		}
		size, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(r, buf); err != nil {
			return
		}
		s.mu.Lock()
		s.frames = append(s.frames, string(buf))
		s.mu.Unlock()
	}
}

func (s *syslogServer) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

var sdRE = regexp.MustCompile(`^<(\d+)>1 (\S+) (\S+) fair-audit - (\S+) \[fair@32473 seq="(\d+)" chain="([0-9a-f]{64})" segment="(\d+)"\] (.*)$`)

type gotFrame struct {
	seq     int64
	chain   string
	segment string
	body    string
	msgID   string
}

// received waits until at least n frames arrived and parses them.
func (s *syslogServer) received(t *testing.T, n int) []gotFrame {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mu.Lock()
		frames := append([]string(nil), s.frames...)
		s.mu.Unlock()
		if len(frames) >= n || time.Now().After(deadline) {
			out := make([]gotFrame, 0, len(frames))
			for _, f := range frames {
				m := sdRE.FindStringSubmatch(f)
				if m == nil {
					t.Fatalf("not an RFC 5424 frame with fair@32473: %q", f)
				}
				seq, _ := strconv.ParseInt(m[5], 10, 64)
				out = append(out, gotFrame{seq: seq, chain: m[6], segment: m[7], body: m[8], msgID: m[4]})
			}
			if len(out) < n {
				t.Fatalf("%d frames, want %d", len(out), n)
			}
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type forwardEnv struct {
	e    *env
	pool *pgxpool.Pool
	seq  auditsvc.Sequencer
	fwd  *auditsvc.Forwarder
	addr string
	recs int
	age  time.Duration
	now  time.Time
}

func newForwardEnv(t *testing.T, e *env, roots *x509.CertPool) *forwardEnv {
	t.Helper()
	return newForwardEnvWith(t, e, auditsvc.SyslogDestination,
		&auditsvc.SyslogTransport{TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Hostname: "audit-0"})
}

// newForwardEnvWith forwards to the destination name through transport.
func newForwardEnvWith(t *testing.T, e *env, name string, transport auditsvc.Transport) *forwardEnv {
	t.Helper()
	pool := e.auditPool()
	fe := &forwardEnv{e: e, pool: pool, seq: auditsvc.Sequencer{DB: pool}, recs: 10_000, age: 15 * time.Minute}
	fe.fwd = &auditsvc.Forwarder{DB: pool, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool}), Name: name, Transport: transport, Batch: 4,
		Address:    func() (string, error) { return fe.addr, nil },
		Thresholds: func() (int, time.Duration) { return fe.recs, fe.age },
		Now: func() time.Time {
			if fe.now.IsZero() {
				return time.Now()
			}
			return fe.now
		}}
	return fe
}

// drain forwards until nothing is left (or an error).
func (fe *forwardEnv) drain(t *testing.T) (int, error) {
	t.Helper()
	total := 0
	for i := 0; i < 1000; i++ {
		n, err := fe.fwd.Step(context.Background())
		total += n
		if err != nil || n == 0 {
			return total, err
		}
	}
	t.Fatal("forwarding does not finish")
	return total, nil
}

// records returns every record's seq, chain hash and body, in order.
func (fe *forwardEnv) records(t *testing.T) []gotFrame {
	t.Helper()
	raw := fe.e.adminQuery(`SELECT coalesce(jsonb_agg(jsonb_build_object('seq', seq, 'chain', encode(chain_hash, 'hex'), 'segment', segment,
		'body', convert_from(body, 'UTF8')) ORDER BY seq), '[]') FROM audit.record`)
	var rows []struct {
		Seq     int64  `json:"seq"`
		Chain   string `json:"chain"`
		Segment int64  `json:"segment"`
		Body    string `json:"body"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatal(err)
	}
	out := make([]gotFrame, len(rows))
	for i, r := range rows {
		out[i] = gotFrame{seq: r.Seq, chain: r.Chain, segment: fmt.Sprint(r.Segment), body: r.Body}
	}
	return out
}

// destination is the syslog destination's status row.
func (fe *forwardEnv) destination(t *testing.T) map[string]any {
	t.Helper()
	var st struct {
		Destinations []map[string]any `json:"destinations"`
	}
	if err := json.Unmarshal([]byte(fe.e.adminQuery("SELECT audit.status()")), &st); err != nil || len(st.Destinations) != 1 {
		t.Fatalf("status destinations %+v %v", st, err)
	}
	return st.Destinations[0]
}

func sameRecords(t *testing.T, got, want []gotFrame) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d frames, %d records", len(got), len(want))
	}
	for i := range want {
		if got[i].seq != want[i].seq || got[i].chain != want[i].chain || got[i].segment != want[i].segment || got[i].body != want[i].body {
			t.Fatalf("frame %d: %+v\nrecord: %+v", i, got[i], want[i])
		}
	}
}

// AC-22, AC-23: every record in order with its position and integrity data;
// an outage queues them and delivery resumes in order.
func TestAuditForwardSyslog(t *testing.T) {
	e := setup(t)
	srv, roots := newSyslogServer(t, 0)
	fe := newForwardEnv(t, e, roots)
	submitN(t, e, "fw", 10)
	drainTrail(t, fe.seq)

	// No destination: nothing is sent and nothing is recorded.
	if n, err := fe.drain(t); n != 0 || err != nil {
		t.Fatalf("without a destination: %d %v", n, err)
	}
	if got := e.adminQuery("SELECT count(*) FROM audit.destination"); got != "0" {
		t.Fatalf("%s destinations", got)
	}

	fe.addr = srv.addr
	if n, err := fe.drain(t); err != nil || n != 10 {
		t.Fatalf("forward: %d %v", n, err)
	}
	sameRecords(t, srv.received(t, 10), fe.records(t))
	d := fe.destination(t)
	if d["address"] != srv.addr || d["backlog"] != float64(0) || d["last_error"] != nil || d["last_sent_at"] == nil || d["backlog_alert"] != false {
		t.Fatalf("destination %v", d)
	}
	f := srv.received(t, 10)[0]
	if f.msgID != "db.migrated" {
		t.Fatalf("MSGID %q", f.msgID)
	}

	// The destination goes down: records wait, and the error is shown.
	srv.stop()
	submitN(t, e, "fw-out", 6)
	drainTrail(t, fe.seq)
	if _, err := fe.drain(t); err == nil {
		t.Fatal("sent to a stopped destination")
	}
	d = fe.destination(t)
	if d["backlog"] != float64(6) || d["last_error"] == nil || d["oldest_waiting_at"] == nil {
		t.Fatalf("during the outage %v", d)
	}
	// Back: delivery resumes after the cursor, in order, with nothing lost.
	srv.start()
	if n, err := fe.drain(t); err != nil || n != 6 {
		t.Fatalf("after the outage: %d %v", n, err)
	}
	all := srv.received(t, 16)
	recs := fe.records(t)
	sameRecords(t, all, recs[:16])
	if d = fe.destination(t); d["backlog"] != float64(0) || d["last_error"] != nil {
		t.Fatalf("after the outage %v", d)
	}

	// The SIEM's copy of the checkpoints (AC-10): the forwarded bodies, as
	// a SIEM exports them, give fair-audit-verify compare the checkpoints.
	cp := checkpointer(t, fe.pool, newCheckpointKey(t))
	if _, err := cp.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	drainTrail(t, fe.seq)
	if _, err := fe.drain(t); err != nil {
		t.Fatal(err)
	}
	var export strings.Builder
	for _, f := range srv.received(t, len(fe.records(t))) {
		export.WriteString(f.body + "\n")
	}
	siem, err := evidence.ReadCheckpointStream(strings.NewReader(export.String()), "siem")
	if err != nil || len(siem) != 1 {
		t.Fatalf("checkpoints from the forwarded stream: %d %v", len(siem), err)
	}

	// The receiver restarts between batches: the connection the forwarder
	// holds is stale, and nothing is lost.
	srv.stop()
	srv.start()
	submitN(t, e, "fw-stale", 3)
	drainTrail(t, fe.seq)
	// The stale connection is noticed before sending: no failed attempt.
	if _, err := fe.drain(t); err != nil {
		t.Fatalf("after a receiver restart: %v", err)
	}
	if d := fe.destination(t); d["last_error"] != nil {
		t.Fatalf("a restart recorded an error: %v", d)
	}
	sameRecords(t, srv.received(t, len(fe.records(t))), fe.records(t))

	// The receiver accepts, then drops the connection before reading the
	// batch: the batch is not counted as sent, and comes again.
	srv.mu.Lock()
	srv.drop = 50 * time.Millisecond
	srv.mu.Unlock()
	srv.stop()
	srv.start()
	cursor := e.adminQuery("SELECT last_seq FROM audit.destination")
	submitN(t, e, "fw-drop", 2)
	drainTrail(t, fe.seq)
	if _, err := fe.drain(t); err == nil {
		t.Fatal("a batch the receiver never read counted as sent")
	}
	if got := e.adminQuery("SELECT last_seq FROM audit.destination"); got != cursor {
		t.Fatalf("the cursor moved from %s to %s over a dropped batch", cursor, got)
	}
	srv.mu.Lock()
	srv.drop = 0
	srv.mu.Unlock()
	if _, err := fe.drain(t); err != nil {
		t.Fatal(err)
	}
	sameRecords(t, srv.received(t, len(fe.records(t))), fe.records(t))

	// The cursor moves forward only, and not past the head.
	head := e.adminQuery("SELECT seq FROM audit.head")
	e.mustFail("app_audit", "SELECT audit.forward_advance('syslog', 1)", "cannot advance")
	e.mustFail("app_audit", "SELECT audit.forward_advance('syslog', "+head+"0)", "cannot advance")
	e.mustFail("app_rw", "SELECT audit.forward_advance('syslog', 1)", "permission denied")
}

// AC-23: the backlog alert is recorded once per crossing, by count or by
// age, and the recovery once.
func TestAuditForwardBacklogAlert(t *testing.T) {
	e := setup(t)
	srv, roots := newSyslogServer(t, 0)
	fe := newForwardEnv(t, e, roots)
	fe.addr, fe.recs = srv.addr, 3
	count := func(typ string) int {
		drainTrail(t, fe.seq)
		return len(trailEventsOf(t, e, typ))
	}

	srv.stop()
	submitN(t, e, "bl", 3)
	drainTrail(t, fe.seq)
	_, _ = fe.drain(t)
	if n := count("audit.forward_backlog"); n != 0 { // 3 waiting is not over 3
		t.Fatalf("%d alerts at the threshold", n)
	}
	submitN(t, e, "bl2", 2)
	drainTrail(t, fe.seq)
	for i := 0; i < 3; i++ {
		_, _ = fe.drain(t)
	}
	drainTrail(t, fe.seq)
	evs := trailEventsOf(t, e, "audit.forward_backlog")
	if len(evs) != 1 {
		t.Fatalf("%d backlog alerts, want one per crossing", len(evs))
	}
	a := attrs(evs[0])
	if evs[0]["severity"] != "high" || evs[0]["target"] != "audit:destination:syslog" || a["threshold_records"] != "3" || a["address"] != srv.addr ||
		a["last_error"] == nil || a["oldest_waiting_at"] == nil {
		t.Fatalf("backlog event %v", evs[0])
	}
	if fe.destination(t)["backlog_alert"] != true {
		t.Fatal("the alert is not shown")
	}

	srv.start()
	_, _ = fe.drain(t)
	if n := count("audit.forward_recovered"); n != 1 {
		t.Fatalf("%d recoveries", n)
	}
	_, _ = fe.drain(t)
	if n := count("audit.forward_recovered"); n != 1 {
		t.Fatalf("%d recoveries after another step", n)
	}
	if fe.destination(t)["backlog_alert"] != false {
		t.Fatal("the alert is still shown")
	}

	// By age: the oldest waiting record is older than the threshold.
	fe.recs = 10_000
	srv.stop()
	submitN(t, e, "age", 1)
	drainTrail(t, fe.seq)
	_, _ = fe.drain(t)
	if n := count("audit.forward_backlog"); n != 1 {
		t.Fatalf("%d alerts with a young backlog", n)
	}
	fe.now = time.Now().Add(time.Hour)
	_, _ = fe.drain(t)
	if n := count("audit.forward_backlog"); n != 2 {
		t.Fatalf("%d alerts after the age crossing", n)
	}
	fe.now = time.Time{}
	srv.start()
	_, _ = fe.drain(t)
	if n := count("audit.forward_recovered"); n != 2 {
		t.Fatalf("%d recoveries", n)
	}
}

// trailEventsOf returns the recorded events of a type, oldest first.
func trailEventsOf(t *testing.T, e *env, typ string) []map[string]any {
	t.Helper()
	raw := e.adminQuery(fmt.Sprintf(`SELECT coalesce(jsonb_agg(convert_from(body, 'UTF8')::jsonb ORDER BY seq), '[]') FROM audit.record WHERE type = '%s'`, typ))
	var out []map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// AC-22: TLS 1.2 is the floor; a destination that cannot be named or is
// refused (air-gapped: outside the enclave) gets nothing.
func TestAuditForwardRefusals(t *testing.T) {
	e := setup(t)
	old, roots := newSyslogServer(t, tls.VersionTLS11)
	fe := newForwardEnv(t, e, roots)
	submitN(t, e, "rf", 2)
	drainTrail(t, fe.seq)

	fe.addr = old.addr
	if _, err := fe.drain(t); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("TLS 1.1 destination: %v", err)
	}
	if got := fe.destination(t); got["last_seq"] != float64(0) || got["last_error"] == nil {
		t.Fatalf("after a refused handshake %v", got)
	}
	old.mu.Lock()
	n := len(old.frames)
	old.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d frames over TLS 1.1", n)
	}

	fe.addr = "no-port"
	if _, err := fe.drain(t); err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("bad address: %v", err)
	}
	fe.fwd.Check = func(context.Context, string) error { return errors.New("outside the enclave") }
	fe.addr = "siem.example.com:6514"
	if _, err := fe.drain(t); err == nil || !strings.Contains(err.Error(), "outside the enclave") {
		t.Fatalf("refused destination: %v", err)
	}
	if got := fe.destination(t); got["last_seq"] != float64(0) {
		t.Fatalf("sent to a refused destination: %v", got)
	}
}

// AC-24, decisions of 2026-11-05: the destination is the F-015 setting. A
// new destination gets the whole online trail; a changed address keeps the
// cursor; clearing it needs a second approver and stops forwarding; setting
// it again starts from the beginning.
func TestAuditForwardDestinationSetting(t *testing.T) {
	e, ev, _ := auditSettingsFixture(t)
	ctx := context.Background()
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	first, roots := newSyslogServer(t, 0)
	fe := newForwardEnv(t, e, roots)
	sc := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: fe.pool}, Service: "audit"})
	if err := sc.Register(settings.F002Defs()...); err != nil {
		t.Fatal(err)
	}
	fe.fwd.Address = func() (string, error) {
		if err := sc.Refresh(ctx); err != nil {
			return "", err
		}
		return sc.Enum(settings.KeyAuditSyslogDestination, "")
	}
	submitN(t, e, "ds", 5)
	drainTrail(t, fe.seq)
	set := func(addr, why string) posture.ChangeResult {
		t.Helper()
		v, _ := json.Marshal(addr)
		res, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuditSyslogDestination, Value: v, Explanation: why})
		if err != nil {
			t.Fatalf("set %q: %v", addr, err)
		}
		return res
	}

	// Set: the whole trail so far.
	set(first.addr, "")
	drainTrail(t, fe.seq)
	if _, err := fe.drain(t); err != nil {
		t.Fatal(err)
	}
	all := fe.records(t)
	got := first.received(t, len(all))
	if got[0].seq != all[0].seq {
		t.Fatalf("the new destination started at %d, not %d", got[0].seq, all[0].seq)
	}

	// Moved: the second address gets only what follows.
	second := first.sibling(t)
	set(second.addr, "")
	submitN(t, e, "moved", 1)
	drainTrail(t, fe.seq)
	cursor := e.adminQuery("SELECT last_seq FROM audit.destination")
	if _, err := fe.drain(t); err != nil {
		t.Fatal(err)
	}
	moved := second.received(t, 1)
	if fmt.Sprint(moved[0].seq) != fmt.Sprint(atoi(cursor)+1) {
		t.Fatalf("after the move the first record was %d, cursor %s", moved[0].seq, cursor)
	}

	// Clearing is a loosening: pending until a second administrator approves,
	// forwarding continues meanwhile.
	clearing := set("", "moving SIEMs")
	if clearing.Outcome != posture.PendingApproval {
		t.Fatalf("clear: %+v", clearing)
	}
	submitN(t, e, "ds2", 1)
	drainTrail(t, fe.seq)
	before := len(second.received(t, 1))
	if _, err := fe.drain(t); err != nil {
		t.Fatal(err)
	}
	if len(second.received(t, before+1)) <= before {
		t.Fatal("forwarding stopped before the clearing was approved")
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin2, clearing.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.ApplyApproved(ctx, clearing.ChangeID); err != nil {
		t.Fatal(err)
	}
	drainTrail(t, fe.seq)
	if _, err := fe.drain(t); err != nil {
		t.Fatal(err)
	}
	if d := fe.destination(t); d["address"] != nil || d["backlog"] != float64(0) {
		t.Fatalf("cleared destination %v", d)
	}
	sent := len(second.received(t, 0))
	submitN(t, e, "ds3", 2)
	drainTrail(t, fe.seq)
	if _, err := fe.drain(t); err != nil {
		t.Fatal(err)
	}
	if len(second.received(t, 0)) != sent {
		t.Fatal("sent after the destination was cleared")
	}

	// Set again: from the beginning of the trail.
	third := first.sibling(t)
	set(third.addr, "")
	drainTrail(t, fe.seq)
	if _, err := fe.drain(t); err != nil {
		t.Fatal(err)
	}
	again := third.received(t, 1)
	if again[0].seq != all[0].seq {
		t.Fatalf("the re-added destination started at %d", again[0].seq)
	}
	sameRecords(t, third.received(t, len(fe.records(t))), fe.records(t))
}
