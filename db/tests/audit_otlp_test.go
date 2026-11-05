package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	auditsvc "github.com/rformer/fair-app/internal/audit"
)

// F-002 T-17 (F-002-AC-22; design §6.4): forwarding the trail as OTLP logs
// over gRPC with TLS, with the cursor semantics of T-16.

// testServerCert is a self-signed server certificate for 127.0.0.1 and the
// pool that trusts it.
func testServerCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "otlp.test"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

// otlpReceiver is an OTLP logs receiver over TLS that can go down, refuse
// exports or reject records.
type otlpReceiver struct {
	collogspb.UnimplementedLogsServiceServer
	t      *testing.T
	conf   *tls.Config
	addr   string
	mu     sync.Mutex
	srv    *grpc.Server
	reqs   []*collogspb.ExportLogsServiceRequest
	recs   []*logspb.LogRecord
	fail   error
	reject int64
}

func newOTLPReceiver(t *testing.T, maxVersion uint16) (*otlpReceiver, *x509.CertPool) {
	t.Helper()
	cert, roots := testServerCert(t)
	r := &otlpReceiver{t: t, conf: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10, MaxVersion: maxVersion}} // #nosec G402 -- offers old versions to prove the client refuses them
	r.start()
	t.Cleanup(r.stop)
	return r, roots
}

func (r *otlpReceiver) start() {
	r.t.Helper()
	addr := r.addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		r.t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(r.conf)))
	collogspb.RegisterLogsServiceServer(srv, r)
	r.mu.Lock()
	r.srv, r.addr = srv, ln.Addr().String()
	r.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
}

func (r *otlpReceiver) stop() {
	r.mu.Lock()
	srv := r.srv
	r.srv = nil
	r.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
}

func (r *otlpReceiver) Export(_ context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return nil, r.fail
	}
	if r.reject > 0 {
		return &collogspb.ExportLogsServiceResponse{PartialSuccess: &collogspb.ExportLogsPartialSuccess{
			RejectedLogRecords: r.reject, ErrorMessage: "quota exceeded"}}, nil
	}
	r.reqs = append(r.reqs, req)
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			r.recs = append(r.recs, sl.GetLogRecords()...)
		}
	}
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func (r *otlpReceiver) set(fail error, reject int64) {
	r.mu.Lock()
	r.fail, r.reject = fail, reject
	r.mu.Unlock()
}

// frames returns the accepted log records as the trail's frames.
func (r *otlpReceiver) frames(t *testing.T) []gotFrame {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]gotFrame, 0, len(r.recs))
	for _, lr := range r.recs {
		f := gotFrame{body: lr.GetBody().GetStringValue(), msgID: lr.GetEventName()}
		for _, kv := range lr.GetAttributes() {
			switch kv.GetKey() {
			case "fair.seq":
				f.seq = kv.GetValue().GetIntValue()
			case "fair.chain":
				f.chain = kv.GetValue().GetStringValue()
			case "fair.segment":
				f.segment = strconv.FormatInt(kv.GetValue().GetIntValue(), 10)
			}
		}
		out = append(out, f)
	}
	return out
}

func newOTLPEnv(t *testing.T, e *env, roots *x509.CertPool) *forwardEnv {
	t.Helper()
	return newForwardEnvWith(t, e, auditsvc.OTLPDestination,
		&auditsvc.OTLPTransport{TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Hostname: "audit-0", Timeout: 5 * time.Second})
}

// AC-22: every record in order, the body exactly as recorded, with its
// position and integrity data; the export response acknowledges.
func TestAuditForwardOTLP(t *testing.T) {
	e := setup(t)
	rcv, roots := newOTLPReceiver(t, 0)
	fe := newOTLPEnv(t, e, roots)
	submitN(t, e, "ot", 10)
	drainTrail(t, fe.seq)

	fe.addr = rcv.addr
	if n, err := fe.drain(t); err != nil || n != 10 {
		t.Fatalf("forward: %d %v", n, err)
	}
	sameRecords(t, rcv.frames(t), fe.records(t))
	rcv.mu.Lock()
	req := rcv.reqs[0]
	rcv.mu.Unlock()
	rl := req.GetResourceLogs()[0]
	attrs := map[string]string{}
	for _, kv := range rl.GetResource().GetAttributes() {
		attrs[kv.GetKey()] = kv.GetValue().GetStringValue()
	}
	lr := rl.GetScopeLogs()[0].GetLogRecords()[0]
	if attrs["service.name"] != "fair-audit" || attrs["host.name"] != "audit-0" || rl.GetScopeLogs()[0].GetScope().GetName() != auditsvc.OTLPScope ||
		lr.GetEventName() != "db.migrated" || lr.GetSeverityNumber() != logspb.SeverityNumber_SEVERITY_NUMBER_INFO || lr.GetSeverityText() != "info" ||
		lr.GetTimeUnixNano() == 0 || lr.GetObservedTimeUnixNano() == 0 {
		t.Fatalf("export %v / %v", attrs, lr)
	}
	if len(rcv.reqs) != 3 { // batches of 4
		t.Fatalf("%d exports for 10 records in batches of 4", len(rcv.reqs))
	}
	d := fe.destination(t)
	if d["name"] != "otlp" || d["kind"] != "otlp" || d["address"] != rcv.addr || d["backlog"] != float64(0) || d["last_error"] != nil {
		t.Fatalf("destination %v", d)
	}

	// Down, then back: records wait and arrive in order, nothing lost.
	rcv.stop()
	submitN(t, e, "ot-out", 5)
	drainTrail(t, fe.seq)
	if _, err := fe.drain(t); err == nil {
		t.Fatal("exported to a stopped receiver")
	}
	if d := fe.destination(t); d["backlog"] != float64(5) || d["last_error"] == nil {
		t.Fatalf("during the outage %v", d)
	}
	rcv.start()
	if n, err := fe.drain(t); err != nil || n != 5 {
		t.Fatalf("after the outage: %d %v", n, err)
	}
	sameRecords(t, rcv.frames(t), fe.records(t))

	// The destination moves: the next records go to the new receiver.
	moved, _ := newOTLPReceiver(t, 0)
	moved.mu.Lock()
	moved.conf = rcv.conf
	moved.mu.Unlock()
	moved.stop()
	moved.addr = ""
	moved.start()
	fe.addr = moved.addr
	submitN(t, e, "ot-moved", 2)
	drainTrail(t, fe.seq)
	if n, err := fe.drain(t); err != nil || n != 2 {
		t.Fatalf("after the move: %d %v", n, err)
	}
	all := fe.records(t)
	if got := moved.frames(t); len(got) != 2 || got[0].seq != all[len(all)-2].seq {
		t.Fatalf("the new receiver got %+v", got)
	}
	fe.addr = rcv.addr
	before := len(rcv.frames(t))

	// A refused export, or one the receiver partly rejects, is not
	// delivered: the cursor stays and the whole batch comes again.
	for name, mode := range map[string]func(){
		"unavailable": func() { rcv.set(status.Error(codes.Unavailable, "overloaded"), 0) },
		"rejected":    func() { rcv.set(nil, 1) },
	} {
		mode()
		cursor := e.adminQuery("SELECT last_seq FROM audit.destination WHERE name = 'otlp'")
		submitN(t, e, "ot-"+name, 2)
		drainTrail(t, fe.seq)
		_, err := fe.drain(t)
		if err == nil {
			t.Fatalf("%s: delivered", name)
		}
		if name == "rejected" && !strings.Contains(err.Error(), "rejected 1 of") {
			t.Fatalf("rejected: %v", err)
		}
		if got := e.adminQuery("SELECT last_seq FROM audit.destination WHERE name = 'otlp'"); got != cursor {
			t.Fatalf("%s: the cursor moved from %s to %s", name, cursor, got)
		}
		rcv.set(nil, 0)
		if _, err := fe.drain(t); err != nil {
			t.Fatalf("%s: after recovery: %v", name, err)
		}
		recs := fe.records(t)
		got := rcv.frames(t)[before:]
		sameRecords(t, got, recs[len(recs)-len(got):])
		before = len(rcv.frames(t))
	}
}

// TLS 1.2 is the floor; OTLP and syslog keep separate cursors.
func TestAuditForwardOTLPRefusalsAndCursors(t *testing.T) {
	e := setup(t)
	old, roots := newOTLPReceiver(t, tls.VersionTLS11)
	fe := newOTLPEnv(t, e, roots)
	submitN(t, e, "oc", 3)
	drainTrail(t, fe.seq)
	fe.addr = old.addr
	if _, err := fe.drain(t); err == nil {
		t.Fatal("exported over TLS 1.1")
	}
	if len(old.frames(t)) != 0 {
		t.Fatal("records reached a TLS 1.1 receiver")
	}
	if d := fe.destination(t); d["last_seq"] != float64(0) || d["last_error"] == nil {
		t.Fatalf("after a refused handshake %v", d)
	}

	// A syslog destination next to it keeps its own cursor.
	good, roots2 := newOTLPReceiver(t, 0)
	fe2 := newOTLPEnv(t, e, roots2)
	fe2.addr = good.addr
	srv, sroots := newSyslogServer(t, 0)
	sy := newForwardEnv(t, e, sroots)
	sy.addr = srv.addr
	if _, err := sy.drain(t); err != nil {
		t.Fatal(err)
	}
	if _, err := fe2.drain(t); err != nil {
		t.Fatal(err)
	}
	cursors := e.adminQuery("SELECT string_agg(name || '=' || last_seq, ',' ORDER BY name) FROM audit.destination")
	head := e.adminQuery("SELECT seq FROM audit.head")
	if !strings.Contains(cursors, "syslog=") || !strings.Contains(cursors, "otlp=") {
		t.Fatalf("cursors %s (head %s)", cursors, head)
	}
	sameRecords(t, good.frames(t), fe2.records(t)[:len(good.frames(t))])
	if len(good.frames(t)) == 0 || len(srv.received(t, 1)) == 0 {
		t.Fatal("a destination received nothing")
	}
}
