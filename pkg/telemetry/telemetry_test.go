package telemetry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// The package's tests share one in-memory provider pair, installed as the
// global providers as Setup installs real ones (they bind once).
var (
	spans  = tracetest.NewInMemoryExporter()
	reader = sdkmetric.NewManualReader()
)

func TestMain(m *testing.M) {
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(Filtered(spans))))
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithView(AllowedView)))
	os.Exit(m.Run())
}

func collect(t *testing.T) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	return rm
}

// metricJSON is every metric with its data points, as JSON, for searching.
func metricJSON(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(collect(t).ScopeMetrics)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// F-012 T-09 (F-012-AC-25; design §3.7): without an endpoint nothing is set
// up, nothing is exported and nothing dials out.
func TestOffWithoutEndpoint(t *testing.T) {
	t.Setenv("FAIR_OTEL_ENDPOINT", "")
	tel, err := Setup(context.Background(), "risk", "test")
	if err != nil {
		t.Fatal(err)
	}
	if tel.Enabled {
		t.Fatal("telemetry on without an endpoint")
	}
	if err := tel.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	// No egress: the package's code never dials unless an endpoint is set;
	// SetupWith with none must not even read a CA file.
	if _, err := SetupWith(context.Background(), Config{CAFile: "/does/not/exist"}, "risk", "test"); err != nil {
		t.Fatalf("read the CA file while off: %v", err)
	}
}

func TestConfig(t *testing.T) {
	for _, c := range []struct {
		endpoint, ratio string
		ok              bool
	}{
		{"collector.example:4317", "", true},
		{"collector.example:4317", "0.5", true},
		{"http://collector.example:4317", "", false}, // a scheme would hint at plaintext
		{"collector.example", "", false},
		{"collector.example:4317", "2", false},
		{"collector.example:4317", "x", false},
	} {
		t.Setenv("FAIR_OTEL_ENDPOINT", c.endpoint)
		t.Setenv("FAIR_OTEL_SAMPLE_RATIO", c.ratio)
		if _, err := ConfigFromEnv(); (err == nil) != c.ok {
			t.Errorf("%q ratio %q: err %v", c.endpoint, c.ratio, err)
		}
	}
	t.Setenv("FAIR_OTEL_SAMPLE_RATIO", "")
	t.Setenv("FAIR_OTEL_ENDPOINT", "collector.example:4317")
	if c, _ := ConfigFromEnv(); c.SampleRatio != DefaultSampleRatio {
		t.Errorf("default ratio %v", c.SampleRatio)
	}
}

// With an endpoint, the exporters use TLS with the given CA; a bad CA file
// fails Setup instead of exporting without verification.
func TestSetupTLS(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SetupWith(ctx, Config{Endpoint: "127.0.0.1:4317", CAFile: bad}, "risk", "test"); err == nil {
		t.Fatal("a CA file without a certificate was accepted")
	}
	tc, err := tlsConfig(writeCA(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if tc.MinVersion < 0x0303 || tc.RootCAs == nil || tc.InsecureSkipVerify {
		t.Fatalf("TLS configuration %+v", tc)
	}
}

func writeCA(t *testing.T, dir string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "collector"}, NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// F-012 T-09 (AC-22): a request is one span and one duration, named by the
// route pattern; ids from the path, the query and the body never appear.
func TestHTTPRoutePatternOnly(t *testing.T) {
	spans.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/scenarios/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})
	h := HTTP(mux)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/v1/scenarios/3f1c-secret-id?owner=alice@example.test", strings.NewReader(`{"name":"Ransomware at HQ"}`))
	h.ServeHTTP(httptest.NewRecorder(), req)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/nowhere/abc", nil))

	got := spans.GetSpans()
	if len(got) != 2 {
		t.Fatalf("%d spans", len(got))
	}
	if got[0].Name != "PUT /api/v1/scenarios/{id}" || got[1].Name != "GET unmatched" {
		t.Errorf("span names %q, %q", got[0].Name, got[1].Name)
	}
	attrs := map[attribute.Key]attribute.Value{}
	for _, a := range got[0].Attributes {
		attrs[a.Key] = a.Value
	}
	if attrs["http.route"].AsString() != "/api/v1/scenarios/{id}" || attrs["http.response.status_code"].AsInt64() != 409 {
		t.Errorf("attributes %v", got[0].Attributes)
	}
	b, _ := json.Marshal(got)
	all := string(b) + metricJSON(t)
	for _, secret := range []string{"3f1c-secret-id", "alice@example.test", "Ransomware"} {
		if strings.Contains(all, secret) {
			t.Errorf("%q in telemetry", secret)
		}
	}
	if !strings.Contains(all, "http.server.request.duration") {
		t.Error("no request duration recorded")
	}
}

func TestPGXOperationOnly(t *testing.T) {
	spans.Reset()
	for sql, want := range map[string]string{
		"SELECT * FROM risk.scenario WHERE name = 'Ransomware'": "SELECT",
		"  -- a comment\n insert into x values ($1)":            "INSERT",
		"WITH a AS (SELECT 1) SELECT * FROM a":                  "WITH",
		"VACUUM risk.scenario":                                  "OTHER",
		"":                                                      "OTHER",
	} {
		if got := Operation(sql); got != want {
			t.Errorf("Operation(%q) = %q, want %q", sql, got, want)
		}
	}
	var tr PGX
	ctx := tr.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "SELECT secret_column FROM risk.scenario WHERE name = $1", Args: []any{"Ransomware"}})
	tr.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: errors.New("relation secret_table does not exist")})
	got := spans.GetSpans()
	if len(got) != 1 || got[0].Name != "db SELECT" {
		t.Fatalf("spans %v", got)
	}
	b, _ := json.Marshal(got)
	all := string(b) + metricJSON(t)
	for _, secret := range []string{"secret_column", "Ransomware", "secret_table"} {
		if strings.Contains(all, secret) {
			t.Errorf("%q in telemetry", secret)
		}
	}
}

// Jobs, messages, engine calls, deliveries and backlogs are recorded with
// allowed attributes; others are dropped.
func TestInstruments(t *testing.T) {
	ctx := context.Background()
	Job(ctx, "analysis", "simulate", "completed", 2*time.Second)
	Message(ctx, "publish", "iam.scope.changed")
	EngineCall(ctx, "Simulate", nil, time.Second)
	Delivery(ctx, "email", "ok")
	if err := Backlog("audit_forwarding", func(context.Context) (int64, error) { return 42, nil }); err != nil {
		t.Fatal(err)
	}
	all := metricJSON(t)
	for _, want := range []string{"job.duration", "analysis", "messaging.messages", "iam.scope.changed", "engine.call.duration",
		"notification.deliveries", "backlog.audit_forwarding", "42"} {
		if !strings.Contains(all, want) {
			t.Errorf("%q not recorded", want)
		}
	}
	if got := Attr(attribute.String("user.email", "a@example.test"), attribute.String("job.queue", "q")); len(got) != 1 || got[0].Key != "job.queue" {
		t.Errorf("Attr kept %v", got)
	}
}

// F-012 T-11: duration histograms have second buckets, so the latency alerts
// (deploy/observability/alerts) can count requests over 1 second.
func TestDurationBucketsInSeconds(t *testing.T) {
	Job(context.Background(), "analysis", "simulate", "completed", 2*time.Second)
	for _, sm := range collect(t).ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "job.duration" {
				continue
			}
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok || len(h.DataPoints) == 0 {
				t.Fatalf("job.duration is %T", m.Data)
			}
			if got := h.DataPoints[0].Bounds; !slices.Equal(got, SecondBuckets) {
				t.Errorf("bounds %v", got)
			}
			return
		}
	}
	t.Error("no job.duration")
}

// A span's events and status text (which can hold error messages with
// data) never leave the process.
func TestFilteredDropsEventsAndStatusText(t *testing.T) {
	spans.Reset()
	_, span := otel.Tracer(Scope).Start(context.Background(), "op")
	span.SetAttributes(attribute.String("scenario.name", "Ransomware"), attribute.String("outcome", "ok"))
	span.AddEvent("error at Ransomware")
	span.RecordError(errors.New("token=abc123"))
	span.End()
	b, _ := json.Marshal(spans.GetSpans())
	for _, secret := range []string{"Ransomware", "abc123", "scenario.name"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("%q exported", secret)
		}
	}
}

func TestLogsCarryTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(Logs(slog.NewJSONHandler(&buf, nil)))
	ctx, span := otel.Tracer(Scope).Start(context.Background(), "op")
	log.InfoContext(ctx, "inside")
	span.End()
	log.Info("outside")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if !strings.Contains(lines[0], `"trace_id":"`+span.SpanContext().TraceID().String()) || !strings.Contains(lines[0], `"span_id"`) {
		t.Errorf("no trace id: %s", lines[0])
	}
	if strings.Contains(lines[1], "trace_id") {
		t.Errorf("trace id without a span: %s", lines[1])
	}
}

// Nothing in the package opens a listener or a connection when off: the
// exporters are the only network code, and SetupWith returns before making
// them (checked here by the absence of connections to a local port).
func TestNoEgressWhenOff(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()
	t.Setenv("FAIR_OTEL_ENDPOINT", "")
	tel, err := Setup(context.Background(), "risk", "test")
	if err != nil || tel.Enabled {
		t.Fatal(tel, err)
	}
	Job(context.Background(), "q", "k", "completed", time.Millisecond)
	select {
	case <-accepted:
		t.Fatal("a connection was made")
	case <-time.After(200 * time.Millisecond):
	}
}

// F-012 T-10: an API mounted under a prefix names its spans by its own
// route, not the prefix the outer mux matched.
func TestRoutedNamesInnerRoute(t *testing.T) {
	spans.Reset()
	inner := http.NewServeMux()
	inner.HandleFunc("GET /api/v1/register/risks/{id}", func(http.ResponseWriter, *http.Request) {})
	outer := http.NewServeMux()
	outer.Handle("/api/v1/register/", Routed(inner))
	HTTP(outer).ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/register/risks/abc-123", nil))
	got := spans.GetSpans()
	if len(got) != 1 || got[0].Name != "GET /api/v1/register/risks/{id}" {
		t.Fatalf("spans %v", got)
	}
}
