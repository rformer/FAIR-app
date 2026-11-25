package tests

// F-012 T-10 (F-012-AC-23; design §3.7): telemetry carries no secrets,
// tokens, risk data or personal data. Representative flows through the
// risk, analysis, register, estimate and report APIs run with the
// production telemetry pipeline (telemetry.HTTP around each API, the pgx
// tracer every pool gets from dbconn.Config, the Filtered span exporter, the
// AllowedView on metrics, the slog wrapper) into in-memory exporters and a
// log capture; no exported value may contain a value the flows used.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/pkg/telemetry"
)

func TestTelemetryRedaction(t *testing.T) {
	ra := strideF003Fixture(t) // analyst a Risk Analyst at A, mallory at B, erin a Risk Owner at A1
	registerUsers(ra)
	reportUsers(ra)
	seedPosture(t, ra.env)
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('dana@example.test', 'Dana Estimator')")
	ra.mustOwner(grant("platform", "user:dana", "Estimator", "A1"))
	ra.drain()

	// The production pipeline, into memory. (The global providers bind
	// once per test binary; spans stop being kept when the test ends.)
	spans := tracetest.NewInMemoryExporter()
	reader := sdkmetric.NewManualReader()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(telemetry.Filtered(spans))))
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithView(telemetry.AllowedView)))
	t.Cleanup(func() { otel.SetTracerProvider(tracenoop.NewTracerProvider()) })
	logs := &syncBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(telemetry.Logs(slog.NewJSONHandler(logs, nil))))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Risk data: a scenario, a library entry, a rejected document.
	const scenarioName, riskTitle, requestTitle, instructions, rejected = "Zebra ransomware 7731", "Okapi exposure 5519",
		"Narwhal contact frequency 8842", "Quokka instructions 6620", "Pangolin 3321"
	scenario := scenarioAt(t, ra, "analyst", ra.bu["A1"], scenarioName)
	if got := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+scenario, nil); got.code != 200 {
		t.Fatalf("read: %d %s", got.code, got.raw)
	}
	bad := ra.scenarioDoc(t)
	bad["name"] = rejected
	bad["schema_version"] = rejected // invalid: refused with problems naming the pointer
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": bad, "change_note": rejected}); got.code < 400 {
		t.Fatalf("an invalid document was accepted: %d", got.code)
	}

	// An analysis run (the fake engine) and a register risk pinning it.
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	run := runWith(t, ae, "analyst", scenario, 1, 100_000, "7") // the register pins runs of register.iterations
	rg := registerAPI(t, ra)
	erin := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'erin@example.test'")
	cyber := ra.adminQuery("SELECT id FROM register.category WHERE name = 'Cyber'")
	risk := rg.call(t, "POST", "erin", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "change_note": riskTitle,
		"document": map[string]any{"schema_version": 1, "title": riskTitle, "owner": erin, "category": cyber, "state": "open",
			"scenarios": []any{map[string]any{"scenario_id": scenario, "pin": map[string]any{"run_id": run, "control_set": "Current"}}}}})
	if risk.code != 201 {
		t.Fatalf("register risk: %d %s", risk.code, risk.raw)
	}

	// An estimate request with its text, to an estimator.
	ea := estimateAPI(t, ra)
	dana := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'dana@example.test'")
	rc := ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "reference_class", "document": modeltest.ReferenceClass(), "change_note": "x"})
	if rc.code != 201 {
		t.Fatalf("reference class: %d %s", rc.code, rc.raw)
	}
	req := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", map[string]any{"scenario_id": scenario, "title": requestTitle,
		"instructions": instructions, "due_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339),
		"factors": []any{"/lef/tef/contact_frequency"}, "estimators": []any{dana}, "context": []any{"name", "asset"},
		"references": []any{map[string]any{"id": rc.body["id"], "version": 1}}})
	if req.code != 201 {
		t.Fatalf("estimate request: %d %s", req.code, req.raw)
	}
	if got := ea.call(t, "GET", "dana", "/api/v1/estimates/inbox", nil); got.code != 200 {
		t.Fatalf("inbox: %d %s", got.code, got.raw)
	}

	// A register report, made by the report worker.
	re := reportAPI(t, ra)
	rep := re.request(t, "pub", ra.bu["A"], map[string]any{"reason": "Wombat committee 4410"})
	if rep.code != 202 && rep.code != 201 {
		t.Fatalf("report: %d %s", rep.code, rep.raw)
	}
	if id, _ := rep.body["id"].(string); id != "" {
		_ = re.attempt(t, id, 1)
	}

	// What telemetry holds.
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	sp, _ := json.Marshal(spans.GetSpans())
	mt, _ := json.Marshal(rm.ScopeMetrics)
	logText := logs.String()
	all := string(sp) + "\n" + string(mt) + "\n" + logText

	// It is there (the pipeline ran)...
	for _, want := range []string{"/api/v1/scenarios", "/api/v1/register/risks", "/api/v1/estimates", "/api/v1/reports",
		"http.server.request.duration", "db.client.operation.duration", "db SELECT"} {
		if !strings.Contains(all, want) {
			t.Errorf("telemetry has no %q", want)
		}
	}
	// ...and holds none of what the flows used.
	secrets := []string{scenarioName, riskTitle, requestTitle, instructions, rejected, "Zebra", "Okapi", "Narwhal", "Quokka", "Pangolin", "Wombat",
		"@example.test", "Dana Estimator", "Bearer ", "eyJ", scenario, run, erin, dana, risk.body["id"].(string)}
	for _, role := range []string{"app_rw", "app_posture", "app_audit"} {
		if b, err := os.ReadFile(ra.secrets[role]); err == nil { // #nosec G304 -- the test's own secret files
			secrets = append(secrets, strings.TrimSpace(string(b)))
		}
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(all, s) {
			i := strings.Index(all, s)
			t.Errorf("telemetry holds %q: …%s…", s, all[max(0, i-120):min(len(all), i+len(s)+40)])
		}
	}
	t.Logf("telemetry checked: %d spans, %d bytes of metrics, %d bytes of logs", len(spans.GetSpans()), len(mt), len(logText))
}

// syncBuf is a buffer safe for concurrent log writers.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
