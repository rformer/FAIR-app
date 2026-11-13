package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/analysisapi"
	"github.com/rformer/fair-app/internal/api/enginev1"
	"github.com/rformer/fair-app/internal/approvals"
	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/auditapi"
	"github.com/rformer/fair-app/internal/estimateapi"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/postureapi"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-32: the UI end-to-end harness (scripts/ui-e2e.sh). It seeds a
// posture scenario through the real services, then serves the built web UI
// (web/dist) and the real Posture API behind the real gateway (F-001 T-13:
// sessions, CSRF, the system-use banner of T-19). /dev/as/{user} stands in
// for a federated login: it creates the user's session, unacknowledged, as
// a redeemed login ticket does, and sets the cookie. It runs until
// web/.harness-stop appears. Not a test of its own: set FAIR_UI_HARNESS=1.
func TestPostureUIHarness(t *testing.T) {
	if os.Getenv("FAIR_UI_HARNESS") != "1" {
		t.Skip("set FAIR_UI_HARNESS=1 (scripts/ui-e2e.sh) to run the UI harness")
	}
	ctx := context.Background()
	ae := apiFixture(t, settings.ProfileEnterpriseBaseline) // admin, admin2, auditor, nobody
	e := ae.e
	// F-002 T-14: the posture scenario's events go to the trail too, so the
	// Posture page's audit links open populated histories (AC-37).
	ae.set.Evaluator.Audit = audit.WithTrail(ae.set.Evaluator.Audit, audit.Trail{DB: ae.set.Evaluator.DB})
	seedPostureScenario(t, ae)
	scenario, second := seedRiskScenario(t, e) // F-003 T-12; F-004 T-13

	pool := e.posturePool()
	api := &postureapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool), MaxAge: time.Second}), Audit: audit.NewMemory()}
	apiHandler := api.Handler(ae.keys, nil)
	dist := filepath.Join("..", "..", "web", "dist")

	posture := httptest.NewServer(apiHandler)
	defer posture.Close()
	up, _ := url.Parse(posture.URL)
	// F-002 T-14: the Audit API, as the audit service serves it.
	ap := e.auditPool()
	auditAPI := &auditapi.API{DB: ap, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(ap), MaxAge: time.Second}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: ap})}
	// F-002 T-15: evidence exports, made by the River job; bundles in memory.
	cp := checkpointer(t, ap, newCheckpointKey(t))
	bundles := newMemStore()
	exporter := &auditsvc.Exporter{DB: ap, Checkpointer: &cp, Store: bundles, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: ap}),
		TempDir: t.TempDir()}
	rc, err := auditsvc.NewExportClient(ap, exporter, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Stop(context.Background()) }()
	auditAPI.Enqueue, auditAPI.Bundles = auditsvc.Enqueuer(rc), bundles
	auditSrv := httptest.NewServer(auditAPI.Handler(ae.keys, nil))
	defer auditSrv.Close()
	auditUp, _ := url.Parse(auditSrv.URL)
	// F-003 T-12: the risk API, as the risk service serves it (app_rw).
	rp := e.appPool()
	riskAPI := &riskapi.API{DB: rp, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(rp), MaxAge: time.Second}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: rp})}
	// F-004 T-12: the estimate API, mounted beside it as cmd/risk does.
	estimateAPI := &estimateapi.API{DB: rp, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(rp), MaxAge: time.Second}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: rp})}
	riskMux := http.NewServeMux()
	riskMux.Handle("/", riskAPI.Handler(ae.keys, nil))
	eh := estimateAPI.Handler(ae.keys, nil)
	for _, prefix := range estimateapi.Prefixes {
		riskMux.Handle(prefix, eh)
		riskMux.Handle(prefix+"/", eh)
	}
	// F-005 T-13: the analysis API, mounted beside them as cmd/risk does,
	// with the River workers and the real engine (scripts/ui-e2e.sh runs it
	// and shares its socket: FAIR_UI_ENGINE_SOCKET).
	analysisAPI := &analysisapi.API{DB: rp, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(rp), MaxAge: time.Second}),
		Settings: fixedLimits{IterationsDefault: 10000, IterationsMin: 1000, IterationsMax: 2000000, MaxActive: 5}}
	engineSocket := os.Getenv("FAIR_UI_ENGINE_SOCKET")
	if engineSocket != "" {
		conn, err := grpc.NewClient("unix://"+engineSocket, grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20)))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		w := &analysis.Worker{DB: rp, Engine: enginev1.NewEngineClient(conn), ThresholdBP: func() int { return 100 }}
		arc, err := analysis.NewClient(rp, w, &analysis.AggregateWorker{DB: rp, Engine: w.Engine}, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := arc.Start(ctx); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = arc.Stop(context.Background()) }()
		analysisAPI.Enqueue, analysisAPI.EnqueueAggregate = analysis.Enqueuer(arc), analysis.AggregateEnqueuer(arc)
	}
	ah := analysisAPI.Handler(ae.keys, nil)
	for _, prefix := range analysisapi.Prefixes {
		riskMux.Handle(prefix, ah)
		riskMux.Handle(prefix+"/", ah)
	}
	riskSrv := httptest.NewServer(riskMux)
	defer riskSrv.Close()
	riskUp, _ := url.Parse(riskSrv.URL)
	seedEstimateRequest(t, e, ae.keys, riskSrv.URL, scenario, second)
	if engineSocket != "" {
		seedAnalysisRun(t, e, ae.keys, riskSrv.URL, scenario)
	}
	// The UI: built assets, and index.html for the app's routes.
	ui := gateway.StaticUI(dist)
	g := &gateway.Gateway{
		Sessions: gateway.Sessions{DB: e.gatewayPool(), Pepper: []byte("harness-pepper-0123456789abcdef-0123"),
			Timeouts: func() (time.Duration, time.Duration, error) { return 30 * time.Minute, 12 * time.Hour, nil }},
		ContextKey: ctxKey1,
		JWT:        ae.keys,
		Origin:     "http://localhost:8099",
		Upstreams:  map[string]*url.URL{"posture": up, "audit": auditUp, "risk": riskUp},
		UI:         ui,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /dev/ready", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /dev/as/{user}", func(w http.ResponseWriter, r *http.Request) {
		id := e.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + r.PathValue("user") + "@example.test'")
		_, tok, err := g.Sessions.Create(r.Context(), gateway.Login{UserID: id, AuthMethod: "oidc",
			MFA: map[string]any{"amr": []string{"mfa"}, "satisfied": true}, UserAgent: r.UserAgent()})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		gateway.SetCookie(w, tok) // Secure: Chromium accepts it from http://localhost
		http.Redirect(w, r, "/posture", http.StatusSeeOther)
	})
	mux.Handle("/", g.Handler())

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "0.0.0.0:8099")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(lis) }()
	defer func() { _ = srv.Close() }()
	t.Log("HARNESS READY on :8099")
	stop := filepath.Join("..", "..", "web", ".harness-stop")
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(stop); err == nil {
			_ = os.Remove(stop)
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("harness timed out without web/.harness-stop")
}

// seedPostureScenario builds what the Posture page shows, through the real
// services: an in-bounds loosening, an approved exception expiring in 10
// days, a reverted exception, BU overrides (one in a restricted BU), a
// pending switch to FedRAMP Moderate with conflicts, drift findings from a
// direct database edit, and undecided Kubernetes access.
func seedPostureScenario(t *testing.T, ae apiEnv) {
	t.Helper()
	ctx := context.Background()
	e := ae.e
	admin, admin2 := e.principal("admin"), e.principal("admin2")
	set := func(key string, value any, explanation string) settings.Result {
		t.Helper()
		res, err := ae.set.Set(ctx, admin, settings.Request{Key: key, Value: value, Explanation: explanation})
		if err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
		return res
	}
	approve := func(res settings.Result) posture.Exception {
		t.Helper()
		if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil {
			t.Fatal(err)
		}
		x, err := ae.set.ApplyApproved(ctx, res.ChangeID)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	set(settings.KeySessionIdleTimeout, 25*time.Minute, "call centre shifts")
	lockout := approve(set(settings.KeyAuthLockoutThreshold, 12, "legacy kiosk accounts"))
	e.timeTravel("UPDATE posture.exception SET expires_at = now() + interval '10 days' WHERE id = '" + lockout.ID + "'")
	token := approve(set(settings.KeyTokenMaxLifetime, 120*24*time.Hour, "integration partner migration"))
	expire(e, token.ID)
	if out, err := posture.RevertDue(ctx, e.posturePool(), audit.NewMemory(), nil); err != nil || len(out) != 1 {
		t.Fatalf("seed revert: %+v %v", out, err)
	}

	e.addBU("A", "ENTERPRISE")
	e.addBU("R", "ENTERPRISE")
	e.drain()
	for _, code := range []string{"A", "R"} {
		bu := e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + code + "'")
		// A fresh context: adding BUs moved the admin's scope version.
		if _, err := ae.set.Set(ctx, e.principal("admin"), settings.Request{Key: settings.KeySessionNetworkBinding, BUID: bu, Value: "reauthenticate"}); err != nil {
			t.Fatal(err)
		}
	}
	e.mustOwner("UPDATE iam.bu SET restricted = true WHERE code = 'R'")
	e.drain()

	sw := posture.Switches{DB: e.posturePool(), Audit: audit.NewMemory()}
	if _, err := sw.Request(ctx, e.principal("admin"), settings.ProfileFedRAMPModerate, "1.5.0", ""); err != nil {
		t.Fatalf("seed switch: %v", err)
	}

	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1.0"' WHERE key = 'tls.min_version' AND bu_id IS NULL`)
	if _, err := (posture.Drift{DB: e.posturePool(), Audit: audit.NewMemory()}).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	// F-002 T-11: a full verification that found record 2 altered, after one
	// that passed (the Audit trail tile and the audit_integrity finding).
	ap := e.auditPool()
	submitN(t, e, "ui", 3)
	drainTrail(t, auditsvc.Sequencer{DB: ap})
	if _, err := checkpointer(t, ap, newCheckpointKey(t)).Close(ctx); err != nil {
		t.Fatal(err)
	}
	ver := auditsvc.Verifier{DB: ap, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: ap})}
	if r, err := ver.Full(ctx); err != nil || !r.OK {
		t.Fatalf("seed verification: %+v %v", r, err)
	}
	// The last record of the closed segment is the one altered, so the
	// posture events before it stay verified on the audit pages (T-14).
	bad := e.adminQuery("SELECT seq FROM audit.record WHERE event_id = 'ui-2'")
	e.tamper("UPDATE audit.record SET body = convert_to('{}', 'UTF8') WHERE seq = " + bad)
	if r, err := ver.Full(ctx); err != nil || r.OK || fmt.Sprint(r.FailedSeq) != bad {
		t.Fatalf("seed failed verification: %+v %v", r, err)
	}
	// F-002 T-14: more than a page of records (search paging), and one
	// request recorded by two services (the request view).
	submitN(t, e, "ui-page", 60)
	adminID := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin@example.test'")
	for i, role := range []string{"app_rw", "app_posture"} {
		submitAs(t, e, role, map[string]any{"id": fmt.Sprintf("ui-req-%d", i), "type": "setting.change_requested", "severity": "high",
			"actor": adminID, "target": "test:ui-request", "request_id": "req-ui-1", "reason": "two services, one request"})
	}
	drainTrail(t, auditsvc.Sequencer{DB: ap})
	// F-002 T-16: a SIEM destination that is down, its backlog over the
	// threshold (the Audit trail tile).
	fwd := &auditsvc.Forwarder{DB: ap, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: ap}),
		Name: auditsvc.SyslogDestination, Transport: &auditsvc.SyslogTransport{},
		Address:    func() (string, error) { return "127.0.0.1:1", nil },
		Thresholds: func() (int, time.Duration) { return 5, 15 * time.Minute }}
	if _, err := fwd.Step(ctx); err == nil {
		t.Fatal("seed forwarding: sent to a closed port")
	}
	// F-002 T-20: audit storage at about 80% of its quota (a warning).
	capm := auditsvc.CapacityMonitor{DB: ap, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: ap}), Quota: 1 << 50}
	r, err := capm.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	capm.Quota = r.Used * 100 / 80
	if r, err := capm.Step(ctx); err != nil || r.Level != "warning" {
		t.Fatalf("seed capacity: %+v %v", r, err)
	}
	drainTrail(t, auditsvc.Sequencer{DB: ap})

	var n int
	if err := e.posturePool().QueryRow(ctx, "SELECT count(*) FROM posture.drift_findings()").Scan(&n); err != nil || n == 0 {
		t.Fatalf("seed drift: %d %v", n, err)
	}
	b, _ := json.Marshal(map[string]any{"exceptions": 2, "drift_findings": n})
	t.Logf("scenario seeded: %s", b)
	if _, err := os.Stat(filepath.Join("..", "..", "web", "dist", "index.html")); errors.Is(err, os.ErrNotExist) {
		t.Fatal(fmt.Errorf("web/dist is not built (npm run build in web/)"))
	}
}

// seedRiskScenario builds what the scenario pages show (F-003 T-12): a risk
// analyst at the root, the currency, a library (asset, threat community,
// control) and a scenario with two versions whose threat community has a
// newer version to adopt. "nobody" (Executive Viewer) can read, not edit.
// It returns the scenario's id, and that of a second scenario on the same
// library ("Phishing of claims staff") for the analyst's estimate pages.
func seedRiskScenario(t *testing.T, e *env) (string, string) {
	t.Helper()
	// A second BU under the root, for moves and imports (T-13).
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'Claims', 'CLAIMS', id, false FROM iam.bu WHERE parent_id IS NULL")
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('riskanalyst@example.test', 'Rae Analyst')")
	e.mustOwner(grant("admin", "user:riskanalyst", "Risk Analyst", "ENTERPRISE"))
	e.drain()
	r := riskEnv{e, map[string]string{"ENTERPRISE": e.adminQuery("SELECT id FROM iam.bu WHERE code = 'ENTERPRISE'")}}
	ra := &riskAPIEnv{riskEnv: r}
	ra.setCurrency(t, "USD")
	root := r.bu["ENTERPRISE"]
	asset := r.create(t, "riskanalyst", "asset", root, modeltest.Asset())
	tc := r.create(t, "riskanalyst", "threat_community", root, modeltest.ThreatCommunity())
	ctl := r.create(t, "riskanalyst", "control", root, modeltest.Control())
	d := modeltest.Scenario()
	modeltest.Set(d, "/owner", e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'riskanalyst@example.test'"))
	modeltest.Set(d, "/asset", map[string]any{"kind": "asset", "id": asset, "version": 1})
	modeltest.Set(d, "/threat_community", map[string]any{"id": tc, "version": 1})
	modeltest.Set(d, "/control_sets", []any{map[string]any{"name": "Current", "current": true, "controls": []any{
		map[string]any{"id": ctl, "version": 1, "status": "in_place"}}}})
	s := r.create(t, "riskanalyst", "scenario", root, d)
	modeltest.Set(d, "/scope/out", "Backups held offline, and the disaster recovery site.")
	b, dg := canonicalDoc(t, "scenario", d)
	if err := r.addVersion("riskanalyst", "scenario_version", s, 2, b, dg); err != nil {
		t.Fatal(err)
	}
	b, dg = canonicalDoc(t, "threat_community", modeltest.Set(modeltest.ThreatCommunity(), "/name", "Organised cyber crime"))
	if err := r.addVersion("riskanalyst", "library_version", tc, 2, b, dg); err != nil {
		t.Fatal(err)
	}
	second := r.create(t, "riskanalyst", "scenario", root, modeltest.Set(d, "/name", "Phishing of claims staff"))
	t.Log("risk scenario seeded")
	return s, second
}

// seedEstimateRequest builds what the estimator pages show (F-004 T-12): an
// estimator at the root ("estimator", Estimator only) and a request on the
// seeded scenario for contact frequency and response costs, with a
// reference class of the organization's own incident counts. For the
// analyst's pages (T-13), a second estimator ("estimator2") and a request on
// the second scenario that both have answered.
func seedEstimateRequest(t *testing.T, e *env, keys *authz.LocalKeys, url, scenario, second string) {
	t.Helper()
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('estimator@example.test', 'Ellis Estimator'), ('estimator2@example.test', 'Sam Okafor')")
	e.mustOwner(grant("admin", "user:estimator", "Estimator", "ENTERPRISE"))
	e.mustOwner(grant("admin", "user:estimator2", "Estimator", "ENTERPRISE"))
	e.drain()
	r := riskEnv{e, map[string]string{"ENTERPRISE": e.adminQuery("SELECT id FROM iam.bu WHERE code = 'ENTERPRISE'")}}
	rc := r.create(t, "riskanalyst", "reference_class", r.bu["ENTERPRISE"], modeltest.ReferenceClass())
	ea := &riskAPIEnv{riskEnv: r, url: url, keys: keys, n: 200000}
	got := ea.call(t, "POST", "riskanalyst", "/api/v1/estimates/requests", map[string]any{"scenario_id": scenario, "title": "Contact frequency and response costs",
		"instructions": "Answer from your own experience of the service desk.", "due_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339),
		"factors":    []any{"/lef/tef/contact_frequency", "/primary_loss/response"},
		"estimators": []any{e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'estimator@example.test'")},
		"references": []any{map[string]any{"id": rc, "version": 1}}})
	if got.code != 201 {
		t.Fatalf("seed estimate request: %d %s", got.code, got.raw)
	}
	ids := []any{e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'estimator@example.test'"),
		e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'estimator2@example.test'")}
	got = ea.call(t, "POST", "riskanalyst", "/api/v1/estimates/requests", map[string]any{"scenario_id": second, "title": "Phishing frequency and response",
		"due_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339), "factors": []any{"/lef/tef/contact_frequency", "/primary_loss/response"},
		"estimators": ids})
	if got.code != 201 {
		t.Fatalf("seed second request: %d %s", got.code, got.raw)
	}
	rid := got.body["id"].(string)
	est := func(unit, lo, ml, hi, ref string) map[string]any {
		return map[string]any{"min": lo, "ml": ml, "max": hi, "unit": unit, "confidence": "0.9", "rationale": "What I have seen at the service desk.",
			"sources": []any{map[string]any{"type": "person", "ref": ref}}}
	}
	for user, answers := range map[string][]any{
		"estimator": {map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": est("events_per_year", "2", "5", "10", "Ellis's notes")},
			map[string]any{"pointer": "/primary_loss/response", "declined": "Not my area"}},
		"estimator2": {map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": est("events_per_year", "4", "7", "12", "SOC tickets")},
			map[string]any{"pointer": "/primary_loss/response", "estimate": est("currency", "40000", "120000", "500000", "Past invoices")}},
	} {
		if got := ea.call(t, "PUT", user, "/api/v1/estimates/inbox/"+rid+"/answers", map[string]any{"submit": true, "answers": answers}); got.code != 200 {
			t.Fatalf("seed %s answers: %d %s", user, got.code, got.raw)
		}
	}
	t.Log("estimate requests seeded")
}

// seedAnalysisRun builds what the run pages show (F-005 T-13): a succeeded
// run of the seeded scenario's version 2 on the real engine (20,000
// iterations, seed 2026).
func seedAnalysisRun(t *testing.T, e *env, keys *authz.LocalKeys, url, scenario string) {
	t.Helper()
	r := riskEnv{e, map[string]string{}}
	ea := &riskAPIEnv{riskEnv: r, url: url, keys: keys, n: 300000}
	got := ea.call(t, "POST", "riskanalyst", "/api/v1/analyses/runs", map[string]any{"scenario_id": scenario, "version": 2, "iterations": 20000, "seed": "2026"})
	if got.code != 202 {
		t.Fatalf("seed run: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	for range 120 {
		switch e.adminQuery("SELECT state FROM analysis.run WHERE id = '" + id + "'") {
		case "succeeded":
			t.Log("analysis run seeded")
			return
		case "failed", "cancelled":
			t.Fatalf("seed run: %s", e.adminQuery("SELECT failure || ': ' || coalesce(failure_detail, '') FROM analysis.run WHERE id = '"+id+"'"))
		}
		time.Sleep(time.Second)
	}
	t.Fatal("seed run: not finished in two minutes")
}
