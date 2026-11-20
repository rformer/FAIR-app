package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/frameworkapi"
	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-013 T-11 (requirements NFR "Performance"; design §3.1, §3.5, §3.6): the
// frameworks gate at the F-001 target scale (2,011 BUs, 10,000 users).
// Budgets:
//   - NIST SP 800-53r5 (the pinned 5.2.0 catalog, as a new family) imported
//     through the framework API and its job, request to outcome: <= 60 s;
//   - coverage of the moderate baseline at the root over 10,000 controls
//     and 50,000 mappings (five each, in the unrestricted units), through
//     the API: <= 2 s p95;
//   - a requirement's controls and scenarios (10,000 scenarios, each
//     pinning one of the controls in its current set): <= 1 s p95.
// Controls and scenarios are written as the seeder (a Risk Analyst at the
// root) through the version triggers, so the projection is the one saves
// make.

const (
	frameworkImportBudget    = 60 * time.Second
	frameworkCoverageBudget  = 2 * time.Second
	frameworkScenariosBudget = time.Second
	frameworkBenchControls   = 10_000
	frameworkBenchMappings   = 5 // per control
	frameworkBenchScenarios  = 10_000
)

func TestBenchmarkGateFrameworks(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	start := time.Now()
	controls, scenarios := frameworkBenchControls, frameworkBenchScenarios
	if n := os.Getenv("FAIR_BENCH_FRAMEWORK_CONTROLS"); n != "" { // a smaller run, by hand
		controls, _ = strconv.Atoi(n)
		scenarios = controls
	}
	(&riskAPIEnv{riskEnv: riskEnv{env: e}}).setCurrency(t, "USD")
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	// The seeder and reader: a Risk Analyst at the root; the importer: a
	// Platform Admin (framework.manage is an admin permission, not held
	// with risk data, AC-30).
	e.mustOwner(`INSERT INTO iam.app_user (email, display_name) VALUES ('benchseed@example.test', 'Bench Seed'), ('benchfw@example.test', 'Bench Frameworks')`)
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = CASE u.email WHEN 'benchseed@example.test' THEN 'Risk Analyst' ELSE 'Platform Admin' END),
		       '%s', '%s' FROM iam.app_user u WHERE u.email IN ('benchseed@example.test', 'benchfw@example.test')`, root, granter))
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	e.mustOwner("DELETE FROM iam.outbox")
	e.mustOwner("GRANT EXECUTE ON FUNCTION risk.canonical(jsonb) TO app_rw") // the seeding below only; a test database

	v520 := e.mustOwner("SELECT id FROM framework.version WHERE family = 'nist-800-53' AND label = '5.2.0'")
	moderate := e.mustOwner("SELECT id FROM framework.baseline WHERE version_id = '" + v520 + "' AND key = 'nist-moderate'")
	selected := e.mustOwner("SELECT array_to_string(selected, ',') FROM framework.baseline WHERE id = '" + moderate + "'")
	bus := e.mustOwner(`SELECT string_agg(b.id::text, ',' ORDER BY b.code) FROM iam.bu b WHERE NOT b.restricted
		AND NOT EXISTS (SELECT 1 FROM iam.bu_closure c JOIN iam.bu x ON x.id = c.ancestor_id WHERE c.descendant_id = b.id AND x.restricted)`)
	seed := func(sql string) {
		t.Helper()
		if err := (riskEnv{env: e}).tx("benchseed", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), sql)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	tmpl := func(kind string, doc map[string]any) string { return templateJSON(t, kind, doc) }
	control := tmpl("control", modeltest.Control())
	// Controls in batches (a context lives a minute), round-robin over the
	// units, each mapped to five requirements of the moderate baseline.
	const batch = 1_000
	var mid time.Time
	for lo := 0; lo < controls; lo += batch {
		seed(fmt.Sprintf(`DO $$
DECLARE
  bus uuid[] := string_to_array('%[1]s', ',')::uuid[];
  reqs text[] := string_to_array('%[2]s', ',');
  st text[] := ARRAY['full', 'partial', 'supports'];
  impl text[] := ARRAY['in_place', 'in_place', 'partial', 'planned', 'not_in_place'];
  id uuid; b bytea; d jsonb; m jsonb;
BEGIN
  FOR i IN %[3]d..%[4]d LOOP
    m := (SELECT jsonb_agg(jsonb_build_object('framework', 'nist-800-53', 'version', '5.2.0', 'requirement', reqs[1 + (i * %[6]d + k) %% cardinality(reqs)],
      'strength', st[1 + (i + k) %% 3])) FROM generate_series(0, %[6]d - 1) k);
    d := '%[5]s'::jsonb || jsonb_build_object('name', 'Control ' || i, 'mappings', m,
      'implementation', jsonb_build_object('status', impl[1 + i %% 5], 'assessed_on', '2026-11-01'));
    INSERT INTO risk.control (bu_id) VALUES (bus[1 + i %% cardinality(bus)]) RETURNING control.id INTO id;
    b := convert_to(risk.canonical(d), 'UTF8');
    INSERT INTO risk.control_version (control_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
END $$`, bus, selected, lo, min(lo+batch, controls)-1, control, frameworkBenchMappings))
		t.Logf("controls to %d: %v", min(lo+batch, controls), time.Since(start).Round(time.Second))
		if lo+batch >= controls/2 && mid.IsZero() {
			mid = time.Now().UTC() // half the controls exist: coverage as of then reads their versions
		}
	}
	// The library and scenarios: each scenario pins one control (round-
	// robin) in its current set, in that control's unit.
	seed(fmt.Sprintf(`DO $$
DECLARE id uuid; b bytea; d jsonb;
BEGIN
  FOREACH d IN ARRAY ARRAY['%[1]s'::jsonb, '%[2]s'::jsonb] LOOP
    INSERT INTO risk.library_entry (bu_id, kind) VALUES ('%[3]s', d->>'kind') RETURNING library_entry.id INTO id;
    b := convert_to(risk.canonical(d), 'UTF8');
    INSERT INTO risk.library_version (entry_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
END $$`, tmpl("asset", modeltest.Asset()), tmpl("threat_community", modeltest.ThreatCommunity()), root))
	owner := e.mustOwner("SELECT id FROM iam.app_user WHERE email = 'benchseed@example.test'")
	scenario := tmpl("scenario", modeltest.Scenario())
	for lo := 0; lo < scenarios; lo += batch {
		seed(fmt.Sprintf(`DO $$
DECLARE
  asset uuid := (SELECT id FROM risk.library_entry WHERE kind = 'asset' LIMIT 1);
  tc uuid := (SELECT id FROM risk.library_entry WHERE kind = 'threat_community' LIMIT 1);
  ctls uuid[] := ARRAY(SELECT id FROM risk.control ORDER BY seq);
  cbus uuid[] := ARRAY(SELECT bu_id FROM risk.control ORDER BY seq);
  id uuid; b bytea; d jsonb; n integer;
BEGIN
  FOR i IN %[1]d..%[2]d LOOP
    n := 1 + i %% cardinality(ctls);
    d := '%[3]s'::jsonb || jsonb_build_object('name', 'Scenario ' || i, 'owner', '%[4]s',
      'asset', jsonb_build_object('kind', 'asset', 'id', asset, 'version', 1),
      'threat_community', jsonb_build_object('id', tc, 'version', 1),
      'control_sets', jsonb_build_array(jsonb_build_object('name', 'Current', 'current', true,
        'controls', jsonb_build_array(jsonb_build_object('id', ctls[n], 'version', 1, 'status', 'in_place')))));
    INSERT INTO risk.scenario (bu_id) VALUES (cbus[n]) RETURNING scenario.id INTO id;
    b := convert_to(risk.canonical(d), 'UTF8');
    INSERT INTO risk.scenario_version (scenario_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
END $$`, lo, min(lo+batch, scenarios)-1, scenario, owner))
		t.Logf("scenarios to %d: %v", min(lo+batch, scenarios), time.Since(start).Round(time.Second))
	}
	e.admin(e.db, "ANALYZE framework.control_mapping; ANALYZE risk.control; ANALYZE risk.control_version; ANALYZE risk.scenario; ANALYZE risk.scenario_version; ANALYZE risk.scenario_pin")
	t.Logf("loaded: %s in %v", e.adminQuery(`SELECT (SELECT count(*) FROM risk.control) || ' controls, ' || (SELECT count(*) FROM framework.control_mapping) || ' mappings, '
		|| (SELECT count(*) FROM risk.scenario) || ' scenarios'`), time.Since(start).Round(time.Second))

	if os.Getenv("FAIR_BENCH_EXPLAIN") == "1" { // the plans, by hand
		out, err := e.superuser(fmt.Sprintf(`BEGIN; LOAD 'auto_explain'; SET LOCAL auto_explain.log_min_duration = 0; SET LOCAL auto_explain.log_analyze = on;
			SET LOCAL auto_explain.log_nested_statements = on; SET LOCAL auto_explain.log_level = notice; SET LOCAL ROLE app_rw;
			SELECT set_config('authz.ctx', '%s', true); SELECT length(framework.coverage('%s', '%s', '%s', NULL)::text); COMMIT;`,
			e.principal("benchseed").DBToken, v520, moderate, root))
		t.Logf("plans (%v): %s", err, out)
	}
	api := newBenchFrameworkAPI(t, e)
	var results []benchResult
	failed := false

	// The import: request to outcome, the job run in the measurement.
	cat, err := os.ReadFile(filepath.Join("..", "..", "third_party", "oscal", "nist", "sp800-53r5", "NIST_SP-800-53_rev5_catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	q := url.Values{"kind": {"catalog"}, "family": {"bench-800-53"}, "family_title": {"Bench SP 800-53"}, "publisher": {"NIST"}}
	code, out, _ := api.b.requestType(t, "benchfw", "POST", "/api/v1/frameworks/imports?"+q.Encode(), cat, "application/json")
	if code != http.StatusAccepted {
		t.Fatalf("import: %d %s", code, out[:min(len(out), 400)])
	}
	var imp struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(out, &imp)
	if err := api.worker.Run(context.Background(), imp.ID); err != nil {
		t.Fatal(err)
	}
	took := time.Since(t0)
	if state := e.mustOwner("SELECT state FROM framework.import WHERE id = '" + imp.ID + "'"); state != "succeeded" {
		t.Fatalf("import %s: %s", state, e.mustOwner("SELECT problems::text FROM framework.import WHERE id = '"+imp.ID+"'"))
	}
	ms := float64(took.Milliseconds())
	results = append(results, benchResult{Name: "NIST SP 800-53r5 catalog imported (" + e.mustOwner("SELECT count(*) FROM framework.requirement r JOIN framework.version v ON v.id = r.version_id WHERE v.family = 'bench-800-53'") +
		" requirements), request to outcome", P50ms: ms, P95ms: ms, P99ms: ms, Budget: float64(frameworkImportBudget.Milliseconds())})
	if took > frameworkImportBudget {
		failed = true
	}

	ac2 := e.mustOwner("SELECT id FROM framework.requirement WHERE version_id = '" + v520 + "' AND identifier = 'ac-2'")
	busy := e.adminQuery(`SELECT requirement_id FROM framework.control_mapping m JOIN framework.requirement r ON r.id = m.requirement_id
		WHERE r.version_id = '` + v520 + `' AND m.current GROUP BY requirement_id ORDER BY count(*) DESC LIMIT 1`)
	for _, c := range []struct {
		name   string
		path   func(int) string
		budget time.Duration
	}{
		{"coverage, moderate baseline, at the root", fixed("/api/v1/frameworks/versions/" + v520 + "/coverage?bu=" + root + "&baseline=" + moderate), frameworkCoverageBudget},
		{"coverage, the whole version, at the root", fixed("/api/v1/frameworks/versions/" + v520 + "/coverage?bu=" + root), frameworkCoverageBudget},
		{"coverage, moderate, as of mid-load (half the controls)", fixed("/api/v1/frameworks/versions/" + v520 + "/coverage?bu=" + root + "&baseline=" + moderate +
			"&as_of=" + url.QueryEscape(mid.Format(time.RFC3339Nano))), frameworkCoverageBudget},
		{"a requirement's controls and scenarios (AC-2)", fixed("/api/v1/frameworks/requirements/" + ac2 + "/scenarios"), frameworkScenariosBudget},
		{"a requirement's controls and scenarios (the most mapped)", fixed("/api/v1/frameworks/requirements/" + busy + "/scenarios"), frameworkScenariosBudget},
	} {
		r := summarize("framework API: "+c.name, api.b.time(t, "benchseed", c.path), c.budget)
		results = append(results, r)
		if r.P95ms > r.Budget {
			failed = true
		}
	}

	var rep strings.Builder
	fmt.Fprintf(&rep, "F-013 frameworks: %d controls with %d mappings each in the unrestricted units, %d scenarios pinning them; as a reader at the root, %d runs after warm-up\n",
		controls, frameworkBenchMappings, scenarios, registerBenchRuns)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.2f | %.2f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("frameworks over budget")
	}
}

type benchFrameworkAPI struct {
	b      *benchRegisterAPI
	worker *frameworkapi.Worker
}

// newBenchFrameworkAPI serves the framework API on the bench keys; queued
// imports are run by the test (worker.Run).
func newBenchFrameworkAPI(t *testing.T, e *env) *benchFrameworkAPI {
	t.Helper()
	k := newBenchRiskAPI(t, e) // its keys
	pool := e.appPool()
	api := &frameworkapi.API{DB: pool, Reasons: reason.Static{}, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool}),
		Enqueue: func(context.Context, pgx.Tx, frameworkapi.ImportArgs) error { return nil }}
	srv := httptest.NewServer(api.Handler(k.keys, nil))
	t.Cleanup(srv.Close)
	return &benchFrameworkAPI{b: &benchRegisterAPI{e: e, url: srv.URL, keys: k.keys}, worker: &frameworkapi.Worker{DB: pool}}
}

// requestType is request with the body's content type (a file upload).
func (b *benchRegisterAPI) requestType(t *testing.T, user, method, path string, body []byte, contentType string) (int, []byte, time.Duration) {
	t.Helper()
	p := b.e.principal(user)
	tok, err := authz.MintJWT(b.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, b.url+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(server.DBContextHeader, p.DBToken)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Idempotency-Key", fmt.Sprintf("bench-%d", time.Now().UnixNano()))
	t0 := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, out, time.Since(t0)
}
