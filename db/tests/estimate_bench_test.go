package tests

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/estimateapi"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-004 T-15 (requirements NFR "Performance"; design §4.4): at the F-001
// target scale (2,011 BUs, 10,000 users), 10,000 open estimate requests on
// 1,000 scenarios, half in one level-1 subtree, each asking 3 of 200
// estimators for 2 factors, every estimator having answered. One estimator
// is addressed by 100 of them. Measured through the estimate API (HTTP,
// JSON, authorization, the DB context, RLS and the definer functions): the
// estimator's inbox and a request as they see it, and the analyst's request
// and review, in <= 300 ms p95; scoring an exercise (submitting one, for a
// person with 25 earlier exercises in the window) in <= 1 s p95.

const (
	estBenchRequests  = 10_000
	estBenchScenarios = 1_000
	estBenchPool      = 200
	estBenchAddressed = 100
	estBenchHistory   = 25
	estBenchRuns      = 20
	estViewBudget     = 300 * time.Millisecond
	estScoreBudget    = time.Second
)

func TestBenchmarkGateEstimates(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	start := time.Now()
	requests := estBenchRequests
	if n := os.Getenv("FAIR_BENCH_ESTIMATE_REQUESTS"); n != "" { // a smaller run, by hand
		requests, _ = strconv.Atoi(n)
	}
	scenarios := max(requests/10, 1)
	(&riskAPIEnv{riskEnv: riskEnv{env: e}}).setCurrency(t, "USD")

	// A risk analyst at the root (the seeder) and at L1_1 (the reviewer);
	// the estimator pool and the measured estimator, Estimators at the root;
	// people for the scoring runs.
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	l1 := e.mustOwner("SELECT id FROM iam.bu WHERE code = 'L1_1'")
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.app_user (email, display_name)
		SELECT 'estpool' || i || '@example.test', 'Estimator ' || i FROM generate_series(1, %d) i
		UNION ALL SELECT 'estcal' || i || '@example.test', 'Calibration ' || i FROM generate_series(1, %d) i
		UNION ALL VALUES ('estseed@example.test', 'Bench Seed'), ('estsub@example.test', 'Bench Subtree'), ('estme@example.test', 'Bench Estimator')`,
		estBenchPool, estBenchRuns+3))
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = CASE WHEN u.email IN ('estseed@example.test', 'estsub@example.test') THEN 'Risk Analyst' ELSE 'Estimator' END),
		       CASE u.email WHEN 'estsub@example.test' THEN '%s'::uuid ELSE '%s'::uuid END, '%s'
		FROM iam.app_user u WHERE u.email LIKE 'est%%@example.test'`, l1, root, granter))
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	e.mustOwner("DELETE FROM iam.outbox")
	e.mustOwner("GRANT EXECUTE ON FUNCTION risk.canonical(jsonb) TO app_rw") // the seeding below only; a test database
	seed := func(sql string) {
		t.Helper()
		if err := (riskEnv{env: e}).tx("estseed", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), sql)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The scenarios, half in L1_1's subtree, on a small library at the root.
	inside := e.mustOwner(`SELECT string_agg(b.id::text, ',' ORDER BY b.code) FROM iam.bu b JOIN iam.bu_closure c ON c.descendant_id = b.id
		WHERE c.ancestor_id = (SELECT id FROM iam.bu WHERE code = 'L1_1') AND NOT b.restricted`)
	outside := e.mustOwner(`SELECT string_agg(b.id::text, ',' ORDER BY b.code) FROM iam.bu b WHERE b.depth > 0 AND NOT b.restricted
		AND NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.descendant_id = b.id AND c.ancestor_id = (SELECT id FROM iam.bu WHERE code = 'L1_1'))`)
	tmpl := func(kind string, doc map[string]any) string { return templateJSON(t, kind, doc) }
	seed(fmt.Sprintf(`DO $$
DECLARE id uuid; b bytea; d jsonb;
BEGIN
  FOREACH d IN ARRAY ARRAY['%[1]s'::jsonb, '%[2]s'::jsonb] LOOP
    INSERT INTO risk.library_entry (bu_id, kind) VALUES ('%[3]s', d->>'kind') RETURNING library_entry.id INTO id;
    b := convert_to(risk.canonical(d), 'UTF8');
    INSERT INTO risk.library_version (entry_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
  d := '%[4]s'::jsonb;
  INSERT INTO risk.control (bu_id) VALUES ('%[3]s') RETURNING control.id INTO id;
  b := convert_to(risk.canonical(d), 'UTF8');
  INSERT INTO risk.control_version (control_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
END $$`, tmpl("asset", modeltest.Asset()), tmpl("threat_community", modeltest.ThreatCommunity()), root, tmpl("control", modeltest.Control())))
	owner := e.mustOwner("SELECT id FROM iam.app_user WHERE email = 'estseed@example.test'")
	scenario := tmpl("scenario", modeltest.Scenario())
	for i, bus := range []string{inside, outside} {
		lo, hi := i*scenarios/2, (i+1)*scenarios/2-1
		seed(fmt.Sprintf(`DO $$
DECLARE
  bus uuid[] := string_to_array('%[1]s', ',')::uuid[];
  a uuid := (SELECT id FROM risk.library_entry WHERE kind = 'asset' LIMIT 1);
  tc uuid := (SELECT id FROM risk.library_entry WHERE kind = 'threat_community' LIMIT 1);
  ctl uuid := (SELECT id FROM risk.control LIMIT 1);
  id uuid; b bytea; d jsonb;
BEGIN
  FOR i IN %[2]d..%[3]d LOOP
    d := '%[4]s'::jsonb || jsonb_build_object('name', 'Scenario ' || i, 'owner', '%[5]s',
      'asset', jsonb_build_object('kind', 'asset', 'id', a, 'version', 1), 'threat_community', jsonb_build_object('id', tc, 'version', 1),
      'control_sets', jsonb_build_array(jsonb_build_object('name', 'Current', 'current', true,
        'controls', jsonb_build_array(jsonb_build_object('id', ctl, 'version', 1, 'status', 'in_place')))));
    INSERT INTO risk.scenario (bu_id) VALUES (bus[1 + i %% cardinality(bus)]) RETURNING scenario.id INTO id;
    b := convert_to(risk.canonical(d), 'UTF8');
    INSERT INTO risk.scenario_version (scenario_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
END $$`, bus, lo, hi, scenario, owner))
	}
	t.Logf("scenarios: %d in %v", scenarios, time.Since(start).Round(time.Second))

	// The requests, ten per scenario, in batches (a context lives a minute):
	// three pool estimators each, and the measured one on every
	// (requests / estBenchAddressed)th.
	every := max(requests/estBenchAddressed, 1)
	poolIDs := e.adminQuery("SELECT string_agg(id::text, ',' ORDER BY email) FROM iam.app_user WHERE email LIKE 'estpool%'")
	me := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'estme@example.test'")
	const batch = 1_000
	for lo := 0; lo < requests; lo += batch {
		seed(fmt.Sprintf(`DO $$
DECLARE
  sc uuid[] := ARRAY(SELECT s.id FROM risk.scenario s ORDER BY s.seq);
  pool uuid[] := string_to_array('%[4]s', ',')::uuid[];
  me uuid := '%[5]s';
  s uuid; id uuid;
BEGIN
  FOR i IN %[1]d..%[2]d LOOP
    s := sc[1 + i %% cardinality(sc)];
    INSERT INTO estimate.request (bu_id, scenario_id, scenario_version, title, due_at, context)
    SELECT x.bu_id, x.id, 1, 'Request ' || i, now() + interval '30 days', jsonb_build_object('name', 'Scenario')
    FROM risk.scenario x WHERE x.id = s RETURNING request.id INTO id;
    INSERT INTO estimate.request_factor (request_id, pointer, factor, unit, definition) VALUES
      (id, '/lef/tef/contact_frequency', 'contact_frequency', 'events_per_year', 'How often threat agents come into contact with the asset.'),
      (id, '/primary_loss/response', 'primary_loss.response', 'currency', 'The cost of responding to a loss event.');
    INSERT INTO estimate.request_estimator (request_id, user_id)
    SELECT id, pool[1 + (i * 3 + k) %% cardinality(pool)] FROM generate_series(0, 2) k;
    IF i %% %[3]d = 0 THEN INSERT INTO estimate.request_estimator (request_id, user_id) VALUES (id, me); END IF;
  END LOOP;
END $$`, lo, min(lo+batch, requests)-1, every, poolIDs, me))
		t.Logf("requests to %d: %v", min(lo+batch, requests), time.Since(start).Round(time.Second))
	}
	// Every estimator's submitted answers (the definer-only table: written
	// here as the test superuser).
	e.admin(e.db, `INSERT INTO estimate.answer (request_id, bu_id, estimator, pointer, revision, state, estimate, calibration)
		SELECT f.request_id, f.bu_id, x.user_id, f.pointer, 1, 'submitted',
		  CASE f.unit WHEN 'currency' THEN '{"min":"40000","ml":"120000","max":"500000","unit":"currency","confidence":"0.9","rationale":"Past invoices.","sources":[{"type":"person","ref":"Finance"}]}'::jsonb
		              ELSE '{"min":"2","ml":"5","max":"10","unit":"events_per_year","confidence":"0.9","rationale":"Tickets.","sources":[{"type":"person","ref":"SOC"}]}'::jsonb END,
		  '{"class":"not_measured","as_of":"2026-11-01"}'::jsonb
		FROM estimate.request_factor f JOIN estimate.request_estimator x ON x.request_id = f.request_id`)
	// Calibration history: estBenchHistory exercises of 20 shipped questions
	// per scoring person, submitted 200 days ago (inside the window, outside
	// the reuse period).
	e.admin(e.db, fmt.Sprintf(`DO $$
DECLARE u record; x uuid; qs jsonb;
BEGIN
  FOR u IN SELECT id FROM iam.app_user WHERE email LIKE 'estcal%%' LOOP
    FOR k IN 1..%d LOOP
      SELECT jsonb_agg(jsonb_build_object('id', q.id, 'version', q.version)) INTO qs FROM (
        (SELECT DISTINCT ON (id) id, version, kind FROM estimate.question WHERE kind = 'range' AND retired_at IS NULL ORDER BY id, version DESC LIMIT 10 OFFSET (k * 10) %% 50)
        UNION ALL
        (SELECT DISTINCT ON (id) id, version, kind FROM estimate.question WHERE kind = 'binary' AND retired_at IS NULL ORDER BY id, version DESC LIMIT 10 OFFSET (k * 10) %% 50)) q;
      INSERT INTO estimate.exercise (user_id, started_at, submitted_at, questions)
      VALUES (u.id, now() - interval '200 days', now() - interval '200 days', qs) RETURNING id INTO x;
      INSERT INTO estimate.exercise_answer (exercise_id, question_id, version, low, high, choice, confidence, correct)
      SELECT x, q.id, q.version,
             CASE WHEN q.kind = 'range' THEN 0 END, CASE WHEN q.kind = 'range' THEN 1 END,
             CASE WHEN q.kind = 'binary' THEN true END, CASE WHEN q.kind = 'binary' THEN 0.9 END, random() < 0.8
      FROM jsonb_array_elements(qs) o JOIN estimate.question q ON q.id = (o ->> 'id')::uuid AND q.version = (o ->> 'version')::int;
    END LOOP;
  END LOOP;
END $$`, estBenchHistory))
	e.admin(e.db, "ANALYZE estimate.request; ANALYZE estimate.request_factor; ANALYZE estimate.request_estimator; ANALYZE estimate.answer; ANALYZE estimate.exercise; ANALYZE estimate.exercise_answer; ANALYZE risk.scenario")
	t.Logf("loaded: %s in %v", e.adminQuery(`SELECT (SELECT count(*) FROM estimate.request WHERE status = 'open') || ' open requests, '
		|| (SELECT count(*) FROM estimate.answer) || ' answers, ' || (SELECT count(*) FROM estimate.exercise_answer) || ' exercise answers'`),
		time.Since(start).Round(time.Second))

	api := newBenchEstimateAPI(t, e)
	mine := strings.Split(e.adminQuery(`SELECT string_agg(x.request_id::text, ',') FROM estimate.request_estimator x
		JOIN iam.app_user u ON u.id = x.user_id WHERE u.email = 'estme@example.test'`), ",")
	sub := strings.Split(e.adminQuery(fmt.Sprintf(`SELECT string_agg(id::text, ',') FROM (SELECT q.id FROM estimate.request q
		JOIN iam.bu_closure c ON c.descendant_id = q.bu_id AND c.ancestor_id = '%s' ORDER BY md5(q.id::text) LIMIT %d) x`, l1, estBenchRuns+3)), ",")
	subScenarios := strings.Split(e.adminQuery(fmt.Sprintf(`SELECT string_agg(scenario_id::text, ',') FROM (SELECT DISTINCT q.scenario_id FROM estimate.request q
		JOIN iam.bu_closure c ON c.descendant_id = q.bu_id AND c.ancestor_id = '%s' LIMIT %d) x`, l1, estBenchRuns+3)), ",")
	pick := func(ids []string) func(int) string { return func(i int) string { return ids[i%len(ids)] } }
	cases := []struct {
		name, user string
		path       func(int) string
		check      string
		budget     time.Duration
	}{
		{"estimator: inbox", "estme", fixed("/api/v1/estimates/inbox"), `"requests"`, estViewBudget},
		{"estimator: a request", "estme", func(i int) string { return "/api/v1/estimates/inbox/" + pick(mine)(i) }, `"factors"`, estViewBudget},
		{"analyst: a scenario's requests, subtree", "estsub", func(i int) string { return "/api/v1/estimates/requests?scenario=" + pick(subScenarios)(i) }, `"requests"`, estViewBudget},
		{"analyst: a request, subtree", "estsub", func(i int) string { return "/api/v1/estimates/requests/" + pick(sub)(i) }, `"estimators"`, estViewBudget},
		{"analyst: review, subtree", "estsub", func(i int) string { return "/api/v1/estimates/requests/" + pick(sub)(i) + "/answers" }, `"previews"`, estViewBudget},
	}
	var results []benchResult
	failed := false
	for _, c := range cases {
		ds := make([]time.Duration, 0, estBenchRuns)
		for i := range estBenchRuns + 3 {
			d, code, body := api.do(t, c.user, "GET", c.path(i), nil, 0)
			if code != http.StatusOK || !strings.Contains(body, c.check) {
				t.Fatalf("%s: GET %s: %d %s", c.name, c.path(i), code, body[:min(len(body), 300)])
			}
			if i >= 3 {
				ds = append(ds, d)
			}
		}
		r := summarize("estimate API: "+c.name, ds, c.budget)
		results = append(results, r)
		failed = failed || r.P95ms > r.Budget
	}
	// Scoring: each person starts an exercise (not timed) and submits it.
	ds := make([]time.Duration, 0, estBenchRuns)
	for i := range estBenchRuns + 3 {
		user := fmt.Sprintf("estcal%d", i+1)
		_, code, body := api.do(t, user, "POST", "/api/v1/calibration/exercises", map[string]any{}, 2*i)
		var ex struct {
			ID        string `json:"id"`
			Questions []struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			} `json:"questions"`
		}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &ex) != nil || len(ex.Questions) == 0 {
			t.Fatalf("start an exercise as %s: %d %s", user, code, body[:min(len(body), 300)])
		}
		answers := make([]any, len(ex.Questions))
		for j, q := range ex.Questions {
			if q.Kind == "range" {
				answers[j] = map[string]any{"id": q.ID, "low": "-1000000000000", "high": "1000000000000000"}
			} else {
				answers[j] = map[string]any{"id": q.ID, "choice": true, "confidence": "0.9"}
			}
		}
		d, code, body := api.do(t, user, "POST", "/api/v1/calibration/exercises/"+ex.ID+"/submit", map[string]any{"answers": answers}, 2*i+1)
		if code != http.StatusOK || !strings.Contains(body, `"score"`) {
			t.Fatalf("submit as %s: %d %s", user, code, body[:min(len(body), 300)])
		}
		if i >= 3 {
			ds = append(ds, d)
		}
	}
	r := summarize(fmt.Sprintf("calibration API: submit and score an exercise (%d earlier exercises in the window)", estBenchHistory), ds, estScoreBudget)
	results = append(results, r)
	failed = failed || r.P95ms > r.Budget

	var rep strings.Builder
	fmt.Fprintf(&rep, "F-004 estimates: %d open requests on %d scenarios (half in L1_1's subtree), 3 of %d estimators each, one estimator addressed by %d; %d runs after warm-up\n",
		requests, scenarios, estBenchPool, estBenchAddressed, estBenchRuns)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.2f | %.2f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("estimate API over budget")
	}
}

type benchEstimateAPI struct {
	e    *env
	url  string
	keys *authz.LocalKeys
}

func newBenchEstimateAPI(t *testing.T, e *env) *benchEstimateAPI {
	t.Helper()
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(filepath.Join(dir, "gw-1.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := authz.LoadLocalKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	pool := e.appPool()
	api := &estimateapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	srv := httptest.NewServer(api.Handler(keys, nil))
	t.Cleanup(srv.Close)
	return &benchEstimateAPI{e: e, url: srv.URL, keys: keys}
}

// do sends one request as user with a fresh token and DB context (and an
// Idempotency-Key numbered n for a mutation), the body read in full.
func (b *benchEstimateAPI) do(t *testing.T, user, method, path string, body any, n int) (time.Duration, int, string) {
	t.Helper()
	p := b.e.principal(user)
	tok, err := authz.MintJWT(b.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, b.url+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(server.DBContextHeader, p.DBToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(server.IdempotencyHeader, fmt.Sprintf("estimate-bench-%06d", n))
	}
	t0 := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return time.Since(t0), resp.StatusCode, string(out)
}
