package tests

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/api/enginev1"
	"github.com/rformer/fair-app/internal/registerapi"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-007 T-10 (requirements NFR "Performance"; design §9): the register gate
// at the F-001 target scale (2,011 BUs, 10,000 users): 10,000 open risks
// across the BUs, each covering one scenario: 8 in 10 pinned to a succeeded
// run of 100,000 iterations (current), 1 in 10 linked without a pin
// (stale), 1 in 10 with none (unquantified). Budgets, p95, through the
// register API (HTTP, JSON, authorization, the DB context and RLS) for a
// user who sees them all:
//   - the list (newest, 200 rows, by status, by mean, a subtree) and
//     coverage: <= 1 s;
//   - a risk's page: <= 1 s;
//   - a roll-up of the 500 current risks of one level-1 subtree, from the
//     request to its record computed, its nodes worked by the aggregate
//     worker: <= 30 s. The engine is the real one when
//     FAIR_BENCH_ENGINE_ADDR names it (CI), else the fake engine.
//
// Runs and their results are written directly (the engine is not what is
// measured); scenarios and risks go through their triggers.

const (
	registerBenchRisks       = 10_000
	registerBenchInside      = 625 // in L1_1's subtree: 500 of them current
	registerBenchIterations  = 100_000
	registerListBudget       = time.Second
	registerPageBudget       = time.Second
	registerRollupBudget     = 30 * time.Second
	registerBenchRuns        = 20
	registerBenchBatch       = 1_000
	registerBenchScenarioDoc = "scenario"
)

func TestBenchmarkGateRegister(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	ctx := context.Background()
	total := registerBenchRisks
	if n := os.Getenv("FAIR_BENCH_REGISTER_RISKS"); n != "" { // a smaller run, by hand
		total, _ = strconv.Atoi(n)
	}
	l1 := seedRegisterBench(t, e, total)

	api := newBenchRegisterAPI(t, e)
	ids := strings.Split(e.adminQuery(`SELECT string_agg(r.id::text, ',') FROM (SELECT r.id FROM register.risk r
		WHERE EXISTS (SELECT 1 FROM register.risk_scenario l WHERE l.risk_id = r.id AND l.run_id IS NOT NULL) ORDER BY md5(r.id::text) LIMIT 23) r`), ",")
	cases := []struct {
		name   string
		path   func(i int) string
		budget time.Duration
	}{
		{"list, newest", fixed("/api/v1/register/risks"), registerListBudget},
		{"list, 200 rows", fixed("/api/v1/register/risks?limit=200"), registerListBudget},
		{"list, deep page", fixed("/api/v1/register/risks?offset=" + strconv.Itoa(total/2)), registerListBudget},
		{"list, stale", fixed("/api/v1/register/risks?status=stale"), registerListBudget},
		{"list, by mean", fixed("/api/v1/register/risks?sort=mean"), registerListBudget},
		{"list, a level-1 subtree", fixed("/api/v1/register/risks?bu=" + l1), registerListBudget},
		{"coverage, everything", fixed("/api/v1/register/coverage"), registerListBudget},
		{"a risk's page", func(i int) string { return "/api/v1/register/risks/" + ids[i%len(ids)] }, registerPageBudget},
	}
	var results []benchResult
	failed := false
	for _, c := range cases {
		r := summarize("register API: "+c.name, api.time(t, "benchowner", c.path), c.budget)
		results = append(results, r)
		if r.P95ms > r.Budget {
			failed = true
		}
	}

	// The roll-up: requested through the API, its nodes worked bottom up.
	engine, kind := registerBenchEngine(t)
	w := &analysis.AggregateWorker{DB: e.appPool(), Engine: engine}
	t0 := time.Now()
	id := api.post(t, "benchowner", "/api/v1/register/rollups", map[string]any{"bu_id": l1})
	requested := time.Since(t0)
	for state := ""; state != "succeeded"; {
		var queued []string
		for _, x := range strings.Split(e.adminQuery("SELECT string_agg(id::text, ',' ORDER BY seq) FROM analysis.aggregate WHERE purpose = 'rollup' AND state = 'queued'"), ",") {
			if x != "" {
				queued = append(queued, x)
			}
		}
		for _, x := range queued {
			if err := w.Attempt(ctx, x, 1, analysis.Attempts); err != nil && !isSnooze(err) {
				t.Fatalf("node %s: %v", x, err)
			}
		}
		state = e.adminQuery("SELECT state FROM register.rollup WHERE id = '" + id + "'")
		if state == "failed" || (len(queued) == 0 && state != "succeeded") {
			t.Fatalf("the roll-up: %s", e.adminQuery("SELECT state || ' ' || coalesce(failure, '') FROM register.rollup WHERE id = '"+id+"'"))
		}
	}
	took := time.Since(t0)
	covers := e.adminQuery("SELECT jsonb_array_length(included) || ' risks, ' || nodes || ' nodes' FROM register.rollup WHERE id = '" + id + "'")
	t.Logf("the roll-up: requested in %v, computed in %v", requested.Round(time.Millisecond), took.Round(time.Millisecond))
	r := benchResult{Name: fmt.Sprintf("roll-up of L1_1 (%s; %s engine), request to computed", covers, kind), P50ms: float64(took.Milliseconds()),
		P95ms: float64(took.Milliseconds()), P99ms: float64(took.Milliseconds()), Budget: float64(registerRollupBudget.Milliseconds())}
	results = append(results, r)
	if took > registerRollupBudget {
		failed = true
	}

	var rep strings.Builder
	fmt.Fprintf(&rep, "F-007 risk register: %d open risks over the BUs (8 in 10 pinned to a run of %d iterations), through the register API as a user who sees them all, %d runs after warm-up\n",
		total, registerBenchIterations, registerBenchRuns)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.2f | %.2f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("the register over budget")
	}
}

// seedRegisterBench loads the register gate's data (above): total open
// risks over the BUs, each covering one scenario (8 in 10 pinned to a
// succeeded run), owned by "benchowner" (Risk Owner and Risk Analyst at the
// root). Answers L1_1's id. F-008's gate builds on it.
func seedRegisterBench(t *testing.T, e *env, total int) string {
	t.Helper()
	ctx := context.Background()
	start := time.Now()
	seedPosture(t, e)
	(&riskAPIEnv{riskEnv: riskEnv{env: e}}).setCurrency(t, "USD")
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	l1 := e.mustOwner("SELECT id FROM iam.bu WHERE code = 'L1_1'")
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('benchowner@example.test', 'Bench Owner')")
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	for _, role := range []string{"Risk Owner", "Risk Analyst"} {
		e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
			SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = '%s'), '%s', '%s' FROM iam.app_user u WHERE u.email = 'benchowner@example.test'`, role, root, granter))
	}
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	e.mustOwner("DELETE FROM iam.outbox")
	e.mustOwner("GRANT EXECUTE ON FUNCTION risk.canonical(jsonb) TO app_rw") // the seeding below only; a test database
	owner := e.mustOwner("SELECT id FROM iam.app_user WHERE email = 'benchowner@example.test'")
	seed := func(sql string) {
		t.Helper()
		if err := (riskEnv{env: e}).tx("benchowner", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Writable BUs, unrestricted: L1_1's subtree and the others.
	inside := e.mustOwner(`SELECT string_agg(b.id::text, ',' ORDER BY b.code) FROM iam.bu b JOIN iam.bu_closure c ON c.descendant_id = b.id
		WHERE c.ancestor_id = (SELECT id FROM iam.bu WHERE code = 'L1_1') AND NOT b.restricted AND b.archived_at IS NULL`)
	outside := e.mustOwner(`SELECT string_agg(b.id::text, ',' ORDER BY b.code) FROM iam.bu b WHERE NOT b.restricted AND b.archived_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.descendant_id = b.id AND c.ancestor_id = (SELECT id FROM iam.bu WHERE code = 'L1_1'))
		AND NOT EXISTS (SELECT 1 FROM iam.bu_closure c JOIN iam.bu r ON r.id = c.ancestor_id WHERE c.descendant_id = b.id AND r.restricted)`)
	tmpl := func(kind string, doc map[string]any) string { return templateJSON(t, kind, doc) }
	seed(fmt.Sprintf(`DO $$
DECLARE id uuid; b bytea; d jsonb;
BEGIN
  FOREACH d IN ARRAY ARRAY['%[1]s'::jsonb, '%[2]s'::jsonb] LOOP
    INSERT INTO risk.library_entry (bu_id, kind) VALUES ('%[3]s', d->>'kind') RETURNING library_entry.id INTO id;
    b := convert_to(risk.canonical(d), 'UTF8');
    INSERT INTO risk.library_version (entry_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
  INSERT INTO risk.control (bu_id) VALUES ('%[3]s') RETURNING control.id INTO id;
  b := convert_to(risk.canonical('%[4]s'::jsonb), 'UTF8');
  INSERT INTO risk.control_version (control_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
END $$`, tmpl("asset", modeltest.Asset()), tmpl("threat_community", modeltest.ThreatCommunity()), root, tmpl("control", modeltest.Control())))

	// Scenarios: the first registerBenchInside in L1_1's subtree, the rest
	// elsewhere, round-robin over the BUs.
	scenario := tmpl(registerBenchScenarioDoc, modeltest.Scenario())
	for lo := 0; lo < total; lo += registerBenchBatch {
		seed(fmt.Sprintf(`DO $$
DECLARE
  inside uuid[] := string_to_array('%[1]s', ',')::uuid[];
  outside uuid[] := string_to_array('%[2]s', ',')::uuid[];
  asset uuid := (SELECT id FROM risk.library_entry WHERE kind = 'asset');
  tc uuid := (SELECT id FROM risk.library_entry WHERE kind = 'threat_community');
  ctl uuid := (SELECT id FROM risk.control);
  id uuid; b bytea; d jsonb;
BEGIN
  FOR i IN %[3]d..%[4]d LOOP
    d := '%[5]s'::jsonb || jsonb_build_object('name', 'Bench scenario ' || i, 'owner', '%[6]s',
      'asset', jsonb_build_object('kind', 'asset', 'id', asset, 'version', 1),
      'threat_community', jsonb_build_object('id', tc, 'version', 1),
      'control_sets', jsonb_build_array(jsonb_build_object('name', 'Current', 'current', true,
        'controls', jsonb_build_array(jsonb_build_object('id', ctl, 'version', 1, 'status', 'in_place')))));
    INSERT INTO risk.scenario (bu_id) VALUES (CASE WHEN i < %[7]d THEN inside[1 + i %% cardinality(inside)] ELSE outside[1 + i %% cardinality(outside)] END)
      RETURNING scenario.id INTO id;
    b := convert_to(risk.canonical(d), 'UTF8');
    INSERT INTO risk.scenario_version (scenario_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
END $$`, inside, outside, lo, min(lo+registerBenchBatch, total)-1, scenario, owner, registerBenchInside))
	}
	t.Logf("scenarios: %v", time.Since(start).Round(time.Second))

	// Runs, written as the worker leaves them (triggers off for the bulk
	// load): one per scenario, its result's summary varying, and a series
	// for those in L1_1's subtree (the roll-up's members).
	series := benchSeriesBytes(registerBenchIterations)
	conn := e.adminConn()
	defer func() { _ = conn.Close(ctx) }()
	for _, q := range []string{
		"SET session_replication_role = replica",
		fmt.Sprintf(`INSERT INTO analysis.run (bu_id, scenario_id, scenario_version, bundle_digest, seed, iterations, control_sets, requested_by, requested_at, state,
			progress, started_at, finished_at, engine_version, architecture, result_digest)
			SELECT s.bu_id, s.id, 1, repeat('a', 64), 1, %d, '{Current}', '%s', now(), 'succeeded', 1, now(), now(), '0.1.0', 'amd64', repeat('b', 64)
			FROM risk.scenario s`, registerBenchIterations, owner),
		`INSERT INTO analysis.result (run_id, bu_id, control_set, summary)
			SELECT r.id, r.bu_id, 'Current', jsonb_build_object('independence', 'Every input is sampled independently.', 'iterations', r.iterations,
			  'ale', jsonb_build_object('mean', 50000 + (r.seq % 997) * 100, 'p_positive', 0.45,
			    'percentiles', jsonb_build_object('p50', 0, 'p90', 150000 + (r.seq % 991) * 300, 'p95', 400000)))
			FROM analysis.run r`,
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q[:40], err)
		}
	}
	if _, err := conn.Exec(ctx, `INSERT INTO analysis.series (run_id, bu_id, control_set, ale)
		SELECT r.id, r.bu_id, 'Current', CASE WHEN EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.ancestor_id = $1 AND c.descendant_id = r.bu_id) THEN $2::bytea END
		FROM analysis.run r`, l1, series); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SET session_replication_role = origin"); err != nil {
		t.Fatal(err)
	}
	t.Logf("runs: %v", time.Since(start).Round(time.Second))

	// Risks, through the version trigger (every check, the links): risk i
	// covers scenario i, in its BU.
	for lo := 0; lo < total; lo += registerBenchBatch {
		seed(fmt.Sprintf(`DO $$
DECLARE
  s record; id uuid; b bytea; d jsonb; k integer;
BEGIN
  FOR s IN SELECT x.id, x.bu_id, x.seq, (SELECT r.id FROM analysis.run r WHERE r.scenario_id = x.id) AS run
           FROM risk.scenario x ORDER BY x.seq OFFSET %[1]d LIMIT %[2]d LOOP
    k := s.seq %% 10;
    d := jsonb_build_object('schema_version', 1, 'title', 'Bench risk ' || s.seq, 'owner', '%[3]s', 'state', 'open',
      'scenarios', CASE WHEN k = 0 THEN '[]'::jsonb
                        WHEN k = 1 THEN jsonb_build_array(jsonb_build_object('scenario_id', s.id))
                        ELSE jsonb_build_array(jsonb_build_object('scenario_id', s.id, 'pin', jsonb_build_object('run_id', s.run, 'control_set', 'Current'))) END);
    INSERT INTO register.risk (bu_id) VALUES (s.bu_id) RETURNING risk.id INTO id;
    b := convert_to(d::text, 'UTF8');
    INSERT INTO register.risk_version (risk_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
END $$`, lo, min(registerBenchBatch, total-lo), owner))
	}
	e.admin(e.db, "ANALYZE register.risk; ANALYZE register.risk_version; ANALYZE register.risk_scenario; ANALYZE analysis.run; ANALYZE analysis.result; ANALYZE analysis.series")
	inRollup := e.adminQuery("SELECT count(*) FROM register.risk_scenario l JOIN iam.bu_closure c ON c.descendant_id = l.bu_id AND c.ancestor_id = '" + l1 + "' WHERE l.run_id IS NOT NULL")
	t.Logf("loaded: %s risks (%s current in L1_1's subtree) in %v", e.adminQuery("SELECT count(*) FROM register.risk"), inRollup, time.Since(start).Round(time.Second))
	return l1
}

func isSnooze(err error) bool {
	var s *river.JobSnoozeError
	return errors.As(err, &s)
}

// benchSeriesBytes is a member's series: benchBase's years, little-endian
// float64.
func benchSeriesBytes(n int) []byte {
	x := benchBase(n)
	b := make([]byte, 8*n)
	for i, v := range x {
		binary.LittleEndian.PutUint64(b[8*i:], math.Float64bits(v))
	}
	return b
}

// registerBenchEngine is the real engine when FAIR_BENCH_ENGINE_ADDR names
// it, else the fake engine.
func registerBenchEngine(t *testing.T) (enginev1.EngineClient, string) {
	t.Helper()
	if os.Getenv("FAIR_BENCH_ENGINE_ADDR") != "" {
		return enginev1.NewEngineClient(dialBenchEngine(t)), "the real"
	}
	fe := &fakeEngine{}
	fe.set("bench", true)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.MaxRecvMsgSize(64 << 20))
	enginev1.RegisterEngineServer(gs, fe)
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///"+ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return enginev1.NewEngineClient(conn), "the fake"
}

type benchRegisterAPI struct {
	e    *env
	url  string
	keys *authz.LocalKeys
}

func newBenchRegisterAPI(t *testing.T, e *env) *benchRegisterAPI {
	t.Helper()
	b := newBenchRiskAPI(t, e) // its keys
	pool := e.appPool()
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: analysis.RiverSchema})
	if err != nil {
		t.Fatal(err)
	}
	api := &registerapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool}), EnqueueAggregate: analysis.AggregateEnqueuer(rc)}
	srv := httptest.NewServer(api.Handler(b.keys, nil))
	t.Cleanup(srv.Close)
	return &benchRegisterAPI{e: e, url: srv.URL, keys: b.keys}
}

func (b *benchRegisterAPI) request(t *testing.T, user, method, path string, body []byte) (int, []byte, time.Duration) {
	t.Helper()
	p := b.e.principal(user)
	tok, err := authz.MintJWT(b.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, b.url+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(server.DBContextHeader, p.DBToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", fmt.Sprintf("bench-%d", time.Now().UnixNano()))
	}
	t0 := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, out, time.Since(t0)
}

// time GETs path(i) as user: 3 warm-up requests, then registerBenchRuns
// timed ones, each with a fresh token and DB context, the body read in full.
func (b *benchRegisterAPI) time(t *testing.T, user string, path func(int) string) []time.Duration {
	t.Helper()
	out := make([]time.Duration, 0, registerBenchRuns)
	for i := range registerBenchRuns + 3 {
		code, body, d := b.request(t, user, "GET", path(i), nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path(i), code, body)
		}
		if !strings.Contains(string(body), `"id"`) && !strings.Contains(string(body), `"open"`) {
			t.Fatalf("GET %s: nothing (the benchmark would measure nothing): %s", path(i), body[:min(len(body), 300)])
		}
		if i >= 3 {
			out = append(out, d)
		}
	}
	return out
}

func (b *benchRegisterAPI) post(t *testing.T, user, path string, body any) string {
	t.Helper()
	raw, _ := json.Marshal(body)
	code, out, _ := b.request(t, user, "POST", path, raw)
	if code != http.StatusAccepted {
		t.Fatalf("POST %s: %d %s", path, code, out)
	}
	var r struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	return r.ID
}
