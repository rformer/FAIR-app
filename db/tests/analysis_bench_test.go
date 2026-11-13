package tests

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/analysisapi"
	"github.com/rformer/fair-app/internal/api/enginev1"
	"github.com/rformer/fair-app/internal/enginetls"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-005 T-15 (requirements NFR performance): the simulation gate, against
// the real engine. FAIR_BENCH_ENGINE_ADDR names it: host:port of an
// engine-gate (with FAIR_BENCH_ENGINE_CLIENT_DIR, the risk side of its keys)
// or unix:///path of an engine's socket. Budgets:
//   - a fully decomposed scenario (contact frequency, probability of
//     action, threat capability, resistance strength, six forms of primary
//     loss, two secondary stakeholder groups) with three control sets,
//     100,000 iterations with sensitivity: p95 <= 30 s, request to results;
//   - an aggregate of 100 runs of 100,000 iterations: <= 10 s;
//   - a queued run starts within 5 s while an engine worker is free.
const (
	simBenchRuns       = 5
	simBenchIterations = 100_000
	simBenchMembers    = 100
	simRunBudget       = 30 * time.Second
	simAggregateBudget = 10 * time.Second
	simStartBudget     = 5 * time.Second
)

func dialBenchEngine(t *testing.T) *grpc.ClientConn {
	t.Helper()
	addr := os.Getenv("FAIR_BENCH_ENGINE_ADDR")
	if addr == "" {
		t.Fatal("the simulation gate needs the engine: set FAIR_BENCH_ENGINE_ADDR (and FAIR_BENCH_ENGINE_CLIENT_DIR for an engine-gate)")
	}
	opts := []grpc.DialOption{grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16 << 20))}
	if strings.HasPrefix(addr, "unix://") {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tc, err := enginetls.ClientConfig(os.Getenv("FAIR_BENCH_ENGINE_CLIENT_DIR"), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		addr = "passthrough:///" + addr
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// decomposedScenario is the NFR's scenario at bu: modeltest's frequencies
// and derived Vulnerability, all six forms of primary loss, two stakeholder
// groups of two forms each, and three control sets (the current one; one
// adding two controls; one removing the current control and adding another).
func decomposedScenario(t *testing.T, ra *riskAPIEnv, bu string) string {
	t.Helper()
	est := func(lo, ml, hi, unit string) map[string]any {
		return map[string]any{"min": lo, "ml": ml, "max": hi, "unit": unit, "confidence": "0.9", "rationale": "Benchmark.",
			"sources": []any{map[string]any{"type": "document", "ref": "bench"}}}
	}
	control := func(name string, effects ...[2]any) string {
		es := []any{}
		for _, e := range effects {
			es = append(es, map[string]any{"factor": e[0], "estimate": e[1]})
		}
		return ra.create(t, "analyst", "control", bu, map[string]any{"kind": "control", "schema_version": 1, "name": name, "effects": es})
	}
	edr := control("EDR", [2]any{"resistance_strength", est("60", "75", "90", "percentile")}, [2]any{"loss.response", est("0.1", "0.3", "0.5", "fraction")})
	training := control("Training", [2]any{"contact_frequency", est("0.1", "0.3", "0.5", "fraction")}, [2]any{"loss.productivity", est("0.05", "0.15", "0.3", "fraction")})
	backup := control("Backups", [2]any{"loss.replacement", est("0.2", "0.5", "0.8", "fraction")})
	filtering := control("Filtering", [2]any{"probability_of_action", est("0.1", "0.25", "0.4", "fraction")})
	asset := modeltest.Asset()
	delete(asset, "value")
	asset["value_basis"] = "Replacement cost."
	a := ra.create(t, "analyst", "asset", bu, asset)
	tc := ra.create(t, "analyst", "threat_community", bu, modeltest.ThreatCommunity())
	d := modeltest.Scenario()
	d["name"] = "Benchmark: fully decomposed"
	modeltest.Set(d, "/owner", ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'analyst@example.test'"))
	modeltest.Set(d, "/asset", map[string]any{"kind": "asset", "id": a, "version": 1})
	modeltest.Set(d, "/threat_community", map[string]any{"id": tc, "version": 1})
	d["primary_loss"] = map[string]any{
		"productivity": est("100000", "400000", "2000000", "currency"), "response": est("50000", "150000", "600000", "currency"),
		"replacement": est("20000", "80000", "300000", "currency"), "fines_judgments": est("0", "50000", "1000000", "currency"),
		"competitive_advantage": est("0", "100000", "2000000", "currency"), "reputation": est("10000", "200000", "3000000", "currency"),
	}
	d["secondary_risk"] = []any{
		map[string]any{"stakeholder": "Regulators", "slef": est("0.2", "0.4", "0.7", "probability"),
			"loss": map[string]any{"fines_judgments": est("0", "250000", "5000000", "currency"), "response": est("10000", "50000", "200000", "currency")}},
		map[string]any{"stakeholder": "Customers", "slef": est("0.1", "0.3", "0.6", "probability"),
			"loss": map[string]any{"reputation": est("50000", "300000", "4000000", "currency"), "competitive_advantage": est("0", "100000", "1000000", "currency")}},
	}
	use := func(id string) map[string]any { return map[string]any{"id": id, "version": 1, "status": "in_place"} }
	d["control_sets"] = []any{
		map[string]any{"name": "Current", "current": true, "controls": []any{use(edr)}},
		map[string]any{"name": "Hardening", "current": false, "controls": []any{use(edr), use(training), use(backup)}},
		map[string]any{"name": "Lean", "current": false, "controls": []any{use(filtering)}},
	}
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": bu, "document": d, "change_note": "benchmark"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	return got.body["id"].(string)
}

func TestBenchmarkGateSimulation(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	ctx := context.Background()
	conn := dialBenchEngine(t)
	ra := strideF003Fixture(t) // analyst, a Risk Analyst at A
	bu := ra.bu["A1"]
	sid := decomposedScenario(t, ra, bu)

	// The analysis API with the River client working the queue, as in the
	// risk service.
	pool := ra.appPool()
	engine := enginev1.NewEngineClient(conn)
	w := &analysis.Worker{DB: pool, Engine: engine, ThresholdBP: func() int { return 100 }}
	rc, err := analysis.NewClient(pool, w, &analysis.AggregateWorker{DB: pool, Engine: engine}, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Stop(context.Background()) }()
	api := &analysisapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Enqueue: analysis.Enqueuer(rc), EnqueueAggregate: analysis.AggregateEnqueuer(rc),
		Settings: fixedLimits{IterationsDefault: simBenchIterations, IterationsMin: 1000, IterationsMax: 2_000_000, MaxActive: 50}}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	defer srv.Close()
	aa := *ra
	aa.url, aa.n = srv.URL, ra.n+900000

	waitFor := func(path, want string, limit time.Duration) (time.Duration, map[string]any) {
		t.Helper()
		start := time.Now()
		for time.Since(start) < limit {
			got := aa.call(t, "GET", "analyst", path, nil)
			switch got.body["state"] {
			case want:
				return time.Since(start), got.body
			case "failed", "cancelled":
				t.Fatalf("%s: %s", path, got.raw)
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s: not %s within %v", path, want, limit)
		return 0, nil
	}

	// Runs: request to results, one at a time (a worker is always free).
	var runTimes, startTimes []time.Duration
	for i := range simBenchRuns + 1 {
		start := time.Now()
		got := aa.call(t, "POST", "analyst", "/api/v1/analyses/runs", map[string]any{"scenario_id": sid, "version": 1, "seed": fmt.Sprint(1000 + i)})
		if got.code != 202 {
			t.Fatalf("request: %d %s", got.code, got.raw)
		}
		id := got.body["id"].(string)
		_, run := waitFor("/api/v1/analyses/runs/"+id, "succeeded", 5*simRunBudget)
		if i == 0 {
			continue // warm-up: the engine's workers load their model the first time
		}
		runTimes = append(runTimes, time.Since(start))
		started, err := strconv.ParseFloat(ra.adminQuery("SELECT EXTRACT(EPOCH FROM started_at - requested_at) * 1000000 FROM analysis.run WHERE id = '"+id+"'"), 64)
		if err != nil {
			t.Fatal(err)
		}
		startTimes = append(startTimes, time.Duration(started)*time.Microsecond)
		if sets := run["results"].([]any); len(sets) != 3 {
			t.Fatalf("results: %d sets", len(sets))
		}
	}

	// Aggregate members: succeeded runs of 100,000 iterations, their series
	// stored through the worker's own functions (seeding 100 simulations
	// would only time the engine again).
	seed := time.Now()
	rng := rand.New(rand.NewPCG(7, 11)) // #nosec G404 -- benchmark data
	members := make([]map[string]any, 0, simBenchMembers)
	series := make([]byte, 8*simBenchIterations)
	for i := range simBenchMembers {
		for j := range simBenchIterations {
			v := 0.0
			if rng.Float64() < 0.3 {
				v = math.Exp(rng.NormFloat64()*1.2 + 12)
			}
			binary.LittleEndian.PutUint64(series[8*j:], math.Float64bits(v))
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('authz.ctx', $1, true)", ra.mint("analyst", ctxKey1)); err != nil {
			t.Fatal(err)
		}
		var id, tok string
		if err := tx.QueryRow(ctx, "SELECT analysis.request_run($1, 1, $2, $3, $4, ARRAY['Current'], NULL, 1000, 2000000, 1000)::text",
			sid, []byte(fmt.Sprintf(`{"bench member":%d}`, i)), i, simBenchIterations).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, "SELECT analysis.start_run($1)", id).Scan(&tok); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SELECT analysis.put_series($1, $2, 'Current', $3)", id, tok, series); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT analysis.finish_run($1, $2, '{"version": "0.1.0", "architecture": "amd64"}', '[]', '{"Current": {}}', $3)`,
			id, tok, strings.Repeat("b", 64)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		members = append(members, map[string]any{"run_id": id, "control_set": "Current"})
	}
	t.Logf("aggregate members: %d runs of %d iterations in %v", simBenchMembers, simBenchIterations, time.Since(seed).Round(time.Second))
	start := time.Now()
	got := aa.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": bu, "name": "Benchmark portfolio", "members": members, "seed": "5"})
	if got.code != 202 {
		t.Fatalf("aggregate: %d %s", got.code, got.raw)
	}
	waitFor("/api/v1/analyses/aggregates/"+got.body["id"].(string), "succeeded", 5*simAggregateBudget)
	aggregateTime := time.Since(start)

	results := []benchResult{
		summarize(fmt.Sprintf("simulation: a fully decomposed scenario, %d iterations, 3 control sets, with sensitivity (request to results)", simBenchIterations), runTimes, simRunBudget),
		summarize("simulation: a queued run starts (a worker free)", startTimes, simStartBudget),
		summarize(fmt.Sprintf("simulation: an aggregate of %d runs of %d iterations (request to results)", simBenchMembers, simBenchIterations), []time.Duration{aggregateTime}, simAggregateBudget),
	}
	var rep strings.Builder
	var info *enginev1.EngineInfo
	if info, err = engine.Info(ctx, &enginev1.InfoRequest{}); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&rep, "F-005 simulation: engine %s on %s, %d timed runs after a warm-up\n", info.GetVersion(), info.GetArchitecture(), simBenchRuns)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	failed := false
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.0f | %.0f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
		failed = failed || r.P95ms > r.Budget
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("simulation over budget")
	}
}
