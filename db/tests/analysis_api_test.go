package tests

import (
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
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/analysisapi"
	"github.com/rformer/fair-app/internal/api/enginev1"
	"github.com/rformer/fair-app/internal/enginetls"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-005 T-11 (F-005-AC-01 to AC-06, AC-11 to AC-15, AC-21 to AC-23; design
// §5, §6.1, §6.3): runs through the analysis API, worked by the real worker
// against a fake engine over gRPC.

// fakeEngine answers as the engine does, or misbehaves as mode says.
type fakeEngine struct {
	enginev1.UnimplementedEngineServer
	mu        sync.Mutex
	mode      string // ok, unavailable_once, unavailable, model_error, block, bad_series, different, ramp, bench
	validated bool
	version   string
	arch      string
	calls     int
	running   chan struct{}
}

func (f *fakeEngine) set(mode string, validated bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode, f.validated, f.calls = mode, validated, 0
	f.version, f.arch = "0.1.0", "amd64"
	f.running = make(chan struct{}, 1)
}

func (f *fakeEngine) Info(context.Context, *enginev1.InfoRequest) (*enginev1.EngineInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &enginev1.EngineInfo{Version: f.version, Architecture: f.arch,
		Validation: &enginev1.Validation{SuiteVersion: "1", Passed: f.validated, RunAtUnixMs: 1762800000000}}, nil
}

func fakeSummary(set string, iterations uint32) string {
	return fmt.Sprintf(`{"independence":"Every input is sampled independently.","iterations":%d,"ale":{"n":%d,"mean":1.5,"sd":0.25,"percentiles":{"p50":1.5}},"control_set":%q}`,
		iterations, iterations, set)
}

func fakeSeries(n int, v float64) []byte {
	b := make([]byte, 8*n)
	for i := range n {
		binary.LittleEndian.PutUint64(b[8*i:], math.Float64bits(v))
	}
	return b
}

// rampSeries is set j's ramp: year i loses (i mod 10)·(j+1), so a tenth of
// the years lose nothing in every set (F-006's histograms).
func rampSeries(n, j int) []byte {
	b := make([]byte, 8*n)
	for i := range n {
		binary.LittleEndian.PutUint64(b[8*i:], math.Float64bits(float64(i%10)*float64(j+1)))
	}
	return b
}

// rampSummary is the summary of set j's ramp, with its comparison with the
// current set (the ramp of set 0) after the first.
func rampSummary(j int) string {
	k := float64(j + 1)
	s := fmt.Sprintf(`{"independence":"Every input is sampled independently.","ale":{"mean":%v,"percentiles":{"p50":%v,"p90":%v}}`, 4.5*k, 4*k, 9*k)
	s += fmt.Sprintf(`,"lef":{"mean":%v},"convergence":{"se":0.06,"converged":true,"intervals":{"p50":[%v,%v]}}`, 0.9, 3*k, 5*k)
	s += fmt.Sprintf(`,"curve":{"points":[[%v,0.9],[%v,0.1],[%v,0]],"at_percentiles":{"p50":0.5}}`, k, 5*k, 9*k)
	s += fmt.Sprintf(`,"breakdown":{"primary":%v,"secondary":%v,"forms":{"response":%v},"stakeholders":{"Customers":%v}}`, 3*k, 1.5*k, 3*k, 1.5*k)
	s += fmt.Sprintf(`,"sensitivity":{"inputs":[{"input":"=Contact frequency","pointer":"/lef/tef/contact_frequency","kind":"estimate",`+
		`"low":{"value":1,"mean":%v,"change":%v},"high":{"value":12,"mean":%v,"change":%v},"swing":%v,"spearman":0.5}]}`, 2*k, -2.5*k, 7*k, 2.5*k, 5*k)
	if j > 0 {
		s += fmt.Sprintf(`,"comparison":{"against":"Current","mean":%v,"difference":{"mean":%v,"percentiles":{"p50":%v}}}`, 4.5*(k-1), 4.5*(k-1), 4*(k-1))
	} else {
		s += `,"comparison":null`
	}
	return s + "}"
}

func (f *fakeEngine) Simulate(req *enginev1.SimulateRequest, stream enginev1.Engine_SimulateServer) error {
	f.mu.Lock()
	f.calls++
	mode, calls, running := f.mode, f.calls, f.running
	f.mu.Unlock()
	send := func(ev *enginev1.SimulateEvent) error { return stream.Send(ev) }
	switch {
	case mode == "unavailable" || (mode == "unavailable_once" && calls == 1):
		return status.Error(codes.Unavailable, "the engine is restarting")
	case mode == "model_error":
		return send(&enginev1.SimulateEvent{Event: &enginev1.SimulateEvent_Failure{Failure: &enginev1.Failure{Code: "invalid_bundle", Detail: "/lef/level: 'x' is not a level"}}})
	case mode == "block":
		select {
		case running <- struct{}{}:
		default:
		}
		for i := uint64(0); ; i++ {
			if err := send(&enginev1.SimulateEvent{Event: &enginev1.SimulateEvent_Progress{Progress: &enginev1.Progress{Done: i, Total: 1 << 40}}}); err != nil {
				return err
			}
			select {
			case <-stream.Context().Done():
				return stream.Context().Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if mode == "bench" {
		return simulateBench(req, stream) // F-006 T-07: results of the engine's size
	}
	n := int(req.GetIterations())
	for _, p := range []uint64{uint64(n / 2), uint64(n)} {
		if err := send(&enginev1.SimulateEvent{Event: &enginev1.SimulateEvent_Progress{Progress: &enginev1.Progress{Done: p, Total: uint64(n)}}}); err != nil {
			return err
		}
	}
	for j, set := range req.GetControlSets() {
		summary := fakeSummary(set, req.GetIterations())
		if mode == "ramp" {
			summary = rampSummary(j)
		}
		if err := send(&enginev1.SimulateEvent{Event: &enginev1.SimulateEvent_Result{Result: &enginev1.ControlSetResult{ControlSet: set, SummaryJson: summary}}}); err != nil {
			return err
		}
		series := fakeSeries(n, 1.5+float64(j))
		if mode == "ramp" {
			series = rampSeries(n, j)
		}
		if mode == "different" {
			series = fakeSeries(n, 9.5+float64(j))
		}
		if mode == "bad_series" {
			series = series[:len(series)-8]
		}
		for off := 0; off < len(series); off += 4000 * 8 {
			end := min(off+4000*8, len(series))
			if err := send(&enginev1.SimulateEvent{Event: &enginev1.SimulateEvent_Series{Series: &enginev1.SeriesChunk{ControlSet: set, Offset: uint64(off / 8), Values: series[off:end]}}}); err != nil {
				return err
			}
		}
	}
	return send(&enginev1.SimulateEvent{Event: &enginev1.SimulateEvent_Done{Done: &enginev1.Done{Warnings: []*enginev1.Warning{
		{Code: "domain_low", Pointer: "/lef/tef/contact_frequency", Detail: "events_per_year 2 to 12"}}}}})
}

// Aggregate sums the members' series year by year (the real engine
// permutes them first; the worker does not care).
func (f *fakeEngine) Aggregate(stream enginev1.Engine_AggregateServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	h := first.GetHeader()
	n := int(h.GetIterations())
	sum := make([]float64, n)
	for {
		in, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		c := in.GetSeries()
		for i := 0; i < len(c.GetValues())/8; i++ {
			sum[int(c.GetOffset())+i] += math.Float64frombits(binary.LittleEndian.Uint64(c.GetValues()[8*i:]))
		}
	}
	out := make([]byte, 8*n)
	for i, v := range sum {
		binary.LittleEndian.PutUint64(out[8*i:], math.Float64bits(v))
	}
	summary := fmt.Sprintf(`{"independence":"Members are combined as independent.","iterations":%d,"members":%d,"ale":{"mean":%v}}`, n, len(h.GetMembers()), sum[0])
	if err := stream.Send(&enginev1.AggregateEvent{Event: &enginev1.AggregateEvent_Result{Result: &enginev1.AggregateResult{SummaryJson: summary}}}); err != nil {
		return err
	}
	if err := stream.Send(&enginev1.AggregateEvent{Event: &enginev1.AggregateEvent_Series{Series: &enginev1.SeriesChunk{Offset: 0, Values: out}}}); err != nil {
		return err
	}
	return stream.Send(&enginev1.AggregateEvent{Event: &enginev1.AggregateEvent_Done{Done: &enginev1.Done{}}})
}

type fixedLimits analysis.Limits

func (l fixedLimits) Limits(context.Context) (analysis.Limits, error) { return analysis.Limits(l), nil }

type analysisEnv struct {
	*riskAPIEnv
	api        *analysisapi.API // tests may swap its Audit
	engine     *fakeEngine
	worker     *analysis.Worker
	aggregates *analysis.AggregateWorker
}

// analysisAPI serves the analysis API on the risk env's keys, with the
// worker and a fake engine; jobs are queued by an insert-only River client
// and worked by calling the worker.
func analysisAPI(t *testing.T, ra *riskAPIEnv, lim analysis.Limits, engine bool) *analysisEnv {
	t.Helper()
	pool := ra.appPool()
	fe := &fakeEngine{}
	fe.set("ok", true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	enginev1.RegisterEngineServer(gs, fe)
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///"+ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: analysis.RiverSchema})
	if err != nil {
		t.Fatal(err)
	}
	api := &analysisapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), Settings: fixedLimits(lim),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	if engine {
		api.Enqueue = analysis.Enqueuer(rc)
		api.EnqueueAggregate = analysis.AggregateEnqueuer(rc)
	}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	aa := *ra
	aa.url = srv.URL
	analysisEnvs++
	aa.n += 200000 * analysisEnvs // its Idempotency-Keys never meet another env's
	return &analysisEnv{riskAPIEnv: &aa, api: api, engine: fe, worker: &analysis.Worker{DB: pool, Engine: enginev1.NewEngineClient(conn),
		ImageDigest: "sha256:" + strings.Repeat("ab", 32)}, aggregates: &analysis.AggregateWorker{DB: pool, Engine: enginev1.NewEngineClient(conn)}}
}

var analysisEnvs int

var defaultLimits = analysis.Limits{IterationsDefault: 10000, IterationsMin: 1000, IterationsMax: 200000, MaxActive: 50}

func (ae *analysisEnv) work(t *testing.T, id string, attempt, maxAttempts int) error {
	t.Helper()
	return ae.worker.Attempt(context.Background(), id, attempt, maxAttempts)
}

func (ae *analysisEnv) state(id string) string {
	return ae.adminQuery("SELECT state || coalesce('/' || failure, '') FROM analysis.run WHERE id = '" + id + "'")
}

// A scenario at A1 with a second control set, owned by analyst.
func analysisScenario(t *testing.T, ra *riskAPIEnv) string {
	t.Helper()
	doc := ra.scenarioDoc(t)
	sets := doc["control_sets"].([]any)
	doc["control_sets"] = append(sets, map[string]any{"name": "Proposed", "current": false, "controls": []any{}})
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	return got.body["id"].(string)
}

func TestAnalysisRunsAPI(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B
	ae := analysisAPI(t, ra, defaultLimits, true)
	sid := analysisScenario(t, ra)
	request := func(user string, body map[string]any) apiResp {
		t.Helper()
		return ae.call(t, "POST", user, "/api/v1/analyses/runs", body)
	}

	// Who may: nobody without an analysis permission (404 everywhere);
	// mallory cannot see the scenario (404); a viewer who sees it, 403.
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('nobody@example.test', 'nobody'), ('viewer@example.test', 'viewer')")
	ra.mustOwner(grant("platform", "user:viewer", "Executive Viewer", "A"))
	ra.drain()
	for _, path := range []string{"/api/v1/analyses/runs?scenario=" + sid, "/api/v1/analyses/runs/" + sid} {
		if got := ae.call(t, "GET", "nobody", path, nil); got.code != 404 {
			t.Errorf("nobody GET %s: %d", path, got.code)
		}
	}
	if got := request("nobody", map[string]any{"scenario_id": sid, "version": 1}); got.code != 404 {
		t.Errorf("nobody requests: %d %s", got.code, got.raw)
	}
	if got := request("mallory", map[string]any{"scenario_id": sid, "version": 1}); got.code != 404 {
		t.Errorf("mallory requests: %d %s", got.code, got.raw)
	}
	// T-13 (migration 0106): where the pages may offer a run.
	busWith := func(user, perm string) string {
		t.Helper()
		got := ra.call(t, "GET", user, "/api/v1/risk/bus?permission="+perm, nil)
		if got.code != 200 {
			t.Fatalf("%s %s: %d %s", user, perm, got.code, got.raw)
		}
		var codes []string
		for _, b := range got.body["bus"].([]any) {
			codes = append(codes, b.(map[string]any)["code"].(string))
		}
		sort.Strings(codes)
		return strings.Join(codes, ",")
	}
	if got := busWith("analyst", "analysis.run"); !strings.Contains(got, "A1") || strings.Contains(got, "B") {
		t.Errorf("analyst's analysis.run BUs: %s", got)
	}
	if got := busWith("viewer", "analysis.run"); got != "" {
		t.Errorf("a viewer's analysis.run BUs: %s", got)
	}
	if got := busWith("viewer", "analysis.view"); !strings.Contains(got, "A") {
		t.Errorf("a viewer's analysis.view BUs: %s", got)
	}
	if got := ra.call(t, "GET", "analyst", "/api/v1/risk/bus?permission=analysis.edit", nil); got.code != 400 {
		t.Errorf("analysis.edit is not offered: %d", got.code)
	}
	if got := request("viewer", map[string]any{"scenario_id": sid, "version": 1}); got.code != 403 {
		t.Errorf("a viewer requests: %d %s", got.code, got.raw)
	}

	// Refusals: the body, the version, the control sets, the iterations.
	for name, c := range map[string]struct {
		body map[string]any
		code int
	}{
		"no scenario":       {map[string]any{"version": 1}, 400},
		"bad seed":          {map[string]any{"scenario_id": sid, "version": 1, "seed": "-1"}, 400},
		"unknown field":     {map[string]any{"scenario_id": sid, "version": 1, "colour": "red"}, 400},
		"no such version":   {map[string]any{"scenario_id": sid, "version": 9}, 422},
		"no such set":       {map[string]any{"scenario_id": sid, "version": 1, "control_sets": []string{"Current", "Nope"}}, 422},
		"current not first": {map[string]any{"scenario_id": sid, "version": 1, "control_sets": []string{"Proposed", "Current"}}, 422},
		"too few":           {map[string]any{"scenario_id": sid, "version": 1, "iterations": 999}, 422},
		"too many":          {map[string]any{"scenario_id": sid, "version": 1, "iterations": 200001}, 422},
		"no such scenario":  {map[string]any{"scenario_id": "00000000-0000-4000-8000-000000000000", "version": 1}, 404},
	} {
		if got := request("analyst", c.body); got.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, got.code, got.raw, c.code)
		}
	}

	// A run: queued with its job and event in the same transaction.
	got := request("analyst", map[string]any{"scenario_id": sid, "version": 1, "iterations": 5000, "seed": "18446744073709551615"})
	if got.code != 202 || got.body["state"] != "queued" || got.body["seed"] != "18446744073709551615" {
		t.Fatalf("request: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	if sets := fmt.Sprint(got.body["control_sets"]); sets != "[Current Proposed]" {
		t.Errorf("default control sets: %s", sets)
	}
	if n := ra.adminQuery("SELECT count(*) FROM risk_river.river_job WHERE kind = 'analysis.simulate' AND args ->> 'run_id' = '" + id + "'"); n != "1" {
		t.Errorf("jobs for the run: %s", n)
	}
	if n := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.run_requested' AND body ->> 'target' = 'analysis_run:" + id + "'"); n != "1" {
		t.Errorf("run_requested events: %s", n)
	}
	if d := ra.adminQuery("SELECT encode(sha256(bundle), 'hex') = (SELECT bundle_digest FROM analysis.run WHERE id = '" + id + "') FROM analysis.run_input WHERE run_id = '" + id + "'"); d != "t" {
		t.Errorf("the stored bundle has the run's digest: %s", d)
	}

	// Worked: succeeded with every set's results, the engine record, the
	// warnings and the digest; the series as stored.
	if err := ae.work(t, id, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	run := ae.call(t, "GET", "analyst", "/api/v1/analyses/runs/"+id, nil)
	if run.code != 200 || run.body["state"] != "succeeded" || run.body["progress"] != 1.0 {
		t.Fatalf("the run: %d %s", run.code, run.raw)
	}
	results := run.body["results"].([]any)
	if len(results) != 2 || results[0].(map[string]any)["control_set"] != "Current" {
		t.Fatalf("results: %v", results)
	}
	eng := run.body["engine"].(map[string]any)
	if eng["version"] != "0.1.0" || eng["architecture"] != "amd64" || eng["image_digest"] != "sha256:"+strings.Repeat("ab", 32) {
		t.Errorf("the engine record: %v", eng)
	}
	if w := run.body["warnings"].([]any); len(w) != 1 || w[0].(map[string]any)["code"] != "domain_low" {
		t.Errorf("warnings: %v", w)
	}
	var sets []analysis.SetResult
	for j, set := range []string{"Current", "Proposed"} {
		s, raw := seriesOf(t, ae, "analyst", id, set)
		if s != 200 || string(raw) != string(fakeSeries(5000, 1.5+float64(j))) {
			t.Fatalf("series %s: %d, %d bytes", set, s, len(raw))
		}
		sets = append(sets, analysis.SetResult{ControlSet: set, Summary: []byte(fakeSummary(set, 5000)), Series: raw})
	}
	want, err := analysis.Digest(analysis.RunInputs{ScenarioID: sid, Version: 1, BundleDigest: run.body["bundle_digest"].(string),
		Seed: "18446744073709551615", Iterations: 5000, ControlSets: []string{"Current", "Proposed"}}, "0.1.0", "amd64", sets)
	if err != nil || run.body["result_digest"] != want {
		t.Errorf("result digest %v, want %s (%v)", run.body["result_digest"], want, err)
	}
	if n := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.run_succeeded' AND body -> 'attributes' ->> 'result_digest' = '" + want + "'"); n != "1" {
		t.Errorf("run_succeeded events with the digest: %s", n)
	}
	if s, _ := seriesOf(t, ae, "mallory", id, "Current"); s != 404 {
		t.Errorf("mallory reads the series: %d", s)
	}
	if got := ae.call(t, "GET", "mallory", "/api/v1/analyses/runs/"+id, nil); got.code != 404 {
		t.Errorf("mallory reads the run: %d", got.code)
	}
	if s, _ := seriesOf(t, ae, "analyst", id, "Nope"); s != 404 {
		t.Errorf("an unknown set's series: %d", s)
	}
	// Finished: worked again, nothing changes; cancelling is refused.
	if err := ae.work(t, id, 1, analysis.Attempts); err != nil || ae.state(id) != "succeeded" {
		t.Errorf("a finished run worked again: %v %s", err, ae.state(id))
	}
	if got := ae.call(t, "POST", "analyst", "/api/v1/analyses/runs/"+id+"/cancel", map[string]any{"reason": "late"}); got.code != 409 {
		t.Errorf("cancelling a finished run: %d %s", got.code, got.raw)
	}

	// Listing, newest first, and paging.
	second := request("analyst", map[string]any{"scenario_id": sid, "version": 1, "control_sets": []string{"Current"}})
	if second.code != 202 || second.body["iterations"] != 10000.0 {
		t.Fatalf("a second run: %d %s", second.code, second.raw)
	}
	list := ae.call(t, "GET", "analyst", "/api/v1/analyses/runs?scenario="+sid, nil)
	runs := list.body["runs"].([]any)
	if list.code != 200 || len(runs) != 2 || runs[0].(map[string]any)["id"] != second.body["id"] {
		t.Fatalf("list: %d %s", list.code, list.raw)
	}
	page := ae.call(t, "GET", "analyst", fmt.Sprintf("/api/v1/analyses/runs?scenario=%s&limit=1", sid), nil)
	next := page.body["next_before"]
	page2 := ae.call(t, "GET", "analyst", fmt.Sprintf("/api/v1/analyses/runs?scenario=%s&limit=1&before=%v", sid, next), nil)
	if r := page2.body["runs"].([]any); len(r) != 1 || r[0].(map[string]any)["id"] != id {
		t.Errorf("the second page: %s", page2.raw)
	}
	if got := ae.call(t, "GET", "mallory", "/api/v1/analyses/runs?scenario="+sid, nil); got.code != 200 || len(got.body["runs"].([]any)) != 0 {
		t.Errorf("mallory lists: %d %s", got.code, got.raw)
	}

	// Cancelled while queued: the worker leaves it; mallory may not cancel.
	q := second.body["id"].(string)
	if got := ae.call(t, "POST", "mallory", "/api/v1/analyses/runs/"+q+"/cancel", map[string]any{"reason": "mine now"}); got.code != 404 {
		t.Errorf("mallory cancels: %d", got.code)
	}
	if got := ae.call(t, "POST", "analyst", "/api/v1/analyses/runs/"+q+"/cancel", map[string]any{}); got.code != 400 {
		t.Errorf("cancel without a reason: %d", got.code)
	}
	if got := ae.call(t, "POST", "analyst", "/api/v1/analyses/runs/"+q+"/cancel", map[string]any{"reason": "Wrong sets"}); got.code != 200 || got.body["state"] != "cancelled" {
		t.Fatalf("cancel: %d %s", got.code, got.raw)
	}
	if err := ae.work(t, q, 1, analysis.Attempts); err != nil || ae.state(q) != "cancelled" {
		t.Errorf("a cancelled run worked: %v %s", err, ae.state(q))
	}
}

func seriesOf(t *testing.T, ae *analysisEnv, user, id, set string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", ae.url+"/api/v1/analyses/runs/"+id+"/series/"+set, nil)
	p := ae.principal(user)
	tok, err := authz.MintJWT(ae.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Fair-DB-Context", p.DBToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("series content type %q", resp.Header.Get("Content-Type"))
	}
	return resp.StatusCode, b
}

// Failures: retried while the engine is unavailable, then failed; a model
// error, an unvalidated engine or malformed results fail at once; no
// partial results are kept; a running run stops when cancelled.
func TestAnalysisRunFailures(t *testing.T) {
	ra := strideF003Fixture(t)
	ae := analysisAPI(t, ra, defaultLimits, true)
	sid := analysisScenario(t, ra)
	newRun := func() string {
		t.Helper()
		got := ae.call(t, "POST", "analyst", "/api/v1/analyses/runs", map[string]any{"scenario_id": sid, "version": 1, "iterations": 2000})
		if got.code != 202 {
			t.Fatalf("request: %d %s", got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	noResults := func(id string) {
		t.Helper()
		if n := ra.adminQuery("SELECT count(*) FROM analysis.result WHERE run_id = '" + id + "' AND summary IS NOT NULL"); n != "0" {
			t.Errorf("%s kept %s summaries", id, n)
		}
		if n := ra.adminQuery("SELECT count(*) FROM analysis.series WHERE run_id = '" + id + "' AND ale IS NOT NULL"); n != "0" {
			t.Errorf("%s kept %s series", id, n)
		}
	}

	// Retry then success.
	ae.engine.set("unavailable_once", true)
	id := newRun()
	if err := ae.work(t, id, 1, 3); err == nil || ae.state(id) != "running" {
		t.Fatalf("a first attempt against a restarting engine: %v %s", err, ae.state(id))
	}
	if err := ae.work(t, id, 2, 3); err != nil || ae.state(id) != "succeeded" {
		t.Fatalf("the retry: %v %s", err, ae.state(id))
	}

	// Unavailable on the last attempt: failed, the job cancelled.
	ae.engine.set("unavailable", true)
	id = newRun()
	var cancel *river.JobCancelError
	if err := ae.work(t, id, 3, 3); !errors.As(err, &cancel) || ae.state(id) != "failed/engine_unavailable" {
		t.Errorf("the last attempt: %v %s", err, ae.state(id))
	}
	noResults(id)

	for mode, want := range map[string]string{"model_error": "failed/invalid_bundle", "bad_series": "failed/invalid_results"} {
		ae.engine.set(mode, true)
		id = newRun()
		if err := ae.work(t, id, 1, 3); !errors.As(err, &cancel) || ae.state(id) != want {
			t.Errorf("%s: %v %s", mode, err, ae.state(id))
		}
		noResults(id)
	}
	ae.engine.set("ok", false)
	id = newRun()
	if err := ae.work(t, id, 1, 3); !errors.As(err, &cancel) || ae.state(id) != "failed/engine_not_validated" {
		t.Errorf("an unvalidated engine: %v %s", err, ae.state(id))
	}
	if ae.engine.calls != 0 {
		t.Error("an unvalidated engine was asked to simulate")
	}
	run := ae.call(t, "GET", "analyst", "/api/v1/analyses/runs/"+id, nil)
	if run.body["failure"] != "engine_not_validated" || len(run.body["results"].([]any)) != 0 {
		t.Errorf("the failed run: %s", run.raw)
	}
	if n := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.run_failed' AND body ->> 'target' = 'analysis_run:" + id + "'"); n != "1" {
		t.Errorf("run_failed events: %s", n)
	}

	// Cancelled while running: the worker stops at its next progress report.
	ae.engine.set("block", true)
	id = newRun()
	done := make(chan error, 1)
	go func() { done <- ae.worker.Attempt(context.Background(), id, 1, 3) }()
	select {
	case <-ae.engine.running:
	case <-time.After(10 * time.Second):
		t.Fatal("the engine was not called")
	}
	if got := ae.call(t, "POST", "analyst", "/api/v1/analyses/runs/"+id+"/cancel", map[string]any{"reason": "Too long"}); got.code != 200 {
		t.Fatalf("cancel a running run: %d %s", got.code, got.raw)
	}
	select {
	case err := <-done:
		if err != nil || ae.state(id) != "cancelled" {
			t.Errorf("the worker after cancelling: %v %s", err, ae.state(id))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the worker did not stop")
	}
	noResults(id)
}

// Limits: the active-run limit, an archived scenario, and no engine.
func TestAnalysisRunLimits(t *testing.T) {
	ra := strideF003Fixture(t)
	ae := analysisAPI(t, ra, analysis.Limits{IterationsDefault: 1000, IterationsMin: 1000, IterationsMax: 10000, MaxActive: 2}, true)
	sid := analysisScenario(t, ra)
	body := map[string]any{"scenario_id": sid, "version": 1}
	for i := range 2 {
		if got := ae.call(t, "POST", "analyst", "/api/v1/analyses/runs", body); got.code != 202 {
			t.Fatalf("run %d: %d %s", i, got.code, got.raw)
		}
	}
	if got := ae.call(t, "POST", "analyst", "/api/v1/analyses/runs", body); got.code != 409 || got.body["error"] != "too_many_runs" {
		t.Errorf("a third active run: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+sid+"/archive", map[string]any{"reason": "done"}); got.code != 200 {
		t.Fatalf("archive: %d %s", got.code, got.raw)
	}
	other := analysisAPI(t, ra, defaultLimits, true)
	if got := other.call(t, "POST", "analyst", "/api/v1/analyses/runs", body); got.code != 409 || got.body["error"] != "archived" {
		t.Errorf("an archived scenario: %d %s", got.code, got.raw)
	}
	none := analysisAPI(t, ra, defaultLimits, false)
	if got := none.call(t, "POST", "analyst", "/api/v1/analyses/runs", body); got.code != 503 || got.body["error"] != "engine_unavailable" {
		t.Errorf("no engine: %d %s", got.code, got.raw)
	}
}

// TestAnalysisLiveEngine runs a scenario on the real engine through
// engine-gate (F-005 T-11's end-to-end test): FAIR_TEST_ENGINE_ADDR names
// the gate and FAIR_TEST_ENGINE_CLIENT_DIR the risk side of the key
// directory.
func TestAnalysisLiveEngine(t *testing.T) {
	addr, dir := os.Getenv("FAIR_TEST_ENGINE_ADDR"), os.Getenv("FAIR_TEST_ENGINE_CLIENT_DIR")
	if addr == "" || dir == "" {
		t.Skip("FAIR_TEST_ENGINE_ADDR and FAIR_TEST_ENGINE_CLIENT_DIR not set")
	}
	ra := strideF003Fixture(t)
	ae := analysisAPI(t, ra, defaultLimits, true)
	tc, err := enginetls.ClientConfig(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ae.worker.Engine = enginev1.NewEngineClient(conn)
	sid := analysisScenario(t, ra)
	got := ae.call(t, "POST", "analyst", "/api/v1/analyses/runs", map[string]any{"scenario_id": sid, "version": 1, "iterations": 20000, "seed": "42"})
	if got.code != 202 {
		t.Fatalf("request: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	if err := ae.work(t, id, 1, 3); err != nil {
		t.Fatal(err)
	}
	run := ae.call(t, "GET", "analyst", "/api/v1/analyses/runs/"+id, nil)
	if run.body["state"] != "succeeded" {
		t.Fatalf("the run: %s", run.raw)
	}
	results := run.body["results"].([]any)
	var summary map[string]any
	b, _ := json.Marshal(results[0].(map[string]any)["summary"])
	_ = json.Unmarshal(b, &summary)
	mean, _ := summary["ale"].(map[string]any)["mean"].(float64)
	if len(results) != 2 || mean <= 0 || summary["independence"] == nil || summary["sensitivity"] == nil {
		t.Errorf("results: %d sets, mean %v", len(results), mean)
	}
	_, raw := seriesOf(t, ae, "analyst", id, "Current")
	if len(raw) != 20000*8 {
		t.Errorf("series: %d bytes", len(raw))
	}
	t.Logf("run %s: engine %v, mean annual loss %.0f, result digest %v", id, run.body["engine"], mean, run.body["result_digest"])

	// T-12: an aggregate of this run and a second one, on the real engine.
	got = ae.call(t, "POST", "analyst", "/api/v1/analyses/runs", map[string]any{"scenario_id": sid, "version": 1, "iterations": 20000, "seed": "43"})
	if got.code != 202 {
		t.Fatalf("second run: %d %s", got.code, got.raw)
	}
	id2 := got.body["id"].(string)
	if err := ae.work(t, id2, 1, 3); err != nil || ae.state(id2) != "succeeded" {
		t.Fatalf("second run: %v %s", err, ae.state(id2))
	}
	ae.aggregates.Engine = ae.worker.Engine
	agg := ae.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": ra.bu["A1"], "name": "Live portfolio", "seed": "5",
		"members": []map[string]any{{"run_id": id, "control_set": "Current"}, {"run_id": id2, "control_set": "Proposed"}}})
	if agg.code != 202 {
		t.Fatalf("aggregate: %d %s", agg.code, agg.raw)
	}
	aid := agg.body["id"].(string)
	if err := ae.aggregates.Attempt(context.Background(), aid, 1, 3); err != nil {
		t.Fatal(err)
	}
	read := ae.call(t, "GET", "analyst", "/api/v1/analyses/aggregates/"+aid, nil)
	as, _ := read.body["summary"].(map[string]any)
	if read.body["state"] != "succeeded" || as == nil || len(as["contributions"].([]any)) != 2 {
		t.Fatalf("the aggregate: %s", read.raw)
	}
	t.Logf("aggregate %s: mean annual loss %.0f, result digest %v", aid, as["ale"].(map[string]any)["mean"], read.body["result_digest"])
}
