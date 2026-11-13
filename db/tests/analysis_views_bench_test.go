package tests

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/api/enginev1"
)

// F-006 T-07 (requirements NFR performance; design §11): the result views
// gate. A succeeded run of 1,000,000 iterations with three control sets
// (results of the size the engine stores: 200-point curves, percentiles,
// convergence, breakdown, 20 sensitivity inputs) is made by the fake
// engine's "bench" mode; the views are timed through the analysis API.
// Budgets, p95:
//   - a run's views (its GET and the three sets' histograms): <= 2 s;
//   - a comparison of six results: <= 3 s;
//   - each CSV view: <= 2 s.
//
// The engine is not involved: the views read stored results.
const (
	viewsBenchIterations = 1_000_000
	viewsBenchSamples    = 20
	viewsRunBudget       = 2 * time.Second
	viewsCompareBudget   = 3 * time.Second
	viewsCSVBudget       = 2 * time.Second
)

var benchPercentiles = []float64{1, 5, 10, 25, 50, 75, 90, 95, 99}

// benchBase is the current set's per-year loss: none in 55% of years, a
// log-normal amount (median about $60,000) otherwise. Set j keeps the same
// years scaled by 1 − 0.2j (common random numbers, as the engine draws).
func benchBase(n int) []float64 {
	r := rand.New(rand.NewPCG(2026, 11))
	out := make([]float64, n)
	for i := range out {
		if r.Float64() >= 0.55 {
			out[i] = math.Exp(11 + 1.5*r.NormFloat64())
		}
	}
	return out
}

// benchSummarize is a distribution's summary as the engine writes it
// (F-005 design §3.4): order statistics by inverted_cdf.
func benchSummarize(x []float64) (map[string]any, []float64) {
	s := slices.Clone(x)
	slices.Sort(s)
	n := len(s)
	sum, pos := 0.0, 0
	for _, v := range s {
		sum += v
		if v > 0 {
			pos++
		}
	}
	mean := sum / float64(n)
	ss := 0.0
	for _, v := range s {
		ss += (v - mean) * (v - mean)
	}
	ps := map[string]any{}
	for _, p := range benchPercentiles {
		ps[fmt.Sprintf("p%v", p)] = s[max(0, int(math.Ceil(p/100*float64(n)))-1)]
	}
	return map[string]any{"n": n, "mean": mean, "sd": math.Sqrt(ss / float64(n-1)), "min": s[0], "max": s[n-1], "percentiles": ps,
		"p_positive": float64(pos) / float64(n)}, s
}

// benchCurve is the 200-point exceedance curve and the exceedance at each
// percentile, from sorted values.
func benchCurve(s []float64, ps map[string]any) map[string]any {
	n := len(s)
	exceed := func(x float64) float64 {
		return float64(n-sort.SearchFloat64s(s, math.Nextafter(x, math.Inf(1)))) / float64(n)
	}
	first := sort.SearchFloat64s(s, math.SmallestNonzeroFloat64)
	points := []any{}
	if first < n {
		pos := s[first:]
		lo, hi := pos[max(0, int(math.Ceil(0.001*float64(len(pos))))-1)], pos[len(pos)-1]
		for k := range 200 {
			x := lo * math.Pow(hi/lo, float64(k)/199)
			points = append(points, []any{x, exceed(x)})
		}
	}
	at := map[string]any{}
	for k, v := range ps {
		at[k] = exceed(v.(float64))
	}
	return map[string]any{"points": points, "at_percentiles": at}
}

func benchSetSummary(j int, ale, current []float64) map[string]any {
	a, sorted := benchSummarize(ale)
	mean := a["mean"].(float64)
	inputs := []any{}
	for k := range 20 {
		swing := mean * 0.5 / float64(k+1)
		inputs = append(inputs, map[string]any{"input": fmt.Sprintf("q%02d", k), "pointer": fmt.Sprintf("/primary_loss/forms/%d/estimate", k), "kind": "estimate",
			"control": nil, "factor": nil, "low": map[string]any{"value": 1.0, "mean": mean - swing/2, "change": -swing / 2},
			"high": map[string]any{"value": 9.0, "mean": mean + swing/2, "change": swing / 2}, "swing": swing, "spearman": 0.9 / float64(k+1)})
	}
	intervals := map[string]any{}
	for _, p := range []string{"p50", "p90", "p95", "p99"} {
		v := a["percentiles"].(map[string]any)[p].(float64)
		intervals[p] = []any{v * 0.98, v * 1.02}
	}
	s := map[string]any{
		"independence": "Every input is sampled independently.", "iterations": len(ale), "ale": a,
		"lef":            map[string]any{"n": len(ale), "mean": 0.6, "sd": 0.8, "min": 0.0, "max": 7.0, "percentiles": map[string]any{"p50": 0.0, "p90": 2.0}},
		"loss_per_event": map[string]any{"n": 600000, "mean": mean / 0.6, "sd": mean, "min": 1.0, "max": a["max"], "percentiles": map[string]any{"p50": mean}},
		"curve":          benchCurve(sorted, a["percentiles"].(map[string]any)),
		"breakdown": map[string]any{"primary": mean * 0.7, "secondary": mean * 0.3, "forms": map[string]any{"productivity": mean * 0.2, "response": mean * 0.3,
			"replacement": mean * 0.1, "fines_judgments": mean * 0.2, "competitive_advantage": mean * 0.1, "reputation": mean * 0.1},
			"stakeholders": map[string]any{"Customers": mean * 0.2, "Regulators": mean * 0.1}},
		"convergence": map[string]any{"se": a["sd"].(float64) / 1000, "rse": 0.004, "threshold_bp": 100, "converged": true, "intervals": intervals},
		"sensitivity": map[string]any{"iterations": 20000, "low": 0.05, "high": 0.95, "base_mean": mean, "inputs": inputs},
		"comparison":  nil,
	}
	if j > 0 {
		diff := make([]float64, len(ale))
		for i := range ale {
			diff[i] = ale[i] - current[i]
		}
		d, _ := benchSummarize(diff)
		cur, _ := benchSummarize(current)
		ps := map[string]any{}
		for _, p := range []string{"p50", "p90", "p95", "p99"} {
			ps[p] = a["percentiles"].(map[string]any)[p].(float64) - cur["percentiles"].(map[string]any)[p].(float64)
		}
		s["comparison"] = map[string]any{"against": "Current", "mean": mean - cur["mean"].(float64), "percentiles": ps, "difference": d}
	}
	return s
}

// simulateBench answers a run with the bench results (the fake engine's
// "bench" mode).
func simulateBench(req *enginev1.SimulateRequest, stream enginev1.Engine_SimulateServer) error {
	n := int(req.GetIterations())
	base := benchBase(n)
	var current []float64
	for j, set := range req.GetControlSets() {
		ale := make([]float64, n)
		for i, v := range base {
			ale[i] = v * (1 - 0.2*float64(j))
		}
		if j == 0 {
			current = ale
		}
		raw, err := json.Marshal(benchSetSummary(j, ale, current))
		if err != nil {
			return err
		}
		if err := stream.Send(&enginev1.SimulateEvent{Event: &enginev1.SimulateEvent_Result{Result: &enginev1.ControlSetResult{ControlSet: set, SummaryJson: string(raw)}}}); err != nil {
			return err
		}
		b := make([]byte, 8*n)
		for i, v := range ale {
			binary.LittleEndian.PutUint64(b[8*i:], math.Float64bits(v))
		}
		for off := 0; off < len(b); off += 65536 * 8 {
			end := min(off+65536*8, len(b))
			if err := stream.Send(&enginev1.SimulateEvent{Event: &enginev1.SimulateEvent_Series{Series: &enginev1.SeriesChunk{ControlSet: set, Offset: uint64(off / 8), Values: b[off:end]}}}); err != nil {
				return err
			}
		}
	}
	return stream.Send(&enginev1.SimulateEvent{Event: &enginev1.SimulateEvent_Done{Done: &enginev1.Done{}}})
}

func TestBenchmarkGateResultViews(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	ra := strideF003Fixture(t) // analyst, a Risk Analyst at A
	ae := analysisAPI(t, ra, analysis.Limits{IterationsDefault: 100_000, IterationsMin: 1000, IterationsMax: 2_000_000, MaxActive: 50}, true)
	ae.engine.set("bench", true)
	sid := decomposedScenario(t, ra, ra.bu["A1"])
	seed := time.Now()
	var runs []string
	var sets []string
	for k := range 2 {
		id := runWith(t, ae, "analyst", sid, 1, viewsBenchIterations, fmt.Sprint(k+1))
		runs = append(runs, id)
		if sets == nil {
			for _, x := range ae.call(t, "GET", "analyst", "/api/v1/analyses/runs/"+id, nil).body["control_sets"].([]any) {
				sets = append(sets, x.(string))
			}
		}
	}
	if len(sets) != 3 {
		t.Fatalf("control sets %v", sets)
	}
	t.Logf("two runs of %d iterations with %d control sets stored in %v", viewsBenchIterations, len(sets), time.Since(seed).Round(time.Second))
	run := runs[0]

	timed := func(name string, f func()) []time.Duration {
		t.Helper()
		f() // warm-up
		ds := make([]time.Duration, 0, viewsBenchSamples)
		for range viewsBenchSamples {
			start := time.Now()
			f()
			ds = append(ds, time.Since(start))
		}
		return ds
	}
	get := func(path string) apiResp {
		t.Helper()
		got := ae.call(t, "GET", "analyst", path, nil)
		if got.code != 200 {
			t.Fatalf("%s: %d %s", path, got.code, got.raw)
		}
		return got
	}

	results := []benchResult{summarize(fmt.Sprintf("views: a run of %d iterations, its record and results and three histograms", viewsBenchIterations),
		timed("run", func() {
			if len(get("/api/v1/analyses/runs/" + run).body["results"].([]any)) != 3 {
				t.Fatal("the run's results")
			}
			for _, s := range sets {
				get("/api/v1/analyses/runs/" + run + "/histogram?set=" + url.QueryEscape(s))
			}
		}), viewsRunBudget)}
	var items []string
	for _, r := range runs {
		for _, s := range sets {
			items = append(items, "run:"+r+":"+s)
		}
	}
	results = append(results, summarize("views: a comparison of six results", timed("compare", func() {
		if len(get(compareURL(items...)).body["items"].([]any)) != 6 {
			t.Fatal("the comparison's items")
		}
	}), viewsCompareBudget))
	for _, v := range []struct{ view, query string }{
		{"summary", ""}, {"curve", ""}, {"histogram", "&set=" + url.QueryEscape(sets[1])}, {"breakdown", ""},
		{"sensitivity", "&set=" + url.QueryEscape(sets[0])}, {"comparison", ""},
	} {
		path := "/api/v1/analyses/runs/" + run + "/data.csv?view=" + v.view + v.query
		results = append(results, summarize("views: the run's "+v.view+" as CSV", timed(v.view, func() { get(path) }), viewsCSVBudget))
	}
	results = append(results, summarize("views: a comparison of six results as CSV", timed("compare.csv", func() { get(compareCSV("summary", items...)) }), viewsCSVBudget))

	var rep strings.Builder
	fmt.Fprintf(&rep, "F-006 result views: %d samples after a warm-up\n", viewsBenchSamples)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	failed := false
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.0f | %.0f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
		failed = failed || r.P95ms > r.Budget
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("result views over budget")
	}
}
