package tests

import (
	"testing"

	"github.com/rformer/fair-app/internal/analysis"
)

// F-006 T-01 (F-006-AC-02, AC-07, AC-09, AC-20; design §3.1, §5):
// histograms of runs and aggregates through the analysis API, from series
// the fake engine ramps: set j loses (i mod 10)·(j+1) in year i.

func sumCounts(h map[string]any) float64 {
	n := 0.0
	for _, c := range h["counts"].([]any) {
		n += c.(float64)
	}
	return n
}

func edge(h map[string]any, i int) float64 { return h["edges"].([]any)[i].(float64) }

func TestAnalysisHistogram(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B, erin an Executive Viewer at A, platform2 at ENTERPRISE
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	sb := scenarioAt(t, ra, "mallory", ra.bu["B"], "Branch outage")
	r1, r2 := runOf(t, ae, "analyst", s1, 2000, false), runOf(t, ae, "analyst", s1, 2000, false)
	rq := runOf(t, ae, "analyst", s1, 2000, true)
	rb := runOf(t, ae, "mallory", sb, 2000, false)
	hist := func(user, path string) apiResp {
		t.Helper()
		return ae.call(t, "GET", user, path, nil)
	}
	run := "/api/v1/analyses/runs/" + r1 + "/histogram"

	// Annual loss, log by default: years 1 to 9 binned, a tenth apart.
	got := hist("analyst", run+"?set=Current")
	h := got.body
	if got.code != 200 || h["scale"] != "log" || h["n"] != 2000.0 || h["zero"] != 200.0 || h["zero_share"] != 0.1 || h["run_id"] != r1 ||
		h["control_set"] != "Current" || h["relative_to"] != nil || len(h["counts"].([]any)) != analysis.HistogramBins ||
		edge(h, 0) != 1 || edge(h, analysis.HistogramBins) != 9 || sumCounts(h) != 1800 || h["both_none"] != nil {
		t.Fatalf("log histogram: %d %s", got.code, got.raw)
	}
	if mk := h["markers"].(map[string]any); mk["mean"] != 4.5 || mk["percentiles"].(map[string]any)["p90"] != 9.0 {
		t.Errorf("markers: %v", mk)
	}
	got = hist("analyst", run+"?set=Proposed&scale=linear")
	if h := got.body; got.code != 200 || h["scale"] != "linear" || edge(h, 0) != 0 || edge(h, analysis.HistogramBins) != 18 || sumCounts(h) != 1800 {
		t.Fatalf("linear histogram: %d %s", got.code, got.raw)
	}

	// The per-year difference from the current set (AC-09): i mod 10.
	got = hist("analyst", run+"?set=Proposed&relative_to=Current")
	h = got.body
	if got.code != 200 || h["scale"] != "linear" || h["relative_to"] != "Current" || h["zero"] != 200.0 || h["both_none"] != 200.0 ||
		edge(h, 0) != 1 || edge(h, analysis.HistogramBins) != 9 || sumCounts(h) != 1800 {
		t.Fatalf("difference: %d %s", got.code, got.raw)
	}
	if mk := h["markers"].(map[string]any); mk["mean"] != 4.5 || mk["percentiles"].(map[string]any)["p50"] != 4.0 {
		t.Errorf("difference markers: %v", mk)
	}
	if got := hist("analyst", run+"?set=Proposed&relative_to=Current&scale=linear"); got.code != 200 {
		t.Errorf("difference, linear named: %d", got.code)
	}

	// Refusals and visibility.
	for name, c := range map[string]struct {
		user, path string
		code       int
	}{
		"no set":                    {"analyst", run, 422},
		"not a set of the run":      {"analyst", run + "?set=Elsewhere", 422},
		"an unknown scale":          {"analyst", run + "?set=Current&scale=cubic", 422},
		"a log difference":          {"analyst", run + "?set=Proposed&relative_to=Current&scale=log", 422},
		"relative to another set":   {"analyst", run + "?set=Current&relative_to=Proposed", 422},
		"relative to itself":        {"analyst", run + "?set=Current&relative_to=Current", 422},
		"a queued run":              {"analyst", "/api/v1/analyses/runs/" + rq + "/histogram?set=Current", 409},
		"a viewer at A":             {"erin", run + "?set=Current", 200},
		"mallory, who cannot see":   {"mallory", run + "?set=Current", 404},
		"analyst, B's run":          {"analyst", "/api/v1/analyses/runs/" + rb + "/histogram?set=Current", 404},
		"no such run":               {"analyst", "/api/v1/analyses/runs/00000000-0000-4000-8000-000000000000/histogram?set=Current", 404},
		"not a uuid":                {"analyst", "/api/v1/analyses/runs/x/histogram?set=Current", 404},
		"mallory, B's run, the set": {"mallory", "/api/v1/analyses/runs/" + rb + "/histogram?set=Current", 200},
	} {
		if got := hist(c.user, c.path); got.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, got.code, got.raw, c.code)
		}
	}
	// Mallory's 404 for a run she cannot see is the same as for none.
	if a, b := hist("mallory", run+"?set=Current"), hist("mallory", "/api/v1/analyses/runs/00000000-0000-4000-8000-000000000000/histogram?set=Current"); a.raw != b.raw {
		t.Errorf("unseen %s, none %s", a.raw, b.raw)
	}

	// Aggregates (AC-07): r1's Current plus r2's Proposed lose 3·(i mod 10).
	aggregate := func(user, bu string, members ...[2]string) string {
		t.Helper()
		ms := []map[string]any{}
		for _, m := range members {
			ms = append(ms, map[string]any{"run_id": m[0], "control_set": m[1]})
		}
		got := ae.call(t, "POST", user, "/api/v1/analyses/aggregates", map[string]any{"bu_id": bu, "name": "Portfolio", "members": ms, "seed": "11"})
		if got.code != 202 {
			t.Fatalf("aggregate: %d %s", got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	a1 := aggregate("analyst", ra.bu["A1"], [2]string{r1, "Current"}, [2]string{r2, "Proposed"})
	agg := "/api/v1/analyses/aggregates/" + a1 + "/histogram"
	if got := hist("analyst", agg); got.code != 409 {
		t.Errorf("a queued aggregate: %d %s", got.code, got.raw)
	}
	if err := ae.aggregates.Attempt(t.Context(), a1, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	got = hist("erin", agg+"?scale=linear")
	if h := got.body; got.code != 200 || h["aggregate_id"] != a1 || h["zero"] != 200.0 || edge(h, analysis.HistogramBins) != 27 || sumCounts(h) != 1800 {
		t.Fatalf("aggregate histogram: %d %s", got.code, got.raw)
	}
	for name, c := range map[string]struct {
		path string
		code int
	}{
		"a set":          {agg + "?set=Current", 422},
		"a relative_to":  {agg + "?relative_to=Current", 422},
		"an odd scale":   {agg + "?scale=cubic", 422},
		"no such":        {"/api/v1/analyses/aggregates/00000000-0000-4000-8000-000000000000/histogram", 404},
		"log by default": {agg, 200},
	} {
		if got := hist("analyst", c.path); got.code != c.code {
			t.Errorf("aggregate, %s: %d %s, want %d", name, got.code, got.raw, c.code)
		}
	}
	// One whose members span A1 and B is hidden from anyone missing one.
	ax := aggregate("platform2", ra.bu["ENTERPRISE"], [2]string{r1, "Current"}, [2]string{rb, "Current"})
	if err := ae.aggregates.Attempt(t.Context(), ax, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	if got := hist("platform2", "/api/v1/analyses/aggregates/"+ax+"/histogram"); got.code != 200 {
		t.Errorf("platform2: %d %s", got.code, got.raw)
	}
	for _, user := range []string{"analyst", "erin", "mallory"} {
		if got := hist(user, "/api/v1/analyses/aggregates/"+ax+"/histogram"); got.code != 404 {
			t.Errorf("%s, missing a member: %d", user, got.code)
		}
	}
}
