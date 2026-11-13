package tests

import (
	"net/url"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/analysis"
)

// F-006 T-02 (F-006-AC-10, AC-11, AC-13, AC-20; design §3.2): comparisons
// through the analysis API, worked by the real workers against the fake
// engine's ramp.

// runWith requests a run of version of scenario and works it to success.
func runWith(t *testing.T, ae *analysisEnv, user, scenario string, version, iterations int, seed string) string {
	t.Helper()
	got := ae.call(t, "POST", user, "/api/v1/analyses/runs", map[string]any{"scenario_id": scenario, "version": version, "iterations": iterations, "seed": seed})
	if got.code != 202 {
		t.Fatalf("run: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	if err := ae.work(t, id, 1, analysis.Attempts); err != nil || ae.state(id) != "succeeded" {
		t.Fatalf("run %s: %v %s", id, err, ae.state(id))
	}
	return id
}

// compareURL is the comparison of items.
func compareURL(items ...string) string {
	return "/api/v1/analyses/compare?" + url.Values{"item": items}.Encode()
}

func compareItems(b map[string]any) []map[string]any {
	var out []map[string]any
	for _, x := range b["items"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

func TestAnalysisCompare(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B, erin an Executive Viewer at A, platform2 at ENTERPRISE
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	s2 := scenarioAt(t, ra, "analyst", ra.bu["A"], "Head office fraud")
	sb := scenarioAt(t, ra, "mallory", ra.bu["B"], "Branch outage")
	r1 := runWith(t, ae, "analyst", s1, 1, 2000, "7")
	r1b := runWith(t, ae, "analyst", s1, 1, 3000, "9")
	doc := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+s1, nil).body["version"].(map[string]any)["document"]
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+s1, map[string]any{"document": doc, "expected_version": 1, "change_note": "v2"}); got.code != 200 {
		t.Fatalf("version 2: %d %s", got.code, got.raw)
	}
	r1v2 := runWith(t, ae, "analyst", s1, 2, 2000, "7")
	ae.engine.mu.Lock()
	ae.engine.version, ae.engine.arch = "0.2.0", "arm64"
	ae.engine.mu.Unlock()
	r2 := runWith(t, ae, "analyst", s2, 1, 2000, "7")
	ae.engine.set("ramp", true)
	rb := runWith(t, ae, "mallory", sb, 1, 2000, "7")
	rq := runOf(t, ae, "analyst", s1, 2000, true)
	got := ae.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": ra.bu["A"], "name": "Head office portfolio",
		"members": []map[string]any{{"run_id": r1, "control_set": "Current"}, {"run_id": r2, "control_set": "Current"}}, "seed": "11"})
	if got.code != 202 {
		t.Fatalf("aggregate: %d %s", got.code, got.raw)
	}
	a1 := got.body["id"].(string)
	if err := ae.aggregates.Attempt(t.Context(), a1, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}

	// Two sets of one run: their random numbers are shared (AC-09, AC-11).
	got = ae.call(t, "GET", "analyst", compareURL("run:"+r1+":Current", "run:"+r1+":Proposed"), nil)
	if got.code != 200 || got.body["sampling_noise"] != false || got.body["statement"] != nil || len(got.body["unlike"].([]any)) != 0 {
		t.Fatalf("one run: %d %s", got.code, got.raw)
	}
	it := compareItems(got.body)
	if it[0]["differences"] != nil || it[0]["label"] != "Claims ransomware v1 · Current" || it[1]["control_set"] != "Proposed" {
		t.Errorf("items: %v", it)
	}
	if m := it[1]["differences"].(map[string]any)["mean"].(map[string]any); m["amount"] != 4.5 || m["share"] != 1.0 {
		t.Errorf("mean difference: %v", m)
	}
	if it[0]["ale"].(map[string]any)["mean"] != 4.5 {
		t.Errorf("the stored summary: %v", it[0])
	}

	// Across runs, versions, scenarios and an aggregate: every unlike input.
	got = ae.call(t, "GET", "analyst", compareURL("run:"+r1+":Current", "run:"+r1b+":Current", "run:"+r1v2+":Current", "run:"+r2+":Proposed", "aggregate:"+a1), nil)
	if got.code != 200 || got.body["sampling_noise"] != true || got.body["statement"] != analysis.SamplingNoise {
		t.Fatalf("across: %d %s", got.code, got.raw)
	}
	unlike := []string{}
	for _, u := range got.body["unlike"].([]any) {
		unlike = append(unlike, u.(string))
	}
	if strings.Join(unlike, ",") != "scenario,scenario_version,iterations,seed,engine_version,architecture" {
		t.Errorf("unlike: %v", unlike)
	}
	it = compareItems(got.body)
	if len(it) != 5 || it[2]["label"] != "Claims ransomware v2 · Current" || it[3]["bu_id"] != ra.bu["A"] || it[4]["kind"] != "aggregate" ||
		it[4]["label"] != "Head office portfolio" || it[3]["engine"].(map[string]any)["version"] != "0.2.0" {
		t.Errorf("items: %v", it)
	}

	// Across business units, for someone who sees both (OQ6); a viewer.
	if got := ae.call(t, "GET", "platform2", compareURL("run:"+r1+":Current", "run:"+rb+":Current"), nil); got.code != 200 {
		t.Errorf("platform2 across BUs: %d %s", got.code, got.raw)
	}
	if got := ae.call(t, "GET", "erin", compareURL("run:"+r1+":Current", "aggregate:"+a1), nil); got.code != 200 {
		t.Errorf("erin, a viewer: %d %s", got.code, got.raw)
	}

	// Refusals, in order: anything unseen first (404), then a set that is
	// not the run's (422), then an item without results (409).
	for name, c := range map[string]struct {
		user  string
		items []string
		code  int
	}{
		"a hidden run":           {"analyst", []string{"run:" + r1 + ":Current", "run:" + rb + ":Current"}, 404},
		"hidden beats a bad set": {"analyst", []string{"run:" + r1 + ":Elsewhere", "run:" + rq + ":Current", "run:" + rb + ":Current"}, 404},
		"a bad set beats queued": {"analyst", []string{"run:" + rq + ":Current", "run:" + r1 + ":Elsewhere"}, 422},
		"a queued run":           {"analyst", []string{"run:" + r1 + ":Current", "run:" + rq + ":Current"}, 409},
		"one item":               {"analyst", []string{"run:" + r1 + ":Current"}, 422},
		"seven items": {"analyst", []string{"run:" + r1 + ":Current", "run:" + r1 + ":Proposed", "run:" + r1b + ":Current", "run:" + r1b + ":Proposed",
			"run:" + r1v2 + ":Current", "run:" + r2 + ":Current", "aggregate:" + a1}, 422},
		"named twice":                   {"analyst", []string{"run:" + r1 + ":Current", "run:" + r1 + ":Current"}, 422},
		"malformed":                     {"analyst", []string{"run:" + r1, "aggregate:" + a1}, 422},
		"an aggregate missing a member": {"mallory", []string{"aggregate:" + a1, "run:" + rb + ":Current"}, 404},
	} {
		if got := ae.call(t, "GET", c.user, compareURL(c.items...), nil); got.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, got.code, got.raw, c.code)
		}
	}
}
