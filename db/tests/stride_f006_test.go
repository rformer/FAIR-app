package tests

import (
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/analysis"
)

// F-006 design §7: the threats to results and their views, attacked
// through the analysis API (the rows join TestSTRIDECatalog with T-08).

// I: a comparison reveals that a hidden result exists, or which item is
// hidden (AC-13). Mallory, at B, compares her own run with a run or an
// aggregate at A1 she cannot see, or with ids that do not exist, at every
// position: the answer is the same 404, byte for byte.
func TestSTRIDEF006ComparisonOracle(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B
	ae := analysisAPI(t, ra, defaultLimits, true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	sb := scenarioAt(t, ra, "mallory", ra.bu["B"], "Branch outage")
	r1 := runWith(t, ae, "analyst", s1, 1, 2000, "7")
	rb := runWith(t, ae, "mallory", sb, 1, 2000, "7")
	got := ae.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": ra.bu["A1"], "name": "Claims",
		"members": []map[string]any{{"run_id": r1, "control_set": "Current"}, {"run_id": r1, "control_set": "Proposed"}}, "seed": "1"})
	if got.code != 202 {
		t.Fatalf("aggregate: %d %s", got.code, got.raw)
	}
	a1 := got.body["id"].(string)
	const none = "00000000-0000-4000-8000-000000000000"
	mine := []string{"run:" + rb + ":Current", "run:" + rb + ":Proposed"}
	var first string
	for _, other := range []string{"run:" + r1 + ":Current", "run:" + r1 + ":Elsewhere", "run:" + none + ":Current", "aggregate:" + a1, "aggregate:" + none} {
		for pos := 0; pos <= len(mine); pos++ {
			items := append(append(append([]string{}, mine[:pos]...), other), mine[pos:]...)
			got := ae.call(t, "GET", "mallory", compareURL(items...), nil)
			if got.code != 404 {
				t.Errorf("%s at %d: %d %s", other, pos, got.code, got.raw)
			}
			if first == "" {
				first = got.raw
			} else if got.raw != first {
				t.Errorf("%s at %d answers %s, not %s", other, pos, got.raw, first)
			}
		}
	}
	if got := ae.call(t, "GET", "mallory", compareURL(mine...), nil); got.code != 200 {
		t.Errorf("her own: %d %s", got.code, got.raw)
	}
}

// I: a histogram, comparison or download shows results of a business unit
// the caller cannot see (F-006-AC-13, AC-20). Mallory, at B, asks for
// every F-006 view of a run and an aggregate at A1; the analyst, at A, for
// those of an aggregate whose members span A1 and B: each is 404, as for
// something that does not exist, and nothing is recorded as downloaded.
func TestSTRIDEF006Visibility(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B, erin an Executive Viewer at A, platform2 at ENTERPRISE
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	sb := scenarioAt(t, ra, "mallory", ra.bu["B"], "Branch outage")
	r1 := runWith(t, ae, "analyst", s1, 1, 2000, "7")
	rb := runWith(t, ae, "mallory", sb, 1, 2000, "7")
	aggregate := func(user, bu string, members ...[2]string) string {
		t.Helper()
		ms := []map[string]any{}
		for _, m := range members {
			ms = append(ms, map[string]any{"run_id": m[0], "control_set": m[1]})
		}
		got := ae.call(t, "POST", user, "/api/v1/analyses/aggregates", map[string]any{"bu_id": bu, "name": "Portfolio", "members": ms, "seed": "1"})
		if got.code != 202 {
			t.Fatalf("aggregate: %d %s", got.code, got.raw)
		}
		id := got.body["id"].(string)
		if err := ae.aggregates.Attempt(t.Context(), id, 1, analysis.Attempts); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a1 := aggregate("analyst", ra.bu["A1"], [2]string{r1, "Current"}, [2]string{r1, "Proposed"})
	ax := aggregate("platform2", ra.bu["ENTERPRISE"], [2]string{r1, "Current"}, [2]string{rb, "Current"})
	// The run views of run, the aggregate views of agg, and comparisons of
	// mine with agg.
	runViews := func(run string) map[string]string {
		return map[string]string{
			"run histogram":  "/api/v1/analyses/runs/" + run + "/histogram?set=Current",
			"run difference": "/api/v1/analyses/runs/" + run + "/histogram?set=Proposed&relative_to=Current",
			"run CSV":        "/api/v1/analyses/runs/" + run + "/data.csv?view=curve",
		}
	}
	aggregateViews := func(agg, mine string) map[string]string {
		return map[string]string{
			"aggregate histogram": "/api/v1/analyses/aggregates/" + agg + "/histogram",
			"aggregate CSV":       "/api/v1/analyses/aggregates/" + agg + "/data.csv?view=curve",
			"comparison":          compareURL("run:"+mine+":Current", "aggregate:"+agg),
			"comparison CSV":      compareCSV("curve", "run:"+mine+":Current", "aggregate:"+agg),
		}
	}
	downloads := func() string {
		return ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.downloaded'")
	}
	before := downloads()
	for _, views := range []map[string]string{runViews(r1), aggregateViews(a1, rb)} {
		for name, path := range views {
			if got := ae.call(t, "GET", "mallory", path, nil); got.code != 404 {
				t.Errorf("mallory, %s: %d %s", name, got.code, got.raw)
			}
		}
	}
	for name, path := range aggregateViews(ax, r1) {
		if got := ae.call(t, "GET", "analyst", path, nil); got.code != 404 {
			t.Errorf("analyst, missing a member, %s: %d %s", name, got.code, got.raw)
		}
	}
	for name, body := range map[string]map[string]any{
		"mallory, the run at A1":                {"subject": "run", "id": r1, "view": "curve", "format": "svg"},
		"mallory, the aggregate at A1":          {"subject": "aggregate", "id": a1, "view": "curve", "format": "svg"},
		"mallory, a comparison with A1 results": {"subject": "comparison", "items": []string{"run:" + rb + ":Current", "run:" + r1 + ":Current"}, "view": "curve", "format": "svg"},
		"analyst, the cross-BU aggregate":       {"subject": "aggregate", "id": ax, "view": "curve", "format": "png"},
	} {
		user := "mallory"
		if strings.HasPrefix(name, "analyst") {
			user = "analyst"
		}
		if got := ae.call(t, "POST", user, "/api/v1/analyses/downloads", body); got.code != 404 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	if after := downloads(); after != before {
		t.Errorf("refused downloads were recorded: %s then %s", before, after)
	}
	// Those who see them get them: erin, a viewer at A; platform2, everything.
	for _, views := range []map[string]string{runViews(r1), aggregateViews(a1, r1)} {
		for name, path := range views {
			if got := ae.call(t, "GET", "erin", path, nil); got.code != 200 {
				t.Errorf("erin, %s: %d %s", name, got.code, got.raw)
			}
		}
	}
	for name, path := range aggregateViews(ax, rb) {
		if got := ae.call(t, "GET", "platform2", path, nil); got.code != 200 {
			t.Errorf("platform2, %s: %d %s", name, got.code, got.raw)
		}
	}
}

// E: a viewer changes results through F-006's routes. Every route is a
// read, apart from recording downloads; after every view, CSV and download
// by a viewer and an analyst, the runs, results, series and aggregates are
// as before, and the read routes take no other method.
func TestSTRIDEF006ReadOnly(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, erin an Executive Viewer at A
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	r1 := runWith(t, ae, "analyst", s1, 1, 2000, "7")
	got := ae.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": ra.bu["A1"], "name": "Portfolio",
		"members": []map[string]any{{"run_id": r1, "control_set": "Current"}, {"run_id": r1, "control_set": "Proposed"}}, "seed": "1"})
	if got.code != 202 {
		t.Fatalf("aggregate: %d %s", got.code, got.raw)
	}
	a1 := got.body["id"].(string)
	if err := ae.aggregates.Attempt(t.Context(), a1, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	state := func() string {
		return ra.adminQuery(`SELECT md5(
			(SELECT string_agg(id::text || state || coalesce(result_digest, '') || seq || coalesce(finished_at::text, ''), ',' ORDER BY id) FROM analysis.run) ||
			(SELECT string_agg(run_id::text || control_set || summary::text, ',' ORDER BY run_id, control_set) FROM analysis.result) ||
			(SELECT string_agg(run_id::text || control_set || md5(ale), ',' ORDER BY run_id, control_set) FROM analysis.series) ||
			(SELECT string_agg(id::text || state || summary::text || md5(ale) || result_digest, ',' ORDER BY id) FROM analysis.aggregate) ||
			(SELECT string_agg(aggregate_id::text || run_id::text || control_set || position, ',' ORDER BY aggregate_id, position) FROM analysis.aggregate_member))`)
	}
	before := state()
	items := []string{"run:" + r1 + ":Current", "aggregate:" + a1}
	reads := []string{
		"/api/v1/analyses/runs/" + r1 + "/histogram?set=Current", "/api/v1/analyses/runs/" + r1 + "/histogram?set=Proposed&relative_to=Current",
		"/api/v1/analyses/aggregates/" + a1 + "/histogram", compareURL(items...), compareCSV("summary", items...), compareCSV("curve", items...),
		"/api/v1/analyses/aggregates/" + a1 + "/data.csv?view=contributions",
		"/api/v1/analyses/runs/" + r1 + "/data.csv?view=sensitivity&set=Current", "/api/v1/analyses/runs/" + r1 + "/data.csv?view=histogram&set=Current",
	}
	for _, v := range []string{"summary", "curve", "breakdown", "comparison"} {
		reads = append(reads, "/api/v1/analyses/runs/"+r1+"/data.csv?view="+v)
	}
	for _, user := range []string{"erin", "analyst"} {
		for _, path := range reads {
			if got := ae.call(t, "GET", user, path, nil); got.code != 200 {
				t.Errorf("%s, %s: %d %s", user, path, got.code, got.raw)
			}
			for _, m := range []string{"POST", "PUT", "PATCH"} {
				if got := ae.call(t, m, user, strings.SplitN(path, "?", 2)[0], map[string]any{}); got.code != 405 {
					t.Errorf("%s %s by %s: %d %s", m, path, user, got.code, got.raw)
				}
			}
		}
		for _, body := range []map[string]any{
			{"subject": "run", "id": r1, "view": "curve", "format": "svg"},
			{"subject": "aggregate", "id": a1, "view": "contributions", "format": "png"},
			{"subject": "comparison", "items": items, "view": "curve", "format": "svg"},
		} {
			if got := ae.call(t, "POST", user, "/api/v1/analyses/downloads", body); got.code != 201 {
				t.Errorf("%s records %v: %d %s", user, body, got.code, got.raw)
			}
		}
	}
	if after := state(); after != before {
		t.Errorf("results changed through F-006's routes: %s then %s", before, after)
	}
}
