package tests

import (
	"testing"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-005 T-12 (F-005-AC-16, AC-18, AC-19, AC-23; design §6.2, §6.4):
// reproductions and aggregates through the analysis API, worked by the real
// workers against the fake engine.

// scenarioAt is a scenario at bu, made by user with library entries of
// their own at bu, with two control sets.
func scenarioAt(t *testing.T, ae *riskAPIEnv, user, bu, name string) string {
	t.Helper()
	asset := modeltest.Asset()
	delete(asset, "value")
	asset["value_basis"] = "Replacement cost."
	a := ae.create(t, user, "asset", bu, asset)
	tc := ae.create(t, user, "threat_community", bu, modeltest.ThreatCommunity())
	ctl := ae.create(t, user, "control", bu, modeltest.Control())
	d := modeltest.Scenario()
	d["name"] = name
	modeltest.Set(d, "/owner", ae.adminQuery("SELECT id FROM iam.app_user WHERE email = '"+user+"@example.test'"))
	modeltest.Set(d, "/asset", map[string]any{"kind": "asset", "id": a, "version": 1})
	modeltest.Set(d, "/threat_community", map[string]any{"id": tc, "version": 1})
	modeltest.Set(d, "/control_sets", []any{
		map[string]any{"name": "Current", "current": true, "controls": []any{map[string]any{"id": ctl, "version": 1, "status": "in_place"}}},
		map[string]any{"name": "Proposed", "current": false, "controls": []any{}},
	})
	got := ae.call(t, "POST", user, "/api/v1/scenarios", map[string]any{"bu_id": bu, "document": d, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("scenario at %s: %d %s", bu, got.code, got.raw)
	}
	return got.body["id"].(string)
}

// runOf requests a run and, unless queued, works it to success.
func runOf(t *testing.T, ae *analysisEnv, user, scenario string, iterations int, queued bool) string {
	t.Helper()
	got := ae.call(t, "POST", user, "/api/v1/analyses/runs", map[string]any{"scenario_id": scenario, "version": 1, "iterations": iterations, "seed": "7"})
	if got.code != 202 {
		t.Fatalf("run: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	if !queued {
		if err := ae.work(t, id, 1, analysis.Attempts); err != nil || ae.state(id) != "succeeded" {
			t.Fatalf("run %s: %v %s", id, err, ae.state(id))
		}
	}
	return id
}

func TestAnalysisReproduce(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B, erin an Executive Viewer at A
	ae := analysisAPI(t, ra, defaultLimits, true)
	// The scenario API serves on the risk env's URL; the analysis API on ae's.
	sid := analysisScenario(t, ra)
	orig := runOf(t, ae, "analyst", sid, 2000, false)
	reproduce := func(user, id string) apiResp {
		t.Helper()
		return ae.call(t, "POST", user, "/api/v1/analyses/runs/"+id+"/reproduce", nil)
	}

	outcomes := []string{}
	for _, c := range []struct{ mode, version, arch, want string }{
		{"ok", "0.1.0", "amd64", "match"},
		{"different", "0.1.0", "amd64", "mismatch"},
		{"ok", "0.2.0", "amd64", "other_version"},
		{"ok", "0.1.0", "arm64", "other_architecture"},
	} {
		ae.engine.set(c.mode, true)
		ae.engine.version, ae.engine.arch = c.version, c.arch
		got := reproduce("analyst", orig)
		if got.code != 202 || got.body["reproduces"] != orig || got.body["seed"] != "7" || got.body["iterations"] != 2000.0 {
			t.Fatalf("reproduce (%s): %d %s", c.want, got.code, got.raw)
		}
		id := got.body["id"].(string)
		if err := ae.work(t, id, 1, analysis.Attempts); err != nil {
			t.Fatal(err)
		}
		run := ae.call(t, "GET", "analyst", "/api/v1/analyses/runs/"+id, nil)
		if run.body["state"] != "succeeded" || run.body["reproduction"] != c.want {
			t.Errorf("%s: %s", c.want, run.raw)
		}
		outcomes = append(outcomes, c.want)
	}
	if got := ra.adminQuery(`SELECT string_agg(body -> 'attributes' ->> 'outcome', ',' ORDER BY id) FROM audit.intake
		WHERE body ->> 'type' = 'analysis.run_reproduced' AND body ->> 'target' = 'analysis_run:` + orig + `'`); got != "match,mismatch,other_version,other_architecture" {
		t.Errorf("run_reproduced events: %s", got)
	}

	// Who may: mallory cannot see the run (404); erin sees it, may not run (403).
	if got := reproduce("mallory", orig); got.code != 404 {
		t.Errorf("mallory reproduces: %d", got.code)
	}
	if got := reproduce("erin", orig); got.code != 403 {
		t.Errorf("a viewer reproduces: %d %s", got.code, got.raw)
	}
	// Only a succeeded run.
	ae.engine.set("ok", true)
	queued := runOf(t, ae, "analyst", sid, 2000, true)
	if got := reproduce("analyst", queued); got.code != 409 {
		t.Errorf("reproduce a queued run: %d %s", got.code, got.raw)
	}
}

func TestAnalysisAggregates(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B, erin an Executive Viewer at A, platform2 at ENTERPRISE
	ae := analysisAPI(t, ra, defaultLimits, true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	s0 := scenarioAt(t, ra, "analyst", ra.bu["A"], "Head office fraud")
	sb := scenarioAt(t, ra, "mallory", ra.bu["B"], "Branch outage")
	r1, r2 := runOf(t, ae, "analyst", s1, 2000, false), runOf(t, ae, "analyst", s1, 2000, false)
	r3 := runOf(t, ae, "analyst", s1, 3000, false)
	r0 := runOf(t, ae, "analyst", s0, 2000, false)
	rb := runOf(t, ae, "mallory", sb, 2000, false)
	rq := runOf(t, ae, "analyst", s1, 2000, true)
	aggregate := func(user, bu string, members ...[2]string) apiResp {
		t.Helper()
		ms := []map[string]any{}
		for _, m := range members {
			ms = append(ms, map[string]any{"run_id": m[0], "control_set": m[1]})
		}
		return ae.call(t, "POST", user, "/api/v1/analyses/aggregates", map[string]any{"bu_id": bu, "name": "Claims portfolio", "members": ms, "seed": "11"})
	}

	// An aggregate at A1 of two runs' sets: queued, worked, read.
	got := aggregate("analyst", ra.bu["A1"], [2]string{r1, "Current"}, [2]string{r2, "Proposed"})
	if got.code != 202 || got.body["state"] != "queued" || got.body["iterations"] != 2000.0 {
		t.Fatalf("aggregate: %d %s", got.code, got.raw)
	}
	a1 := got.body["id"].(string)
	if n := ra.adminQuery("SELECT count(*) FROM risk_river.river_job WHERE kind = 'analysis.aggregate' AND args ->> 'aggregate_id' = '" + a1 + "'"); n != "1" {
		t.Errorf("aggregate jobs: %s", n)
	}
	if err := ae.aggregates.Attempt(t.Context(), a1, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	agg := ae.call(t, "GET", "analyst", "/api/v1/analyses/aggregates/"+a1, nil)
	members, _ := agg.body["members"].([]any)
	if agg.code != 200 || agg.body["state"] != "succeeded" || agg.body["result_digest"] == nil || len(members) != 2 ||
		members[0].(map[string]any)["scenario_name"] != "Claims ransomware" || agg.body["mixed_engine_versions"] != false {
		t.Fatalf("the aggregate: %d %s", agg.code, agg.raw)
	}
	summary := agg.body["summary"].(map[string]any)
	if summary["members"] != 2.0 || summary["ale"].(map[string]any)["mean"] != 4.0 { // 1.5 + 2.5 in every year
		t.Errorf("summary: %v", summary)
	}

	// Refusals.
	for name, c := range map[string]struct {
		user, bu string
		members  [][2]string
		code     int
	}{
		"unequal iterations":   {"analyst", ra.bu["A1"], [][2]string{{r1, "Current"}, {r3, "Current"}}, 409},
		"outside the subtree":  {"analyst", ra.bu["A1"], [][2]string{{r1, "Current"}, {r0, "Current"}}, 409},
		"a member not visible": {"analyst", ra.bu["A1"], [][2]string{{r1, "Current"}, {rb, "Current"}}, 422},
		"a queued member":      {"analyst", ra.bu["A1"], [][2]string{{r1, "Current"}, {rq, "Current"}}, 409},
		"one member":           {"analyst", ra.bu["A1"], [][2]string{{r1, "Current"}}, 400},
		"a set named twice":    {"analyst", ra.bu["A1"], [][2]string{{r1, "Current"}, {r1, "Current"}}, 422},
		"not a set of the run": {"analyst", ra.bu["A1"], [][2]string{{r1, "Current"}, {r2, "Elsewhere"}}, 409},
		"mallory at A1":        {"mallory", ra.bu["A1"], [][2]string{{r1, "Current"}, {r2, "Current"}}, 404},
		"a viewer":             {"erin", ra.bu["A1"], [][2]string{{r1, "Current"}, {r2, "Current"}}, 403},
	} {
		if got := aggregate(c.user, c.bu, c.members...); got.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, got.code, got.raw, c.code)
		}
	}

	// An aggregate whose members span A1 and B (by platform2 at
	// ENTERPRISE) is hidden from anyone missing a member (AC-19).
	got = aggregate("platform2", ra.bu["ENTERPRISE"], [2]string{r1, "Current"}, [2]string{rb, "Current"})
	if got.code != 202 {
		t.Fatalf("a cross-BU aggregate: %d %s", got.code, got.raw)
	}
	ax := got.body["id"].(string)
	if err := ae.aggregates.Attempt(t.Context(), ax, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	ids := func(user string) map[string]bool {
		t.Helper()
		got := ae.call(t, "GET", user, "/api/v1/analyses/aggregates", nil)
		out := map[string]bool{}
		for _, x := range got.body["aggregates"].([]any) {
			out[x.(map[string]any)["id"].(string)] = true
		}
		return out
	}
	if l := ids("platform2"); !l[ax] || !l[a1] {
		t.Errorf("platform2 sees %v", l)
	}
	for _, user := range []string{"analyst", "erin", "mallory"} {
		if ids(user)[ax] {
			t.Errorf("%s, missing a member, lists the cross-BU aggregate", user)
		}
		if got := ae.call(t, "GET", user, "/api/v1/analyses/aggregates/"+ax, nil); got.code != 404 {
			t.Errorf("%s reads the cross-BU aggregate: %d", user, got.code)
		}
	}
	if !ids("erin")[a1] || ids("mallory")[a1] {
		t.Error("erin, a viewer at A, sees the A1 aggregate; mallory does not")
	}
	if got := ae.call(t, "GET", "analyst", "/api/v1/analyses/aggregates?bu="+ra.bu["A1"], nil); len(got.body["aggregates"].([]any)) != 1 {
		t.Errorf("by BU: %s", got.raw)
	}

	// Events: created and succeeded, each in its transaction.
	for _, typ := range []string{"analysis.aggregate_created", "analysis.aggregate_succeeded"} {
		if n := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '" + typ + "' AND body ->> 'target' IN ('analysis_aggregate:" + a1 + "', 'analysis_aggregate:" + ax + "')"); n != "2" {
			t.Errorf("%s events: %s", typ, n)
		}
	}
}
