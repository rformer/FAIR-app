package tests

import (
	"math"
	"strconv"
	"strings"
	"testing"
)

// F-007 T-06 (F-007-AC-15 to AC-18, AC-21; design §3.2, §6): treatment
// plans through the register API.

func TestRegisterTreatment(t *testing.T) {
	ra := strideF003Fixture(t) // analyst a Risk Analyst at A, erin a Risk Owner at A1
	registerUsers(ra)          // est without register permissions
	seedPosture(t, ra.env)
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	rg := registerAPI(t, ra)
	// viewer reads the register at A, not treatment.
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('viewer@example.test', 'Viewer')")
	ra.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Register Reader') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['register.view'], 'test' FROM r`)
	ra.mustOwner(grant("platform", "user:viewer", "Register Reader", "A"))
	ra.drain()
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	s2 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims fraud")
	r1 := runWith(t, ae, "analyst", s1, 1, 100_000, "7")
	r2 := runWith(t, ae, "analyst", s2, 1, 100_000, "7")
	erin := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'erin@example.test'")
	pin := func(run string) map[string]any { return map[string]any{"run_id": run, "control_set": "Current"} }
	created := rg.call(t, "POST", "erin", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "change_note": "First assessment",
		"document": map[string]any{"schema_version": 1, "title": "Claims losses", "owner": erin, "state": "open",
			"scenarios": []any{map[string]any{"scenario_id": s1, "pin": pin(r1)}, map[string]any{"scenario_id": s2, "pin": pin(r2)}}}})
	if created.code != 201 {
		t.Fatalf("create: %d %s", created.code, created.raw)
	}
	risk := created.body["id"].(string)
	path := "/api/v1/register/risks/" + risk + "/treatment"
	save := func(user string, expected int, doc map[string]any) apiResp {
		t.Helper()
		return rg.call(t, "PUT", user, path, map[string]any{"document": doc, "expected_version": expected, "change_note": "Plan"})
	}
	action := func(id, due, state string) map[string]any {
		return map[string]any{"id": id, "title": "Action " + id[:4], "owner": erin, "due": due, "state": state}
	}
	a1, a2, a3 := "a1a1a1a1-0000-4000-8000-000000000001", "a2a2a2a2-0000-4000-8000-000000000002", "a3a3a3a3-0000-4000-8000-000000000003"
	plan := map[string]any{"schema_version": 1, "decision": "mitigate", "rationale": "Phishing-resistant MFA and segmentation.",
		"targets": []any{map[string]any{"scenario_id": s1, "control_set": "Proposed"}, map[string]any{"scenario_id": s2, "control_set": "Proposed"}},
		"actions": []any{action(a1, "2020-01-01", "planned"), action(a2, "2099-01-01", "in_progress"), action(a3, "2020-01-01", "done")}}

	// No plan yet; who may read and change it (AC-21).
	got := rg.call(t, "GET", "erin", path, nil)
	if got.code != 200 || got.body["version"] != 0.0 || got.body["expected"].(map[string]any)["reason"] != "no_targets" {
		t.Fatalf("no plan: %d %s", got.code, got.raw)
	}
	for user, code := range map[string]int{"analyst": 200, "viewer": 403, "est": 404, "mallory": 404} {
		if got := rg.call(t, "GET", user, path, nil); got.code != code {
			t.Errorf("%s reads the plan: %d, want %d", user, got.code, code)
		}
	}
	if got := save("analyst", 0, plan); got.code != 403 {
		t.Errorf("a treatment viewer saves: %d %s", got.code, got.raw)
	}
	if got := save("viewer", 0, plan); got.code != 403 {
		t.Errorf("a register viewer saves: %d %s", got.code, got.raw)
	}

	// The database's checks, by pointer (AC-15).
	if got := save("erin", 0, with(plan, "targets", []any{map[string]any{"scenario_id": s1, "control_set": "Elsewhere"}})); got.code != 422 ||
		!strings.Contains(got.raw, "/targets/0/control_set") {
		t.Errorf("an unknown target set: %d %s", got.code, got.raw)
	}
	if got := save("erin", 0, with(plan, "decision", "transfer")); got.code != 422 || !strings.Contains(got.raw, "/targets") {
		t.Errorf("targets without mitigate: %d %s", got.code, got.raw)
	}

	// The first plan; a stale save.
	if got := save("erin", 0, plan); got.code != 200 || got.body["version"] != 1.0 || got.body["acceptance_needed"] != false {
		t.Fatalf("first plan: %d %s", got.code, got.raw)
	}
	if got := save("erin", 0, plan); got.code != 409 || got.body["error"] != "stale_version" {
		t.Errorf("stale: %d %s", got.code, got.raw)
	}
	if n := ra.adminQuery("SELECT body -> 'attributes' ->> 'decision' || '|' || (body -> 'attributes' ->> 'actions_changed') || '|' || (body ->> 'bu_id') FROM audit.intake WHERE body ->> 'type' = 'register.treatment_changed' AND body ->> 'target' = 'register_risk:" + risk + "'"); n !=
		"mitigate|3|"+ra.bu["A1"] {
		t.Errorf("the event: %s", n)
	}

	// Overdue actions (AC-17) and the expected exposure (AC-16): each
	// scenario's pinned set against its target set of the same run.
	got = rg.call(t, "GET", "erin", path, nil)
	if got.code != 200 || got.body["overdue_actions"] != 1.0 {
		t.Fatalf("plan: %d %s", got.code, got.raw)
	}
	for _, x := range got.body["actions"].([]any) {
		a := x.(map[string]any)
		if (a["id"] == a1) != (a["overdue"] == true) {
			t.Errorf("overdue: %v", a)
		}
	}
	mean := func(run, set string) float64 {
		v, err := strconv.ParseFloat(ra.adminQuery("SELECT summary -> 'ale' ->> 'mean' FROM analysis.result WHERE run_id = '"+run+"' AND control_set = '"+set+"'"), 64)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	exp := got.body["expected"].(map[string]any)
	if exp["available"] != true || len(exp["scenarios"].([]any)) != 2 || len(exp["compare_items"].([]any)) != 4 {
		t.Fatalf("expected: %v", exp)
	}
	var cur, tgt float64
	for _, x := range exp["scenarios"].([]any) {
		e := x.(map[string]any)
		run := e["run_id"].(string)
		if e["status"] != "ok" || e["current_mean"] != mean(run, "Current") || e["target_mean"] != mean(run, "Proposed") {
			t.Errorf("a scenario's expected exposure: %v", e)
		}
		cur += mean(run, "Current")
		tgt += mean(run, "Proposed")
	}
	if math.Abs(exp["current_mean_total"].(float64)-cur) > 1e-9 || math.Abs(exp["target_mean_total"].(float64)-tgt) > 1e-9 || math.Abs(exp["reduction"].(float64)-(cur-tgt)) > 1e-9 {
		t.Errorf("totals: %v (want %v, %v)", exp, cur, tgt)
	}

	// The risk carries the plan's summary for those who see treatment.
	tr := rg.call(t, "GET", "erin", "/api/v1/register/risks/"+risk, nil).body["risk"].(map[string]any)["treatment"].(map[string]any)
	if tr["decision"] != "mitigate" || tr["overdue"] != true || tr["next_due"] != "2020-01-01" || tr["version"] != 1.0 {
		t.Errorf("the risk's treatment: %v", tr)
	}
	if got := rg.call(t, "GET", "viewer", "/api/v1/register/risks/"+risk, nil); got.code != 200 || got.body["risk"].(map[string]any)["treatment"] != nil {
		t.Errorf("a register viewer sees treatment: %d %s", got.code, got.raw)
	}

	// List filters (AC-19), among risks whose treatment the caller sees.
	ids := func(user, query string) string {
		t.Helper()
		got := rg.call(t, "GET", user, "/api/v1/register/risks?"+query, nil)
		if got.code != 200 {
			t.Fatalf("list %s: %d %s", query, got.code, got.raw)
		}
		var out []string
		for _, x := range got.body["risks"].([]any) {
			out = append(out, x.(map[string]any)["id"].(string))
		}
		return strings.Join(out, ",")
	}
	other := rg.call(t, "POST", "erin", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "change_note": "x",
		"document": map[string]any{"schema_version": 1, "title": "Claims compliance", "owner": erin, "state": "open", "scenarios": []any{}}})
	if other.code != 201 {
		t.Fatalf("other: %d %s", other.code, other.raw)
	}
	for q, want := range map[string]string{"decision=mitigate": risk, "overdue=true": risk, "decision=accept": "", "decision=none": other.body["id"].(string)} {
		if got := ids("erin", q); got != want {
			t.Errorf("erin %s: %s, want %s", q, got, want)
		}
	}
	if got := ids("viewer", "decision=none"); got != "" {
		t.Errorf("a register viewer filters by decision: %s", got)
	}
	if got := rg.call(t, "GET", "erin", "/api/v1/register/risks?decision=maybe", nil); got.code != 400 {
		t.Errorf("an unknown decision: %d", got.code)
	}

	// A target set the pinned run does not hold: no expected exposure.
	sdoc := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+s1, nil).body["version"].(map[string]any)["document"].(map[string]any)
	sdoc["control_sets"] = append(sdoc["control_sets"].([]any), map[string]any{"name": "Segmented", "current": false, "controls": []any{}})
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+s1, map[string]any{"document": sdoc, "expected_version": 1, "change_note": "v2"}); got.code != 200 {
		t.Fatalf("scenario version 2: %d %s", got.code, got.raw)
	}
	if got := save("erin", 1, with(plan, "targets", []any{map[string]any{"scenario_id": s1, "control_set": "Segmented"}})); got.code != 200 {
		t.Fatalf("target Segmented: %d %s", got.code, got.raw)
	}
	exp = rg.call(t, "GET", "erin", path, nil).body["expected"].(map[string]any)
	if exp["available"] != false || exp["reason"] != "incomplete" {
		t.Errorf("a target not in the pinned run: %v", exp)
	}
	for _, x := range exp["scenarios"].([]any) {
		e := x.(map[string]any)
		want := map[string]string{s1: "target_not_in_pinned_run", s2: "ok"}[e["scenario_id"].(string)]
		if e["status"] != want {
			t.Errorf("scenario %v: %v, want %s", e["scenario_id"], e["status"], want)
		}
	}

	// Accept: an acceptance is needed; F-007 does not decide it (AC-18).
	accept := map[string]any{"schema_version": 1, "decision": "accept", "rationale": "Within appetite.",
		"actions": []any{action(a1, "2020-01-01", "done"), action(a2, "2099-01-01", "in_progress"), action(a3, "2020-01-01", "done")}}
	if got := save("erin", 2, accept); got.code != 200 || got.body["acceptance_needed"] != true {
		t.Fatalf("accept: %d %s", got.code, got.raw)
	}
	got = rg.call(t, "GET", "erin", path, nil)
	if got.body["acceptance"].(map[string]any)["needed"] != true || got.body["overdue_actions"] != 0.0 {
		t.Errorf("accepted: %s", got.raw)
	}
	if n := ra.adminQuery("SELECT body -> 'attributes' ->> 'actions_changed' FROM audit.intake WHERE body ->> 'type' = 'register.treatment_changed' AND body ->> 'target' = 'register_risk:" + risk + "' AND body -> 'attributes' ->> 'version' = '3'"); n != "1" {
		t.Errorf("actions changed: %s", n)
	}
	if got := ids("erin", "overdue=true"); got != "" {
		t.Errorf("no longer overdue: %s", got)
	}

	// History (AC-03): both streams for those who see treatment; diffs of either.
	streams := func(user string) string {
		var out []string
		for _, x := range rg.call(t, "GET", user, "/api/v1/register/risks/"+risk+"/versions", nil).body["versions"].([]any) {
			v := x.(map[string]any)
			out = append(out, v["stream"].(string)+strconv.Itoa(int(v["version"].(float64))))
		}
		return strings.Join(out, ",")
	}
	if got := streams("erin"); got != "treatment3,treatment2,treatment1,risk1" {
		t.Errorf("erin's history: %s", got)
	}
	if got := streams("viewer"); got != "risk1" {
		t.Errorf("viewer's history: %s", got)
	}
	d := rg.call(t, "GET", "erin", "/api/v1/register/risks/"+risk+"/diff?stream=treatment&from=2&to=3", nil)
	if d.code != 200 || !strings.Contains(d.raw, `"/decision"`) {
		t.Errorf("treatment diff: %d %s", d.code, d.raw)
	}
	if d := rg.call(t, "GET", "viewer", "/api/v1/register/risks/"+risk+"/diff?stream=treatment&from=2&to=3", nil); d.code != 404 {
		t.Errorf("a register viewer's treatment diff: %d", d.code)
	}

	// A closed risk's plan does not change.
	if got := rg.call(t, "POST", "erin", "/api/v1/register/risks/"+risk+"/close", map[string]any{"reason": "accepted"}); got.code != 200 {
		t.Fatalf("close: %d %s", got.code, got.raw)
	}
	if got := save("erin", 3, accept); got.code != 409 || got.body["error"] != "closed" {
		t.Errorf("a closed risk's plan: %d %s", got.code, got.raw)
	}
}
