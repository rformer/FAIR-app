package tests

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/analysis"
)

// F-007 T-05 (F-007-AC-06 to AC-10; design §3.3, §5.2, §10): pins, the
// exposure they make (one result, or an aggregate of purpose exposure
// worked by the aggregate worker against the fake engine), every stale
// reason, newer runs and adoption, coverage, and the F-003 scenario move
// check.

// riskStatus is a risk's status as user reads it: "status:reason/scenario,…".
func riskStatus(t *testing.T, rg *riskAPIEnv, user, risk string) string {
	t.Helper()
	got := rg.call(t, "GET", user, "/api/v1/register/risks/"+risk, nil)
	if got.code != 200 {
		t.Fatalf("read %s: %d %s", risk, got.code, got.raw)
	}
	st := got.body["risk"].(map[string]any)["status"].(map[string]any)
	var reasons []string
	for _, x := range st["reasons"].([]any) {
		r := x.(map[string]any)
		s, _ := r["scenario_id"].(string)
		reasons = append(reasons, r["reason"].(string)+"/"+s)
	}
	slices.Sort(reasons)
	return st["status"].(string) + ":" + strings.Join(reasons, ",")
}

func TestRegisterExposure(t *testing.T) {
	ra := strideF003Fixture(t) // analyst a Risk Analyst at A, mallory at B, erin a Risk Owner at A1
	registerUsers(ra)          // owen a Risk Owner at A, chief at the root
	seedPosture(t, ra.env)
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	rg := registerAPI(t, ra)
	ctx := context.Background()
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	s2 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims fraud")
	s3 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims outage")
	r1 := runWith(t, ae, "analyst", s1, 1, 100_000, "7")
	r2 := runWith(t, ae, "analyst", s2, 1, 100_000, "7")
	small := runWith(t, ae, "analyst", s2, 1, 2000, "7")
	erin := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'erin@example.test'")
	link := func(scenario string, pin map[string]any) map[string]any {
		l := map[string]any{"scenario_id": scenario}
		if pin != nil {
			l["pin"] = pin
		}
		return l
	}
	pin := func(run string) map[string]any { return map[string]any{"run_id": run, "control_set": "Current"} }
	doc := map[string]any{"schema_version": 1, "title": "Claims losses", "owner": erin, "state": "open",
		"scenarios": []any{link(s1, pin(r1)), link(s2, nil)}}
	risk := func() string {
		t.Helper()
		got := rg.call(t, "POST", "erin", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "First assessment"})
		if got.code != 201 {
			t.Fatalf("create: %d %s", got.code, got.raw)
		}
		return got.body["id"].(string)
	}()
	version := 1
	save := func(user string, d map[string]any) apiResp {
		t.Helper()
		got := rg.call(t, "PUT", user, "/api/v1/register/risks/"+risk, map[string]any{"document": d, "expected_version": version, "change_note": "Pins"})
		if got.code == 200 {
			version++
		}
		return got
	}
	read := func(user string) map[string]any {
		t.Helper()
		got := rg.call(t, "GET", user, "/api/v1/register/risks/"+risk, nil)
		if got.code != 200 {
			t.Fatalf("read: %d %s", got.code, got.raw)
		}
		return got.body
	}
	aggregate := func() string {
		return ra.adminQuery("SELECT coalesce(exposure_aggregate_id::text, '') FROM register.risk WHERE id = '" + risk + "'")
	}
	work := func(id string) {
		t.Helper()
		if err := ae.aggregates.Attempt(ctx, id, 1, analysis.Attempts); err != nil {
			t.Fatalf("aggregate %s: %v", id, err)
		}
	}

	// ADR-007 amendment 5: definer inserts only for NOLOGIN *_definer roles,
	// one per table.
	if got := ra.adminState("SELECT authz.allow_definer_insert('analysis.run', 'app_rw')"); got != "22023" {
		t.Errorf("an application role as inserter: %s", got)
	}
	if got := ra.adminState("SELECT authz.allow_definer_insert('analysis.aggregate', 'estimate_definer')"); got != "42P16" {
		t.Errorf("a second inserter: %s", got)
	}

	// One pin (AC-06, AC-07): its result is the exposure; the unpinned
	// scenario makes it stale. Each pin set is recorded.
	if got := riskStatus(t, rg, "erin", risk); got != "stale:no_pin/"+s2 {
		t.Errorf("one pin of two: %s", got)
	}
	exp := read("erin")["exposure"].(map[string]any)
	if exp["kind"] != "run" || exp["run_id"] != r1 || exp["visible"] != true || exp["summary"] == nil {
		t.Errorf("one pin's exposure: %v", exp)
	}
	if aggregate() != "" || registerEvents(ra, risk, "register.pin_set") != "1" {
		t.Errorf("one pin: aggregate %q, pin events %s", aggregate(), registerEvents(ra, risk, "register.pin_set"))
	}
	l0 := read("erin")["links"].([]any)
	var p1 map[string]any
	for _, x := range l0 {
		if x.(map[string]any)["scenario_id"] == s1 {
			p1 = x.(map[string]any)["pin"].(map[string]any)
		}
	}
	if p1 == nil || p1["pinned_by"] != erin || p1["pinned_version"] != 1.0 || p1["run_scenario_version"] != 1.0 || p1["run_finished_at"] == nil {
		t.Errorf("the pin: %v", p1)
	}

	// The register's iteration count (design §1): another count is refused.
	if got := save("erin", with(doc, "scenarios", []any{link(s1, pin(r1)), link(s2, pin(small))})); got.code != 422 || !strings.Contains(got.raw, "has 2000 iterations") {
		t.Errorf("a pin of 2,000 iterations: %d %s", got.code, got.raw)
	}

	// Two pins: an exposure aggregate at the risk's BU, requested by the
	// pinner, queued in the change's transaction; computing until worked.
	both := with(doc, "scenarios", []any{link(s1, pin(r1)), link(s2, pin(r2))})
	if got := save("erin", both); got.code != 200 {
		t.Fatalf("pin both: %d %s", got.code, got.raw)
	}
	agg := aggregate()
	if agg == "" {
		t.Fatal("no exposure aggregate")
	}
	if got := ra.adminQuery("SELECT purpose || '|' || bu_id || '|' || requested_by || '|' || state || '|' || (SELECT count(*) FROM analysis.aggregate_member m WHERE m.aggregate_id = a.id) FROM analysis.aggregate a WHERE id = '" + agg + "'"); got !=
		"exposure|"+ra.bu["A1"]+"|"+erin+"|queued|2" {
		t.Errorf("the exposure aggregate: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM risk_river.river_job WHERE kind = 'analysis.aggregate' AND args ->> 'aggregate_id' = '" + agg + "'"); got != "1" {
		t.Errorf("queued jobs: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.aggregate_created' AND body ->> 'target' = 'analysis_aggregate:" + agg + "' AND body ->> 'actor' = '" + erin + "'"); got != "1" {
		t.Errorf("aggregate_created by erin: %s", got)
	}
	if got := riskStatus(t, rg, "erin", risk); got != "computing:" {
		t.Errorf("before the aggregate: %s", got)
	}
	work(agg)
	if got := riskStatus(t, rg, "erin", risk); got != "current:" {
		t.Errorf("worked: %s", got)
	}
	exp = read("erin")["exposure"].(map[string]any)
	if exp["kind"] != "aggregate" || exp["aggregate_id"] != agg || exp["visible"] != true || exp["state"] != "succeeded" || exp["summary"] == nil || exp["assumption"] == nil {
		t.Errorf("the aggregate exposure: %v", exp)
	}
	// Register aggregates are reached through the register, not the analyst's list.
	if got := ae.call(t, "GET", "analyst", "/api/v1/analyses/aggregates", nil); strings.Contains(got.raw, agg) {
		t.Errorf("listed among analysis aggregates: %s", got.raw)
	}
	// Unchanged pins keep the aggregate.
	if got := save("erin", with(both, "title", "Claims losses (all)")); got.code != 200 || aggregate() != agg {
		t.Errorf("unchanged pins: %d %s, aggregate %s", got.code, got.raw, aggregate())
	}

	// Stale reasons (AC-08). A newer scenario version:
	sdoc := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+s1, nil).body["version"].(map[string]any)["document"]
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+s1, map[string]any{"document": sdoc, "expected_version": 1, "change_note": "v2"}); got.code != 200 {
		t.Fatalf("scenario version 2: %d %s", got.code, got.raw)
	}
	if got := riskStatus(t, rg, "erin", risk); got != "stale:newer_version/"+s1 {
		t.Errorf("a newer scenario version: %s", got)
	}
	// A result too old (register.analysis_max_age_days, 365): the copy as
	// the version trigger keeps it.
	ra.admin(ra.db, "SET ROLE register_definer; UPDATE register.risk_scenario SET run_finished_at = now() - interval '400 days' WHERE risk_id = '"+risk+"' AND scenario_id = '"+s2+"'")
	if got := riskStatus(t, rg, "erin", risk); got != "stale:newer_version/"+s1+",too_old/"+s2 {
		t.Errorf("too old: %s", got)
	}
	ra.admin(ra.db, "SET ROLE register_definer; UPDATE register.risk_scenario SET run_finished_at = now() WHERE risk_id = '"+risk+"' AND scenario_id = '"+s2+"'")

	// Newer runs (AC-10): shown, adopted only on request.
	r1v2 := runWith(t, ae, "analyst", s1, 2, 100_000, "8")
	_ = runWith(t, ae, "analyst", s1, 2, 2000, "8") // another count: never offered
	var newer []any
	for _, x := range read("erin")["links"].([]any) {
		if l := x.(map[string]any); l["scenario_id"] == s1 {
			newer = l["newer_runs"].([]any)
		}
	}
	if len(newer) != 1 || newer[0].(map[string]any)["run_id"] != r1v2 || newer[0].(map[string]any)["scenario_version"] != 2.0 {
		t.Errorf("newer runs: %v", newer)
	}
	if got := riskStatus(t, rg, "erin", risk); !strings.HasPrefix(got, "stale:newer_version/") {
		t.Errorf("a newer run is not adopted by itself: %s", got)
	}
	adopt := func(user string, body map[string]any) apiResp {
		t.Helper()
		b := map[string]any{"expected_version": version, "change_note": "Adopt the version 2 analysis"}
		for k, v := range body {
			b[k] = v
		}
		got := rg.call(t, "POST", user, "/api/v1/register/risks/"+risk+"/adopt", b)
		if got.code == 200 {
			version++
		}
		return got
	}
	if got := adopt("analyst", nil); got.code != 403 {
		t.Errorf("a viewer adopts: %d %s", got.code, got.raw)
	}
	if got := adopt("erin", map[string]any{"expected_version": version - 1}); got.code != 409 || got.body["error"] != "stale_version" {
		t.Errorf("a stale adoption: %d %s", got.code, got.raw)
	}
	if got := adopt("erin", map[string]any{"pins": []any{map[string]any{"scenario_id": s3, "run_id": r1v2}}}); got.code != 422 || !strings.Contains(got.raw, "/pins/0/scenario_id") {
		t.Errorf("adopting for an unlinked scenario: %d %s", got.code, got.raw)
	}
	pinEvents := registerEvents(ra, risk, "register.pin_set")
	got := adopt("erin", nil)
	if got.code != 200 || len(got.body["adopted"].([]any)) != 1 || got.body["adopted"].([]any)[0] != s1 {
		t.Fatalf("adopt: %d %s", got.code, got.raw)
	}
	if n := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'register.pin_set' AND body ->> 'target' = 'register_risk:" + risk + "' AND body -> 'attributes' ->> 'adopted' = 'true' AND body -> 'attributes' ->> 'run' = '" + r1v2 + "'"); n != "1" || pinEvents == registerEvents(ra, risk, "register.pin_set") {
		t.Errorf("adoption events: %s", n)
	}
	agg2 := aggregate()
	if agg2 == "" || agg2 == agg {
		t.Fatalf("adoption's aggregate: %q (was %s)", agg2, agg)
	}
	work(agg2)
	if got := riskStatus(t, rg, "erin", risk); got != "current:" {
		t.Errorf("adopted: %s", got)
	}
	if got := adopt("erin", nil); got.code != 409 || got.body["error"] != "nothing_newer" {
		t.Errorf("nothing newer: %d %s", got.code, got.raw)
	}

	// A failed exposure aggregate: stale, exposure_unavailable, until the pins change.
	r2b := runWith(t, ae, "analyst", s2, 1, 100_000, "9")
	if got := adopt("erin", map[string]any{"pins": []any{map[string]any{"scenario_id": s2, "run_id": r2b}}}); got.code != 200 {
		t.Fatalf("adopt a named run: %d %s", got.code, got.raw)
	}
	agg3 := aggregate()
	if _, err := ae.aggregates.DB.Exec(ctx, "SELECT analysis.fail_aggregate($1, '', 'engine_unavailable', 'test')", agg3); err != nil {
		t.Fatal(err)
	}
	if got := riskStatus(t, rg, "erin", risk); got != "stale:exposure_unavailable/" {
		t.Errorf("a failed exposure: %s", got)
	}
	if got := save("erin", with(both, "title", "Claims losses (retried)", "scenarios", []any{link(s1, pin(r1v2)), link(s2, pin(r2b))})); got.code != 200 {
		t.Fatalf("save after failure: %d %s", got.code, got.raw)
	}
	if agg4 := aggregate(); agg4 == "" || agg4 == agg3 {
		t.Errorf("a failed exposure is requested again: %q", agg4)
	} else {
		work(agg4)
	}

	// Archived and unquantified; coverage and the status filter (AC-09).
	other := rg.call(t, "POST", "erin", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "change_note": "x",
		"document": with(doc, "title", "Claims outage", "scenarios", []any{link(s3, nil)})})
	empty := rg.call(t, "POST", "erin", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "change_note": "x",
		"document": with(doc, "title", "Claims compliance", "scenarios", []any{})})
	if other.code != 201 || empty.code != 201 {
		t.Fatalf("more risks: %d %d", other.code, empty.code)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+s3+"/archive", map[string]any{"reason": "retired"}); got.code != 200 {
		t.Fatalf("archive: %d %s", got.code, got.raw)
	}
	if got := riskStatus(t, rg, "erin", other.body["id"].(string)); got != "stale:archived/"+s3+",no_pin/"+s3 {
		t.Errorf("archived: %s", got)
	}
	if got := riskStatus(t, rg, "erin", empty.body["id"].(string)); got != "unquantified:" {
		t.Errorf("no scenarios: %s", got)
	}
	cov := rg.call(t, "GET", "erin", "/api/v1/register/coverage?bu="+ra.bu["A1"], nil)
	if cov.code != 200 || cov.body["open"] != 3.0 || cov.body["current"] != 1.0 || cov.body["stale"] != 1.0 || cov.body["unquantified"] != 1.0 ||
		cov.body["computing"] != 0.0 || cov.body["current_share"].(float64) < 0.33 || cov.body["current_share"].(float64) > 0.34 {
		t.Errorf("coverage: %d %s", cov.code, cov.raw)
	}
	if got := rg.call(t, "GET", "est", "/api/v1/register/coverage", nil); got.code != 404 {
		t.Errorf("coverage without the register: %d", got.code)
	}
	if got := rg.call(t, "GET", "chief", "/api/v1/register/coverage?bu="+ra.bu["B"], nil); got.code != 200 || got.body["open"] != 0.0 || got.body["current_share"] != nil {
		t.Errorf("coverage of an empty subtree: %d %s", got.code, got.raw)
	}
	list := rg.call(t, "GET", "erin", "/api/v1/register/risks?status=stale", nil)
	if list.code != 200 || len(list.body["risks"].([]any)) != 1 || list.body["risks"].([]any)[0].(map[string]any)["id"] != other.body["id"] {
		t.Errorf("stale risks: %d %s", list.code, list.raw)
	}
	if got := rg.call(t, "GET", "erin", "/api/v1/register/risks?status=pending", nil); got.code != 400 {
		t.Errorf("an unknown status: %d", got.code)
	}

	// F-003 (design §10): a scenario linked to an open risk stays in its
	// subtree; the risk is named to those who see it, and only to them.
	moveTo := func(user, scenario, bu string) apiResp {
		t.Helper()
		return ra.call(t, "POST", user, "/api/v1/scenarios/"+scenario+"/move", map[string]any{"to_bu_id": bu, "reason": "reorganised"})
	}
	got = moveTo("analyst", s1, ra.bu["A"])
	if got.code != 409 || got.body["error"] != "linked_to_risk" || got.body["risk"].(map[string]any)["risk_id"] != risk {
		t.Errorf("moving a linked scenario out: %d %s", got.code, got.raw)
	}
	// mover edits scenarios at A and sees no register.
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('mover@example.test', 'Mover')")
	ra.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Scenario Editor') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['scenario.view', 'scenario.edit'], 'test' FROM r`)
	ra.mustOwner(grant("platform", "user:mover", "Scenario Editor", "A"))
	ra.drain()
	got = moveTo("mover", s1, ra.bu["A"])
	if got.code != 409 || got.body["error"] != "linked_to_risk" || got.body["risk"] != nil {
		t.Errorf("the risk named to someone who does not see it: %d %s", got.code, got.raw)
	}
	// Closing frees the scenario (AC-04).
	closed := rg.call(t, "POST", "erin", "/api/v1/register/risks/"+other.body["id"].(string)+"/close", map[string]any{"reason": "outage retired"})
	if closed.code != 200 {
		t.Fatalf("close: %d %s", closed.code, closed.raw)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+s3+"/restore", map[string]any{"reason": "back"}); got.code != 200 {
		t.Fatalf("restore: %d %s", got.code, got.raw)
	}
	if got := moveTo("analyst", s3, ra.bu["A"]); got.code != 200 {
		t.Errorf("moving a scenario of a closed risk: %d %s", got.code, got.raw)
	}

	// Moving the risk: its exposure is made again at its new BU.
	before := aggregate()
	if got := rg.call(t, "POST", "chief", "/api/v1/register/risks/"+risk+"/move", map[string]any{"to_bu_id": ra.bu["A"], "reason": "head office owns it"}); got.code != 200 {
		t.Fatalf("move the risk: %d %s", got.code, got.raw)
	}
	after := aggregate()
	if after == "" || after == before || ra.adminQuery("SELECT bu_id || '|' || requested_by FROM analysis.aggregate WHERE id = '"+after+"'") !=
		ra.bu["A"]+"|"+ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'chief@example.test'") {
		t.Errorf("the moved risk's exposure: %q (was %s)", after, before)
	}
}
