package tests

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/riverqueue/river"

	"github.com/rformer/fair-app/internal/analysis"
)

// F-007 T-07 (F-007-AC-11 to AC-14; design §3.4): business unit roll-ups
// through the register API, their nodes worked by the aggregate worker
// against the fake engine: a three-level tree, a level split, node reuse,
// each restricted mode, staleness, the limits, a failed node, and the
// requester-only record.

func TestRegisterRollups(t *testing.T) {
	ra := strideF003Fixture(t) // analyst a Risk Analyst at A, mallory at B; buadmin3 at R, buadmin2 at R1 (Risk Analysts inside R)
	registerUsers(ra)          // owen a Risk Owner at A, chief at the root
	seedPosture(t, ra.env)
	setInstance(ra.env, "register.iterations", "2000") // small runs for the test
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('rowner@example.test', 'Rowner')")
	ra.mustOwner(grant("platform", "user:rowner", "Risk Owner", "R"))
	ra.drain()
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	rg := registerAPI(t, ra)
	ctx := context.Background()
	user := func(name string) string {
		return ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + name + "@example.test'")
	}
	chief, owen, rowner := user("chief"), user("owen"), user("rowner")

	type pinned struct{ scenario, run, set, reason string }
	risk := func(who, owner, bu, title string, pins ...pinned) string {
		t.Helper()
		links := []any{}
		for _, p := range pins {
			l := map[string]any{"scenario_id": p.scenario}
			if p.run != "" {
				pin := map[string]any{"run_id": p.run, "control_set": p.set}
				if p.reason != "" {
					pin["reason"] = p.reason
				}
				l["pin"] = pin
			}
			links = append(links, l)
		}
		got := rg.call(t, "POST", who, "/api/v1/register/risks", map[string]any{"bu_id": bu, "change_note": "x",
			"document": map[string]any{"schema_version": 1, "title": title, "owner": owner, "state": "open", "scenarios": links}})
		if got.code != 201 {
			t.Fatalf("risk %s: %d %s", title, got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	scenarioRun := func(who, bu, name string) (string, string) {
		t.Helper()
		s := scenarioAt(t, ra, who, bu, name)
		return s, runWith(t, ae, who, s, 1, 2000, "7")
	}
	work := func(id string) {
		t.Helper()
		if err := ae.aggregates.Attempt(ctx, id, 1, analysis.Attempts); err != nil {
			t.Fatalf("aggregate %s: %v", id, err)
		}
	}

	// The register: at A one risk; at A1 two single-pin risks (one on its
	// Proposed set, the larger mean) and one of two scenarios (an exposure
	// aggregate), one stale (no pin) and one unquantified; at B one risk;
	// inside the restricted R and R1 one risk each.
	sa, ra0 := scenarioRun("analyst", ra.bu["A"], "Head office fraud")
	s1, r1 := scenarioRun("analyst", ra.bu["A1"], "Claims ransomware")
	s2, r2 := scenarioRun("analyst", ra.bu["A1"], "Claims fraud")
	s3, r3 := scenarioRun("analyst", ra.bu["A1"], "Claims outage")
	s4, r4 := scenarioRun("analyst", ra.bu["A1"], "Claims data loss")
	s5 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims vendor")
	sb, rb := scenarioRun("mallory", ra.bu["B"], "Branch outage")
	sr, rr := scenarioRun("buadmin3", ra.bu["R"], "Restricted fraud")
	sr1, rr1 := scenarioRun("buadmin2", ra.bu["R1"], "Restricted outage")
	headOffice := risk("chief", chief, ra.bu["A"], "Head office fraud", pinned{sa, ra0, "Current", ""})
	ransomware := risk("owen", owen, ra.bu["A1"], "Claims ransomware", pinned{s1, r1, "Current", ""})
	fraud := risk("owen", owen, ra.bu["A1"], "Claims fraud", pinned{s2, r2, "Proposed", "the plan in force"})
	outage := risk("owen", owen, ra.bu["A1"], "Claims outage and data loss", pinned{s3, r3, "Current", ""}, pinned{s4, r4, "Current", ""})
	vendor := risk("owen", owen, ra.bu["A1"], "Claims vendor", pinned{s5, "", "", ""})
	_ = risk("owen", owen, ra.bu["A1"], "Claims compliance")
	branch := risk("chief", chief, ra.bu["B"], "Branch outage", pinned{sb, rb, "Current", ""})
	restricted := risk("rowner", rowner, ra.bu["R"], "Restricted fraud", pinned{sr, rr, "Current", ""})
	restricted1 := risk("rowner", rowner, ra.bu["R1"], "Restricted outage", pinned{sr1, rr1, "Current", ""})
	_, _, _ = vendor, restricted, restricted1
	work(ra.adminQuery("SELECT exposure_aggregate_id FROM register.risk WHERE id = '" + outage + "'"))

	mode := func(m string) {
		ra.mustOwner("UPDATE iam.bu SET rollup_mode = '" + m + "' WHERE code IN ('R', 'R1')")
		ra.drain()
	}
	request := func(who, bu string) apiResp {
		t.Helper()
		return rg.call(t, "POST", who, "/api/v1/register/rollups", map[string]any{"bu_id": bu})
	}
	read := func(who, id string, q string) apiResp {
		t.Helper()
		return rg.call(t, "GET", who, "/api/v1/register/rollups/"+id+q, nil)
	}
	age := func(id string) { // as if requested two minutes ago (the rate limit)
		ra.admin(ra.db, "SET ROLE register_definer; UPDATE register.rollup SET requested_at = requested_at - interval '2 minutes' WHERE id = '"+id+"'")
	}
	nodes := func(string) []string { // the nodes still queued, children first
		got := ra.adminQuery("SELECT string_agg(id::text, ',' ORDER BY seq) FROM analysis.aggregate WHERE purpose = 'rollup' AND state = 'queued'")
		if got == "" {
			return nil
		}
		return strings.Split(got, ",")
	}
	mean := func(run, set string) float64 {
		v, _ := strconv.ParseFloat(ra.adminQuery("SELECT summary -> 'ale' ->> 'mean' FROM analysis.result WHERE run_id = '"+run+"' AND control_set = '"+set+"'"), 64)
		return v
	}

	// Excluded (the default): a three-level tree, ENTERPRISE over A over A1
	// (AC-11, AC-13).
	mode("excluded")
	got := request("chief", ra.bu["ENTERPRISE"])
	if got.code != 202 || got.body["state"] != "queued" || got.body["nodes"] != 3.0 {
		t.Fatalf("roll-up: %d %s", got.code, got.raw)
	}
	top := got.body["id"].(string)
	queued := nodes(top)
	if len(queued) != 3 {
		t.Fatalf("queued nodes: %v", queued)
	}
	if got := ra.adminQuery("SELECT count(*) FROM risk_river.river_job WHERE kind = 'analysis.aggregate' AND args ->> 'aggregate_id' IN ('" + queued[0] + "', '" + queued[1] + "', '" + queued[2] + "')"); got != "3" {
		t.Errorf("jobs: %s", got)
	}
	tree := ra.adminQuery(`SELECT string_agg(b.code || ':' || (SELECT count(*) FROM analysis.aggregate_member m WHERE m.aggregate_id = a.id), ',' ORDER BY a.seq)
		FROM analysis.aggregate a JOIN iam.bu b ON b.id = a.bu_id WHERE a.id = ANY ('{` + queued[0] + "," + queued[1] + "," + queued[2] + `}')`)
	if tree != "A1:3,A:2,ENTERPRISE:2" {
		t.Errorf("the tree: %s", tree)
	}
	// One running roll-up per BU and requester.
	if got := request("chief", ra.bu["ENTERPRISE"]); got.code != 409 || got.body["error"] != "rollup_running" {
		t.Errorf("a second roll-up while one runs: %d %s", got.code, got.raw)
	}
	// A node waits for its members.
	var snooze *river.JobSnoozeError
	if err := ae.aggregates.Attempt(ctx, queued[1], 1, analysis.Attempts); !errors.As(err, &snooze) {
		t.Errorf("a node before its members: %v", err)
	}
	for _, id := range queued {
		work(id)
	}
	got = read("chief", top, "")
	if got.code != 200 || got.body["state"] != "succeeded" || got.body["covers"] != 5.0 || got.body["excluded_bus"] != 2.0 || got.body["aggregate_only"] != nil ||
		got.body["stale"] != false || got.body["summary"] == nil {
		t.Fatalf("the roll-up: %d %s", got.code, got.raw)
	}
	left := got.body["left_out"].(map[string]any)
	if left["stale"] != 1.0 || left["unquantified"] != 1.0 || got.body["left_out_total"] != 2.0 {
		t.Errorf("left out: %v", left)
	}
	// Ordered by mean, each with its share (AC-14): fraud's Proposed set first.
	risks := got.body["risks"].([]any)
	if first := risks[0].(map[string]any); first["risk_id"] != fraud || first["mean"] != mean(r2, "Proposed") || first["share"] == nil || first["title"] != "Claims fraud" {
		t.Errorf("the first risk: %v", first)
	}
	if got := ra.adminQuery("SELECT string_agg(body ->> 'type', ',' ORDER BY body ->> 'type') FROM audit.intake WHERE body ->> 'target' = 'register_rollup:" + top + "'"); got != "register.rollup_computed,register.rollup_requested" {
		t.Errorf("events: %s", got)
	}
	// The list's exposure sort (AC-14, AC-19).
	list := rg.call(t, "GET", "chief", "/api/v1/register/risks?bu="+ra.bu["A1"]+"&sort=mean&state=open", nil)
	if list.code != 200 || list.body["risks"].([]any)[0].(map[string]any)["id"] != fraud {
		t.Errorf("sort=mean: %d %s", list.code, list.raw)
	}
	// The record is the requester's alone.
	if got := read("owen", top, ""); got.code != 404 {
		t.Errorf("owen reads chief's roll-up: %d", got.code)
	}
	if got := rg.call(t, "GET", "owen", "/api/v1/register/rollups", nil); got.code != 200 || len(got.body["rollups"].([]any)) != 0 {
		t.Errorf("owen's roll-ups: %s", got.raw)
	}
	if got := rg.call(t, "GET", "chief", "/api/v1/register/rollups?bu="+ra.bu["ENTERPRISE"], nil); got.code != 200 || len(got.body["rollups"].([]any)) != 1 {
		t.Errorf("chief's roll-ups: %s", got.raw)
	}
	if got := request("est", ra.bu["A"]); got.code != 404 {
		t.Errorf("a roll-up without the register: %d", got.code)
	}
	if got := request("owen", ra.bu["B"]); got.code != 404 {
		t.Errorf("a roll-up of an unseen BU: %d", got.code)
	}

	// Reuse: a roll-up of A has A's node already (nothing new; done at once).
	got = request("owen", ra.bu["A"])
	if got.code != 202 || got.body["state"] != "succeeded" || got.body["nodes"] != 0.0 {
		t.Errorf("a roll-up of A reuses its node: %d %s", got.code, got.raw)
	}
	ofA := got.body["id"].(string)
	if root := read("owen", ofA, "").body["root"].(map[string]any)["aggregate_id"]; root != queued[1] {
		t.Errorf("A's root: %v, want %s", root, queued[1])
	}
	// One request per BU per minute, whoever asks.
	if got := request("chief", ra.bu["A"]); got.code != 429 || got.body["error"] != "rollup_rate" {
		t.Errorf("a second roll-up of A within the minute: %d %s", got.code, got.raw)
	}

	// Staleness (AC-12): a pin changed, then a risk closed.
	r1b := runWith(t, ae, "analyst", s1, 1, 2000, "8")
	v := rg.call(t, "GET", "owen", "/api/v1/register/risks/"+ransomware, nil).body["risk"].(map[string]any)["current_version"].(float64)
	if got := rg.call(t, "POST", "owen", "/api/v1/register/risks/"+ransomware+"/adopt", map[string]any{"expected_version": int(v), "change_note": "newer"}); got.code != 200 {
		t.Fatalf("adopt: %d %s", got.code, got.raw)
	}
	if got := read("chief", top, ""); got.body["stale"] != true {
		t.Errorf("a changed pin: %s", got.raw)
	}
	_ = r1b
	age(top)
	got = request("chief", ra.bu["ENTERPRISE"])
	if got.code != 202 || got.body["nodes"] != 3.0 {
		t.Fatalf("again: %d %s", got.code, got.raw)
	}
	again := got.body["id"].(string)
	for _, id := range nodes(again) {
		work(id)
	}
	if got := read("chief", again, ""); got.body["state"] != "succeeded" || got.body["stale"] != false {
		t.Errorf("fresh: %s", got.raw)
	}
	if got := rg.call(t, "POST", "chief", "/api/v1/register/risks/"+headOffice+"/close", map[string]any{"reason": "merged"}); got.code != 200 {
		t.Fatalf("close: %d %s", got.code, got.raw)
	}
	if got := read("chief", again, ""); got.body["stale"] != true {
		t.Errorf("a closed risk: %s", got.raw)
	}

	// Aggregate only (AC-13, OQ6): one mean total for R and R1, added to
	// the mean, never a member.
	mode("aggregate")
	age(again)
	got = request("chief", ra.bu["ENTERPRISE"])
	if got.code != 202 {
		t.Fatalf("aggregate mode: %d %s", got.code, got.raw)
	}
	agg := got.body["id"].(string)
	for _, id := range nodes(agg) {
		work(id)
	}
	got = read("chief", agg, "")
	ao, _ := got.body["aggregate_only"].(map[string]any)
	if ao == nil || ao["bus"] != 2.0 || math.Abs(ao["mean_total"].(float64)-(mean(rr, "Current")+mean(rr1, "Current"))) > 1e-9 || got.body["excluded_bus"] != 0.0 {
		t.Fatalf("aggregate only: %s", got.raw)
	}
	base := got.body["summary"].(map[string]any)["ale"].(map[string]any)["mean"].(float64)
	if math.Abs(got.body["mean_with_aggregate_only"].(float64)-(base+ao["mean_total"].(float64))) > 1e-9 {
		t.Errorf("the mean with the aggregate-only total: %v", got.body["mean_with_aggregate_only"])
	}
	for _, x := range got.body["risks"].([]any) {
		if id := x.(map[string]any)["risk_id"]; id == restricted || id == restricted1 {
			t.Errorf("a restricted risk in an aggregate-only roll-up: %v", id)
		}
	}
	if got := ra.adminQuery("SELECT count(*) FROM analysis.aggregate_member m JOIN analysis.run r ON r.id = m.run_id WHERE r.id IN ('" + rr + "', '" + rr1 + "')"); got != "0" {
		t.Errorf("restricted runs as members: %s", got)
	}

	// Full: R's and R1's risks are members like any other.
	mode("full")
	age(agg)
	got = request("chief", ra.bu["ENTERPRISE"])
	if got.code != 202 {
		t.Fatalf("full mode: %d %s", got.code, got.raw)
	}
	full := got.body["id"].(string)
	fullNodes := nodes(full)
	// A failed node fails the roll-up (AC-11; availability NFR).
	if _, err := ae.aggregates.DB.Exec(ctx, "SELECT analysis.fail_aggregate($1, '', 'engine_unavailable', 'test')", fullNodes[0]); err != nil {
		t.Fatal(err)
	}
	for _, id := range fullNodes[1:] {
		if err := ae.aggregates.Attempt(ctx, id, 1, analysis.Attempts); err != nil && !errors.As(err, new(*river.JobCancelError)) {
			t.Fatalf("node %s: %v", id, err)
		}
	}
	got = read("chief", full, "")
	if got.body["state"] != "failed" || got.body["failure"] != analysis.FailMemberFailed {
		t.Errorf("a failed node: %s", got.raw)
	}
	if got := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'register.rollup_failed' AND body ->> 'target' = 'register_rollup:" + full + "'"); got != "1" {
		t.Errorf("rollup_failed events: %s", got)
	}
	age(full)
	got = request("chief", ra.bu["ENTERPRISE"])
	if got.code != 202 {
		t.Fatalf("full mode again: %d %s", got.code, got.raw)
	}
	fullAgain := got.body["id"].(string)
	for _, id := range nodes(fullAgain) {
		work(id)
	}
	got = read("chief", fullAgain, "")
	ids := map[any]bool{}
	for _, x := range got.body["risks"].([]any) {
		ids[x.(map[string]any)["risk_id"]] = true
	}
	if got.body["state"] != "succeeded" || !ids[restricted] || !ids[restricted1] || !ids[branch] || got.body["aggregate_only"] != nil {
		t.Errorf("full mode: %s", got.raw)
	}

	// A level split (design §3.4), with the node size lowered for the
	// test: A1's three members make a part of two and pass one on.
	ra.admin(ra.db, "CREATE OR REPLACE FUNCTION register.rollup_node_max() RETURNS integer LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$")
	age(fullAgain)
	mode("excluded")
	got = request("chief", ra.bu["A1"])
	if got.code != 202 {
		t.Fatalf("split: %d %s", got.code, got.raw)
	}
	parts := ra.adminQuery(`SELECT string_agg((a.name LIKE '% (part 1)') || ':' || (SELECT count(*) FROM analysis.aggregate_member m WHERE m.aggregate_id = a.id), ',' ORDER BY a.seq)
		FROM analysis.aggregate a WHERE a.purpose = 'rollup' AND a.state = 'queued'`)
	if parts != "true:2,false:2" {
		t.Errorf("the split: %s", parts)
	}
	for _, id := range nodes(got.body["id"].(string)) {
		work(id)
	}

	// The size limit, lowered for the test.
	ra.admin(ra.db, "CREATE OR REPLACE FUNCTION register.rollup_max_risks() RETURNS integer LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$ SELECT 2 $$")
	if got := request("chief", ra.bu["B"]); got.code != 202 {
		t.Errorf("a roll-up within the size: %d %s", got.code, got.raw)
	}
	age(ofA)
	if got := request("owen", ra.bu["A"]); got.code != 409 || got.body["error"] != "rollup_too_large" {
		t.Errorf("too large: %d %s", got.code, got.raw)
	}
}
