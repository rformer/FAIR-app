package tests

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/registerapi"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-007 T-11 (F-007 Q5; design §7): the STRIDE suite for the risk register.
// Each test is one row of design §7 (TestSTRIDECatalog maps them).

type f007Env struct {
	ra       *riskAPIEnv
	ae       *analysisEnv
	rg       *riskAPIEnv
	s1, s2   string // scenarios at A1
	r1, r2   string // their runs (the register's 2,000 iterations)
	risk     string // owen's risk at A1, pinned to r1
	owen     string
	chief    string
	viewerID string
}

// strideF007Fixture: the F-003 STRIDE fixture (analyst a Risk Analyst at A,
// mallory at B, buadmin3 at R, buadmin2 at R1), owen a Risk Owner at A,
// chief at the root, est without the register, "viewer" with register.view
// alone at A (no analysis, no treatment); two scenarios at A1 with runs,
// and owen's risk on the first, pinned.
func strideF007Fixture(t *testing.T) *f007Env {
	t.Helper()
	ra := strideF003Fixture(t)
	registerUsers(ra)
	seedPosture(t, ra.env)
	setInstance(ra.env, "register.iterations", "2000")
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('viewer@example.test', 'Viewer')")
	ra.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Register Reader') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['register.view'], 'test' FROM r`)
	ra.mustOwner(grant("platform", "user:viewer", "Register Reader", "A"))
	ra.drain()
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	f := &f007Env{ra: ra, ae: ae, rg: registerAPI(t, ra)}
	user := func(n string) string {
		return ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + n + "@example.test'")
	}
	f.owen, f.chief, f.viewerID = user("owen"), user("chief"), user("viewer")
	f.s1 = scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	f.s2 = scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims fraud")
	f.r1 = runWith(t, ae, "analyst", f.s1, 1, 2000, "7")
	f.r2 = runWith(t, ae, "analyst", f.s2, 1, 2000, "7")
	f.risk = f.create(t, "owen", ra.bu["A1"], "Claims ransomware", f.s1, f.r1)
	return f
}

// create makes a risk at bu covering scenario, pinned to run (none if "").
func (f *f007Env) create(t *testing.T, user, bu, title, scenario, run string) string {
	t.Helper()
	got := f.rg.call(t, "POST", user, "/api/v1/register/risks", map[string]any{"bu_id": bu, "change_note": "x", "document": f.doc(title, scenario, run)})
	if got.code != 201 {
		t.Fatalf("create %s: %d %s", title, got.code, got.raw)
	}
	return got.body["id"].(string)
}

func (f *f007Env) doc(title, scenario, run string) map[string]any {
	links := []any{}
	if scenario != "" {
		l := map[string]any{"scenario_id": scenario}
		if run != "" {
			l["pin"] = map[string]any{"run_id": run, "control_set": "Current"}
		}
		links = append(links, l)
	}
	return map[string]any{"schema_version": 1, "title": title, "owner": f.owen, "state": "open", "scenarios": links}
}

func (f *f007Env) treatment(t *testing.T) {
	t.Helper()
	got := f.rg.call(t, "PUT", "owen", "/api/v1/register/risks/"+f.risk+"/treatment", map[string]any{"expected_version": 0, "change_note": "plan",
		"document": map[string]any{"schema_version": 1, "decision": "avoid", "rationale": "Retire the platform."}})
	if got.code != 200 {
		t.Fatalf("treatment: %d %s", got.code, got.raw)
	}
}

// count reads table's rows as user (app_rw under their context: RLS).
func (f *f007Env) count(t *testing.T, user, table string) string {
	t.Helper()
	var n string
	if err := f.ra.tx(user, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*)::text FROM "+table).Scan(&n)
	}); err != nil {
		t.Fatalf("%s as %s: %v", table, user, err)
	}
	return n
}

// I: a risk, its treatment or a roll-up crosses business units.
func TestSTRIDEF007Visibility(t *testing.T) {
	f := strideF007Fixture(t)
	f.treatment(t)
	rollup := f.rg.call(t, "POST", "owen", "/api/v1/register/rollups", map[string]any{"bu_id": f.ra.bu["A1"]})
	if rollup.code != 202 {
		t.Fatalf("roll-up: %d %s", rollup.code, rollup.raw)
	}
	rid := rollup.body["id"].(string)

	// Another BU's reader sees nothing of it: not through the API, not in the tables.
	for _, path := range []string{"/api/v1/register/risks/" + f.risk, "/api/v1/register/risks/" + f.risk + "/treatment",
		"/api/v1/register/risks/" + f.risk + "/versions", "/api/v1/register/rollups/" + rid} {
		if got := f.rg.call(t, "GET", "mallory", path, nil); got.code != 404 {
			t.Errorf("mallory GET %s: %d", path, got.code)
		}
	}
	if got := f.rg.call(t, "GET", "mallory", "/api/v1/register/risks", nil); got.code != 200 || len(got.body["risks"].([]any)) != 0 {
		t.Errorf("mallory's list: %s", got.raw)
	}
	if got := f.rg.call(t, "GET", "mallory", "/api/v1/register/coverage", nil); got.body["open"] != 0.0 {
		t.Errorf("mallory's coverage: %s", got.raw)
	}
	for _, table := range []string{"register.risk", "register.risk_version", "register.risk_scenario", "register.treatment", "register.treatment_version", "register.rollup"} {
		if n := f.count(t, "mallory", table); n != "0" {
			t.Errorf("mallory reads %s rows of %s", n, table)
		}
	}
	// A roll-up is its requester's alone, even for a reader above.
	if got := f.rg.call(t, "GET", "chief", "/api/v1/register/rollups/"+rid, nil); got.code != 404 {
		t.Errorf("chief reads owen's roll-up: %d", got.code)
	}
	if n := f.count(t, "chief", "register.rollup"); n != "0" {
		t.Errorf("chief reads %s roll-up rows", n)
	}
	// Roll-ups include only results their requester sees: the viewer (no
	// analysis.view) sees the risk, never its result.
	got := f.rg.call(t, "POST", "viewer", "/api/v1/register/rollups", map[string]any{"bu_id": f.ra.bu["A"]})
	if got.code != 202 {
		t.Fatalf("the viewer's roll-up: %d %s", got.code, got.raw)
	}
	read := f.rg.call(t, "GET", "viewer", "/api/v1/register/rollups/"+got.body["id"].(string), nil)
	if read.body["covers"] != 0.0 || read.body["left_out"].(map[string]any)["not_visible"] != 1.0 || read.body["summary"] != nil {
		t.Errorf("a roll-up of results the requester cannot see: %s", read.raw)
	}
	if exp := f.rg.call(t, "GET", "viewer", "/api/v1/register/risks/"+f.risk, nil).body["exposure"].(map[string]any); exp["visible"] != false || exp["summary"] != nil {
		t.Errorf("the viewer sees the exposure: %v", exp)
	}
	// A nested aggregate (a roll-up node) is visible only with every leaf.
	r3 := f.create(t, "owen", f.ra.bu["A1"], "Claims fraud", f.s2, f.r2)
	_ = r3
	f.ra.admin(f.ra.db, "SET ROLE register_definer; UPDATE register.rollup SET requested_at = requested_at - interval '2 minutes'")
	got = f.rg.call(t, "POST", "chief", "/api/v1/register/rollups", map[string]any{"bu_id": f.ra.bu["A1"]})
	node := f.ra.adminQuery("SELECT root_aggregate_id FROM register.rollup WHERE id = '" + got.body["id"].(string) + "'")
	if node == "" {
		t.Fatalf("no node: %s", got.raw)
	}
	if n := f.count(t, "mallory", "analysis.aggregate WHERE id = '"+node+"'"); n != "0" {
		t.Errorf("mallory reads the node")
	}
	if n := f.count(t, "owen", "analysis.aggregate WHERE id = '"+node+"'"); n != "1" {
		t.Errorf("owen (who sees every leaf) does not read the node")
	}
}

// I: a roll-up reveals a restricted subtree's detail.
func TestSTRIDEF007RestrictedRollup(t *testing.T) {
	f := strideF007Fixture(t)
	ra := f.ra
	// Inside R: buadmin3 (Risk Analyst there) makes a scenario, a run and a risk.
	ra.mustOwner(grant("platform", "user:buadmin3", "Risk Owner", "R"))
	ra.drain()
	buadmin3 := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'buadmin3@example.test'")
	sr := scenarioAt(t, ra, "buadmin3", ra.bu["R"], "Restricted fraud")
	rr := runWith(t, f.ae, "buadmin3", sr, 1, 2000, "7")
	d := f.doc("Restricted fraud", sr, rr)
	d["owner"] = buadmin3
	if got := f.rg.call(t, "POST", "buadmin3", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["R"], "change_note": "x", "document": d}); got.code != 201 {
		t.Fatalf("restricted risk: %d %s", got.code, got.raw)
	}
	restricted := ra.adminQuery("SELECT id FROM register.risk WHERE bu_id = '" + ra.bu["R"] + "'")
	rollup := func(mode string) map[string]any {
		t.Helper()
		ra.mustOwner("UPDATE iam.bu SET rollup_mode = '" + mode + "' WHERE code IN ('R', 'R1')")
		ra.drain()
		ra.admin(ra.db, "SET ROLE register_definer; UPDATE register.rollup SET requested_at = requested_at - interval '2 minutes'")
		got := f.rg.call(t, "POST", "chief", "/api/v1/register/rollups", map[string]any{"bu_id": ra.bu["ENTERPRISE"]})
		if got.code != 202 {
			t.Fatalf("%s roll-up: %d %s", mode, got.code, got.raw)
		}
		return f.rg.call(t, "GET", "chief", "/api/v1/register/rollups/"+got.body["id"].(string), nil).body
	}
	// Aggregate only: one labelled mean total; the risk, its scenario and
	// its series never enter the roll-up.
	agg := rollup("aggregate")
	ao, _ := agg["aggregate_only"].(map[string]any)
	if ao == nil || len(ao) != 3 || ao["bus"] == nil || ao["mean_total"] == nil || ao["label"] != "restricted business units (mean only)" {
		t.Errorf("the aggregate-only total: %v", agg["aggregate_only"])
	}
	for _, x := range agg["risks"].([]any) {
		if x.(map[string]any)["risk_id"] == restricted {
			t.Error("a restricted risk in the roll-up's risks")
		}
	}
	if got := ra.adminQuery("SELECT count(*) FROM register.rollup WHERE included::text LIKE '%" + restricted + "%' OR included::text LIKE '%" + rr + "%'"); got != "0" {
		t.Errorf("the restricted risk or run recorded in a roll-up: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM analysis.aggregate_member WHERE run_id = '" + rr + "'"); got != "0" {
		t.Errorf("the restricted run is a member of an aggregate: %s", got)
	}
	// Only rollup_definer's function reads those rows, and only the register's functions call it.
	if err := ra.tx("chief", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "SELECT register.rollup_means($1)", ra.bu["ENTERPRISE"])
		return err
	}); !strings.HasPrefix(pgCode(err), "42501 ") {
		t.Errorf("the application calls rollup_means: %v", pgCode(err))
	}
	// Excluded: counted, nothing more.
	ex := rollup("excluded")
	if ex["aggregate_only"] != nil || ex["excluded_bus"].(float64) < 1 {
		t.Errorf("excluded: %v / %v", ex["aggregate_only"], ex["excluded_bus"])
	}
}

// I: treatment details reach people without treatment.view.
func TestSTRIDEF007TreatmentScope(t *testing.T) {
	f := strideF007Fixture(t)
	f.treatment(t)
	if got := f.rg.call(t, "GET", "viewer", "/api/v1/register/risks/"+f.risk+"/treatment", nil); got.code != 403 {
		t.Errorf("the viewer reads the plan: %d %s", got.code, got.raw)
	}
	read := f.rg.call(t, "GET", "viewer", "/api/v1/register/risks/"+f.risk, nil)
	if read.code != 200 || read.body["risk"].(map[string]any)["treatment"] != nil {
		t.Errorf("the risk carries treatment for the viewer: %s", read.raw)
	}
	for _, v := range f.rg.call(t, "GET", "viewer", "/api/v1/register/risks/"+f.risk+"/versions", nil).body["versions"].([]any) {
		if v.(map[string]any)["stream"] == "treatment" {
			t.Error("the viewer's history shows treatment versions")
		}
	}
	if got := f.rg.call(t, "GET", "viewer", "/api/v1/register/risks/"+f.risk+"/diff?stream=treatment&from=1&to=2", nil); got.code != 404 {
		t.Errorf("the viewer's treatment diff: %d", got.code)
	}
	if got := f.rg.call(t, "GET", "viewer", "/api/v1/register/risks?decision=avoid", nil); len(got.body["risks"].([]any)) != 0 {
		t.Errorf("the viewer filters by a decision they cannot see: %s", got.raw)
	}
	for _, table := range []string{"register.treatment", "register.treatment_version"} {
		if n := f.count(t, "viewer", table); n != "0" {
			t.Errorf("the viewer reads %s rows of %s", n, table)
		}
	}
	if n := f.count(t, "owen", "register.treatment_version"); n != "1" {
		t.Errorf("owen reads %s treatment versions", n)
	}
}

// T: a risk's history is altered.
func TestSTRIDEF007HistoryTamper(t *testing.T) {
	f := strideF007Fixture(t)
	f.treatment(t)
	got := f.rg.call(t, "POST", "owen", "/api/v1/register/rollups", map[string]any{"bu_id": f.ra.bu["A1"]})
	if got.code != 202 {
		t.Fatalf("roll-up: %d", got.code)
	}
	for _, sql := range []string{
		"UPDATE register.risk_version SET change_note = 'rewritten'",
		"DELETE FROM register.risk_version",
		"UPDATE register.treatment_version SET change_note = 'rewritten'",
		"DELETE FROM register.treatment_version",
		"UPDATE register.risk SET title = 'rewritten'",
		"UPDATE register.risk SET state = 'closed'",
		"DELETE FROM register.risk",
		"UPDATE register.risk_scenario SET run_id = NULL, control_set = NULL, pinned_version = NULL",
		"DELETE FROM register.risk_scenario",
		"UPDATE register.treatment SET decision = 'accept'",
		"UPDATE register.rollup SET state = 'failed', failure = 'x'",
		"DELETE FROM register.rollup",
		"TRUNCATE register.risk_version",
		"INSERT INTO register.risk_scenario (risk_id, scenario_id, bu_id, open) VALUES ('" + f.risk + "', '" + f.s2 + "', '" + f.ra.bu["A1"] + "', true)",
	} {
		err := f.ra.tx("owen", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), sql)
			return err
		})
		if code := pgCode(err); !strings.HasPrefix(code, "PF025 ") && !strings.HasPrefix(code, "42501 ") {
			t.Errorf("%s: %v", sql, code)
		}
	}
	if got := f.ra.adminQuery("SELECT title || '|' || state FROM register.risk WHERE id = '" + f.risk + "'"); got != "Claims ransomware|open" {
		t.Errorf("the head: %s", got)
	}
}

// T: loss counted twice, or a pin that does not stand for the scenario.
func TestSTRIDEF007Pins(t *testing.T) {
	f := strideF007Fixture(t)
	if got := f.ra.adminQuery("SELECT indexdef FROM pg_indexes WHERE schemaname = 'register' AND indexname = 'risk_scenario_open'"); !strings.Contains(got, "UNIQUE") || !strings.Contains(got, "WHERE open") {
		t.Errorf("the one-open-risk index: %s", got)
	}
	got := f.rg.call(t, "POST", "owen", "/api/v1/register/risks", map[string]any{"bu_id": f.ra.bu["A1"], "change_note": "x", "document": f.doc("Twice", f.s1, "")})
	if got.code != 409 || got.body["error"] != "scenario_linked" {
		t.Errorf("a scenario in two open risks: %d %s", got.code, got.raw)
	}
	small := runWith(t, f.ae, "analyst", f.s2, 1, 1000, "7")
	queued := runOf(t, f.ae, "analyst", f.s2, 2000, true)
	for name, c := range map[string]struct {
		run, set, want string
	}{
		"another scenario's run": {f.r1, "Current", "is not a run of this scenario"},
		"an unfinished run":      {queued, "Current", "is not a succeeded run"},
		"other iterations":       {small, "Current", "has 1000 iterations"},
		"not a set of the run":   {f.r2, "Elsewhere", "is not a control set of the run"},
	} {
		d := f.doc("Fraud", f.s2, c.run)
		d["scenarios"].([]any)[0].(map[string]any)["pin"].(map[string]any)["control_set"] = c.set
		got := f.rg.call(t, "POST", "owen", "/api/v1/register/risks", map[string]any{"bu_id": f.ra.bu["A1"], "change_note": "x", "document": d})
		if got.code != 422 || !strings.Contains(got.raw, c.want) {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	// The database checks them whoever writes: straight to the table.
	err := f.ra.tx("owen", func(tx pgx.Tx) error {
		ctx := context.Background()
		var id string
		if err := tx.QueryRow(ctx, "INSERT INTO register.risk (bu_id) VALUES ($1) RETURNING id::text", f.ra.bu["A1"]).Scan(&id); err != nil {
			return err
		}
		b, digest := registerDoc(t, f.doc("Direct", f.s2, f.r1))
		_, err := tx.Exec(ctx, "INSERT INTO register.risk_version (risk_id, version, document, digest, change_note) VALUES ($1, 1, $2, $3, 'x')", id, b, digest)
		return err
	})
	if !strings.HasPrefix(pgCode(err), "PF026 ") || !strings.Contains(pgCode(err), "is not a run of this scenario") {
		t.Errorf("a direct insert with another scenario's run: %v", pgCode(err))
	}
}

// R: a change cannot be attributed.
func TestRegisterAuditEvents(t *testing.T) {
	f := strideF007Fixture(t)
	ra, rg := f.ra, f.rg
	v := 1
	call := func(method, user, path string, body map[string]any) {
		t.Helper()
		got := rg.call(t, method, user, path, body)
		if got.code >= 300 {
			t.Fatalf("%s %s: %d %s", method, path, got.code, got.raw)
		}
	}
	base := "/api/v1/register/risks/" + f.risk
	call("PUT", "owen", base, map[string]any{"expected_version": v, "change_note": "both scenarios",
		"document": map[string]any{"schema_version": 1, "title": "Claims losses", "owner": f.owen, "state": "open",
			"scenarios": []any{map[string]any{"scenario_id": f.s1, "pin": map[string]any{"run_id": f.r1, "control_set": "Current"}}, map[string]any{"scenario_id": f.s2}}}})
	call("POST", "owen", base+"/close", map[string]any{"reason": "merged into another"})
	call("POST", "owen", base+"/reopen", map[string]any{"reason": "split out again"})
	call("POST", "owen", base+"/move", map[string]any{"to_bu_id": ra.bu["A"], "reason": "head office owns it"})
	f.treatment(t)
	call("POST", "owen", "/api/v1/register/rollups", map[string]any{"bu_id": ra.bu["A"]})
	call("POST", "chief", "/api/v1/register/categories", map[string]any{"name": "Supply chain"})
	types := []string{"register.risk_created", "register.risk_changed", "register.scenario_linked", "register.pin_set", "register.risk_closed",
		"register.risk_reopened", "register.risk_moved", "register.treatment_changed", "register.rollup_requested", "register.rollup_computed", "register.category_changed"}
	for _, typ := range types {
		got := ra.adminQuery("SELECT count(*) || '|' || count(*) FILTER (WHERE body ->> 'actor' IS NULL OR body ->> 'bu_id' IS NULL) FROM audit.intake WHERE body ->> 'type' = '" + typ + "'")
		if n, missing, _ := strings.Cut(got, "|"); n == "0" || missing != "0" {
			t.Errorf("%s: %s (events | without actor or BU)", typ, got)
		}
	}
	if got := ra.adminQuery("SELECT string_agg(body -> 'attributes' ->> 'reason', ',' ORDER BY body ->> 'type') FROM audit.intake WHERE body ->> 'type' IN ('register.risk_closed', 'register.risk_reopened', 'register.risk_moved')"); got != "merged into another,head office owns it,split out again" {
		t.Errorf("reasons: %s", got)
	}
	if got := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' LIKE 'register.%' AND body ->> 'actor' NOT IN ('" + f.owen + "', '" + f.chief + "', 'system:risk')"); got != "0" {
		t.Errorf("%s events attributed to someone else", got)
	}
	// Fail closed: without the trail the change is not made.
	api := &registerapi.API{DB: ra.appPool(), Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(ra.appPool())}), Audit: failingEmitter{}}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	defer srv.Close()
	broken := *rg
	broken.url = srv.URL
	before := ra.adminQuery("SELECT count(*) FROM register.risk")
	got := broken.call(t, "POST", "owen", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "change_note": "x", "document": f.doc("Unrecorded", "", "")})
	if got.code != 503 || ra.adminQuery("SELECT count(*) FROM register.risk") != before {
		t.Errorf("a change without its event: %d %s", got.code, got.raw)
	}
}

// D: roll-up floods.
func TestRegisterRollupLimits(t *testing.T) {
	f := strideF007Fixture(t)
	ra, rg := f.ra, f.rg
	f.create(t, "owen", ra.bu["A1"], "Claims fraud", f.s2, f.r2) // two members: a node, queued
	request := func(user, bu string) apiResp {
		t.Helper()
		return rg.call(t, "POST", user, "/api/v1/register/rollups", map[string]any{"bu_id": bu})
	}
	age := func() {
		ra.admin(ra.db, "SET ROLE register_definer; UPDATE register.rollup SET requested_at = requested_at - interval '2 minutes'")
	}
	first := request("owen", ra.bu["A1"])
	if first.code != 202 || first.body["state"] != "queued" || first.body["nodes"] != 1.0 {
		t.Fatalf("first: %d %s", first.code, first.raw)
	}
	age()
	if got := request("owen", ra.bu["A1"]); got.code != 409 || got.body["error"] != "rollup_running" {
		t.Errorf("one running per BU and requester: %d %s", got.code, got.raw)
	}
	if got := request("chief", ra.bu["A1"]); got.code != 202 || got.body["nodes"] != 0.0 {
		t.Errorf("another requester, the same node reused: %d %s", got.code, got.raw)
	}
	if got := request("analyst", ra.bu["A1"]); got.code != 429 || got.body["error"] != "rollup_rate" {
		t.Errorf("one request per BU per minute: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT register.rollup_node_max() || '|' || register.rollup_max_risks()"); got != "200|2000" {
		t.Errorf("the limits: %s", got)
	}
	ra.admin(ra.db, "CREATE OR REPLACE FUNCTION register.rollup_max_risks() RETURNS integer LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$")
	age()
	if got := request("analyst", ra.bu["A1"]); got.code != 409 || got.body["error"] != "rollup_too_large" {
		t.Errorf("too many risks: %d %s", got.code, got.raw)
	}
	// F-005's member limit holds under the register's nodes.
	if got := ra.adminState("SELECT analysis.request_aggregate('" + ra.bu["A1"] + "', 'x', 1, (SELECT jsonb_agg(jsonb_build_object('run_id', '" + f.r1 + "', 'control_set', 'Current')) FROM generate_series(1, 201)))"); got != "PF024" {
		t.Errorf("an aggregate of 201 members: %s", got)
	}
}

// E: a viewer edits risks, or a risk owner gains engine use beyond the register.
func TestSTRIDEF007Escalation(t *testing.T) {
	f := strideF007Fixture(t)
	ra, rg := f.ra, f.rg
	base := "/api/v1/register/risks/" + f.risk
	// The analyst holds register.view and treatment.view at A, not .edit.
	for _, c := range []struct {
		method, path string
		body         map[string]any
	}{
		{"POST", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "change_note": "x", "document": f.doc("x", "", "")}},
		{"PUT", base, map[string]any{"expected_version": 1, "change_note": "x", "document": f.doc("x", f.s1, f.r1)}},
		{"POST", base + "/close", map[string]any{"reason": "x"}},
		{"POST", base + "/move", map[string]any{"to_bu_id": ra.bu["A"], "reason": "x"}},
		{"POST", base + "/adopt", map[string]any{"expected_version": 1, "change_note": "x"}},
		{"PUT", base + "/treatment", map[string]any{"expected_version": 0, "change_note": "x", "document": map[string]any{"schema_version": 1, "decision": nil}}},
		{"POST", "/api/v1/register/categories", map[string]any{"name": "x"}},
	} {
		if got := rg.call(t, c.method, "analyst", c.path, c.body); got.code != 403 {
			t.Errorf("the analyst %s %s: %d %s", c.method, c.path, got.code, got.raw)
		}
	}
	// A risk owner (analysis.view) runs nothing on the engine but through the register.
	if got := f.ae.call(t, "POST", "owen", "/api/v1/analyses/aggregates", map[string]any{"bu_id": ra.bu["A1"], "name": "x",
		"members": []any{map[string]any{"run_id": f.r1, "control_set": "Current"}, map[string]any{"run_id": f.r2, "control_set": "Current"}}}); got.code != 403 && got.code != 404 {
		t.Errorf("owen requests an analysis aggregate: %d %s", got.code, got.raw)
	}
	for _, sql := range []string{
		"INSERT INTO analysis.aggregate (id, bu_id, name, seed, iterations, purpose) VALUES (gen_random_uuid(), '" + ra.bu["A1"] + "', 'x', 1, 2000, 'rollup')",
		"SELECT register.rollup_node('" + ra.bu["A1"] + "', 'x', 2000, '[]')",
		"SELECT register.rollup_group('" + ra.bu["A1"] + "', 'x', 2000, '[]')",
		"SELECT analysis.exposure_view('" + f.risk + "')",
	} {
		err := ra.tx("owen", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), sql)
			return err
		})
		if !strings.HasPrefix(pgCode(err), "42501 ") {
			t.Errorf("owen: %s: %v", sql, pgCode(err))
		}
	}
	// The register's own requests need register.edit at the risk's BU.
	err := ra.tx("analyst", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "SELECT register.request_exposure($1, 1)", f.risk)
		return err
	})
	if !strings.HasPrefix(pgCode(err), "P0002 ") {
		t.Errorf("the analyst requests an exposure: %v", pgCode(err))
	}
	// An exposure aggregates only results its requester sees: a pin to a
	// run the owner cannot see is refused.
	sb := scenarioAt(t, ra, "mallory", ra.bu["B"], "Branch outage")
	rb := runWith(t, f.ae, "mallory", sb, 1, 2000, "7")
	got := rg.call(t, "PUT", "owen", base, map[string]any{"expected_version": 1, "change_note": "x", "document": f.doc("x", f.s1, rb)})
	if got.code != 422 || !strings.Contains(got.raw, "is not a run of this scenario you can see") {
		t.Errorf("a pin of a run owen cannot see: %d %s", got.code, got.raw)
	}
}
