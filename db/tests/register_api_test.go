package tests

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/registerapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-007 T-04 (F-007-AC-01 to AC-05, AC-19, AC-21, AC-22; design §6, §8):
// the register API for risks and categories.

var registerEnvs int

// registerAPI serves the register API on the risk env's keys.
func registerAPI(t *testing.T, ra *riskAPIEnv) *riskAPIEnv {
	t.Helper()
	pool := ra.appPool()
	// Exposure aggregates are queued by an insert-only River client and
	// worked by the tests (analysisEnv.aggregates).
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: analysis.RiverSchema})
	if err != nil {
		t.Fatal(err)
	}
	api := &registerapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool}), EnqueueAggregate: analysis.AggregateEnqueuer(rc)}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	rg := *ra
	rg.url = srv.URL
	registerEnvs++
	rg.n += 400000 + 100000*registerEnvs // its Idempotency-Keys never meet another env's
	return &rg
}

// registerUsers adds owen (Risk Owner at A), chief (Risk Owner at the
// root) and est (an Estimator at A: no register permission).
func registerUsers(ra *riskAPIEnv) {
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('owen@example.test', 'Owen'), ('chief@example.test', 'Chief'), ('est@example.test', 'Est')")
	ra.mustOwner(grant("platform", "user:owen", "Risk Owner", "A"))
	ra.mustOwner(grant("platform", "user:chief", "Risk Owner", "ENTERPRISE"))
	ra.mustOwner(grant("platform", "user:est", "Estimator", "A"))
	ra.drain()
}

func registerEvents(ra *riskAPIEnv, risk, typ string) string {
	return ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '" + typ + "' AND body ->> 'target' = 'register_risk:" + risk + "'")
}

func TestRegisterRisksAPI(t *testing.T) {
	ra := strideF003Fixture(t) // analyst a Risk Analyst at A, mallory at B, erin a Risk Owner at A1
	registerUsers(ra)
	seedPosture(t, ra.env)
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	rg := registerAPI(t, ra)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	s2 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims fraud")
	r1 := runWith(t, ae, "analyst", s1, 1, 100_000, "7")
	erin := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'erin@example.test'")
	mallory := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'mallory@example.test'")
	cyber := ra.adminQuery("SELECT id FROM register.category WHERE name = 'Cyber'")
	doc := map[string]any{"schema_version": 1, "title": "Ransomware on claims", "owner": erin, "category": cyber, "state": "open",
		"scenarios": []any{map[string]any{"scenario_id": s1, "pin": map[string]any{"run_id": r1, "control_set": "Current"}}}}
	create := func(user, bu string, d map[string]any) apiResp {
		t.Helper()
		return rg.call(t, "POST", user, "/api/v1/register/risks", map[string]any{"bu_id": bu, "document": d, "change_note": "First assessment"})
	}

	// Create, read, and who may (AC-01, AC-21).
	got := create("erin", ra.bu["A1"], doc)
	if got.code != 201 || got.body["version"] != 1.0 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	risk := got.body["id"].(string)
	read := rg.call(t, "GET", "analyst", "/api/v1/register/risks/"+risk, nil)
	links, _ := read.body["links"].([]any)
	if read.code != 200 || read.body["risk"].(map[string]any)["title"] != "Ransomware on claims" || len(links) != 1 ||
		links[0].(map[string]any)["pin"].(map[string]any)["run_id"] != r1 || read.body["risk"].(map[string]any)["category"].(map[string]any)["name"] != "Cyber" {
		t.Fatalf("read: %d %s", read.code, read.raw)
	}
	for name, c := range map[string]struct {
		user, bu string
		code     int
	}{
		"a viewer creates":   {"analyst", ra.bu["A1"], 403},
		"outside their BUs":  {"erin", ra.bu["B"], 404},
		"no register at all": {"est", ra.bu["A"], 404},
	} {
		if got := create(c.user, c.bu, with(doc, "scenarios", []any{})); got.code != c.code {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	if got := rg.call(t, "GET", "mallory", "/api/v1/register/risks/"+risk, nil); got.code != 404 {
		t.Errorf("mallory reads: %d", got.code)
	}
	if got := rg.call(t, "GET", "est", "/api/v1/register/risks/"+risk, nil); got.code != 404 {
		t.Errorf("est reads: %d", got.code)
	}

	// Problems: the service's (structure) and the database's (references).
	problems := func(got apiResp) string {
		var out []string
		for _, p := range got.body["problems"].([]any) {
			out = append(out, p.(map[string]any)["pointer"].(string))
		}
		return strings.Join(out, ",")
	}
	if got := create("erin", ra.bu["A1"], with(doc, "colour", "red", "scenarios", []any{})); got.code != 422 || problems(got) != "/colour" {
		t.Errorf("an unknown field: %d %s", got.code, got.raw)
	}
	if got := create("erin", ra.bu["A1"], with(doc, "owner", mallory, "scenarios", []any{})); got.code != 422 || problems(got) != "/owner" {
		t.Errorf("an owner who cannot see it: %d %s", got.code, got.raw)
	}
	if got := create("erin", ra.bu["A1"], with(doc, "state", "closed", "close_reason", "x", "scenarios", []any{})); got.code != 422 || problems(got) != "/state" {
		t.Errorf("created closed: %d %s", got.code, got.raw)
	}
	// One open risk per scenario (AC-02).
	if got := create("erin", ra.bu["A1"], with(doc, "title", "Another")); got.code != 409 || got.body["error"] != "scenario_linked" {
		t.Errorf("a linked scenario: %d %s", got.code, got.raw)
	}

	// Saving (AC-02, AC-03): versions, stale ones, links.
	save := func(user string, expected int, d map[string]any) apiResp {
		t.Helper()
		return rg.call(t, "PUT", user, "/api/v1/register/risks/"+risk, map[string]any{"document": d, "expected_version": expected, "change_note": "Reviewed"})
	}
	v2 := with(doc, "title", "Ransomware on the claims platform", "scenarios", []any{doc["scenarios"].([]any)[0], map[string]any{"scenario_id": s2}})
	if got := save("erin", 1, v2); got.code != 200 || got.body["version"] != 2.0 {
		t.Fatalf("save: %d %s", got.code, got.raw)
	}
	if got := save("erin", 1, v2); got.code != 409 || got.body["error"] != "stale_version" {
		t.Errorf("a stale save: %d %s", got.code, got.raw)
	}
	if got := save("analyst", 2, v2); got.code != 403 {
		t.Errorf("a viewer saves: %d", got.code)
	}
	if got := save("erin", 2, with(v2, "state", "closed", "close_reason", "x")); got.code != 422 {
		t.Errorf("closing through save: %d %s", got.code, got.raw)
	}
	if got := save("erin", 2, with(v2, "scenarios", []any{map[string]any{"scenario_id": s2}})); got.code != 200 {
		t.Fatalf("unlinking: %d %s", got.code, got.raw)
	}
	for typ, want := range map[string]string{"register.risk_created": "1", "register.risk_changed": "2", "register.scenario_linked": "2", "register.scenario_unlinked": "1"} {
		if n := registerEvents(ra, risk, typ); n != want {
			t.Errorf("%s events: %s, want %s", typ, n, want)
		}
	}

	// Versions and differences (AC-03).
	got = rg.call(t, "GET", "analyst", "/api/v1/register/risks/"+risk+"/versions", nil)
	if vs, _ := got.body["versions"].([]any); got.code != 200 || len(vs) != 3 || vs[0].(map[string]any)["version"] != 3.0 {
		t.Errorf("versions: %d %s", got.code, got.raw)
	}
	got = rg.call(t, "GET", "analyst", fmt.Sprintf("/api/v1/register/risks/%s/diff?from=1&to=2", risk), nil)
	var pointers []string
	for _, c := range got.body["changes"].([]any) {
		pointers = append(pointers, c.(map[string]any)["pointer"].(string)+":"+c.(map[string]any)["kind"].(string))
	}
	if got.code != 200 || !slices.Contains(pointers, "/title:changed") || !slices.Contains(pointers, "/scenarios/1:added") {
		t.Errorf("diff: %d %v", got.code, pointers)
	}

	// Closing and reopening (AC-04).
	if got := rg.call(t, "POST", "erin", "/api/v1/register/risks/"+risk+"/close", map[string]any{"reason": "Merged into the group register"}); got.code != 200 {
		t.Fatalf("close: %d %s", got.code, got.raw)
	}
	if got := rg.call(t, "POST", "erin", "/api/v1/register/risks/"+risk+"/close", map[string]any{"reason": "again"}); got.code != 409 || got.body["error"] != "same_state" {
		t.Errorf("closing a closed risk: %d %s", got.code, got.raw)
	}
	if got := save("erin", 4, v2); got.code != 409 || got.body["error"] != "closed" {
		t.Errorf("saving a closed risk: %d %s", got.code, got.raw)
	}
	if got := rg.call(t, "POST", "erin", "/api/v1/register/risks/"+risk+"/reopen", map[string]any{"reason": ""}); got.code != 400 {
		t.Errorf("reopening without a reason: %d", got.code)
	}
	if got := rg.call(t, "POST", "erin", "/api/v1/register/risks/"+risk+"/reopen", map[string]any{"reason": "Back in our hands"}); got.code != 200 || got.body["version"] != 5.0 {
		t.Fatalf("reopen: %d %s", got.code, got.raw)
	}
	if n := registerEvents(ra, risk, "register.risk_closed") + registerEvents(ra, risk, "register.risk_reopened"); n != "11" {
		t.Errorf("close and reopen events: %s", n)
	}
	if d := ra.adminQuery("SELECT convert_from(document, 'UTF8')::jsonb - 'state' - 'close_reason' = (SELECT convert_from(document, 'UTF8')::jsonb - 'state' FROM register.risk_version WHERE risk_id = '" + risk + "' AND version = 3) FROM register.risk_version WHERE risk_id = '" + risk + "' AND version = 4"); d != "t" {
		t.Errorf("closing changed something else")
	}

	// Moving (AC-05).
	move := func(user, to string) apiResp {
		t.Helper()
		return rg.call(t, "POST", user, "/api/v1/register/risks/"+risk+"/move", map[string]any{"to_bu_id": to, "reason": "Reorganization"})
	}
	if got := move("erin", ra.bu["A"]); got.code != 403 {
		t.Errorf("erin moves to A (a viewer there): %d %s", got.code, got.raw)
	}
	if got := move("erin", ra.bu["B"]); got.code != 404 {
		t.Errorf("erin moves to B (nothing there): %d %s", got.code, got.raw)
	}
	if got := move("owen", ra.bu["A"]); got.code != 200 {
		t.Fatalf("owen moves to A: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT (SELECT bu_id FROM register.risk WHERE id = '" + risk + "') = '" + ra.bu["A"] + "' AND NOT EXISTS (SELECT 1 FROM register.risk_version WHERE risk_id = '" + risk + "' AND bu_id <> '" + ra.bu["A"] + "') AND NOT EXISTS (SELECT 1 FROM register.risk_scenario WHERE risk_id = '" + risk + "' AND bu_id <> '" + ra.bu["A"] + "')"); got != "t" {
		t.Error("the move left something behind")
	}
	if got := move("owen", ra.bu["A"]); got.code != 409 || got.body["error"] != "same_bu" {
		t.Errorf("moving to the same BU: %d %s", got.code, got.raw)
	}
	if got := move("chief", ra.bu["B"]); got.code != 409 || got.body["error"] != "scenario_outside" {
		t.Errorf("a scenario left behind: %d %s", got.code, got.raw)
	}
	if n := registerEvents(ra, risk, "register.risk_moved"); n != "1" {
		t.Errorf("moved events: %s", n)
	}

	// Listing (AC-19).
	other := create("owen", ra.bu["A"], with(doc, "title", "Accounts payable fraud", "owner", ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'owen@example.test'"), "scenarios", []any{}))
	if other.code != 201 {
		t.Fatalf("another risk: %d %s", other.code, other.raw)
	}
	list := func(user, q string) []string {
		t.Helper()
		got := rg.call(t, "GET", user, "/api/v1/register/risks"+q, nil)
		if got.code != 200 {
			t.Fatalf("list %s: %d %s", q, got.code, got.raw)
		}
		var out []string
		for _, x := range got.body["risks"].([]any) {
			out = append(out, x.(map[string]any)["title"].(string))
		}
		return out
	}
	if got := list("analyst", "?sort=title"); !slices.Equal(got, []string{"Accounts payable fraud", "Ransomware on the claims platform"}) {
		t.Errorf("by title: %v", got)
	}
	if got := list("analyst", "?owner="+erin); !slices.Equal(got, []string{"Ransomware on the claims platform"}) {
		t.Errorf("by owner: %v", got)
	}
	if got := list("analyst", "?bu="+ra.bu["A1"]); len(got) != 0 {
		t.Errorf("A1's subtree after the move: %v", got)
	}
	if got := list("analyst", "?state=closed"); len(got) != 0 {
		t.Errorf("closed: %v", got)
	}
	if got := list("mallory", ""); len(got) != 0 {
		t.Errorf("mallory lists: %v", got)
	}
	if got := rg.call(t, "GET", "analyst", "/api/v1/register/risks?limit=1", nil); got.body["more"] != true {
		t.Errorf("paging: %s", got.raw)
	}

	// Categories (OQ3).
	cats := func() map[string]any {
		got := rg.call(t, "GET", "analyst", "/api/v1/register/categories", nil)
		out := map[string]any{}
		for _, c := range got.body["categories"].([]any) {
			out[c.(map[string]any)["name"].(string)] = c.(map[string]any)["archived_at"]
		}
		return out
	}
	if len(cats()) != 7 {
		t.Errorf("default categories: %v", cats())
	}
	if got := rg.call(t, "POST", "erin", "/api/v1/register/categories", map[string]any{"name": "Climate"}); got.code != 403 {
		t.Errorf("not at the root: %d %s", got.code, got.raw)
	}
	got = rg.call(t, "POST", "chief", "/api/v1/register/categories", map[string]any{"name": "Climate"})
	if got.code != 201 {
		t.Fatalf("add: %d %s", got.code, got.raw)
	}
	climate := got.body["id"].(string)
	if got := rg.call(t, "POST", "chief", "/api/v1/register/categories", map[string]any{"name": "climate"}); got.code != 409 {
		t.Errorf("a duplicate: %d %s", got.code, got.raw)
	}
	if got := rg.call(t, "PATCH", "chief", "/api/v1/register/categories/"+climate, map[string]any{"name": "Climate and weather"}); got.code != 200 {
		t.Errorf("rename: %d %s", got.code, got.raw)
	}
	if got := rg.call(t, "PATCH", "chief", "/api/v1/register/categories/"+climate, map[string]any{"archived": true}); got.code != 200 || cats()["Climate and weather"] == nil {
		t.Errorf("archive: %d %s", got.code, got.raw)
	}
	if got := create("owen", ra.bu["A"], with(doc, "title", "Flooding", "owner", ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'owen@example.test'"), "category", climate, "scenarios", []any{})); got.code != 422 || problems(got) != "/category" {
		t.Errorf("an archived category: %d %s", got.code, got.raw)
	}
	if n := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'register.category_changed' AND body ->> 'target' = 'register_category:" + climate + "'"); n != "3" {
		t.Errorf("category events: %s", n)
	}
}

// The service's structural checks and the database's agree, problem for
// problem (design §3.1), over a corpus of documents broken one way each.
func TestRegisterValidationParity(t *testing.T) {
	ra := strideF003Fixture(t)
	erin := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'erin@example.test'")
	base := map[string]any{"schema_version": 1, "title": "Ransomware", "owner": erin, "state": "open", "scenarios": []any{}}
	many := make([]any, 201)
	for i := range many {
		many[i] = map[string]any{"scenario_id": "x"}
	}
	corpus := map[string]any{
		"valid":                    base,
		"not an object":            []any{},
		"an unknown field":         with(base, "colour", "red"),
		"schema version 2":         with(base, "schema_version", 2),
		"no title":                 with(base, "title", nil),
		"a long title":             with(base, "title", strings.Repeat("x", 201)),
		"a numeric title":          with(base, "title", 5),
		"an empty description":     with(base, "description", " "),
		"an owner that is no id":   with(base, "owner", "x"),
		"a category that is no id": with(base, "category", "x"),
		"an unknown state":         with(base, "state", "x"),
		"closed without reason":    with(base, "state", "closed"),
		"a reason while open":      with(base, "close_reason", "x"),
		"scenarios not a list":     with(base, "scenarios", "x"),
		"a scenario not an object": with(base, "scenarios", []any{"x"}),
		"a scenario id no id":      with(base, "scenarios", []any{map[string]any{"scenario_id": "x"}}),
		"a scenario's unknown key": with(base, "scenarios", []any{map[string]any{"scenario_id": "x", "weight": 1}}),
		"too many scenarios":       with(base, "scenarios", many),
	}
	for name, doc := range corpus {
		raw, _ := json.Marshal(doc)
		_, _, problems := register.Validate(raw)
		var goSide []string
		for _, p := range problems {
			goSide = append(goSide, p.Pointer+": "+p.Message)
		}
		dbSide := []string{}
		if s := ra.adminQuery("SELECT array_to_string(register.check_risk($$" + strings.ReplaceAll(string(raw), "$", "") + "$$::jsonb, '" + ra.bu["A1"] + "', NULL), E'\\n')"); s != "" {
			dbSide = strings.Split(s, "\n")
		}
		slices.Sort(goSide)
		slices.Sort(dbSide)
		if goSide == nil {
			goSide = []string{}
		}
		if !slices.Equal(goSide, dbSide) {
			t.Errorf("%s:\n go %q\n db %q", name, goSide, dbSide)
		}
	}
}
