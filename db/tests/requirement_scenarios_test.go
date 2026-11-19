package tests

import (
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-013 T-09 (F-013-AC-16 to AC-18; design §3.6): from a requirement to
// the controls mapped to it and the scenarios that use them or could; a
// proposed scenario version adding a control, never saved by itself; the
// requirements a register risk's scenarios address.
func TestRequirementScenarios(t *testing.T) {
	fe := frameworkAPI(t)
	ra := fe.risk
	ra.setCurrency(t, "USD")
	ra.mustOwner(grant("platform", "user:buadmin", "BU Admin", "A")) // no scenario or control permission
	registerUsers(ra)                                                // owen: Risk Owner at A
	seedPosture(t, ra.env)
	fe.drain()

	ac2 := ra.adminQuery("SELECT r.id FROM framework.requirement r JOIN framework.version v ON v.id = r.version_id WHERE v.family = 'nist-800-53' AND v.label = '5.2.0' AND r.identifier = 'ac-2'")
	ctl := func(user, bu, name, strength string) string {
		t.Helper()
		d := modeltest.Control()
		d["name"] = name
		d["mappings"] = []any{mapping("nist-800-53", "5.2.0", "ac-2", strength)}
		got := ra.call(t, "POST", user, "/api/v1/controls", map[string]any{"bu_id": ra.bu[bu], "document": d, "change_note": "x"})
		if got.code != 201 {
			t.Fatalf("%s: %d %s", name, got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	reviews := ctl("analyst", "A", "Access reviews", "full")
	ctl("analyst", "A1", "Provisioning", "partial")
	hidden := ctl("mallory", "B", "B's access control", "full")
	other := ra.create(t, "analyst", "control", ra.bu["A"], modeltest.Control()) // maps nothing

	asset := modeltest.Asset()
	delete(asset, "value")
	asset["value_basis"] = "Replacement cost."
	a := ra.create(t, "analyst", "asset", ra.bu["A"], asset)
	tc := ra.create(t, "analyst", "threat_community", ra.bu["A"], modeltest.ThreatCommunity())
	use := func(id string) map[string]any { return map[string]any{"id": id, "version": 1, "status": "in_place"} }
	scenario := func(user, bu, name string, sets ...any) string {
		t.Helper()
		d := modeltest.Scenario()
		d["name"] = name
		d["owner"] = ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + user + "@example.test'")
		d["asset"] = map[string]any{"kind": "asset", "id": a, "version": 1}
		d["threat_community"] = map[string]any{"id": tc, "version": 1}
		d["control_sets"] = sets
		got := ra.call(t, "POST", user, "/api/v1/scenarios", map[string]any{"bu_id": ra.bu[bu], "document": d, "change_note": "v1"})
		if got.code != 201 {
			t.Fatalf("%s: %d %s", name, got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	set := func(name string, current bool, uses ...any) map[string]any {
		return map[string]any{"name": name, "current": current, "controls": uses}
	}
	s1 := scenario("analyst", "A1", "Uses reviews", set("Current", true, use(reviews)))
	s2 := scenario("analyst", "A1", "Only proposes reviews", set("Current", true, use(other)), set("Proposed", false, use(reviews)))
	scenario("analyst", "A", "Plain", set("Current", true, use(other)))

	// AC-16: the analyst's view.
	got := fe.call(t, "GET", "analyst", "/api/v1/frameworks/requirements/"+ac2+"/scenarios", nil)
	if got.code != 200 {
		t.Fatalf("scenarios: %d %s", got.code, got.raw)
	}
	names := func(key string) string {
		var out []string
		for _, x := range got.body[key].([]any) {
			out = append(out, x.(map[string]any)["name"].(string))
		}
		return strings.Join(out, ", ")
	}
	if n := names("controls"); n != "Access reviews, Provisioning" {
		t.Errorf("controls: %s", n)
	}
	if !strings.Contains(got.raw, `"factor":"resistance_strength"`) {
		t.Error("the controls' FAIR effects are missing")
	}
	if n := names("uses"); n != "Uses reviews" {
		t.Errorf("uses: %s", n)
	}
	if n := names("could_use"); n != "Only proposes reviews, Plain" {
		t.Errorf("could use: %s", n)
	}
	if strings.Contains(got.raw, hidden) {
		t.Error("B's control is listed for A's analyst")
	}
	got = fe.call(t, "GET", "analyst", "/api/v1/frameworks/requirements/"+ac2+"/scenarios?limit=1", nil)
	if got.body["could_use_more"] != true || got.body["uses_more"] != false || len(got.body["could_use"].([]any)) != 1 {
		t.Errorf("limit: %s", got.raw)
	}
	for user, code := range map[string]int{"buadmin": 404, "erin": 200} {
		if got := fe.call(t, "GET", user, "/api/v1/frameworks/requirements/"+ac2+"/scenarios", nil); got.code != code {
			t.Errorf("%s: %d %s", user, got.code, got.raw)
		}
	}
	if got := fe.call(t, "GET", "mallory", "/api/v1/frameworks/requirements/"+ac2+"/scenarios", nil); got.code != 200 ||
		strings.Contains(got.raw, "Access reviews") || !strings.Contains(got.raw, "B's access control") {
		t.Errorf("mallory: %d %s", got.code, got.raw)
	}

	// AC-17: a proposal, never saved by itself.
	prop := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+s2+"/proposed?add_control="+reviews, nil)
	if prop.code != 200 || prop.body["set"] != "With Access reviews" || prop.body["copied_from"] != "Current" || prop.body["base_version"] != float64(1) {
		t.Fatalf("proposed: %d %s", prop.code, prop.raw)
	}
	sets := prop.body["document"].(map[string]any)["control_sets"].([]any)
	last := sets[len(sets)-1].(map[string]any)
	if len(sets) != 3 || last["current"] != false || len(last["controls"].([]any)) != 2 ||
		last["controls"].([]any)[1].(map[string]any)["status"] != "proposed" {
		t.Errorf("proposed sets: %v", sets)
	}
	if v := ra.adminQuery("SELECT current_version FROM risk.scenario WHERE id = '" + s2 + "'"); v != "1" {
		t.Errorf("the proposal saved version %s", v)
	}
	// The analyst saves it as F-003's save.
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+s2, map[string]any{"document": prop.body["document"], "expected_version": 1,
		"change_note": "Add access reviews"}); got.code != 200 {
		t.Errorf("save the proposal: %d %s", got.code, got.raw)
	}
	for name, c := range map[string]struct {
		user, path string
		code       int
	}{
		"already used":      {"analyst", s1 + "/proposed?add_control=" + reviews, 409},
		"an unknown set":    {"analyst", s1 + "/proposed?add_control=" + reviews + "&set=Nope", 422},
		"an unseen control": {"analyst", s1 + "/proposed?add_control=" + hidden, 422},
		"no control":        {"analyst", s1 + "/proposed", 400},
		"a viewer":          {"erin", s1 + "/proposed?add_control=" + reviews, 403},
		"another BU":        {"mallory", s1 + "/proposed?add_control=" + reviews, 404},
	} {
		if got := ra.call(t, "GET", c.user, "/api/v1/scenarios/"+c.path, nil); got.code != c.code {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}

	// AC-18: a register risk shows the requirements its scenarios' current
	// controls address.
	rg := registerAPI(t, ra)
	owen := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'owen@example.test'")
	got = rg.call(t, "POST", "owen", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A"], "change_note": "x",
		"document": map[string]any{"schema_version": 1, "title": "Account misuse", "owner": owen, "state": "open",
			"scenarios": []any{map[string]any{"scenario_id": s1}}}})
	if got.code != 201 {
		t.Fatalf("risk: %d %s", got.code, got.raw)
	}
	risk := rg.call(t, "GET", "owen", "/api/v1/register/risks/"+got.body["id"].(string), nil)
	reqs := mustJSON(risk.body["risk"].(map[string]any)["requirements"])
	if risk.code != 200 || !strings.Contains(reqs, `"label":"5.2.0"`) || !strings.Contains(reqs, `"identifier":"ac-2"`) || !strings.Contains(reqs, "Access reviews") {
		t.Errorf("risk requirements: %d %s", risk.code, reqs)
	}
}
