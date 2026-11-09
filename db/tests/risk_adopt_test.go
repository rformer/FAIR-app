package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-003 T-07 (AC-09, AC-10, AC-17): a newer library version changes nothing
// until adopted; pins say when one exists; versions are compared.
func TestRiskAdoptAndDiff(t *testing.T) {
	ra := newRiskAPI(t)
	ra.setCurrency(t, "USD")
	doc := ra.scenarioDoc(t)
	tcID := doc["threat_community"].(map[string]any)["id"].(string)
	ctlID := doc["control_sets"].([]any)[0].(map[string]any)["controls"].([]any)[0].(map[string]any)["id"].(string)
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	pins := func(user string) map[string]map[string]any {
		t.Helper()
		got := ra.call(t, "GET", user, "/api/v1/scenarios/"+id, nil)
		if got.code != 200 {
			t.Fatalf("read: %d %s", got.code, got.raw)
		}
		out := map[string]map[string]any{}
		for _, p := range got.body["pins"].([]any) {
			m := p.(map[string]any)
			out[m["pointer"].(string)] = m
		}
		return out
	}
	if p := pins("erin"); p["/threat_community"]["newer"] != false || p["/threat_community"]["current_version"] != float64(1) {
		t.Fatalf("fresh pins: %v", p)
	}

	// New library and control versions leave the scenario as it was (AC-09)
	// and flag its pins (AC-10).
	tc2 := modeltest.Set(modeltest.ThreatCommunity(), "/name", "Organised crime")
	if got := ra.call(t, "PUT", "analyst", "/api/v1/library/"+tcID, map[string]any{"document": tc2, "expected_version": 1, "change_note": "Renamed"}); got.code != 200 {
		t.Fatalf("new threat community version: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/controls/"+ctlID, map[string]any{"document": modeltest.Set(modeltest.Control(), "/name", "EDR, tuned"), "expected_version": 1, "change_note": "Tuned"}); got.code != 200 {
		t.Fatalf("new control version: %d %s", got.code, got.raw)
	}
	p := pins("erin")
	if p["/threat_community"]["newer"] != true || p["/threat_community"]["current_version"] != float64(2) || p["/threat_community"]["version"] != float64(1) ||
		p["/control_sets/0/controls/0"]["newer"] != true || p["/asset"]["newer"] != false {
		t.Fatalf("flags: %v", p)
	}
	if v := ra.call(t, "GET", "erin", "/api/v1/scenarios/"+id, nil).body["scenario"].(map[string]any)["current_version"]; v != float64(1) {
		t.Fatalf("the scenario changed: version %v", v)
	}
	// A reader of scenarios only cannot see the entries: no current version.
	ra.mustOwner(`WITH ro AS (INSERT INTO iam.role (name) VALUES ('Scenario Reader') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['scenario.view'], 'test' FROM ro`)
	ra.mustOwner(grant("platform", "user:buadmin2", "Scenario Reader", "A1"))
	ra.drain()
	if p := pins("buadmin2"); p["/threat_community"]["current_version"] != nil || p["/threat_community"]["newer"] != false {
		t.Fatalf("scenario reader's pins: %v", p)
	}

	// Adopt one pin, then the rest.
	adopt := func(user string, body map[string]any) apiResp {
		t.Helper()
		return ra.call(t, "POST", user, "/api/v1/scenarios/"+id+"/adopt", body)
	}
	if got := adopt("erin", map[string]any{"expected_version": 1, "pins": []string{"/threat_community"}, "change_note": "x"}); got.code != 403 {
		t.Fatalf("viewer adopts: %d", got.code)
	}
	if got := adopt("analyst", map[string]any{"expected_version": 1, "pins": []string{"/asset"}, "change_note": "x"}); got.code != 409 {
		t.Fatalf("a pin without a newer version: %d %s", got.code, got.raw)
	}
	if got := adopt("analyst", map[string]any{"pins": []string{"/threat_community"}, "change_note": "x"}); got.code != 400 {
		t.Fatalf("no expected_version: %d", got.code)
	}
	got = adopt("analyst", map[string]any{"expected_version": 1, "pins": []string{"/threat_community"}, "change_note": "Adopt the renamed community"})
	if got.code != 200 || got.body["version"] != float64(2) || strings.Join(toStrings(got.body["adopted"]), ",") != "/threat_community" {
		t.Fatalf("adopt one: %d %s", got.code, got.raw)
	}
	if got := adopt("analyst", map[string]any{"expected_version": 1, "change_note": "x"}); got.code != 409 || got.body["error"] != "stale_version" {
		t.Fatalf("stale adopt: %d %s", got.code, got.raw)
	}
	if p := pins("erin"); p["/threat_community"]["newer"] != false || p["/threat_community"]["version"] != float64(2) || p["/control_sets/0/controls/0"]["newer"] != true {
		t.Fatalf("after adopting one: %v", p)
	}
	got = adopt("analyst", map[string]any{"expected_version": 2, "change_note": "Adopt the rest"})
	if got.code != 200 || strings.Join(toStrings(got.body["adopted"]), ",") != "/control_sets/0/controls/0" {
		t.Fatalf("adopt the rest: %d %s", got.code, got.raw)
	}
	if got := adopt("analyst", map[string]any{"expected_version": 3, "change_note": "x"}); got.code != 409 || got.body["error"] != "not_applicable" {
		t.Fatalf("nothing to adopt: %d %s", got.code, got.raw)
	}
	if ev := ra.adminQuery(`SELECT string_agg((body -> 'attributes' ->> 'version') || '=' || coalesce(body -> 'attributes' ->> 'adopted', '-'), ',' ORDER BY id)
		FROM audit.intake WHERE body ->> 'type' = 'scenario.version_saved'`); ev != "2=/threat_community,3=/control_sets/0/controls/0" {
		t.Fatalf("events: %s", ev)
	}

	// Diffs (AC-17).
	got = ra.call(t, "GET", "erin", "/api/v1/scenarios/"+id+"/diff?from=1&to=3", nil)
	if got.code != 200 {
		t.Fatalf("diff: %d %s", got.code, got.raw)
	}
	changes, pinChanges := map[string]string{}, map[string]string{}
	for _, c := range got.body["changes"].([]any) {
		m := c.(map[string]any)
		changes[m["pointer"].(string)] = m["op"].(string)
	}
	for _, c := range got.body["pins"].([]any) {
		m := c.(map[string]any)
		pinChanges[m["pointer"].(string)] = strings.Join([]string{toString(m["from_version"]), toString(m["to_version"])}, ">")
	}
	if len(changes) != 2 || changes["/threat_community/version"] != "changed" || changes["/control_sets/0/controls/0/version"] != "changed" {
		t.Fatalf("changes: %v", changes)
	}
	if len(pinChanges) != 2 || pinChanges["/threat_community"] != "1>2" || pinChanges["/control_sets/0/controls/0"] != "1>2" {
		t.Fatalf("pin changes: %v", pinChanges)
	}
	got = ra.call(t, "GET", "erin", "/api/v1/library/"+tcID+"/diff?from=1&to=2", nil)
	if got.code != 200 || !strings.Contains(got.raw, `"pointer":"/name","op":"changed","from":"Cyber criminals","to":"Organised crime"`) {
		t.Fatalf("library diff: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "GET", "erin", "/api/v1/controls/"+ctlID+"/diff?from=1&to=2", nil); got.code != 200 {
		t.Fatalf("control diff: %d", got.code)
	}
	for q, code := range map[string]int{"?from=1": 400, "?from=x&to=2": 400, "?from=1&to=9": 404} {
		if got := ra.call(t, "GET", "erin", "/api/v1/scenarios/"+id+"/diff"+q, nil); got.code != code {
			t.Errorf("diff %s: %d, want %d", q, got.code, code)
		}
	}
	if got := ra.call(t, "GET", "mallory", "/api/v1/scenarios/"+id+"/diff?from=1&to=2", nil); got.code != 404 {
		t.Fatalf("outsider's diff: %d", got.code)
	}
}

func toStrings(v any) []string {
	var out []string
	a, _ := v.([]any)
	for _, x := range a {
		out = append(out, toString(x))
	}
	return out
}

func toString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v) // float64(1) prints as 1
}
