package tests

import (
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-003 T-09 (AC-19, AC-20, AC-22): moving scenarios, archiving and
// restoring, and the archive guard.
func TestRiskMoveAndArchive(t *testing.T) {
	ra := newRiskAPI(t)
	ra.setCurrency(t, "USD")
	doc := ra.scenarioDoc(t) // library and control at A
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	digest := got.body["digest"].(string)
	move := func(user, to string, reason ...string) apiResp {
		t.Helper()
		r := "Reorganisation"
		if len(reason) > 0 {
			r = reason[0]
		}
		return ra.call(t, "POST", user, "/api/v1/scenarios/"+id+"/move", map[string]any{"to_bu_id": to, "reason": r})
	}
	reachable := func(user string) map[string]any {
		t.Helper()
		got := ra.call(t, "GET", user, "/api/v1/scenarios/"+id, nil)
		if got.code != 200 {
			t.Fatalf("read as %s: %d %s", user, got.code, got.raw)
		}
		out := map[string]any{}
		for _, p := range got.body["pins"].([]any) {
			m := p.(map[string]any)
			out[m["pointer"].(string)] = m["reachable"]
		}
		return out
	}
	if r := reachable("analyst"); r["/asset"] != true || r["/threat_community"] != true {
		t.Fatalf("before the move: %v", r)
	}

	// Edit is needed at both BUs: analyst cannot see B yet (404); erin can
	// view A1 but not edit (403).
	if got := move("analyst", ra.bu["B"]); got.code != 404 {
		t.Fatalf("to an unseen BU: %d %s", got.code, got.raw)
	}
	if got := move("erin", ra.bu["A"]); got.code != 403 {
		t.Fatalf("a viewer moves: %d", got.code)
	}
	if got := move("analyst", ra.bu["A"], ""); got.code != 400 {
		t.Fatalf("no reason: %d", got.code)
	}
	if got := move("analyst", ra.bu["A1"]); got.code != 409 {
		t.Fatalf("to its own BU: %d %s", got.code, got.raw)
	}
	ra.mustOwner(grant("platform", "user:analyst", "Risk Analyst", "B"))
	ra.drain()
	got = move("analyst", ra.bu["B"])
	if got.code != 200 || got.body["bu_id"] != ra.bu["B"] || got.body["from_bu_id"] != ra.bu["A1"] {
		t.Fatalf("move: %d %s", got.code, got.raw)
	}
	// Versions and pins followed; documents and digests did not change.
	if got := ra.adminQuery(`SELECT (SELECT count(DISTINCT bu_id) || ':' || min(bu_id::text) FROM risk.scenario_version WHERE scenario_id = '` + id + `') || '|' ||
		(SELECT count(DISTINCT bu_id) || ':' || min(bu_id::text) FROM risk.scenario_pin WHERE scenario_id = '` + id + `') || '|' ||
		(SELECT digest FROM risk.scenario_version WHERE scenario_id = '` + id + `' AND version = 1)`); got != "1:"+ra.bu["B"]+"|1:"+ra.bu["B"]+"|"+digest {
		t.Fatalf("after the move: %s", got)
	}
	// From B the library at A is not read: the pins are flagged (AC-20); the
	// scenario keeps its copies, and its bundle works.
	if r := reachable("mallory"); r["/asset"] != false || r["/threat_community"] != false || r["/control_sets/0/controls/0"] != false {
		t.Fatalf("flags after the move: %v", r)
	}
	if got := ra.call(t, "GET", "mallory", "/api/v1/scenarios/"+id+"/versions/1/bundle", nil); got.code != 200 {
		t.Fatalf("bundle after the move: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "GET", "erin", "/api/v1/scenarios/"+id, nil); got.code != 404 {
		t.Fatalf("A's viewer still sees it: %d", got.code)
	}
	if ev := ra.adminQuery(`SELECT (body ->> 'bu_id') || '|' || (body -> 'attributes' ->> 'from_bu') || '|' || (body -> 'attributes' ->> 'reason')
		FROM audit.intake WHERE body ->> 'type' = 'scenario.moved'`); ev != ra.bu["B"]+"|"+ra.bu["A1"]+"|Reorganisation" {
		t.Fatalf("scenario.moved: %s", ev)
	}
	if got := move("analyst", ra.bu["A1"]); got.code != 200 {
		t.Fatalf("move back: %d %s", got.code, got.raw)
	}
	if r := reachable("erin"); r["/asset"] != true {
		t.Fatalf("flags after moving back: %v", r)
	}

	// A scenario inside a restricted BU never leaves its subtree.
	ra.mustOwner(grant("platform", "user:analyst", "Risk Analyst", "R"))
	ra.drain()
	r1 := ra.adminQuery("SELECT id FROM iam.bu WHERE code = 'R1'")
	got = ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": r1, "document": doc, "change_note": "restricted"})
	if got.code != 201 {
		t.Fatalf("restricted scenario: %d %s", got.code, got.raw)
	}
	rid := got.body["id"].(string)
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+rid+"/move", map[string]any{"to_bu_id": ra.bu["A1"], "reason": "x"}); got.code != 409 || got.body["error"] != "restricted_move" {
		t.Fatalf("out of a restricted subtree: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+rid+"/move", map[string]any{"to_bu_id": ra.bu["R"], "reason": "x"}); got.code != 200 {
		t.Fatalf("within the restricted subtree: %d %s", got.code, got.raw)
	}
	// The database refuses it too, whatever the caller (PF020).
	if out, err := ra.asCtx(ra.mint("analyst", ctxKey1), "SELECT risk.move_scenario('"+rid+"', '"+ra.bu["B"]+"')"); err == nil || !strings.Contains(out, "restricted") {
		t.Fatalf("SQL move out of R: %v %s", err, out)
	}

	// Archive and restore (AC-22), and the archive guard (F-001 T-31).
	active := func() string {
		return ra.adminQuery("SELECT coalesce(string_agg(table_name, ',' ORDER BY table_name), '') FROM iam.bu_active_records('" + ra.bu["A1"] + "') WHERE table_name LIKE 'risk.scenario%'")
	}
	if a := active(); a != "risk.scenario,risk.scenario_pin,risk.scenario_version" {
		t.Fatalf("active before archiving: %q", a)
	}
	archive := func(user, action, reason string) apiResp {
		t.Helper()
		return ra.call(t, "POST", user, "/api/v1/scenarios/"+id+"/"+action, map[string]any{"reason": reason})
	}
	if got := archive("erin", "archive", "x"); got.code != 403 {
		t.Fatalf("a viewer archives: %d", got.code)
	}
	if got := archive("analyst", "archive", " "); got.code != 400 {
		t.Fatalf("no reason: %d", got.code)
	}
	if got := archive("analyst", "archive", "Superseded"); got.code != 200 {
		t.Fatalf("archive: %d %s", got.code, got.raw)
	}
	if a := active(); a != "" {
		t.Fatalf("archived data holds A1 open: %q", a)
	}
	if got := archive("analyst", "archive", "again"); got.code != 409 {
		t.Fatalf("archive twice: %d", got.code)
	}
	if l := ra.call(t, "GET", "erin", "/api/v1/scenarios", nil).body["scenarios"].([]any); len(l) != 0 {
		t.Fatalf("archived in the active list: %v", l)
	}
	if l := ra.call(t, "GET", "erin", "/api/v1/scenarios?archived=true", nil).body["scenarios"].([]any); len(l) != 1 {
		t.Fatalf("archived list: %v", l)
	}
	// Read-only while archived: reads work, changes are refused.
	if got := ra.call(t, "GET", "erin", "/api/v1/scenarios/"+id, nil); got.code != 200 {
		t.Fatalf("read archived: %d", got.code)
	}
	modeltest.Set(doc, "/name", "Changed")
	for path, body := range map[string]map[string]any{
		"":       {"document": doc, "expected_version": 1, "change_note": "x"},
		"/adopt": {"expected_version": 1, "change_note": "x"},
		"/move":  {"to_bu_id": ra.bu["A"], "reason": "x"},
	} {
		method := "POST"
		if path == "" {
			method = "PUT"
		}
		if got := ra.call(t, method, "analyst", "/api/v1/scenarios/"+id+path, body); got.code != 409 || got.body["error"] != "archived" {
			t.Errorf("%s %s while archived: %d %s", method, path, got.code, got.raw)
		}
	}
	if got := archive("analyst", "restore", "Needed again"); got.code != 200 {
		t.Fatalf("restore: %d %s", got.code, got.raw)
	}
	if a := active(); a != "risk.scenario,risk.scenario_pin,risk.scenario_version" {
		t.Fatalf("active after restoring: %q", a)
	}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+id, map[string]any{"document": doc, "expected_version": 1, "change_note": "After restore"}); got.code != 200 {
		t.Fatalf("save after restore: %d %s", got.code, got.raw)
	}

	// The library and controls archive and restore the same way.
	tcID := doc["threat_community"].(map[string]any)["id"].(string)
	ctlID := doc["control_sets"].([]any)[0].(map[string]any)["controls"].([]any)[0].(map[string]any)["id"].(string)
	for _, path := range []string{"/api/v1/library/" + tcID, "/api/v1/controls/" + ctlID} {
		for _, action := range []string{"archive", "restore"} {
			if got := ra.call(t, "POST", "analyst", path+"/"+action, map[string]any{"reason": "Tidy"}); got.code != 200 {
				t.Fatalf("%s %s: %d %s", action, path, got.code, got.raw)
			}
		}
	}
	// app_rw cannot archive or move rows itself.
	for _, q := range []string{"UPDATE risk.scenario SET archived_at = now()", "UPDATE risk.scenario_version SET archived_at = now()",
		"UPDATE risk.scenario SET bu_id = '" + ra.bu["A"] + "'"} {
		if out, err := ra.asCtx(ra.mint("analyst", ctxKey1), q); err == nil || !strings.Contains(out, "permission denied") {
			t.Errorf("%s: %v %s", q, err, out)
		}
	}
	if ev := ra.adminQuery(`SELECT string_agg(body ->> 'type', ',' ORDER BY id) FROM audit.intake WHERE body ->> 'type' ~ '\.(archived|restored)$'`); ev !=
		"scenario.archived,scenario.restored,library.archived,library.restored,control.archived,control.restored" {
		t.Fatalf("events: %s", ev)
	}
}
