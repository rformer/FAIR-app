package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-004 T-06 (F-004-AC-01 to AC-06; design §5, §6.1, §6.4): estimate
// requests through the API.
func TestEstimateRequestsAPI(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, buadmin at A1, mallory at B
	ea := estimateAPI(t, ra)
	for _, u := range []string{"dana", "sam", "viewer"} {
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
	}
	ra.mustOwner(grant("platform", "user:dana", "Estimator", "A"))
	ra.mustOwner(grant("platform", "user:sam", "Estimator", "A1"))
	ra.mustOwner(grant("platform", "user:viewer", "Executive Viewer", "A"))
	ra.drain()
	id := func(u string) string {
		return ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + u + "@example.test'")
	}
	dana, sam := id("dana"), id("sam")

	doc := ra.scenarioDoc(t) // library and control at A
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	sid := got.body["id"].(string)
	rc := ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "reference_class", "document": modeltest.ReferenceClass(), "change_note": "x"})
	if rc.code != 201 {
		t.Fatalf("reference class: %d %s", rc.code, rc.raw)
	}
	due := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	request := func(over map[string]any) map[string]any {
		b := map[string]any{"scenario_id": sid, "title": "Contact frequency of ransomware crews", "instructions": "Use the last three years.",
			"due_at": due, "factors": []any{"/lef/tef/contact_frequency", "/primary_loss/response"}, "estimators": []any{dana, sam},
			"context":    []any{"name", "asset", "threat_community", "loss_event"},
			"references": []any{map[string]any{"id": rc.body["id"], "version": 1}}}
		for k, v := range over {
			b[k] = v
		}
		return b
	}

	// Who may send: estimate.request and scenario.edit at the scenario's BU.
	if got := ea.call(t, "POST", "viewer", "/api/v1/estimates/requests", request(nil)); got.code != 403 {
		t.Fatalf("a viewer: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "POST", "mallory", "/api/v1/estimates/requests", request(nil)); got.code != 404 {
		t.Fatalf("an outsider: %d %s", got.code, got.raw)
	}
	// What may be asked: factors the levels require; estimators who hold
	// estimate.submit there.
	if got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", request(map[string]any{"factors": []any{"/lef/estimate", "/primary_loss/reputation"}})); got.code != 422 ||
		!strings.Contains(got.raw, `"/lef/estimate"`) || !strings.Contains(got.raw, `"/primary_loss/reputation"`) {
		t.Fatalf("factors not required: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", request(map[string]any{"estimators": []any{id("viewer")}})); got.code != 409 || !strings.Contains(got.raw, "estimate.submit") {
		t.Fatalf("an estimator without estimate.submit: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", request(map[string]any{"due_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})); got.code != 409 {
		t.Fatalf("due in the past: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", request(map[string]any{"context": []any{"primary_loss"}})); got.code != 400 {
		t.Fatalf("an estimate as context: %d %s", got.code, got.raw)
	}
	got = ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", request(nil))
	if got.code != 201 || got.body["scenario_version"] != float64(1) {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	rid := got.body["id"].(string)

	// The request as analysts read it: the context exactly as chosen.
	got = ea.call(t, "GET", "viewer", "/api/v1/estimates/requests/"+rid, nil)
	if got.code != 200 || got.body["request"].(map[string]any)["factors"] != float64(2) || len(got.body["estimators"].([]any)) != 2 ||
		len(got.body["references"].([]any)) != 1 {
		t.Fatalf("read: %d %s", got.code, got.raw)
	}
	c := got.body["context"].(map[string]any)
	if len(c) != 4 || c["name"] != "Ransomware on the claims platform" || c["asset"].(map[string]any)["name"] != "Claims database" ||
		c["threat_community"].(map[string]any)["name"] != "Cyber criminals" || strings.Contains(got.raw, `"threat_capability"`) {
		t.Fatalf("context: %v", c)
	}
	if !strings.Contains(got.raw, "come into contact with the asset") {
		t.Fatalf("factor definitions: %s", got.raw)
	}
	if got := ea.call(t, "GET", "mallory", "/api/v1/estimates/requests/"+rid, nil); got.code != 404 {
		t.Fatalf("an outsider reads: %d", got.code)
	}
	if got := ea.call(t, "GET", "analyst", "/api/v1/estimates/requests?scenario="+sid, nil); got.code != 200 || len(got.body["requests"].([]any)) != 1 {
		t.Fatalf("list: %d %s", got.code, got.raw)
	}
	notices := func(kind string) string {
		return ra.adminQuery("SELECT count(*) FROM estimate.notice_outbox WHERE kind = '" + kind + "' AND request_id = '" + rid + "'")
	}
	if n := notices("assigned"); n != "2" {
		t.Fatalf("assigned notices: %s", n)
	}

	// Changes while open: a later due date, estimators added and removed.
	later := time.Now().Add(240 * time.Hour).UTC().Truncate(time.Second)
	got = ea.call(t, "PATCH", "analyst", "/api/v1/estimates/requests/"+rid, map[string]any{"due_at": later.Format(time.RFC3339), "remove_estimators": []any{sam}, "reason": "More time"})
	if got.code != 200 || got.body["request"].(map[string]any)["estimators"] != float64(1) || got.body["request"].(map[string]any)["due_at"] != later.Format(time.RFC3339) {
		t.Fatalf("change: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "PATCH", "analyst", "/api/v1/estimates/requests/"+rid, map[string]any{"add_estimators": []any{sam}}); got.code != 422 && got.code != 409 {
		t.Fatalf("re-adding a removed estimator: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "PATCH", "viewer", "/api/v1/estimates/requests/"+rid, map[string]any{"due_at": later.Format(time.RFC3339)}); got.code != 403 {
		t.Fatalf("a viewer changes: %d", got.code)
	}
	if got := ea.call(t, "PATCH", "analyst", "/api/v1/estimates/requests/"+rid, map[string]any{"due_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}); got.code != 409 {
		t.Fatalf("a due date in the past: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT (removed_at IS NOT NULL)::text FROM estimate.request_estimator WHERE request_id = '" + rid + "' AND user_id = '" + sam + "'"); got != "true" {
		t.Fatalf("sam removed: %s", got)
	}

	// Cancel: a reason, the estimators told, nothing more after.
	if got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests/"+rid+"/cancel", map[string]any{"reason": ""}); got.code != 400 {
		t.Fatalf("cancel without a reason: %d", got.code)
	}
	if got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests/"+rid+"/cancel", map[string]any{"reason": "Superseded"}); got.code != 200 ||
		got.body["request"].(map[string]any)["status"] != "cancelled" {
		t.Fatalf("cancel: %d %s", got.code, got.raw)
	}
	if n := notices("closed"); n != "1" {
		t.Fatalf("closed notices: %s", n)
	}
	if got := ea.call(t, "PATCH", "analyst", "/api/v1/estimates/requests/"+rid, map[string]any{"due_at": later.Format(time.RFC3339)}); got.code != 409 {
		t.Fatalf("a cancelled request changed: %d %s", got.code, got.raw)
	}

	// Affected marks: a new version without a requested factor, a move, an
	// archive; each once, recorded, nothing re-pointed.
	open := func(factors ...any) string {
		got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", request(map[string]any{"factors": factors, "estimators": []any{dana}}))
		if got.code != 201 {
			t.Fatalf("request: %d %s", got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	cf, loss := open("/lef/tef/contact_frequency"), open("/primary_loss/response")
	lef := modeltest.Set(doc, "/lef", map[string]any{"level": "lef", "estimate": map[string]any{"min": "0.1", "ml": "0.5", "max": "2", "unit": "events_per_year",
		"confidence": "0.9", "rationale": "Incident history.", "sources": []any{map[string]any{"type": "document", "ref": "IR review"}}}})
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+sid, map[string]any{"document": lef, "expected_version": 1, "change_note": "LEF directly"}); got.code != 200 {
		t.Fatalf("v2: %d %s", got.code, got.raw)
	}
	affected := func(rid string) string {
		return ra.adminQuery("SELECT coalesce(affected, '-') || '/' || scenario_version FROM estimate.request WHERE id = '" + rid + "'")
	}
	if a, b := affected(cf), affected(loss); a != "factor_changed/1" || b != "-/1" {
		t.Fatalf("after v2: %s %s", a, b)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+sid+"/move", map[string]any{"to_bu_id": ra.bu["A"], "reason": "Up"}); got.code != 200 {
		t.Fatalf("move: %d %s", got.code, got.raw)
	}
	if a, b := affected(cf), affected(loss); a != "factor_changed/1" || b != "moved/1" {
		t.Fatalf("after the move: %s %s", a, b)
	}
	third := open("/primary_loss/response")
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+sid+"/archive", map[string]any{"reason": "Done"}); got.code != 200 {
		t.Fatalf("archive: %d %s", got.code, got.raw)
	}
	if a := affected(third); a != "archived/2" {
		t.Fatalf("after the archive: %s", a)
	}
	if got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", request(nil)); got.code != 409 {
		t.Fatalf("a request for an archived scenario: %d %s", got.code, got.raw)
	}

	// Every change in the trail with the actor and BU.
	analyst := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'analyst@example.test'")
	if got := ra.adminQuery(`SELECT string_agg((body ->> 'type') || ':' || coalesce(body -> 'attributes' ->> 'cause', '-') || ':' || (body ->> 'actor' = '` + analyst + `'), ',' ORDER BY id)
		FROM audit.intake WHERE body ->> 'type' LIKE 'estimate.%'`); got != "estimate.request_created:-:true,estimate.request_changed:-:true,estimate.request_cancelled:-:true,"+
		"estimate.request_created:-:true,estimate.request_created:-:true,estimate.request_affected:factor_changed:true,estimate.request_affected:moved:true,"+
		"estimate.request_created:-:true,estimate.request_affected:archived:true" {
		t.Fatalf("events: %s", got)
	}
}
