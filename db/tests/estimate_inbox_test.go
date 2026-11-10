package tests

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/estimate"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-004 T-07 (F-004-AC-04, AC-05, AC-07 to AC-10; design §3.3, §6.2,
// §6.7): the estimator's inbox, answers, completion, due dates, reminders.
func TestEstimateInbox(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A
	ea := estimateAPI(t, ra)
	for _, u := range []string{"dana", "sam"} {
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
		ra.mustOwner(grant("platform", "user:"+u, "Estimator", "A"))
	}
	ra.drain()
	id := func(u string) string {
		return ra.adminQuery("SELECT id FROM iam.app_user WHERE email = '" + u + "@example.test'")
	}
	dana, sam := id("dana"), id("sam")
	doc := ra.scenarioDoc(t)
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	sid := got.body["id"].(string)
	send := func(due time.Duration, estimators ...any) string {
		t.Helper()
		got := ea.call(t, "POST", "analyst", "/api/v1/estimates/requests", map[string]any{"scenario_id": sid, "title": "CF and response",
			"due_at": time.Now().Add(due).UTC().Format(time.RFC3339), "factors": []any{"/lef/tef/contact_frequency", "/primary_loss/response"},
			"estimators": estimators, "context": []any{"name", "loss_event"}})
		if got.code != 201 {
			t.Fatalf("request: %d %s", got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	r1 := send(72*time.Hour, dana, sam)
	r2 := send(72*time.Hour, sam)

	// Each estimator sees exactly their requests; others see no inbox.
	inbox := func(user string) []any {
		t.Helper()
		got := ea.call(t, "GET", user, "/api/v1/estimates/inbox", nil)
		if got.code != 200 {
			t.Fatalf("%s's inbox: %d %s", user, got.code, got.raw)
		}
		return got.body["requests"].([]any)
	}
	if n, m := len(inbox("dana")), len(inbox("sam")); n != 1 || m != 2 {
		t.Fatalf("inboxes: dana %d, sam %d", n, m)
	}
	if got := ea.call(t, "GET", "analyst", "/api/v1/estimates/inbox", nil); got.code != 404 {
		t.Fatalf("an analyst's inbox: %d", got.code)
	}
	view := ea.call(t, "GET", "dana", "/api/v1/estimates/inbox/"+r1, nil)
	if view.code != 200 || len(view.body["factors"].([]any)) != 2 || len(view.body["context"].(map[string]any)) != 2 {
		t.Fatalf("dana's view: %d %s", view.code, view.raw)
	}
	for _, never := range []string{`"control_sets"`, `"primary_loss":`, `"lef"`, `"scope"`} {
		if strings.Contains(view.raw, never) {
			t.Errorf("dana's view holds %s: %s", never, view.raw)
		}
	}
	if got := ea.call(t, "GET", "dana", "/api/v1/estimates/inbox/"+r2, nil); got.code != 404 {
		t.Fatalf("dana reads sam's request: %d", got.code)
	}
	// Estimators read nothing of the scenario itself.
	if got := ra.call(t, "GET", "dana", "/api/v1/scenarios/"+sid, nil); got.code != 404 {
		t.Fatalf("dana reads the scenario: %d", got.code)
	}

	cf := func(lo, ml, hi string) map[string]any {
		return map[string]any{"min": lo, "ml": ml, "max": hi, "unit": "events_per_year", "confidence": "0.9",
			"rationale": "From the help desk's phishing reports.", "sources": []any{map[string]any{"type": "person", "ref": "Help desk lead"}}}
	}
	save := func(user, rid string, submit bool, answers ...any) apiResp {
		return ea.call(t, "PUT", user, "/api/v1/estimates/inbox/"+rid+"/answers", map[string]any{"submit": submit, "answers": answers})
	}
	// A draft, then refused answers, then the submission.
	if got := save("dana", r1, false, map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": cf("1", "4", "9")}); got.code != 200 {
		t.Fatalf("draft: %d %s", got.code, got.raw)
	}
	for name, a := range map[string]map[string]any{
		"wrong unit":     {"pointer": "/primary_loss/response", "estimate": cf("1", "2", "3")},
		"unordered":      {"pointer": "/lef/tef/contact_frequency", "estimate": cf("5", "2", "9")},
		"provenance":     {"pointer": "/lef/tef/contact_frequency", "estimate": modeltest.Elicited()},
		"not a factor":   {"pointer": "/lef/vulnerability/resistance_strength", "estimate": cf("1", "2", "3")},
		"both":           {"pointer": "/lef/tef/contact_frequency", "estimate": cf("1", "2", "3"), "declined": "No idea"},
		"secret decline": {"pointer": "/primary_loss/response", "declined": "Bearer abcdefghijklmnopqrstuvwxyz0123456789"},
	} {
		if got := save("dana", r1, true, a); got.code != 422 && got.code != 400 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	if got := save("dana", r1, true, map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": cf("2", "5", "10")},
		map[string]any{"pointer": "/primary_loss/response", "declined": "Outside my knowledge"}); got.code != 200 || !strings.Contains(got.raw, `"finished_at":"`) {
		t.Fatalf("submit: %d %s", got.code, got.raw)
	}
	if got := save("dana", r1, true, map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": cf("3", "5", "8")}); got.code != 200 {
		t.Fatalf("revise: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery(`SELECT string_agg(revision || ':' || state || ':' || (estimate IS NULL) || ':' || (calibration ->> 'class'), ',' ORDER BY pointer, revision)
		FROM estimate.answer WHERE request_id = '` + r1 + `' AND estimator = '` + dana + `'`); got !=
		"1:draft:false:not_measured,2:submitted:false:not_measured,3:submitted:false:not_measured,1:submitted:true:not_measured" {
		t.Fatalf("dana's revisions: %s", got)
	}
	// sam never sees dana's answers, drafts or not.
	if got := ea.call(t, "GET", "sam", "/api/v1/estimates/inbox/"+r1, nil); got.code != 200 || len(got.body["answers"].([]any)) != 0 {
		t.Fatalf("sam's view of r1: %d %s", got.code, got.raw)
	}
	status := func(rid string) string {
		return ra.adminQuery("SELECT status FROM estimate.request WHERE id = '" + rid + "'")
	}
	if s := status(r1); s != "open" {
		t.Fatalf("r1 with sam unfinished: %s", s)
	}
	if got := save("sam", r1, true, map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": cf("1", "3", "6")},
		map[string]any{"pointer": "/primary_loss/response", "declined": "Ask finance"}); got.code != 200 {
		t.Fatalf("sam submits: %d %s", got.code, got.raw)
	}
	if s := status(r1); s != "complete" {
		t.Fatalf("r1 with every estimator finished: %s", s)
	}
	if n := ra.adminQuery("SELECT count(*) FROM estimate.notice_outbox WHERE kind = 'finished' AND request_id = '" + r1 + "'"); n != "2" {
		t.Fatalf("finished notices: %s", n)
	}
	// A complete request still takes revisions until its due date.
	if got := save("sam", r1, true, map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": cf("1", "3", "7")}); got.code != 200 {
		t.Fatalf("revising a complete request: %d %s", got.code, got.raw)
	}

	// A removed estimator, or one without estimate.submit, sees nothing.
	if got := ea.call(t, "PATCH", "analyst", "/api/v1/estimates/requests/"+r2, map[string]any{"add_estimators": []any{dana}}); got.code != 200 {
		t.Fatalf("add dana: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "GET", "dana", "/api/v1/estimates/inbox/"+r2, nil); got.code != 200 {
		t.Fatalf("dana added: %d", got.code)
	}
	if got := ea.call(t, "PATCH", "analyst", "/api/v1/estimates/requests/"+r2, map[string]any{"remove_estimators": []any{dana}}); got.code != 200 {
		t.Fatalf("remove dana: %d %s", got.code, got.raw)
	}
	if got := save("dana", r2, false, map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": cf("1", "2", "3")}); got.code != 404 {
		t.Fatalf("a removed estimator answers: %d %s", got.code, got.raw)
	}
	ra.mustOwner(revoke("platform", "sam", "Estimator", "A"))
	ra.drain()
	if got := ea.call(t, "GET", "sam", "/api/v1/estimates/inbox", nil); got.code != 404 {
		t.Fatalf("sam without estimate.submit: %d %s", got.code, got.raw)
	}
	ra.mustOwner(grant("platform", "user:sam", "Estimator", "A"))
	ra.drain()

	// Due dates and reminders (the leader's job).
	jobs := estimate.Jobs{DB: ra.appPool(), ReminderLead: func() time.Duration { return 2 * time.Hour }}
	ctx := context.Background()
	soon := send(time.Hour, dana, sam)
	if closed, reminded, err := jobs.Step(ctx); err != nil || closed != 0 || reminded != 2 {
		t.Fatalf("first step: closed %d, reminded %d, %v", closed, reminded, err)
	}
	if _, reminded, err := jobs.Step(ctx); err != nil || reminded != 0 {
		t.Fatalf("second step: reminded %d, %v", reminded, err)
	}
	ra.admin(ra.db, "UPDATE estimate.request SET due_at = now() - interval '1 minute' WHERE id IN ('"+soon+"', '"+r1+"')")
	if closed, _, err := jobs.Step(ctx); err != nil || closed != 2 {
		t.Fatalf("closing: %d %v", closed, err)
	}
	if s, s1 := status(soon), status(r1); s != "closed" || s1 != "closed" {
		t.Fatalf("after the due date: %s %s", s, s1)
	}
	if got := save("dana", soon, true, map[string]any{"pointer": "/lef/tef/contact_frequency", "estimate": cf("1", "2", "3")}); got.code != 409 {
		t.Fatalf("an answer after the due date: %d %s", got.code, got.raw)
	}
	if n := ra.adminQuery("SELECT count(*) FROM estimate.notice_outbox WHERE kind = 'closed' AND request_id = '" + soon + "'"); n != "2" {
		t.Fatalf("closed notices: %s", n)
	}
	// The trail: submitted revisions (not drafts), and the closings.
	if got := ra.adminQuery(`SELECT (SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'estimate.answer_saved') || '/' ||
		(SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'estimate.request_closed' AND body ->> 'actor' = 'system:risk')`); got != "6/2" {
		t.Fatalf("events: %s", got)
	}
}
