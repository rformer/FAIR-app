package tests

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/estimate/bank"
)

// F-004 T-11 (F-004-AC-24 to AC-26; design §6.6): the shipped bank and
// custom question sets.
func TestQuestionSets(t *testing.T) {
	ra := strideF003Fixture(t) // platform is the Platform Admin (calibration.manage)
	ea := estimateAPI(t, ra)

	// The install synced the shipped bank: 120 questions in an active,
	// shipped set; syncing it again changes nothing.
	if n := len(ra.install.Bank.Added); n != 120 {
		t.Fatalf("installed %d shipped questions", n)
	}
	if got := ra.adminQuery("SELECT origin || '/' || status || '/' || (SELECT count(*) FROM estimate.question WHERE set_id = s.id AND retired_at IS NULL) FROM estimate.question_set s WHERE id = '" + bank.SetID + "'"); got != "shipped/active/120" {
		t.Fatalf("shipped set: %s", got)
	}
	sync := func(payload []byte) map[string][]string {
		t.Helper()
		var out map[string][]string
		raw := ra.mustOwner("SELECT estimate.sync_bank('" + strings.ReplaceAll(string(payload), "'", "''") + "'::jsonb)")
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	p, _ := bank.SyncPayload()
	if out := sync(p); len(out["added"])+len(out["changed"])+len(out["retired"]) != 0 {
		t.Fatalf("re-sync: %v", out)
	}
	// A release that changes r01's answer and drops b60.
	var payload map[string]any
	_ = json.Unmarshal(p, &payload)
	qs := payload["questions"].([]any)
	qs[0].(map[string]any)["answer"] = "1216"
	payload["questions"] = qs[:len(qs)-1]
	next, _ := json.Marshal(payload)
	if out := sync(next); strings.Join(out["changed"], ",") != "r01" || len(out["retired"]) != 1 || out["retired"][0] != bank.QuestionID("b60") {
		t.Fatalf("a changed release: %v", out)
	}
	if got := ra.adminQuery("SELECT string_agg(version || ':' || answer || ':' || (retired_at IS NULL), ',' ORDER BY version) FROM estimate.question WHERE id = '" + bank.QuestionID("r01") + "'"); got != "1:1215:false,2:1216:true" {
		t.Fatalf("r01 versions: %s", got)
	}
	sync(p) // back to the release

	// Managers only; the shipped set is read-only.
	if got := ea.call(t, "GET", "analyst", "/api/v1/calibration/question-sets", nil); got.code != 404 {
		t.Fatalf("a non-manager lists sets: %d", got.code)
	}
	got := ea.call(t, "GET", "platform", "/api/v1/calibration/question-sets", nil)
	if got.code != 200 || !strings.Contains(got.raw, `"origin":"shipped"`) {
		t.Fatalf("list: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "PUT", "platform", "/api/v1/calibration/questions/"+bank.QuestionID("r02"), map[string]any{"text": "x", "unit": "year", "answer": "1", "source": "y"}); got.code != 409 {
		t.Fatalf("editing a shipped question: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "POST", "platform", "/api/v1/calibration/question-sets/"+bank.SetID+"/retire", nil); got.code != 409 {
		t.Fatalf("retiring the shipped set: %d %s", got.code, got.raw)
	}

	// A custom set: draft, questions, versions, activation, retirement.
	got = ea.call(t, "POST", "platform", "/api/v1/calibration/question-sets", map[string]any{"name": "Our incidents", "description": "From our own history."})
	if got.code != 201 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	set := got.body["id"].(string)
	if got := ea.call(t, "POST", "platform", "/api/v1/calibration/question-sets/"+set+"/activate", nil); got.code != 409 {
		t.Fatalf("activating an empty set: %d %s", got.code, got.raw)
	}
	add := func(q map[string]any) apiResp {
		return ea.call(t, "POST", "platform", "/api/v1/calibration/question-sets/"+set+"/questions", q)
	}
	got = add(map[string]any{"kind": "range", "text": "How many phishing reports did the help desk log in 2025?", "unit": "reports", "answer": "1840.50", "source": "Help desk annual report 2025"})
	if got.code != 201 {
		t.Fatalf("add: %d %s", got.code, got.raw)
	}
	q1 := got.body["id"].(string)
	for name, q := range map[string]map[string]any{
		"a binary with a unit": {"kind": "binary", "text": "Is it?", "unit": "x", "answer": "true", "source": "s"},
		"a binary maybe":       {"kind": "binary", "text": "Is it?", "answer": "maybe", "source": "s"},
		"a range without unit": {"kind": "range", "text": "How many?", "answer": "3", "source": "s"},
		"a non-decimal range":  {"kind": "range", "text": "How many?", "unit": "u", "answer": "lots", "source": "s"},
		"a secret source":      {"kind": "binary", "text": "Is it?", "answer": "true", "source": "Bearer abcdefghijklmnopqrstuvwxyz0123456789"},
		"no text":              {"kind": "binary", "text": " ", "answer": "true", "source": "s"},
	} {
		if got := add(q); got.code != 422 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	if got := ea.call(t, "PUT", "platform", "/api/v1/calibration/questions/"+q1, map[string]any{"text": "How many phishing reports did the help desk log in 2025 (all channels)?",
		"unit": "reports", "answer": "1902", "source": "Help desk annual report 2025, revised"}); got.code != 200 || got.body["version"] != float64(2) {
		t.Fatalf("edit: %d %s", got.code, got.raw)
	}
	got = ea.call(t, "GET", "platform", "/api/v1/calibration/question-sets/"+set, nil)
	if got.code != 200 || got.body["status"] != "draft" || !strings.Contains(got.raw, `"answer":"1902"`) || !strings.Contains(got.raw, `"version":2`) {
		t.Fatalf("read: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery("SELECT answer FROM estimate.question WHERE id = '" + q1 + "' AND version = 1"); got != "1840.5" {
		t.Fatalf("the canonical answer: %s", got)
	}
	// Answers stay with managers: an estimator or analyst cannot read a set.
	if got := ea.call(t, "GET", "analyst", "/api/v1/calibration/question-sets/"+set, nil); got.code != 404 {
		t.Fatalf("a taker reads the answers: %d", got.code)
	}
	for i := 0; i < 11; i++ {
		kind, unit, answer := "binary", any(nil), "true"
		if i%2 == 0 {
			kind, unit, answer = "range", "units", "7"
		}
		if got := add(map[string]any{"kind": kind, "text": "Question " + string(rune('A'+i)) + "?", "unit": unit, "answer": answer, "source": "Our records"}); got.code != 201 {
			t.Fatalf("add %d: %d %s", i, got.code, got.raw)
		}
	}
	if got := ea.call(t, "POST", "platform", "/api/v1/calibration/questions/"+q1+"/retire", nil); got.code != 200 {
		t.Fatalf("retire a question: %d %s", got.code, got.raw)
	}
	if got := ea.call(t, "POST", "platform", "/api/v1/calibration/question-sets/"+set+"/activate", nil); got.code != 200 {
		t.Fatalf("activate: %d %s", got.code, got.raw)
	}
	// With the shipped set retired (as a release might), exercises draw only
	// from the active custom set, and never a retired question.
	ra.admin(ra.db, "UPDATE estimate.question_set SET status = 'retired' WHERE id = '"+bank.SetID+"'")
	got = ea.call(t, "POST", "analyst", "/api/v1/calibration/exercises", nil)
	if got.code != 200 || len(got.body["questions"].([]any)) != 11 {
		t.Fatalf("an exercise from the custom set: %d %s", got.code, got.raw)
	}
	for _, x := range got.body["questions"].([]any) {
		if x.(map[string]any)["id"] == q1 {
			t.Fatal("a retired question in an exercise")
		}
		if _, ok := x.(map[string]any)["answer"]; ok {
			t.Fatal("an answer in an exercise")
		}
	}
	if got := ea.call(t, "POST", "platform", "/api/v1/calibration/question-sets/"+set+"/retire", nil); got.code != 200 {
		t.Fatalf("retire the set: %d %s", got.code, got.raw)
	}
	if got := add(map[string]any{"kind": "binary", "text": "Late?", "answer": "true", "source": "s"}); got.code != 409 {
		t.Fatalf("adding to a retired set: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery(`SELECT string_agg(DISTINCT body -> 'attributes' ->> 'action', ',' ORDER BY body -> 'attributes' ->> 'action') FROM audit.intake WHERE body ->> 'type' = 'calibration.question_set_changed'`); got !=
		"activated,created,question_added,question_edited,question_retired,retired" {
		t.Fatalf("events: %s", got)
	}
}
