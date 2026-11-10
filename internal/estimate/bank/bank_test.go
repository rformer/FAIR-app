package bank_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/estimate/bank"
)

// F-004 T-11 (AC-24): the shipped bank: 60 range and 60 true-or-false
// questions, each with an answer, a unit (ranges) and a source; stable ids.
func TestShippedBank(t *testing.T) {
	bk, err := bank.Load()
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	answers := map[string]int{}
	for _, q := range bk.Questions {
		kinds[q.Kind]++
		if q.Kind == "binary" {
			answers[q.Answer]++
		}
		if len(q.Source) < 10 {
			t.Errorf("%s: source %q is not citable", q.Key, q.Source)
		}
	}
	if kinds["range"] != 60 || kinds["binary"] != 60 {
		t.Fatalf("kinds %v", kinds)
	}
	// Neither answer dominates, so guessing one way is not rewarded.
	if answers["true"] < 25 || answers["false"] < 25 {
		t.Fatalf("binary answers %v", answers)
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuid.MatchString(bank.SetID) || bank.QuestionID("r01") != bank.QuestionID("r01") || bank.QuestionID("r01") == bank.QuestionID("r02") || !uuid.MatchString(bank.QuestionID("r01")) {
		t.Fatalf("ids %s %s", bank.SetID, bank.QuestionID("r01"))
	}
	p, err := bank.SyncPayload()
	if err != nil || !strings.Contains(string(p), `"set_id":"`+bank.SetID+`"`) {
		t.Fatalf("payload: %v %.200s", err, p)
	}
}

func TestParseRefuses(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{"release": "r", "name": "n", "description": "d", "questions": []any{
			map[string]any{"key": "r01", "kind": "range", "text": "How many?", "unit": "things", "answer": "3", "source": "A source"},
			map[string]any{"key": "b01", "kind": "binary", "text": "Is it?", "answer": "true", "source": "A source"},
		}}
	}
	b, _ := json.Marshal(good())
	if _, err := bank.Parse(b); err != nil {
		t.Fatalf("a good bank refused: %v", err)
	}
	for name, mutate := range map[string]func(q []any){
		"no source":          func(q []any) { q[0].(map[string]any)["source"] = "" },
		"no unit":            func(q []any) { delete(q[0].(map[string]any), "unit") },
		"a non-decimal":      func(q []any) { q[0].(map[string]any)["answer"] = "three" },
		"a non-canonical":    func(q []any) { q[0].(map[string]any)["answer"] = "3.0" },
		"a binary maybe":     func(q []any) { q[1].(map[string]any)["answer"] = "maybe" },
		"a binary with unit": func(q []any) { q[1].(map[string]any)["unit"] = "x" },
		"a duplicate key":    func(q []any) { q[1].(map[string]any)["key"] = "r01" },
		"a duplicate text":   func(q []any) { q[1].(map[string]any)["text"] = "How many?" },
		"an unknown kind":    func(q []any) { q[0].(map[string]any)["kind"] = "essay" },
		"a secret":           func(q []any) { q[0].(map[string]any)["source"] = "Bearer abcdefghijklmnopqrstuvwxyz0123456789" },
		"a multi-line text":  func(q []any) { q[0].(map[string]any)["text"] = "How\nmany?" },
	} {
		g := good()
		mutate(g["questions"].([]any))
		b, _ := json.Marshal(g)
		if _, err := bank.Parse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
