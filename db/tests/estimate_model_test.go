package tests

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-004 T-03 (F-004-AC-13, AC-18, AC-31; design §3.5, §3.8): reference
// classes through the library API, inherited down the tree like the rest
// of the library; accepted estimates' provenance in scenario documents;
// both carried by the risk export and import.
func TestEstimateModel(t *testing.T) {
	ra := strideF003Fixture(t) // platform2 at ENTERPRISE, analyst at A, buadmin at A1, mallory at B
	rc := func(name string) map[string]any { return modeltest.Set(modeltest.ReferenceClass(), "/name", name) }

	// Created at the root, versioned there, read below it, written only there.
	got := ra.call(t, "POST", "platform2", "/api/v1/library", map[string]any{"bu_id": ra.bu["ENTERPRISE"], "kind": "reference_class",
		"document": rc("Group incidents"), "change_note": "Incident register"})
	if got.code != 201 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	root := got.body["id"].(string)
	if got := ra.call(t, "PUT", "platform2", "/api/v1/library/"+root, map[string]any{"expected_version": 1, "change_note": "2025 added",
		"document": modeltest.Set(rc("Group incidents"), "/period/end", "2026-01-01")}); got.code != 200 || got.body["version"] != float64(2) {
		t.Fatalf("version 2: %d %s", got.code, got.raw)
	}
	list := ra.call(t, "GET", "buadmin", "/api/v1/library?kind=reference_class", nil)
	if list.code != 200 || len(list.body["entries"].([]any)) != 1 || list.body["entries"].([]any)[0].(map[string]any)["inherited"] != true {
		t.Fatalf("inherited list: %d %s", list.code, list.raw)
	}
	if got := ra.call(t, "PUT", "buadmin", "/api/v1/library/"+root, map[string]any{"expected_version": 2, "change_note": "x", "document": rc("Taken")}); got.code != 403 {
		t.Fatalf("an inherited entry saved: %d", got.code)
	}
	// Losses need the installation currency, like any amount (set here).
	losses := modeltest.Set(rc("Claims losses"), "/data", map[string]any{"kind": "losses", "unit": "currency", "amounts": []any{"12000", "250000"}})
	got = ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "reference_class", "document": losses, "change_note": "Claims"})
	if got.code != 201 {
		t.Fatalf("losses: %d %s", got.code, got.raw)
	}
	local := got.body["id"].(string)
	// An invalid one is refused by pointer.
	if got := ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "reference_class",
		"document": modeltest.Set(rc("Bad"), "/data/series/0/count", -1), "change_note": "x"}); got.code != 422 || !strings.Contains(got.raw, "/data/series/0/count") {
		t.Fatalf("invalid: %d %s", got.code, got.raw)
	}

	// A scenario whose contact frequency was accepted from an estimate
	// request: the provenance is stored as given.
	doc := modeltest.Set(ra.scenarioDoc(t), "/lef/tef/contact_frequency", modeltest.Elicited())
	// Its request is not in this installation: provenance from elsewhere is
	// marked imported (T-08 verifies the rest).
	modeltest.Set(doc, "/lef/tef/contact_frequency/elicitation/imported", true)
	got = ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A"], "document": doc, "change_note": "Accepted"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	sid := got.body["id"].(string)
	elicited := func(raw string) string {
		var m map[string]any
		_ = json.Unmarshal([]byte(raw), &m)
		e := m["version"].(map[string]any)["document"].(map[string]any)["lef"].(map[string]any)["tef"].(map[string]any)["contact_frequency"].(map[string]any)["elicitation"]
		b, _ := json.Marshal(e)
		return string(b)
	}
	read := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+sid, nil)
	original := elicited(read.raw)
	if !strings.Contains(original, `"method":"equal"`) || !strings.Contains(original, `"Sam Okafor"`) {
		t.Fatalf("provenance: %s", original)
	}

	// Export A's subtree and import it into B: the reference class and the
	// provenance arrive unchanged.
	exp := ra.call(t, "GET", "analyst", "/api/v1/risk/export?bu="+ra.bu["A"], nil)
	if exp.code != 200 || !strings.Contains(exp.raw, `"reference_class"`) || !strings.Contains(exp.raw, `"elicitation"`) {
		t.Fatalf("export: %d %s", exp.code, exp.raw[:min(len(exp.raw), 400)])
	}
	var file any
	if err := json.Unmarshal([]byte(exp.raw), &file); err != nil {
		t.Fatal(err)
	}
	imp := ra.call(t, "POST", "mallory", "/api/v1/risk/imports", map[string]any{"bu_id": ra.bu["B"], "file": file})
	if imp.code != 201 && imp.code != 200 {
		t.Fatalf("import: %d %s", imp.code, imp.raw)
	}
	var newScenario, newRC string
	for _, c := range imp.body["created"].([]any) {
		m := c.(map[string]any)
		switch {
		case m["source_id"] == sid:
			newScenario = m["id"].(string)
		case m["source_id"] == local:
			newRC = m["id"].(string)
		}
	}
	if newScenario == "" || newRC == "" {
		t.Fatalf("created: %s", imp.raw)
	}
	if got := elicited(ra.call(t, "GET", "mallory", "/api/v1/scenarios/"+newScenario, nil).raw); got != original {
		t.Fatalf("imported provenance %s, want %s", got, original)
	}
	if got := ra.call(t, "GET", "mallory", "/api/v1/library/"+newRC, nil); got.code != 200 || !strings.Contains(got.raw, `"amounts":["12000","250000"]`) {
		t.Fatalf("imported reference class: %d %s", got.code, got.raw)
	}
}
