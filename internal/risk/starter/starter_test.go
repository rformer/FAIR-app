package starter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model"
)

// The shipped library is valid, covers the design §6.6 content, and marks
// every number as illustrative (AC-11).
func TestShippedLibrary(t *testing.T) {
	l, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	forms := map[string]bool{}
	for _, e := range l.Entries {
		var d struct {
			Kind       string                     `json:"kind"`
			Magnitudes map[string]json.RawMessage `json:"magnitudes"`
		}
		_ = json.Unmarshal(e.Document, &d)
		kinds[d.Kind]++
		for f := range d.Magnitudes {
			forms[f] = true
		}
	}
	if kinds[model.KindThreatCommunity] != 6 {
		t.Errorf("threat communities: %d, want 6", kinds[model.KindThreatCommunity])
	}
	for _, f := range model.FormsOfLoss {
		if !forms[f] {
			t.Errorf("no guidance for %s", f)
		}
	}
	if !strings.Contains(l.About, "illustrative") || !strings.Contains(l.About, "none is industry data") {
		t.Error("the library's statement about its numbers is missing")
	}
	if _, err := SyncPayload(); err != nil {
		t.Fatal(err)
	}
}

// The checks refuse what AC-11 forbids.
func TestParseRefuses(t *testing.T) {
	good := func() map[string]any {
		var m map[string]any
		_ = json.Unmarshal(content, &m)
		return m
	}
	entry0 := func(m map[string]any) map[string]any { return m["entries"].([]any)[0].(map[string]any) }
	for name, mut := range map[string]func(map[string]any){
		"unmarked entry": func(m map[string]any) { entry0(m)["illustrative"] = false },
		"unmarked estimate": func(m map[string]any) {
			entry0(m)["document"].(map[string]any)["threat_capability"].(map[string]any)["rationale"] = "Industry average."
		},
		"duplicate key": func(m map[string]any) { m["entries"] = append(m["entries"].([]any), entry0(m)) },
		"bad key":       func(m map[string]any) { entry0(m)["key"] = "No Key" },
		"no guidance":   func(m map[string]any) { entry0(m)["guidance"] = " " },
		"invalid document": func(m map[string]any) {
			entry0(m)["document"].(map[string]any)["threat_capability"].(map[string]any)["min"] = "99"
		},
		"a control": func(m map[string]any) {
			entry0(m)["document"] = map[string]any{"kind": "control"}
		},
		"no release":    func(m map[string]any) { delete(m, "release") },
		"unknown field": func(m map[string]any) { m["extra"] = true },
	} {
		m := good()
		mut(m)
		b, _ := json.Marshal(m)
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
