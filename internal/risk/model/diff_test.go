package model_test

import (
	"encoding/json"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

func canonical(t *testing.T, kind string, d map[string]any) []byte {
	t.Helper()
	raw, _ := json.Marshal(d)
	doc, p := model.Validate(kind, raw)
	if p != nil {
		t.Fatal(p)
	}
	return doc.Canonical
}

// Diff vectors (AC-17): added, removed and changed members by pointer,
// estimates whole, pins summarised.
func TestDiffDocuments(t *testing.T) {
	a := modeltest.Scenario()
	b := modeltest.Scenario()
	modeltest.Set(b, "/name", "Renamed")
	modeltest.Set(b, "/description", nil)                                                        // removed
	modeltest.Set(b, "/scope/out", "Nothing")                                                    // changed
	modeltest.Set(b, "/primary_loss/reputation", b["primary_loss"].(map[string]any)["response"]) // added estimate
	modeltest.Set(b, "/lef/tef/contact_frequency/max", "20")                                     // changed estimate: whole
	modeltest.Set(b, "/threat_community/version", 3)                                             // a pin
	b["control_sets"] = b["control_sets"].([]any)[:1] // a removed set (its pins too)
	d, err := model.DiffDocuments("scenario", canonical(t, "scenario", a), canonical(t, "scenario", b))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range d.Changes {
		got[c.Pointer] = c.Op
	}
	want := map[string]string{
		"/name": "changed", "/description": "removed", "/scope/out": "changed", "/primary_loss/reputation": "added",
		"/lef/tef/contact_frequency": "changed", "/threat_community/version": "changed", "/control_sets/1": "removed",
	}
	if len(got) != len(want) {
		t.Errorf("changes %v, want %v", got, want)
	}
	for p, op := range want {
		if got[p] != op {
			t.Errorf("%s: %q, want %q (all: %v)", p, got[p], op, got)
		}
	}
	for _, c := range d.Changes {
		if c.Pointer == "/lef/tef/contact_frequency" {
			from, to := c.From.(map[string]any), c.To.(map[string]any)
			if from["max"] != "12" || to["max"] != "20" || to["unit"] != "events_per_year" {
				t.Errorf("estimate not whole: %v -> %v", from, to)
			}
		}
	}
	pins := map[string]model.PinChange{}
	for _, p := range d.Pins {
		pins[p.Pointer] = p
	}
	if tc := pins["/threat_community"]; tc.FromVersion != 2 || tc.ToVersion != 3 || tc.Kind != "threat_community" {
		t.Errorf("threat community pin: %+v", tc)
	}
	for _, p := range []string{"/control_sets/1/controls/0", "/control_sets/1/controls/1"} {
		if c := pins[p]; c.FromID == "" || c.ToID != "" {
			t.Errorf("%s: %+v", p, c)
		}
	}
	if len(d.Pins) != 3 {
		t.Errorf("pins %+v", d.Pins)
	}
	// No difference, no changes.
	if d, _ := model.DiffDocuments("scenario", canonical(t, "scenario", a), canonical(t, "scenario", a)); len(d.Changes)+len(d.Pins) != 0 {
		t.Errorf("self diff: %+v", d)
	}
}

func TestSetPinVersion(t *testing.T) {
	doc := canonical(t, "scenario", modeltest.Scenario())
	out, err := model.SetPinVersion(doc, "/control_sets/1/controls/1", 4)
	if err != nil {
		t.Fatal(err)
	}
	d, p := model.Validate("scenario", out)
	if p != nil {
		t.Fatal(p)
	}
	for _, pin := range d.Pins {
		if pin.Pointer == "/control_sets/1/controls/1" && pin.Version != 4 {
			t.Fatalf("version %d", pin.Version)
		}
	}
	for _, bad := range []string{"/name", "/control_sets/9/controls/0", "/nothing", "/lef"} {
		if _, err := model.SetPinVersion(doc, bad, 2); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
