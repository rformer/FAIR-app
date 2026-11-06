package model_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

func taxonomy(t *testing.T, d map[string]any) map[string]string {
	t.Helper()
	raw, _ := json.Marshal(d)
	doc, problems := model.Validate("scenario", raw)
	if problems != nil {
		t.Fatal(problems)
	}
	got := map[string]string{}
	for _, n := range model.Taxonomy(doc.Value.(*model.Scenario)) {
		got[n.Factor] = n.Status
		if (n.Status == model.NodeEntered) != (n.Pointer != "") {
			t.Errorf("%s: status %s with pointer %q", n.Factor, n.Status, n.Pointer)
		}
		if n.Pointer != "" && !strings.HasPrefix(n.Pointer, "/") {
			t.Errorf("%s: pointer %q", n.Factor, n.Pointer)
		}
	}
	return got
}

// The view marks exactly what the levels make the analyst enter (AC-28).
func TestTaxonomy(t *testing.T) {
	deep := taxonomy(t, modeltest.Scenario())
	for f, want := range map[string]string{
		"risk": "derived", "loss_event_frequency": "derived", "threat_event_frequency": "derived",
		"contact_frequency": "entered", "probability_of_action": "entered", "vulnerability": "derived",
		"threat_capability": "entered", "resistance_strength": "entered", "loss_magnitude": "derived",
		"primary_loss.productivity": "entered", "primary_loss.response": "entered", "primary_loss.reputation": "not_used",
		"secondary_risk": "derived", "secondary_risk.0.slef": "entered", "secondary_risk.0.loss.fines_judgments": "entered",
		"secondary_risk.0.loss.response": "not_used",
	} {
		if deep[f] != want {
			t.Errorf("deep: %s is %q, want %q", f, deep[f], want)
		}
	}

	d := modeltest.Scenario()
	modeltest.Set(d, "/lef", map[string]any{"level": "lef", "estimate": modeltest.Scenario()["lef"].(map[string]any)["tef"].(map[string]any)["contact_frequency"]})
	modeltest.Set(d, "/secondary_risk", nil)
	direct := taxonomy(t, d)
	for f, want := range map[string]string{
		"loss_event_frequency": "entered", "threat_event_frequency": "not_used", "contact_frequency": "not_used",
		"vulnerability": "not_used", "threat_capability": "not_used", "resistance_strength": "not_used", "secondary_risk": "not_used",
	} {
		if direct[f] != want {
			t.Errorf("LEF entered: %s is %q, want %q", f, direct[f], want)
		}
	}

	d = modeltest.Scenario()
	modeltest.Set(d, "/lef/vulnerability/threat_capability", map[string]any{"source": "threat_community"})
	if got := taxonomy(t, d)["threat_capability"]; got != "library" {
		t.Errorf("threat capability from the community: %q", got)
	}
}
