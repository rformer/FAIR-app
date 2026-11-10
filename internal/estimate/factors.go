// Package estimate holds F-004's estimate capture logic in the risk
// service: the factors a request can ask for, the scenario context it
// shares, the estimating aids, and (later tasks) combination and
// calibration scoring (F-004 design §3).
package estimate

import (
	"fmt"
	"strings"

	"github.com/rformer/fair-app/internal/risk/model"
)

// Factor is one factor of a scenario that an estimate request may ask for:
// an estimate the scenario's taxonomy levels require (F-004 design §3.1).
type Factor struct {
	Pointer    string `json:"pointer"`    // where its estimate is in the scenario document
	Factor     string `json:"factor"`     // the taxonomy factor, e.g. "contact_frequency", "secondary_risk.0.slef"
	Name       string `json:"name"`       // for people, e.g. "Contact frequency", "Fines and judgments (Regulators)"
	Unit       string `json:"unit"`       // model.Unit*
	Definition string `json:"definition"` // shown to estimators (F-004 AC-02)
}

// FormLabels name the six forms of loss for people.
var FormLabels = map[string]string{
	"productivity":          "Productivity",
	"response":              "Response",
	"replacement":           "Replacement",
	"fines_judgments":       "Fines and judgments",
	"competitive_advantage": "Competitive advantage",
	"reputation":            "Reputation",
}

// formMeaning says what each form of loss covers (Open FAIR).
var formMeaning = map[string]string{
	"productivity":          "the reduced ability to deliver goods or services, and the revenue or value lost while it lasts",
	"response":              "the cost of managing the event: incident response, investigation, notification, communication",
	"replacement":           "the cost of replacing or repairing the affected assets",
	"fines_judgments":       "fines, judgments, settlements and the legal costs around them",
	"competitive_advantage": "lost competitive advantage, such as disclosed trade secrets or plans",
	"reputation":            "revenue or value lost because stakeholders think less of the organization",
}

// base factors: name, unit and definition.
var glossary = map[string]Factor{
	"loss_event_frequency": {Name: "Loss event frequency", Unit: model.UnitEventsPerYear,
		Definition: "How many times a year the threat community is expected to act against the asset and cause a loss: the loss events of this scenario, in events per year."},
	"threat_event_frequency": {Name: "Threat event frequency", Unit: model.UnitEventsPerYear,
		Definition: "How many times a year the threat community is expected to act against the asset, whether or not the action succeeds, in events per year."},
	"contact_frequency": {Name: "Contact frequency", Unit: model.UnitEventsPerYear,
		Definition: "How many times a year the threat community is expected to come into contact with the asset, in events per year. Contact may be random, regular or intentional."},
	"probability_of_action": {Name: "Probability of action", Unit: model.UnitProbability,
		Definition: "Once in contact, the probability that the threat community acts against the asset (from 0 to 1): it depends on what they would gain, what it would cost them and the risk to them."},
	"vulnerability": {Name: "Vulnerability", Unit: model.UnitProbability,
		Definition: "The probability (from 0 to 1) that a threat event becomes a loss event: that the threat community's action succeeds."},
	"threat_capability": {Name: "Threat capability", Unit: model.UnitPercentile,
		Definition: "How capable the threat community is, as a percentile of the whole threat continuum: 0 is the least capable threat, 100 the most capable."},
	"resistance_strength": {Name: "Resistance strength", Unit: model.UnitPercentile,
		Definition: "How strong the asset's protection is, as the percentile of the same threat continuum it resists: protection at 70 withstands the weakest 70% of threats."},
}

// Factors returns the factors of a valid scenario that an estimate request
// may ask for: every estimate its taxonomy levels require (model.Taxonomy's
// entered nodes), in the taxonomy's order.
func Factors(s *model.Scenario) []Factor {
	var out []Factor
	for _, n := range model.Taxonomy(s) {
		if n.Status != model.NodeEntered {
			continue
		}
		f := describe(s, n.Factor)
		f.Pointer, f.Factor = n.Pointer, n.Factor
		out = append(out, f)
	}
	return out
}

// describe gives a factor's name, unit and definition.
func describe(s *model.Scenario, factor string) Factor {
	if g, ok := glossary[factor]; ok {
		return g
	}
	if form, ok := strings.CutPrefix(factor, "primary_loss."); ok {
		return Factor{Name: FormLabels[form] + " loss", Unit: model.UnitCurrency,
			Definition: fmt.Sprintf("The %s loss the organization suffers directly from one loss event of this scenario, in the installation currency: %s.",
				strings.ToLower(FormLabels[form]), formMeaning[form])}
	}
	var i int
	var rest string
	if _, err := fmt.Sscanf(factor, "secondary_risk.%d.%s", &i, &rest); err == nil && i < len(s.SecondaryRisk) {
		who := s.SecondaryRisk[i].Stakeholder
		if rest == "slef" {
			return Factor{Name: "Secondary loss event frequency (" + who + ")", Unit: model.UnitProbability,
				Definition: fmt.Sprintf("The probability (from 0 to 1) that a loss event of this scenario also brings a reaction from %s that causes further loss: a secondary loss event.", who)}
		}
		if form, ok := strings.CutPrefix(rest, "loss."); ok {
			return Factor{Name: FormLabels[form] + " (" + who + ")", Unit: model.UnitCurrency,
				Definition: fmt.Sprintf("The %s loss from %s's reaction to one secondary loss event, in the installation currency: %s.",
					strings.ToLower(FormLabels[form]), who, formMeaning[form])}
		}
	}
	return Factor{Name: factor}
}

// FactorAt returns the requestable factor at a pointer, if the scenario has
// one there.
func FactorAt(s *model.Scenario, pointer string) (Factor, bool) {
	for _, f := range Factors(s) {
		if f.Pointer == pointer {
			return f, true
		}
	}
	return Factor{}, false
}
