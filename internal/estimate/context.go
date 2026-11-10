package estimate

import (
	"fmt"
	"slices"

	"github.com/rformer/fair-app/internal/risk/model"
)

// ContextFields are the parts of a scenario an analyst may share with a
// request's estimators (F-004 AC-02; design §3.2).
var ContextFields = []string{"name", "description", "scope", "analysis_period", "asset", "threat_community", "threat_effects", "loss_event"}

// Snapshot is the context a request shows its estimators: the chosen
// fields of the scenario and of the documents it pins (the asset or asset
// group and the threat community, as copied into the scenario's pins). It
// never holds an estimate: not the scenario's values, not the threat
// community's capability, not an asset's value (AC-07: nothing to anchor
// on).
func Snapshot(s *model.Scenario, asset, threatCommunity map[string]any, fields []string) (map[string]any, error) {
	out := map[string]any{}
	for _, f := range fields {
		if !slices.Contains(ContextFields, f) {
			return nil, fmt.Errorf("estimate: %q is not shareable context (one of %v)", f, ContextFields)
		}
		switch f {
		case "name":
			out[f] = s.Name
		case "description":
			if s.Description != "" {
				out[f] = s.Description
			}
		case "scope":
			sc := map[string]any{"in": s.Scope.In}
			if s.Scope.Out != "" {
				sc["out"] = s.Scope.Out
			}
			out[f] = sc
		case "analysis_period":
			out[f] = map[string]any{"start": s.AnalysisPeriod.Start, "end": s.AnalysisPeriod.End}
		case "asset":
			a := map[string]any{"kind": s.Asset.Kind}
			for _, k := range []string{"name", "asset_type", "description", "valuation"} {
				if v, ok := asset[k].(string); ok && v != "" {
					a[k] = v
				}
			}
			if m, ok := asset["members"].([]any); ok {
				a["members"] = len(m)
			}
			out[f] = a
		case "threat_community":
			tc := map[string]any{}
			for _, k := range []string{"name", "description"} {
				if v, ok := threatCommunity[k].(string); ok && v != "" {
					tc[k] = v
				}
			}
			out[f] = tc
		case "threat_effects":
			out[f] = slices.Clone(s.ThreatEffects)
		case "loss_event":
			out[f] = s.LossEvent
		}
	}
	return out, nil
}
