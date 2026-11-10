// Package modeltest is the corpus of valid and invalid F-003 documents. The
// Go validator, the published JSON Schemas and the database's
// risk.check_document (T-03) are each tested against it, so all three agree.
package modeltest

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Case is one document and the verdict every validator must reach.
type Case struct {
	Name  string
	Kind  string
	Doc   []byte
	Valid bool
	// Pointer is where the problem is (invalid cases): the validator must
	// report a problem at this pointer.
	Pointer string
	// Structural cases break the document's shape (unknown, missing or
	// mistyped fields, values outside an enumeration), so the JSON Schema
	// refuses them too. Other invalid cases break rules a schema does not
	// express (ordering, exactly-one, uniqueness, secrets).
	Structural bool
}

const (
	assetID  = "11111111-1111-4111-8111-111111111111"
	tcID     = "22222222-2222-4222-8222-222222222222"
	ctrlID   = "33333333-3333-4333-8333-333333333333"
	ctrl2ID  = "44444444-4444-4444-8444-444444444444"
	ownerID  = "5555aaaa-5555-4555-8555-55555555bbbb"
	asset2ID = "66666666-6666-4666-8666-666666666666"
	// F-004: an estimate request and its estimators.
	requestID = "77777777-7777-4777-8777-777777777777"
	expertA   = "88888888-8888-4888-8888-888888888888"
	expertB   = "99999999-9999-4999-8999-999999999999"
)

func est(lo, ml, hi, unit string) map[string]any {
	return map[string]any{
		"min": lo, "ml": ml, "max": hi, "unit": unit, "confidence": "0.9",
		"rationale": "Calibrated estimate from the 2025 incident review.",
		"sources":   []any{map[string]any{"type": "document", "ref": "IR review 2025"}},
	}
}

// Scenario returns a valid scenario at the deepest levels: contact
// frequency and probability of action, Vulnerability derived from threat
// capability (entered on the scenario) against resistance strength.
func Scenario() map[string]any {
	return map[string]any{
		"kind": "scenario", "schema_version": 1,
		"name":             "Ransomware on the claims platform",
		"description":      "Encryption of claims data by an external actor.",
		"scope":            map[string]any{"in": "Claims platform production.", "out": "Backups held offline."},
		"analysis_period":  map[string]any{"start": "2027-01-01", "end": "2027-12-31"},
		"owner":            ownerID,
		"asset":            map[string]any{"kind": "asset", "id": assetID, "version": 1},
		"threat_community": map[string]any{"id": tcID, "version": 2},
		"threat_effects":   []any{"availability", "confidentiality"},
		"loss_event":       "Claims processing halted and data exfiltrated.",
		"lef": map[string]any{
			"level": "tef_vuln",
			"tef": map[string]any{
				"level":                 "cf_poa",
				"contact_frequency":     est("2", "6", "12", "events_per_year"),
				"probability_of_action": est("0.1", "0.3", "0.5", "probability"),
			},
			"vulnerability": map[string]any{
				"level":               "derived",
				"threat_capability":   map[string]any{"source": "scenario", "estimate": est("40", "60", "85", "percentile")},
				"resistance_strength": est("50", "65", "80", "percentile"),
			},
		},
		"primary_loss": map[string]any{
			"productivity": est("100000", "400000", "2000000", "currency"),
			"response":     est("50000", "150000", "600000", "currency"),
		},
		"secondary_risk": []any{map[string]any{
			"stakeholder": "Regulators",
			"slef":        est("0.2", "0.4", "0.7", "probability"),
			"loss":        map[string]any{"fines_judgments": est("0", "250000", "5000000", "currency")},
		}},
		"control_sets": []any{
			map[string]any{"name": "Current", "current": true, "controls": []any{
				map[string]any{"id": ctrlID, "version": 1, "status": "in_place"},
			}},
			map[string]any{"name": "With EDR", "current": false, "controls": []any{
				map[string]any{"id": ctrlID, "version": 1, "status": "in_place"},
				map[string]any{"id": ctrl2ID, "version": 3, "status": "proposed", "effects": []any{
					map[string]any{"factor": "resistance_strength", "estimate": est("70", "80", "90", "percentile")},
				}},
			}},
		},
	}
}

// Asset returns a valid asset valued by an estimate.
func Asset() map[string]any {
	return map[string]any{
		"kind": "asset", "schema_version": 1, "name": "Claims database", "asset_type": "Database",
		"description": "Policyholder claims.", "value": est("1000000", "3000000", "8000000", "currency"),
	}
}

// AssetGroup returns a valid asset group valued as a whole.
func AssetGroup() map[string]any {
	return map[string]any{
		"kind": "asset_group", "schema_version": 1, "name": "Customer databases",
		"members":   []any{map[string]any{"id": assetID, "version": 1}, map[string]any{"id": asset2ID, "version": 4}},
		"valuation": "whole", "value": est("5000000", "9000000", "20000000", "currency"),
	}
}

// ThreatCommunity returns a valid threat community.
func ThreatCommunity() map[string]any {
	return map[string]any{
		"kind": "threat_community", "schema_version": 1, "name": "Cyber criminals",
		"description": "Financially motivated external actors.", "threat_capability": est("30", "60", "90", "percentile"),
	}
}

// LossProfile returns a valid loss profile.
func LossProfile() map[string]any {
	return map[string]any{
		"kind": "loss_profile", "schema_version": 1, "name": "Data breach, mid-size",
		"magnitudes": map[string]any{"response": est("20000", "80000", "400000", "currency"), "reputation": est("0", "100000", "3000000", "currency")},
	}
}

// Control returns a valid control.
func Control() map[string]any {
	return map[string]any{
		"kind": "control", "schema_version": 1, "name": "Endpoint detection and response",
		"references": []any{map[string]any{"framework": "NIST SP 800-53r5", "identifier": "SI-4"}},
		"effects": []any{
			map[string]any{"factor": "resistance_strength", "estimate": est("60", "75", "90", "percentile")},
			map[string]any{"factor": "loss.response", "estimate": est("0.1", "0.3", "0.5", "fraction")},
		},
	}
}

// ReferenceClass returns a valid reference class of event counts (F-004
// design §3.8).
func ReferenceClass() map[string]any {
	return map[string]any{
		"kind": "reference_class", "schema_version": 1, "name": "Ransomware incidents, claims division",
		"description": "Incidents recorded by the claims division's security team.",
		"period":      map[string]any{"start": "2022-01-01", "end": "2025-01-01"},
		"data": map[string]any{"kind": "counts", "series": []any{
			map[string]any{"start": "2022-01-01", "end": "2023-01-01", "count": 2},
			map[string]any{"start": "2023-01-01", "end": "2024-01-01", "count": 0},
			map[string]any{"start": "2024-01-01", "end": "2025-01-01", "count": 3},
		}},
		"sources": []any{map[string]any{"type": "dataset", "ref": "Incident register export, 2025-01"}},
	}
}

// Elicited returns a valid contact frequency estimate accepted from an
// estimate request by an equal-weight pool of two answers (F-004 design
// §3.5).
func Elicited() map[string]any {
	e := est("3", "6", "11", "events_per_year")
	e["rationale"] = "Equal-weight average of 2 answers to estimate request " + requestID + "."
	e["sources"] = []any{
		map[string]any{"type": "elicitation", "ref": requestID},
		map[string]any{"type": "person", "ref": "Dana Ruiz"},
	}
	e["elicitation"] = map[string]any{
		"request": requestID, "method": "equal", "confidence": "0.9",
		"answers": []any{
			map[string]any{"estimator": expertA, "name": "Dana Ruiz", "revision": 2, "weight": "0.5", "min": "2", "ml": "5", "max": "10",
				"confidence": "0.9", "calibration": map[string]any{"class": "calibrated", "range_rate": "0.9", "as_of": "2026-11-09"}},
			map[string]any{"estimator": expertB, "name": "Sam Okafor", "revision": 1, "weight": "0.5", "min": "4", "ml": "7", "max": "12",
				"confidence": "0.9", "calibration": map[string]any{"class": "not_measured", "as_of": "2026-11-09"}},
		},
	}
	return e
}

// Bases maps each kind to its valid base document.
var Bases = map[string]func() map[string]any{
	"scenario": Scenario, "asset": Asset, "asset_group": AssetGroup,
	"threat_community": ThreatCommunity, "loss_profile": LossProfile, "control": Control,
	"reference_class": ReferenceClass,
}

// Set returns doc with the value at a JSON pointer replaced (or added); a
// nil value removes it. Array elements are addressed by index.
func Set(doc map[string]any, pointer string, value any) map[string]any {
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	var cur any = doc
	for i, p := range parts {
		last := i == len(parts)-1
		switch c := cur.(type) {
		case map[string]any:
			if last {
				if value == nil {
					delete(c, p)
				} else {
					c[p] = value
				}
				return doc
			}
			cur = c[p]
		case []any:
			n, _ := strconv.Atoi(p)
			if last {
				c[n] = value
				return doc
			}
			cur = c[n]
		}
	}
	return doc
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

type mutation struct {
	name, pointer string
	value         any
	problem       string // pointer of the expected problem ("" = the mutated pointer)
	structural    bool
}

const remove = "\x00remove"

// Corpus returns every case.
func Corpus() []Case {
	var out []Case
	for _, k := range []string{"scenario", "asset", "asset_group", "threat_community", "loss_profile", "control", "reference_class"} {
		out = append(out, Case{Name: k + ": base", Kind: k, Doc: mustJSON(Bases[k]()), Valid: true})
	}
	valid := []struct {
		name, kind, pointer string
		value               any
	}{
		{"LEF entered directly", "scenario", "/lef", map[string]any{"level": "lef", "estimate": est("0.1", "0.5", "2", "events_per_year")}},
		{"TEF and direct Vulnerability", "scenario", "/lef", map[string]any{"level": "tef_vuln",
			"tef":           map[string]any{"level": "tef", "estimate": est("1", "3", "9", "events_per_year")},
			"vulnerability": map[string]any{"level": "direct", "estimate": est("0.05", "0.2", "0.4", "probability")}}},
		{"threat capability from the community", "scenario", "/lef/vulnerability/threat_capability", map[string]any{"source": "threat_community"}},
		{"numbers as JSON numbers", "scenario", "/lef/tef/contact_frequency", map[string]any{"min": 2, "ml": 6.0, "max": 1.2e1, "unit": "events_per_year",
			"confidence": 0.9, "rationale": "r", "sources": []any{map[string]any{"type": "person", "ref": "CISO"}}}},
		{"no secondary risk", "scenario", "/secondary_risk", nil},
		{"asset group as the asset", "scenario", "/asset/kind", "asset_group"},
		{"equal range", "asset", "/value", est("5", "5", "5", "currency")},
		{"value basis instead of a value", "asset", "/value", nil},
		{"group valued by members", "asset_group", "/value", nil},
		{"all six forms", "loss_profile", "/magnitudes", map[string]any{
			"productivity": est("0", "1", "2", "currency"), "response": est("0", "1", "2", "currency"),
			"replacement": est("0", "1", "2", "currency"), "fines_judgments": est("0", "1", "2", "currency"),
			"competitive_advantage": est("0", "1", "2", "currency"), "reputation": est("0", "1", "2", "currency")}},
		{"an accepted estimate", "scenario", "/lef/tef/contact_frequency", Elicited()},
		{"observed losses", "reference_class", "/data", map[string]any{"kind": "losses", "unit": "currency", "amounts": []any{"12000", "250000.5", "0"}}},
	}
	for _, c := range valid {
		d := Set(Bases[c.kind](), c.pointer, c.value)
		switch c.name {
		case "value basis instead of a value":
			d["value_basis"] = "Replacement cost of the platform and its data."
		case "group valued by members":
			d["valuation"] = "members"
		}
		out = append(out, Case{Name: c.kind + ": " + c.name, Kind: c.kind, Doc: mustJSON(d), Valid: true})
	}

	invalid := map[string][]mutation{
		"scenario": {
			{"unknown field", "/colour", "red", "", true},
			{"missing name", "/name", remove, "/name", true},
			{"empty name", "/name", "  ", "", false},
			{"name too long", "/name", strings.Repeat("n", 201), "", true},
			{"multi-line name", "/name", "a\nb", "", false},
			{"control character", "/description", "a\x01b", "", false},
			{"secret in text", "/description", "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x", "", false},
			{"wrong schema version", "/schema_version", 2, "", true},
			{"mistyped schema version", "/schema_version", "1", "/schema_version", true},
			{"bad owner", "/owner", "not-a-uuid", "", true},
			{"period backwards", "/analysis_period/end", "2026-01-01", "/analysis_period", false},
			{"bad date", "/analysis_period/start", "2027-13-01", "", true},
			{"no scope", "/scope/in", "", "", false},
			{"asset kind", "/asset/kind", "server", "", true},
			{"asset version zero", "/asset/version", 0, "", true},
			{"threat community id", "/threat_community/id", "x", "", true},
			{"no threat effects", "/threat_effects", []any{}, "", true},
			{"unknown threat effect", "/threat_effects", []any{"availability", "privacy"}, "/threat_effects/1", true},
			{"threat effect twice", "/threat_effects", []any{"availability", "availability"}, "/threat_effects/1", false},
			{"level unknown", "/lef/level", "risk", "", true},
			{"LEF estimate with tef_vuln", "/lef/estimate", est("1", "2", "3", "events_per_year"), "", true},
			{"missing vulnerability", "/lef/vulnerability", nil, "/lef/vulnerability", true},
			{"cf_poa with a TEF estimate", "/lef/tef/estimate", est("1", "2", "3", "events_per_year"), "", true},
			{"missing probability of action", "/lef/tef/probability_of_action", nil, "/lef/tef/probability_of_action", true},
			{"derived with a direct estimate", "/lef/vulnerability/estimate", est("0.1", "0.2", "0.3", "probability"), "", true},
			{"missing resistance strength", "/lef/vulnerability/resistance_strength", nil, "/lef/vulnerability/resistance_strength", true},
			{"tcap source unknown", "/lef/vulnerability/threat_capability/source", "guess", "", true},
			{"tcap from scenario without estimate", "/lef/vulnerability/threat_capability/estimate", nil, "/lef/vulnerability/threat_capability/estimate", true},
			{"wrong unit", "/lef/tef/contact_frequency/unit", "probability", "", true},
			{"unordered", "/lef/tef/contact_frequency/min", "20", "/lef/tef/contact_frequency", false},
			{"most likely above max", "/lef/tef/contact_frequency/ml", "13", "/lef/tef/contact_frequency", false},
			{"TEF branch with lef", "/lef/level", "lef", "/lef/tef", true},
			{"period of no length", "/analysis_period/end", "2027-01-01", "/analysis_period", false},
			{"negative frequency", "/lef/tef/contact_frequency/min", "-1", "", false},
			{"probability above 1", "/lef/tef/probability_of_action/max", "1.5", "", false},
			{"percentile above 100", "/lef/vulnerability/resistance_strength/max", "101", "", false},
			{"confidence 1", "/lef/tef/contact_frequency/confidence", "1", "", false},
			{"confidence 0", "/lef/tef/contact_frequency/confidence", "0", "", false},
			{"not a decimal", "/lef/tef/contact_frequency/ml", "six", "", true},
			{"more than 34 digits", "/lef/tef/contact_frequency/max", "1" + strings.Repeat("0", 34), "", false},
			{"decimal with exponent text", "/lef/tef/contact_frequency/ml", "6e0x", "", true},
			{"no rationale", "/lef/tef/contact_frequency/rationale", "", "", false},
			{"no sources", "/lef/tef/contact_frequency/sources", []any{}, "", true},
			{"source type", "/lef/tef/contact_frequency/sources/0/type", "rumour", "", true},
			{"source without ref", "/lef/tef/contact_frequency/sources/0/ref", "", "", false},
			{"no primary loss", "/primary_loss", map[string]any{}, "", true},
			{"unknown form of loss", "/primary_loss/goodwill", est("0", "1", "2", "currency"), "", true},
			{"magnitude in the wrong unit", "/primary_loss/response/unit", "events_per_year", "", true},
			{"secondary without loss", "/secondary_risk/0/loss", map[string]any{}, "", true},
			{"stakeholder twice", "/secondary_risk", []any{
				map[string]any{"stakeholder": "Regulators", "slef": est("0", "0.1", "0.2", "probability"), "loss": map[string]any{"response": est("0", "1", "2", "currency")}},
				map[string]any{"stakeholder": "Regulators", "slef": est("0", "0.1", "0.2", "probability"), "loss": map[string]any{"response": est("0", "1", "2", "currency")}},
			}, "/secondary_risk/1/stakeholder", false},
			{"no control sets", "/control_sets", []any{}, "", true},
			{"two current sets", "/control_sets/1/current", true, "/control_sets", false},
			{"no current set", "/control_sets/0/current", false, "/control_sets", false},
			{"set name twice", "/control_sets/1/name", "Current", "", false},
			{"control twice in a set", "/control_sets/1/controls/1/id", ctrlID, "/control_sets/1/controls/1/id", false},
			{"control status", "/control_sets/0/controls/0/status", "planned", "", true},
			{"effect factor", "/control_sets/1/controls/1/effects/0/factor", "luck", "", true},
			{"effect in the wrong unit", "/control_sets/1/controls/1/effects/0/estimate/unit", "fraction", "", true},
		},
		"asset": {
			{"value and basis", "/value_basis", "Book value.", "/value", false},
			{"neither value nor basis", "/value", nil, "/value_basis", false},
			{"no asset type", "/asset_type", remove, "/asset_type", true},
			{"value in the wrong unit", "/value/unit", "percentile", "", true},
		},
		"asset_group": {
			{"no members", "/members", []any{}, "", true},
			{"member twice", "/members/1/id", assetID, "/members/1/id", false},
			{"whole without value", "/value", nil, "/value", true},
			{"valuation unknown", "/valuation", "average", "", true},
		},
		"threat_community": {
			{"capability in the wrong unit", "/threat_capability/unit", "probability", "", true},
			{"capability above 100", "/threat_capability/max", "150", "", false},
		},
		"loss_profile": {
			{"no magnitudes", "/magnitudes", map[string]any{}, "", true},
			{"unknown form", "/magnitudes/brand", est("0", "1", "2", "currency"), "", true},
		},
		"reference_class": {
			{"no data kind", "/data/kind", "anecdotes", "", true},
			{"no periods", "/data/series", []any{}, "", true},
			{"negative count", "/data/series/0/count", -1, "", true},
			{"period backwards", "/period/end", "2021-01-01", "/period", false},
			{"count period backwards", "/data/series/1/end", "2022-06-01", "/data/series/1", false},
			{"amounts with counts", "/data/amounts", []any{"1"}, "", true},
			{"no sources", "/sources", []any{}, "", true},
			{"an elicitation source", "/sources/0/type", "elicitation", "", false},
			{"secret in a source", "/sources/0/note", "Bearer abcdefghijklmnopqrstuvwxyz0123456789", "", false},
		},
		"control": {
			{"no effects", "/effects", []any{}, "", true},
			{"effect twice", "/effects/1/factor", "resistance_strength", "/effects/1/factor", false},
			{"reduction above 1", "/effects/1/estimate/max", "2", "", false},
			{"unknown loss form", "/effects/1/factor", "loss.brand", "", true},
			{"reference twice", "/references", []any{
				map[string]any{"framework": "ISO 27001", "identifier": "A.8.7"},
				map[string]any{"framework": "ISO 27001", "identifier": "A.8.7"}}, "/references/1", false},
			{"reference without identifier", "/references/0/identifier", "", "", false},
		},
	}
	for _, k := range []string{"scenario", "asset", "asset_group", "threat_community", "loss_profile", "control", "reference_class"} {
		for _, m := range invalid[k] {
			v := m.value
			if v == remove {
				v = nil
			}
			d := Set(Bases[k](), m.pointer, v)
			p := m.problem
			if p == "" {
				p = m.pointer
			}
			out = append(out, Case{Name: k + ": " + m.name, Kind: k, Doc: mustJSON(d), Pointer: p, Structural: m.structural})
		}
	}
	// Accepted estimates (F-004 design §3.5): mutations of a scenario whose
	// contact frequency carries elicitation provenance.
	const cf = "/lef/tef/contact_frequency"
	for _, m := range []mutation{
		{"elicitation source without provenance", cf + "/sources/0/type", "elicitation", "", false},
		{"provenance without its source", cf + "/elicitation/request", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", cf + "/sources", false},
		{"unknown method", cf + "/elicitation/method", "median", "", true},
		{"bad request id", cf + "/elicitation/request", "request-1", "", true},
		{"single with two answers", cf + "/elicitation/method", "single", cf + "/elicitation/answers", false},
		{"weight above 1", cf + "/elicitation/answers/0/weight", "1.5", "", false},
		{"answer unordered", cf + "/elicitation/answers/0/min", "6", cf + "/elicitation/answers/0", false},
		{"answer confidence 1", cf + "/elicitation/answers/0/confidence", "1", "", false},
		{"estimator twice", cf + "/elicitation/answers/1/estimator", expertA, "", false},
		{"unknown calibration class", cf + "/elicitation/answers/0/calibration/class", "great", "", true},
		{"calibration date", cf + "/elicitation/answers/0/calibration/as_of", "yesterday", "", true},
		{"revision zero", cf + "/elicitation/answers/0/revision", 0, "", true},
		{"answer without a name", cf + "/elicitation/answers/0/name", "", "", true},
		{"unknown provenance field", cf + "/elicitation/colour", "red", "", true},
	} {
		d := Set(Scenario(), cf, Elicited())
		if m.name == "elicitation source without provenance" {
			d = Scenario()
		}
		d = Set(d, m.pointer, m.value) // "provenance without its source": the source still names the original request
		p := m.problem
		if p == "" {
			p = m.pointer
		}
		out = append(out, Case{Name: "scenario: " + m.name, Kind: "scenario", Doc: mustJSON(d), Pointer: p, Structural: m.structural})
	}

	// Documents that are not the kind asked for, or not documents at all.
	out = append(out,
		Case{Name: "wrong kind", Kind: "asset", Doc: mustJSON(Control()), Pointer: "/kind", Structural: true},
		Case{Name: "duplicate member", Kind: "asset", Doc: []byte(`{"kind": "asset", "kind": "asset"}`), Pointer: "", Structural: true},
		Case{Name: "not an object", Kind: "asset", Doc: []byte(`[]`), Pointer: "", Structural: true},
	)
	return out
}
