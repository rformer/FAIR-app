// Package model holds the F-003 document kinds (design §3) and their
// validator. Validate is the runtime authority on what a valid document is;
// the database re-checks the same rules (T-03, parity test), and the
// published JSON Schemas in schema/ are kept in step by a test.
package model

import "encoding/json"

// Kinds of document.
const (
	KindScenario        = "scenario"
	KindAsset           = "asset"
	KindAssetGroup      = "asset_group"
	KindThreatCommunity = "threat_community"
	KindLossProfile     = "loss_profile"
	KindControl         = "control"
	KindReferenceClass  = "reference_class" // F-004 design §3.8
)

// Kinds lists every document kind.
var Kinds = []string{KindScenario, KindAsset, KindAssetGroup, KindThreatCommunity, KindLossProfile, KindControl, KindReferenceClass}

// SchemaVersion is the document schema version this release writes and reads.
const SchemaVersion = 1

// Units of an estimate (design §3.2, §3.5).
const (
	UnitEventsPerYear = "events_per_year" // LEF, TEF, contact frequency
	UnitProbability   = "probability"     // probability of action, Vulnerability, SLEF
	UnitCurrency      = "currency"        // magnitudes, in the installation currency
	UnitPercentile    = "percentile"      // threat capability, resistance strength
	UnitFraction      = "fraction"        // a control's reduction of a factor
)

// FormsOfLoss are the six Open FAIR forms of loss (AC-04).
var FormsOfLoss = []string{"productivity", "response", "replacement", "fines_judgments", "competitive_advantage", "reputation"}

// ThreatEffects are the threat effects a scenario may name (AC-01).
var ThreatEffects = []string{"confidentiality", "integrity", "availability"}

// SourceTypes are the kinds of an estimate's source (AC-05). An
// "elicitation" source names the estimate request an estimate was accepted
// from (F-004 design §3.4), and goes with the estimate's elicitation
// provenance.
var SourceTypes = []string{"person", "document", "dataset", "integration", SourceElicitation}

// SourceElicitation is the source type of an accepted estimate request.
const SourceElicitation = "elicitation"

// ElicitationMethods are how an accepted estimate was made from the answers
// to an estimate request (F-004 design §3.4).
var ElicitationMethods = []string{"single", "equal", "calibration", "own"}

// CalibrationClasses classify a person's calibration (F-004 design §3.6).
var CalibrationClasses = []string{"calibrated", "overconfident", "underconfident", "not_measured"}

// Decimal is a decimal number, written in a document as a canonical decimal
// string (canon.Decimal). On input it may be a JSON number or a string.
type Decimal string

// UnmarshalJSON takes a JSON number or string as given; Validate checks and
// canonicalises it (so that a bad value is reported with its pointer).
func (d *Decimal) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		*d = Decimal(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*d = Decimal(s)
	return nil
}

// Estimate is a calibrated range with its provenance (AC-05, AC-06).
type Estimate struct {
	Min        Decimal  `json:"min"`
	ML         Decimal  `json:"ml"`
	Max        Decimal  `json:"max"`
	Unit       string   `json:"unit"`
	Confidence Decimal  `json:"confidence"`
	Rationale  string   `json:"rationale"`
	Sources    []Source `json:"sources"`
	// Elicitation is the provenance of an estimate accepted from an
	// estimate request (F-004 design §3.5).
	Elicitation *Elicitation `json:"elicitation,omitempty"`
}

// Elicitation records how an estimate was accepted from an estimate
// request: the request, the method, and the answers used, each with its
// estimator, weight and calibration at the time (F-004 AC-17, AC-18).
type Elicitation struct {
	Request    string           `json:"request"`
	Method     string           `json:"method"`
	Confidence Decimal          `json:"confidence"`
	Answers    []ElicitedAnswer `json:"answers"`
}

// ElicitedAnswer is one answer an accepted estimate used.
type ElicitedAnswer struct {
	Estimator   string      `json:"estimator"`
	Name        string      `json:"name"`
	Revision    int64       `json:"revision"`
	Weight      Decimal     `json:"weight"`
	Min         Decimal     `json:"min"`
	ML          Decimal     `json:"ml"`
	Max         Decimal     `json:"max"`
	Confidence  Decimal     `json:"confidence"`
	Calibration Calibration `json:"calibration"`
}

// Calibration is an estimator's calibration when they answered.
type Calibration struct {
	Class     string   `json:"class"`
	RangeRate *Decimal `json:"range_rate,omitempty"`
	AsOf      string   `json:"as_of"`
}

// Source is where an estimate came from.
type Source struct {
	Type string `json:"type"`
	Ref  string `json:"ref"`
	Note string `json:"note,omitempty"`
}

// Pin names one version of a library entry or control.
type Pin struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

// AssetPin names the scenario's asset: an asset or an asset group.
type AssetPin struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

// Scenario is a loss scenario (AC-01 to AC-04, AC-12, AC-13, AC-29).
type Scenario struct {
	Kind            string                 `json:"kind"`
	SchemaVersion   int                    `json:"schema_version"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description,omitempty"`
	Scope           Scope                  `json:"scope"`
	AnalysisPeriod  Period                 `json:"analysis_period"`
	Owner           string                 `json:"owner"`
	Asset           AssetPin               `json:"asset"`
	ThreatCommunity Pin                    `json:"threat_community"`
	ThreatEffects   []string               `json:"threat_effects"`
	LossEvent       string                 `json:"loss_event"`
	LEF             LEF                    `json:"lef"`
	PrimaryLoss     map[string]Estimate    `json:"primary_loss"`
	SecondaryRisk   []SecondaryStakeholder `json:"secondary_risk,omitempty"`
	ControlSets     []ControlSet           `json:"control_sets"`
}

// Scope states what the scenario covers (AC-02).
type Scope struct {
	In  string `json:"in"`
	Out string `json:"out,omitempty"`
}

// Period is the analysis period, as dates (YYYY-MM-DD).
type Period struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// LEF is the loss event frequency branch: estimated directly ("lef") or
// from threat event frequency and Vulnerability ("tef_vuln").
type LEF struct {
	Level         string         `json:"level"`
	Estimate      *Estimate      `json:"estimate,omitempty"`
	TEF           *TEF           `json:"tef,omitempty"`
	Vulnerability *Vulnerability `json:"vulnerability,omitempty"`
}

// TEF is the threat event frequency branch: estimated directly ("tef") or
// from contact frequency and probability of action ("cf_poa").
type TEF struct {
	Level               string    `json:"level"`
	Estimate            *Estimate `json:"estimate,omitempty"`
	ContactFrequency    *Estimate `json:"contact_frequency,omitempty"`
	ProbabilityOfAction *Estimate `json:"probability_of_action,omitempty"`
}

// Vulnerability is estimated directly as a probability ("direct") or derived
// from threat capability against resistance strength ("derived") (AC-29).
type Vulnerability struct {
	Level              string            `json:"level"`
	Estimate           *Estimate         `json:"estimate,omitempty"`
	ThreatCapability   *ThreatCapability `json:"threat_capability,omitempty"`
	ResistanceStrength *Estimate         `json:"resistance_strength,omitempty"`
}

// ThreatCapability comes from the pinned threat community's estimate
// ("threat_community") or is entered on the scenario ("scenario").
type ThreatCapability struct {
	Source   string    `json:"source"`
	Estimate *Estimate `json:"estimate,omitempty"`
}

// SecondaryStakeholder is one secondary stakeholder group's secondary risk:
// its secondary loss event frequency (a probability per primary loss event)
// and secondary loss magnitude per form (AC-04).
type SecondaryStakeholder struct {
	Stakeholder string              `json:"stakeholder"`
	SLEF        Estimate            `json:"slef"`
	Loss        map[string]Estimate `json:"loss"`
}

// ControlSet is the current state or a named alternative (AC-13).
type ControlSet struct {
	Name     string       `json:"name"`
	Current  bool         `json:"current"`
	Controls []ControlUse `json:"controls"`
}

// ControlUse is a pinned control in a set, in place or proposed, optionally
// with effects overriding the control's own for this scenario (AC-12).
type ControlUse struct {
	ID      string   `json:"id"`
	Version int64    `json:"version"`
	Status  string   `json:"status"`
	Effects []Effect `json:"effects,omitempty"`
}

// Effect is a control's effect on one FAIR factor (design §3.5): a fraction
// by which contact frequency, probability of action, threat capability or a
// form of loss ("loss.<form>") is reduced, or the resistance strength the
// control provides (a percentile).
type Effect struct {
	Factor   string   `json:"factor"`
	Estimate Estimate `json:"estimate"`
}

// Asset is a library asset (AC-08): its value is an estimate or a basis in
// words, exactly one.
type Asset struct {
	Kind          string    `json:"kind"`
	SchemaVersion int       `json:"schema_version"`
	Name          string    `json:"name"`
	AssetType     string    `json:"asset_type"`
	Description   string    `json:"description,omitempty"`
	Value         *Estimate `json:"value,omitempty"`
	ValueBasis    string    `json:"value_basis,omitempty"`
}

// AssetGroup is a named set of assets, valued as a whole (with its own
// value) or by its members (OQ7).
type AssetGroup struct {
	Kind          string    `json:"kind"`
	SchemaVersion int       `json:"schema_version"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Members       []Pin     `json:"members"`
	Valuation     string    `json:"valuation"`
	Value         *Estimate `json:"value,omitempty"`
}

// ThreatCommunity is a library threat community with its threat capability.
type ThreatCommunity struct {
	Kind             string   `json:"kind"`
	SchemaVersion    int      `json:"schema_version"`
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	ThreatCapability Estimate `json:"threat_capability"`
}

// LossProfile holds typical magnitudes per form of loss.
type LossProfile struct {
	Kind          string              `json:"kind"`
	SchemaVersion int                 `json:"schema_version"`
	Name          string              `json:"name"`
	Description   string              `json:"description,omitempty"`
	Magnitudes    map[string]Estimate `json:"magnitudes"`
}

// Control is a safeguard with its effects and framework references (AC-12,
// AC-14).
type Control struct {
	Kind          string      `json:"kind"`
	SchemaVersion int         `json:"schema_version"`
	Name          string      `json:"name"`
	Description   string      `json:"description,omitempty"`
	References    []Reference `json:"references,omitempty"`
	Effects       []Effect    `json:"effects"`
}

// ReferenceClass is the customer's own data to inform estimates: counts of
// events over periods, or observed losses (F-004 AC-13; design §3.8).
type ReferenceClass struct {
	Kind          string        `json:"kind"`
	SchemaVersion int           `json:"schema_version"`
	Name          string        `json:"name"`
	Description   string        `json:"description,omitempty"`
	Period        Period        `json:"period"`
	Data          ReferenceData `json:"data"`
	Sources       []Source      `json:"sources"`
}

// ReferenceData is a reference class's data: kind "counts" with a series,
// or kind "losses" with amounts in the installation currency.
type ReferenceData struct {
	Kind    string        `json:"kind"`
	Unit    string        `json:"unit,omitempty"`
	Series  []CountPeriod `json:"series,omitempty"`
	Amounts []Decimal     `json:"amounts,omitempty"`
}

// CountPeriod is a count of events in a period.
type CountPeriod struct {
	Start string `json:"start"`
	End   string `json:"end"`
	Count int64  `json:"count"`
}

// Reference is a control's identifier in an external framework, as text
// until F-013 provides managed crosswalks.
type Reference struct {
	Framework  string `json:"framework"`
	Identifier string `json:"identifier"`
}
