package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/pkg/audit"
)

// Limits (design §3.3, §8).
const (
	MaxDocumentBytes = 1 << 20 // one document
	MaxName          = 200     // names
	MaxLine          = 1000    // other single-line text
	MaxText          = 10000   // descriptions, scope, loss event, rationale
	MaxSources       = 20
	MaxControlSets   = 20
	MaxControlsInSet = 200
	MaxStakeholders  = 20
	MaxMembers       = 1000
	MaxReferences    = 50
	MaxEffects       = 20
	MaxAnswers       = 50   // answers an accepted estimate used (F-004 design §4.4)
	MaxSeries        = 200  // a reference class's count periods (F-004 design §3.8)
	MaxAmounts       = 1000 // a reference class's observed losses
)

// Problem is one reason a document is invalid, at a JSON pointer (RFC 6901;
// "" is the whole document).
type Problem struct {
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}

// Problems is every reason a document is invalid.
type Problems []Problem

func (p Problems) Error() string {
	s := make([]string, len(p))
	for i, x := range p {
		s[i] = x.Pointer + ": " + x.Message
	}
	return "invalid document: " + strings.Join(s, "; ")
}

// PinRef is one pin a document holds, with where it is.
type PinRef struct {
	Kind    string // asset, asset_group, threat_community, control
	ID      string
	Version int64
	Pointer string
}

// Document is a valid document in canonical form.
type Document struct {
	Kind      string
	Value     any    // *Scenario, *Asset, *AssetGroup, *ThreatCommunity, *LossProfile, *Control or *ReferenceClass
	Canonical []byte // canonical JSON (package canon)
	Digest    string // hex SHA-256 of Canonical
	Pins      []PinRef
}

// Validate checks raw as a document of the given kind and returns it in
// canonical form, or every problem found. Structural problems (bad JSON,
// unknown or mistyped fields) stop at the first; rule problems are all
// reported.
func Validate(kind string, raw []byte) (*Document, Problems) {
	v := &validator{}
	if len(raw) > MaxDocumentBytes {
		return nil, Problems{{"", fmt.Sprintf("larger than %d bytes", MaxDocumentBytes)}}
	}
	generic, err := canon.Parse(raw)
	if err != nil {
		return nil, Problems{{"", "not a JSON document: " + err.Error()}}
	}
	obj, ok := generic.(map[string]any)
	if !ok {
		return nil, Problems{{"", "not a JSON object"}}
	}
	if k, _ := obj["kind"].(string); k != kind {
		return nil, Problems{{"/kind", fmt.Sprintf("is %q, want %q", k, kind)}}
	}
	var doc any
	switch kind {
	case KindScenario:
		doc = &Scenario{}
	case KindAsset:
		doc = &Asset{}
	case KindAssetGroup:
		doc = &AssetGroup{}
	case KindThreatCommunity:
		doc = &ThreatCommunity{}
	case KindLossProfile:
		doc = &LossProfile{}
	case KindControl:
		doc = &Control{}
	case KindReferenceClass:
		doc = &ReferenceClass{}
	default:
		return nil, Problems{{"/kind", fmt.Sprintf("unknown kind %q", kind)}}
	}
	var unknown Problems
	unknownFields(reflect.TypeOf(doc), generic, "", &unknown)
	if len(unknown) > 0 {
		return nil, unknown
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(doc); err != nil {
		return nil, Problems{structural(err)}
	}
	switch x := doc.(type) {
	case *Scenario:
		v.scenario(x)
	case *Asset:
		v.asset(x)
	case *AssetGroup:
		v.assetGroup(x)
	case *ThreatCommunity:
		v.header(x.SchemaVersion)
		v.text("/name", x.Name, MaxName, true, false)
		v.text("/description", x.Description, MaxText, false, true)
		v.estimate("/threat_capability", &x.ThreatCapability, UnitPercentile)
	case *LossProfile:
		v.header(x.SchemaVersion)
		v.text("/name", x.Name, MaxName, true, false)
		v.text("/description", x.Description, MaxText, false, true)
		v.lossMap("/magnitudes", x.Magnitudes)
	case *Control:
		v.control(x)
	case *ReferenceClass:
		v.referenceClass(x)
	}
	if len(v.problems) > 0 {
		return nil, v.problems
	}
	out, err := json.Marshal(doc)
	if err == nil {
		out, err = canon.Canonicalize(out)
	}
	if err != nil {
		return nil, Problems{{"", "cannot write the canonical form: " + err.Error()}}
	}
	return &Document{Kind: kind, Value: doc, Canonical: out, Digest: canon.Digest(out), Pins: v.pins}, nil
}

// structural turns a decoding error into a problem, with a pointer where
// encoding/json gives a field path.
func structural(err error) Problem {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) && te.Field != "" {
		return Problem{"/" + strings.ReplaceAll(te.Field, ".", "/"), fmt.Sprintf("must be %s, not %s", jsonType(te.Type.Kind().String()), te.Value)}
	}
	msg := strings.TrimPrefix(err.Error(), "json: ")
	return Problem{"", msg}
}

func jsonType(k string) string {
	switch k {
	case "string":
		return "a string"
	case "bool":
		return "true or false"
	case "int", "int64":
		return "an integer"
	case "slice":
		return "an array"
	case "map", "struct", "ptr":
		return "an object"
	}
	return k
}

// unknownFields reports every member of the parsed document that its Go
// type does not have, at its pointer (encoding/json names only the first,
// without a path).
func unknownFields(t reflect.Type, v any, ptr string, out *Problems) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return // a type error, which decoding reports
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			fields[name] = t.Field(i).Type
		}
		for _, k := range sortedKeys(m) {
			ft, ok := fields[k]
			if !ok {
				*out = append(*out, Problem{ptr + "/" + ptrKey(k), "is not a field of this document"})
				continue
			}
			unknownFields(ft, m[k], ptr+"/"+ptrKey(k), out)
		}
	case reflect.Map:
		if m, ok := v.(map[string]any); ok {
			for _, k := range sortedKeys(m) {
				unknownFields(t.Elem(), m[k], ptr+"/"+ptrKey(k), out)
			}
		}
	case reflect.Slice:
		if a, ok := v.([]any); ok {
			for i, x := range a {
				unknownFields(t.Elem(), x, fmt.Sprintf("%s/%d", ptr, i), out)
			}
		}
	}
}

type validator struct {
	problems Problems
	pins     []PinRef
}

func (v *validator) add(ptr, format string, args ...any) {
	v.problems = append(v.problems, Problem{ptr, fmt.Sprintf(format, args...)})
}

func ptrKey(k string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(k) }

func (v *validator) header(schema int) {
	if schema != SchemaVersion {
		v.add("/schema_version", "is %d, want %d", schema, SchemaVersion)
	}
}

// text checks a text field: required, length in characters, single line,
// no control characters but newline and tab in multi-line text, nothing
// that looks like a secret (AC-23).
func (v *validator) text(ptr, s string, max int, required, multiline bool) {
	switch {
	case required && strings.TrimSpace(s) == "":
		v.add(ptr, "is required")
		return
	case utf8.RuneCountInString(s) > max:
		v.add(ptr, "is longer than %d characters", max)
		return
	}
	for _, r := range s {
		if r == '\n' || r == '\r' {
			if !multiline {
				v.add(ptr, "must be a single line")
				return
			}
			continue
		}
		if (r < 0x20 && r != '\t') || r == 0x7f {
			v.add(ptr, "contains a control character")
			return
		}
	}
	if audit.LooksSecret(s) {
		v.add(ptr, "looks like a secret; secrets do not belong in risk data")
	}
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (v *validator) uuid(ptr string, id *string) {
	*id = strings.ToLower(*id)
	if !uuidRE.MatchString(*id) {
		v.add(ptr, "must be a UUID")
	}
}

func (v *validator) pin(ptr, kind string, p *Pin) {
	v.uuid(ptr+"/id", &p.ID)
	if p.Version < 1 {
		v.add(ptr+"/version", "must be 1 or more")
	}
	v.pins = append(v.pins, PinRef{kind, p.ID, p.Version, ptr})
}

func oneOf(s string, set []string) bool { return slices.Contains(set, s) }

// decimal canonicalises a decimal in place and returns its value (nil if
// invalid, reported).
func (v *validator) decimal(ptr string, d *Decimal) *big.Rat {
	if *d == "" {
		v.add(ptr, "is required")
		return nil
	}
	c, err := canon.Decimal(string(*d))
	if err != nil {
		v.add(ptr, "%v", err)
		return nil
	}
	*d = Decimal(c)
	r, _ := new(big.Rat).SetString(c)
	return r
}

var (
	ratZero    = new(big.Rat)
	ratOne     = big.NewRat(1, 1)
	ratHundred = big.NewRat(100, 1)
)

// estimate checks an estimate for the unit its factor needs (AC-05, AC-06).
func (v *validator) estimate(ptr string, e *Estimate, unit string) {
	if e.Unit != unit {
		v.add(ptr+"/unit", "is %q; this factor is estimated in %q", e.Unit, unit)
	}
	v.triple(ptr, &e.Min, &e.ML, &e.Max, unit)
	v.confidence(ptr+"/confidence", &e.Confidence)
	v.text(ptr+"/rationale", e.Rationale, MaxText, true, true)
	request := ""
	if e.Elicitation != nil {
		v.elicitation(ptr+"/elicitation", e.Elicitation, unit)
		request = e.Elicitation.Request
	}
	v.sources(ptr+"/sources", e.Sources, request)
}

// triple checks a minimum, most likely and maximum for a unit: decimals,
// ordered, within the unit's range.
func (v *validator) triple(ptr string, min, ml, max *Decimal, unit string) {
	lo, m, hi := v.decimal(ptr+"/min", min), v.decimal(ptr+"/ml", ml), v.decimal(ptr+"/max", max)
	if lo != nil && m != nil && hi != nil && (lo.Cmp(m) > 0 || m.Cmp(hi) > 0) {
		v.add(ptr, "must be ordered: min ≤ ml ≤ max")
	}
	for _, x := range []struct {
		name string
		r    *big.Rat
	}{{"min", lo}, {"ml", m}, {"max", hi}} {
		if x.r == nil {
			continue
		}
		switch {
		case x.r.Sign() < 0:
			v.add(ptr+"/"+x.name, "must not be negative")
		case (unit == UnitProbability || unit == UnitFraction) && x.r.Cmp(ratOne) > 0:
			v.add(ptr+"/"+x.name, "must be between 0 and 1")
		case unit == UnitPercentile && x.r.Cmp(ratHundred) > 0:
			v.add(ptr+"/"+x.name, "must be between 0 and 100")
		}
	}
}

// confidence checks a confidence level: between 0 and 1, exclusive.
func (v *validator) confidence(ptr string, d *Decimal) {
	if c := v.decimal(ptr, d); c != nil && (c.Cmp(ratZero) <= 0 || c.Cmp(ratOne) >= 0) {
		v.add(ptr, "must be between 0 and 1, exclusive")
	}
}

// sources checks an estimate's or a reference class's sources. An
// elicitation source is allowed only with elicitation provenance, and then
// one of them must name its request (F-004 design §3.4).
func (v *validator) sources(ptr string, sources []Source, request string) {
	switch {
	case len(sources) == 0:
		v.add(ptr, "at least one source is required")
	case len(sources) > MaxSources:
		v.add(ptr, "at most %d sources", MaxSources)
	}
	named := false
	for i := range sources {
		s := &sources[i]
		sp := fmt.Sprintf("%s/%d", ptr, i)
		switch {
		case !oneOf(s.Type, SourceTypes):
			v.add(sp+"/type", "is %q, want one of %s", s.Type, strings.Join(SourceTypes, ", "))
		case s.Type == SourceElicitation && request == "":
			v.add(sp+"/type", "is elicitation, which goes only with an accepted estimate's elicitation provenance")
		case s.Type == SourceElicitation && strings.ToLower(s.Ref) == request:
			named = true
		}
		v.text(sp+"/ref", s.Ref, MaxLine, true, false)
		v.text(sp+"/note", s.Note, MaxLine, false, false)
	}
	if request != "" && !named && len(sources) > 0 {
		v.add(ptr, "must include an elicitation source whose ref is the request %s", request)
	}
}

// elicitation checks an accepted estimate's provenance (F-004 design §3.5).
// That the values follow from the answers by the method is checked where
// the answers are known (F-004 T-08).
func (v *validator) elicitation(ptr string, el *Elicitation, unit string) {
	v.uuid(ptr+"/request", &el.Request)
	if !oneOf(el.Method, ElicitationMethods) {
		v.add(ptr+"/method", "is %q, want one of %s", el.Method, strings.Join(ElicitationMethods, ", "))
	}
	v.confidence(ptr+"/confidence", &el.Confidence)
	n := len(el.Answers)
	switch {
	case n > MaxAnswers:
		v.add(ptr+"/answers", "at most %d answers", MaxAnswers)
	case el.Method == "single" && n != 1:
		v.add(ptr+"/answers", "the single method uses exactly one answer")
	case (el.Method == "equal" || el.Method == "calibration") && n == 0:
		v.add(ptr+"/answers", "a pool uses at least one answer")
	}
	seen := map[string]bool{}
	for i := range el.Answers {
		a := &el.Answers[i]
		ap := fmt.Sprintf("%s/answers/%d", ptr, i)
		v.uuid(ap+"/estimator", &a.Estimator)
		if seen[a.Estimator] {
			v.add(ap+"/estimator", "the estimator's answer is listed twice")
		}
		seen[a.Estimator] = true
		v.text(ap+"/name", a.Name, MaxName, true, false)
		if a.Revision < 1 {
			v.add(ap+"/revision", "must be 1 or more")
		}
		if w := v.decimal(ap+"/weight", &a.Weight); w != nil && (w.Sign() < 0 || w.Cmp(ratOne) > 0) {
			v.add(ap+"/weight", "must be between 0 and 1")
		}
		v.triple(ap, &a.Min, &a.ML, &a.Max, unit)
		v.confidence(ap+"/confidence", &a.Confidence)
		cp := ap + "/calibration"
		if !oneOf(a.Calibration.Class, CalibrationClasses) {
			v.add(cp+"/class", "is %q, want one of %s", a.Calibration.Class, strings.Join(CalibrationClasses, ", "))
		}
		if a.Calibration.RangeRate != nil {
			if r := v.decimal(cp+"/range_rate", a.Calibration.RangeRate); r != nil && r.Cmp(ratOne) > 0 {
				v.add(cp+"/range_rate", "must be between 0 and 1")
			}
		}
		if _, err := time.Parse(time.DateOnly, a.Calibration.AsOf); err != nil {
			v.add(cp+"/as_of", "must be a date (YYYY-MM-DD)")
		}
	}
}

// required and absent check the fields a level uses (AC-03: exactly the
// estimates the level needs).
func (v *validator) requiredEstimate(ptr string, e *Estimate, unit string) {
	if e == nil {
		v.add(ptr, "is required at this level")
		return
	}
	v.estimate(ptr, e, unit)
}

func (v *validator) absent(ptr string, present bool, level string) {
	if present {
		v.add(ptr, "is not used at level %q", level)
	}
}

func (v *validator) lossMap(ptr string, m map[string]Estimate) {
	if len(m) == 0 {
		v.add(ptr, "at least one form of loss is required")
	}
	for _, form := range sortedKeys(m) {
		if !oneOf(form, FormsOfLoss) {
			v.add(ptr+"/"+ptrKey(form), "is not an Open FAIR form of loss (%s)", strings.Join(FormsOfLoss, ", "))
			continue
		}
		e := m[form]
		v.estimate(ptr+"/"+form, &e, UnitCurrency)
		m[form] = e
	}
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	slices.Sort(k)
	return k
}

func (v *validator) scenario(s *Scenario) {
	v.header(s.SchemaVersion)
	v.text("/name", s.Name, MaxName, true, false)
	v.text("/description", s.Description, MaxText, false, true)
	v.text("/scope/in", s.Scope.In, MaxText, true, true)
	v.text("/scope/out", s.Scope.Out, MaxText, false, true)
	start, err1 := time.Parse(time.DateOnly, s.AnalysisPeriod.Start)
	end, err2 := time.Parse(time.DateOnly, s.AnalysisPeriod.End)
	if err1 != nil {
		v.add("/analysis_period/start", "must be a date (YYYY-MM-DD)")
	}
	if err2 != nil {
		v.add("/analysis_period/end", "must be a date (YYYY-MM-DD)")
	}
	if err1 == nil && err2 == nil && !end.After(start) {
		v.add("/analysis_period", "must end after it starts")
	}
	v.uuid("/owner", &s.Owner)

	// The asset (or asset group) and the threat community (AC-02).
	if s.Asset.Kind != KindAsset && s.Asset.Kind != KindAssetGroup {
		v.add("/asset/kind", "is %q, want %q or %q", s.Asset.Kind, KindAsset, KindAssetGroup)
	}
	p := Pin{s.Asset.ID, s.Asset.Version}
	v.pin("/asset", s.Asset.Kind, &p)
	s.Asset.ID = p.ID
	v.pin("/threat_community", KindThreatCommunity, &s.ThreatCommunity)

	switch {
	case len(s.ThreatEffects) == 0:
		v.add("/threat_effects", "at least one threat effect is required")
	default:
		seen := map[string]bool{}
		for i, t := range s.ThreatEffects {
			switch {
			case !oneOf(t, ThreatEffects):
				v.add(fmt.Sprintf("/threat_effects/%d", i), "is %q, want one of %s", t, strings.Join(ThreatEffects, ", "))
			case seen[t]:
				v.add(fmt.Sprintf("/threat_effects/%d", i), "%q is listed twice", t)
			}
			seen[t] = true
		}
		// Order carries no meaning: the canonical form sorts them.
		slices.Sort(s.ThreatEffects)
	}
	v.text("/loss_event", s.LossEvent, MaxText, true, true)

	v.lef(&s.LEF)
	v.lossMap("/primary_loss", s.PrimaryLoss)

	if len(s.SecondaryRisk) > MaxStakeholders {
		v.add("/secondary_risk", "at most %d secondary stakeholder groups", MaxStakeholders)
	}
	names := map[string]bool{}
	for i := range s.SecondaryRisk {
		g := &s.SecondaryRisk[i]
		gp := fmt.Sprintf("/secondary_risk/%d", i)
		v.text(gp+"/stakeholder", g.Stakeholder, MaxName, true, false)
		if names[g.Stakeholder] {
			v.add(gp+"/stakeholder", "%q is listed twice", g.Stakeholder)
		}
		names[g.Stakeholder] = true
		v.estimate(gp+"/slef", &g.SLEF, UnitProbability)
		v.lossMap(gp+"/loss", g.Loss)
	}

	v.controlSets(s.ControlSets)
}

func (v *validator) lef(l *LEF) {
	const p = "/lef"
	switch l.Level {
	case "lef":
		v.requiredEstimate(p+"/estimate", l.Estimate, UnitEventsPerYear)
		v.absent(p+"/tef", l.TEF != nil, l.Level)
		v.absent(p+"/vulnerability", l.Vulnerability != nil, l.Level)
	case "tef_vuln":
		v.absent(p+"/estimate", l.Estimate != nil, l.Level)
		if l.TEF == nil {
			v.add(p+"/tef", "is required at this level")
		} else {
			v.tef(l.TEF)
		}
		if l.Vulnerability == nil {
			v.add(p+"/vulnerability", "is required at this level")
		} else {
			v.vulnerability(l.Vulnerability)
		}
	default:
		v.add(p+"/level", "is %q, want \"lef\" or \"tef_vuln\"", l.Level)
	}
}

func (v *validator) tef(t *TEF) {
	const p = "/lef/tef"
	switch t.Level {
	case "tef":
		v.requiredEstimate(p+"/estimate", t.Estimate, UnitEventsPerYear)
		v.absent(p+"/contact_frequency", t.ContactFrequency != nil, t.Level)
		v.absent(p+"/probability_of_action", t.ProbabilityOfAction != nil, t.Level)
	case "cf_poa":
		v.absent(p+"/estimate", t.Estimate != nil, t.Level)
		v.requiredEstimate(p+"/contact_frequency", t.ContactFrequency, UnitEventsPerYear)
		v.requiredEstimate(p+"/probability_of_action", t.ProbabilityOfAction, UnitProbability)
	default:
		v.add(p+"/level", "is %q, want \"tef\" or \"cf_poa\"", t.Level)
	}
}

func (v *validator) vulnerability(x *Vulnerability) {
	const p = "/lef/vulnerability"
	switch x.Level {
	case "direct":
		v.requiredEstimate(p+"/estimate", x.Estimate, UnitProbability)
		v.absent(p+"/threat_capability", x.ThreatCapability != nil, x.Level)
		v.absent(p+"/resistance_strength", x.ResistanceStrength != nil, x.Level)
	case "derived":
		v.absent(p+"/estimate", x.Estimate != nil, x.Level)
		switch {
		case x.ThreatCapability == nil:
			v.add(p+"/threat_capability", "is required at this level")
		case x.ThreatCapability.Source == "threat_community":
			if x.ThreatCapability.Estimate != nil {
				v.add(p+"/threat_capability/estimate", "is not used when threat capability comes from the threat community")
			}
		case x.ThreatCapability.Source == "scenario":
			v.requiredEstimate(p+"/threat_capability/estimate", x.ThreatCapability.Estimate, UnitPercentile)
		default:
			v.add(p+"/threat_capability/source", "is %q, want \"threat_community\" or \"scenario\"", x.ThreatCapability.Source)
		}
		v.requiredEstimate(p+"/resistance_strength", x.ResistanceStrength, UnitPercentile)
	default:
		v.add(p+"/level", "is %q, want \"direct\" or \"derived\"", x.Level)
	}
}

func (v *validator) controlSets(sets []ControlSet) {
	switch {
	case len(sets) == 0:
		v.add("/control_sets", "the current control set is required")
		return
	case len(sets) > MaxControlSets:
		v.add("/control_sets", "at most %d control sets", MaxControlSets)
	}
	current := 0
	names := map[string]bool{}
	for i := range sets {
		cs := &sets[i]
		sp := fmt.Sprintf("/control_sets/%d", i)
		v.text(sp+"/name", cs.Name, MaxName, true, false)
		if names[cs.Name] {
			v.add(sp+"/name", "%q is used twice", cs.Name)
		}
		names[cs.Name] = true
		if cs.Current {
			current++
		}
		if len(cs.Controls) > MaxControlsInSet {
			v.add(sp+"/controls", "at most %d controls in a set", MaxControlsInSet)
		}
		ids := map[string]bool{}
		for j := range cs.Controls {
			c := &cs.Controls[j]
			cp := fmt.Sprintf("%s/controls/%d", sp, j)
			p := Pin{c.ID, c.Version}
			v.pin(cp, KindControl, &p)
			c.ID = p.ID
			if ids[c.ID] {
				v.add(cp+"/id", "the control is in this set twice")
			}
			ids[c.ID] = true
			if c.Status != "in_place" && c.Status != "proposed" {
				v.add(cp+"/status", "is %q, want \"in_place\" or \"proposed\"", c.Status)
			}
			if len(c.Effects) > 0 {
				v.effects(cp+"/effects", c.Effects)
			}
		}
	}
	if current != 1 {
		v.add("/control_sets", "exactly one control set must be current; %d are", current)
	}
}

// Factors a control can affect, and the unit of its effect (design §3.5).
func effectUnit(factor string) (string, bool) {
	switch factor {
	case "contact_frequency", "probability_of_action", "threat_capability":
		return UnitFraction, true
	case "resistance_strength":
		return UnitPercentile, true
	}
	if form, ok := strings.CutPrefix(factor, "loss."); ok && oneOf(form, FormsOfLoss) {
		return UnitFraction, true
	}
	return "", false
}

func (v *validator) effects(ptr string, effects []Effect) {
	switch {
	case len(effects) == 0:
		v.add(ptr, "at least one effect is required")
	case len(effects) > MaxEffects:
		v.add(ptr, "at most %d effects", MaxEffects)
	}
	seen := map[string]bool{}
	for i := range effects {
		e := &effects[i]
		ep := fmt.Sprintf("%s/%d", ptr, i)
		unit, ok := effectUnit(e.Factor)
		if !ok {
			v.add(ep+"/factor", "is %q, not a factor a control affects", e.Factor)
			continue
		}
		if seen[e.Factor] {
			v.add(ep+"/factor", "%q is listed twice", e.Factor)
		}
		seen[e.Factor] = true
		v.estimate(ep+"/estimate", &e.Estimate, unit)
	}
}

func (v *validator) asset(a *Asset) {
	v.header(a.SchemaVersion)
	v.text("/name", a.Name, MaxName, true, false)
	v.text("/asset_type", a.AssetType, MaxName, true, false)
	v.text("/description", a.Description, MaxText, false, true)
	switch {
	case a.Value != nil && a.ValueBasis != "":
		v.add("/value", "give a value or a value basis, not both")
	case a.Value != nil:
		v.estimate("/value", a.Value, UnitCurrency)
	default:
		v.text("/value_basis", a.ValueBasis, MaxText, true, true)
	}
}

func (v *validator) assetGroup(g *AssetGroup) {
	v.header(g.SchemaVersion)
	v.text("/name", g.Name, MaxName, true, false)
	v.text("/description", g.Description, MaxText, false, true)
	switch {
	case len(g.Members) == 0:
		v.add("/members", "at least one member asset is required")
	case len(g.Members) > MaxMembers:
		v.add("/members", "at most %d members", MaxMembers)
	}
	ids := map[string]bool{}
	for i := range g.Members {
		mp := fmt.Sprintf("/members/%d", i)
		v.pin(mp, KindAsset, &g.Members[i])
		if ids[g.Members[i].ID] {
			v.add(mp+"/id", "the asset is a member twice")
		}
		ids[g.Members[i].ID] = true
	}
	switch g.Valuation {
	case "whole":
		v.requiredEstimate("/value", g.Value, UnitCurrency)
	case "members":
		if g.Value != nil {
			v.add("/value", "is not used when the group is valued by its members")
		}
	default:
		v.add("/valuation", "is %q, want \"whole\" or \"members\"", g.Valuation)
	}
}

// referenceClass checks a reference class (F-004 AC-13; design §3.8).
func (v *validator) referenceClass(r *ReferenceClass) {
	v.header(r.SchemaVersion)
	v.text("/name", r.Name, MaxName, true, false)
	v.text("/description", r.Description, MaxText, false, true)
	v.period("/period", r.Period)
	d := &r.Data
	switch d.Kind {
	case "counts":
		if d.Unit != "" {
			v.add("/data/unit", "is not used with counts")
		}
		if len(d.Amounts) > 0 {
			v.add("/data/amounts", "is not used with counts")
		}
		switch {
		case len(d.Series) == 0:
			v.add("/data/series", "at least one period is required")
		case len(d.Series) > MaxSeries:
			v.add("/data/series", "at most %d periods", MaxSeries)
		}
		for i, c := range d.Series {
			sp := fmt.Sprintf("/data/series/%d", i)
			v.period(sp, Period{c.Start, c.End})
			if c.Count < 0 {
				v.add(sp+"/count", "must not be negative")
			}
		}
	case "losses":
		if d.Unit != UnitCurrency {
			v.add("/data/unit", "is %q, want %q", d.Unit, UnitCurrency)
		}
		if len(d.Series) > 0 {
			v.add("/data/series", "is not used with losses")
		}
		switch {
		case len(d.Amounts) == 0:
			v.add("/data/amounts", "at least one amount is required")
		case len(d.Amounts) > MaxAmounts:
			v.add("/data/amounts", "at most %d amounts", MaxAmounts)
		}
		for i := range d.Amounts {
			ap := fmt.Sprintf("/data/amounts/%d", i)
			if a := v.decimal(ap, &d.Amounts[i]); a != nil && a.Sign() < 0 {
				v.add(ap, "must not be negative")
			}
		}
	default:
		v.add("/data/kind", "is %q, want counts or losses", d.Kind)
	}
	v.sources("/sources", r.Sources, "")
}

// period checks a period of dates that ends after it starts.
func (v *validator) period(ptr string, p Period) {
	start, err1 := time.Parse(time.DateOnly, p.Start)
	end, err2 := time.Parse(time.DateOnly, p.End)
	if err1 != nil {
		v.add(ptr+"/start", "must be a date (YYYY-MM-DD)")
	}
	if err2 != nil {
		v.add(ptr+"/end", "must be a date (YYYY-MM-DD)")
	}
	if err1 == nil && err2 == nil && !end.After(start) {
		v.add(ptr, "must end after it starts")
	}
}

func (v *validator) control(c *Control) {
	v.header(c.SchemaVersion)
	v.text("/name", c.Name, MaxName, true, false)
	v.text("/description", c.Description, MaxText, false, true)
	if len(c.References) > MaxReferences {
		v.add("/references", "at most %d references", MaxReferences)
	}
	refs := map[Reference]bool{}
	for i, r := range c.References {
		rp := fmt.Sprintf("/references/%d", i)
		v.text(rp+"/framework", r.Framework, MaxName, true, false)
		v.text(rp+"/identifier", r.Identifier, MaxName, true, false)
		if refs[r] {
			v.add(rp, "is listed twice")
		}
		refs[r] = true
	}
	v.effects("/effects", c.Effects)
}
