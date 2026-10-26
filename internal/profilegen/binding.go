package profilegen

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/pkg/settings"
)

// Binding is one setting's binding file (design §4.1): its type and
// strictness, the OSCAL parameters it implements, and per profile its default
// and bound, with where each value comes from.
type Binding struct {
	Setting           string                    `yaml:"setting"`
	Type              string                    `yaml:"type"`
	Direction         string                    `yaml:"direction"`
	Order             []string                  `yaml:"order"` // enum: weakest -> strictest
	BUScopable        bool                      `yaml:"bu_scopable"`
	HardFloor         any                       `yaml:"hard_floor"`
	HardFloorFamilies []string                  `yaml:"hard_floor_families"` // empty: every profile
	Params            []ParamRef                `yaml:"params"`
	Profiles          map[string]ProfileBinding `yaml:"profiles"`

	file string
}

// ParamRef names an OSCAL parameter.
type ParamRef struct {
	Catalog string `yaml:"catalog"`
	Param   string `yaml:"param"`
}

// ProfileBinding is one profile's default and bound for the setting. Exactly
// one of Source and PlatformChoice says where the value comes from.
type ProfileBinding struct {
	Default        any        `yaml:"default"`
	Bound          *BoundSpec `yaml:"bound"`
	Source         *Source    `yaml:"source"`
	PlatformChoice string     `yaml:"platform_choice"`
}

// BoundSpec is a bound in the strict direction: max for lower_is_stricter,
// min for higher_is_stricter, allowed for bool and enum. Omitted, the bound
// is the default itself.
type BoundSpec struct {
	Max     any   `yaml:"max"`
	Min     any   `yaml:"min"`
	Allowed []any `yaml:"allowed"`
}

// Source is the published constraint a value was transcribed from. The
// build re-checks it against the resolved profile (drift check).
type Source struct {
	Param      string `yaml:"param"`
	Constraint string `yaml:"constraint"`
}

// CatalogNIST80053r5 is the only catalog name params may use for now.
const CatalogNIST80053r5 = "nist-sp-800-53-r5"

// LoadBindings reads every *.yaml file in dir, decoding strictly.
func LoadBindings(dir string) ([]Binding, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	var out []Binding
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- build-time input directory
		if err != nil {
			return nil, err
		}
		bd, err := ParseBinding(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		bd.file = filepath.Base(f)
		out = append(out, bd)
	}
	return out, nil
}

// ParseBinding decodes one binding file; unknown keys are errors.
func ParseBinding(data []byte) (Binding, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var b Binding
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("binding: %w", err)
	}
	return b, nil
}

// Context is what Validate checks bindings against.
type Context struct {
	// Defs are the registered setting definitions (pkg/settings); a binding
	// for a registered key must agree with its definition.
	Defs []settings.Def
	// Profiles lists every profile a binding must cover, with its family.
	Profiles map[string]settings.Family
	// HasParam reports whether a catalog defines a parameter.
	HasParam func(catalog, param string) bool
	// Resolved holds each profile's resolved catalog ({"catalog": ...});
	// sources are drift-checked against it. A source for a profile without
	// one is an error (fail closed).
	Resolved map[string]map[string]any
}

// Validate returns every problem with b; nil means the binding is valid.
func (c Context) Validate(b Binding) []error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", b.label(), fmt.Sprintf(format, args...)))
	}

	def, err := b.Def()
	if err != nil {
		fail("%v", err)
		return errs
	}
	if i := slices.IndexFunc(c.Defs, func(d settings.Def) bool { return d.Key == b.Setting }); i >= 0 {
		reg := c.Defs[i]
		if reg.Kind != def.Kind || reg.Direction != def.Direction || !slices.Equal(reg.Order, def.Order) {
			fail("type/direction/order disagree with the registered definition of %s", b.Setting)
		}
		if fmt.Sprint(reg.Floor) != fmt.Sprint(def.Floor) || !slices.Equal(reg.FloorFamilies, def.FloorFamilies) {
			fail("hard floor %v %v disagrees with the registered %v %v", def.Floor, def.FloorFamilies, reg.Floor, reg.FloorFamilies)
		}
	}

	for _, p := range b.Params {
		if p.Catalog != CatalogNIST80053r5 {
			fail("unknown catalog %q", p.Catalog)
		} else if c.HasParam != nil && !c.HasParam(p.Catalog, p.Param) {
			fail("parameter %s is not in %s", p.Param, p.Catalog)
		}
	}

	for id := range c.Profiles {
		if _, ok := b.Profiles[id]; !ok {
			fail("no entry for profile %s", id)
		}
	}
	ids := make([]string, 0, len(b.Profiles))
	for id := range b.Profiles {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		pb := b.Profiles[id]
		family, known := c.Profiles[id]
		if !known {
			fail("unknown profile %s", id)
			continue
		}
		bound, err := b.Bound(id)
		if err != nil {
			fail("profile %s: %v", id, err)
			continue
		}
		if cmp, err := def.Compare(bound.Default, bound.Weakest); err != nil || cmp < 0 {
			fail("profile %s: default %v is weaker than its bound %v", id, bound.Default, bound.Weakest)
		}
		if def.Floor != nil && (len(def.FloorFamilies) == 0 || slices.Contains(def.FloorFamilies, family)) {
			if cmp, err := def.Compare(bound.Weakest, def.Floor); err != nil || cmp < 0 {
				fail("profile %s: bound %v is weaker than the hard floor %v", id, bound.Weakest, def.Floor)
			}
		}
		switch {
		case pb.Source != nil && strings.TrimSpace(pb.PlatformChoice) != "":
			fail("profile %s: give either source or platform_choice, not both", id)
		case pb.Source == nil && strings.TrimSpace(pb.PlatformChoice) == "":
			fail("profile %s: say where the value comes from (source or platform_choice)", id)
		case pb.Source != nil:
			if err := c.checkSource(b, id, pb.Source); err != nil {
				fail("profile %s: %v", id, err)
			}
		}
	}
	return errs
}

// checkSource is the drift check: the transcribed constraint must still be
// what the resolved profile says.
func (c Context) checkSource(b Binding, profile string, s *Source) error {
	if !slices.ContainsFunc(b.Params, func(p ParamRef) bool { return p.Param == s.Param }) {
		return fmt.Errorf("source parameter %s is not one of the binding's params", s.Param)
	}
	cat, ok := c.Resolved[profile]
	if !ok {
		return fmt.Errorf("no resolved catalog for %s, so source %s cannot be checked", profile, s.Param)
	}
	p, found := findParam(cat, s.Param)
	if !found {
		return fmt.Errorf("parameter %s is not in the resolved %s profile", s.Param, profile)
	}
	var texts []string
	for _, ct := range list(p["constraints"]) {
		texts = append(texts, normalizeText(str(ct.(obj)["description"])))
	}
	if len(texts) == 0 {
		return fmt.Errorf("the resolved %s profile leaves %s unconstrained; use platform_choice", profile, s.Param)
	}
	if !slices.Contains(texts, normalizeText(s.Constraint)) {
		return fmt.Errorf("constraint for %s changed: binding says %q, resolved profile says %q; re-review the transcription", s.Param, s.Constraint, texts)
	}
	return nil
}

func findParam(doc map[string]any, id string) (obj, bool) {
	var found obj
	var walk func(n obj)
	walk = func(n obj) {
		for _, p := range list(n["params"]) {
			if str(p.(obj)["id"]) == id {
				found = p.(obj)
			}
		}
		for _, k := range []string{"groups", "controls"} {
			for _, x := range list(n[k]) {
				walk(x.(obj))
			}
		}
	}
	if cat, ok := doc["catalog"].(obj); ok {
		walk(cat)
	}
	return found, found != nil
}

func normalizeText(s string) string { return strings.Join(strings.Fields(s), " ") }

func (b Binding) label() string {
	if b.file != "" {
		return b.file
	}
	return b.Setting
}

// Def converts the binding's declaration to a settings.Def.
func (b Binding) Def() (settings.Def, error) {
	d := settings.Def{Key: b.Setting, BUScopable: b.BUScopable, Order: b.Order}
	if b.Setting == "" {
		return d, errors.New("setting is required")
	}
	for _, p := range b.Params {
		d.Params = append(d.Params, p.Param)
	}
	switch b.Type {
	case "duration":
		d.Kind = settings.KindDuration
	case "int":
		d.Kind = settings.KindInt
	case "bool":
		d.Kind = settings.KindBool
	case "enum":
		d.Kind = settings.KindEnum
		if len(b.Order) < 2 || len(slices.Compact(slices.Clone(b.Order))) != len(b.Order) {
			return d, errors.New("enum needs an order of at least two distinct values")
		}
	case "set":
		return d, errors.New(`type "set" is not supported until a setting needs it`)
	default:
		return d, fmt.Errorf("unknown type %q", b.Type)
	}
	dirs := map[string]settings.Direction{
		"lower_is_stricter": settings.LowerIsStricter, "higher_is_stricter": settings.HigherIsStricter,
		"true_is_stricter": settings.TrueIsStricter, "false_is_stricter": settings.FalseIsStricter, "ordered": settings.OrderedEnum,
	}
	dir, ok := dirs[b.Direction]
	valid := map[settings.Kind][]string{
		settings.KindDuration: {"lower_is_stricter", "higher_is_stricter"},
		settings.KindInt:      {"lower_is_stricter", "higher_is_stricter"},
		settings.KindBool:     {"true_is_stricter", "false_is_stricter"},
		settings.KindEnum:     {"ordered"},
	}
	if !ok || !slices.Contains(valid[d.Kind], b.Direction) {
		return d, fmt.Errorf("direction %q does not fit type %s", b.Direction, b.Type)
	}
	d.Direction = dir
	if b.HardFloor != nil {
		v, err := parseValue(d, b.HardFloor)
		if err != nil {
			return d, fmt.Errorf("hard_floor: %w", err)
		}
		d.Floor = v
	}
	for _, f := range b.HardFloorFamilies {
		d.FloorFamilies = append(d.FloorFamilies, settings.Family(f))
	}
	return d, nil
}

// Bound converts one profile entry to a settings.Bound.
func (b Binding) Bound(profile string) (settings.Bound, error) {
	d, err := b.Def()
	if err != nil {
		return settings.Bound{}, err
	}
	pb := b.Profiles[profile]
	def, err := parseValue(d, pb.Default)
	if err != nil {
		return settings.Bound{}, fmt.Errorf("default: %w", err)
	}
	weakest := def
	if pb.Bound != nil {
		var raw any
		switch {
		case d.Kind == settings.KindBool || d.Kind == settings.KindEnum:
			if pb.Bound.Max != nil || pb.Bound.Min != nil || len(pb.Bound.Allowed) == 0 {
				return settings.Bound{}, fmt.Errorf("%s bounds use allowed", b.Type)
			}
		case d.Direction == settings.LowerIsStricter:
			if pb.Bound.Min != nil || pb.Bound.Allowed != nil || pb.Bound.Max == nil {
				return settings.Bound{}, errors.New("lower_is_stricter bounds use max")
			}
			raw = pb.Bound.Max
		default:
			if pb.Bound.Max != nil || pb.Bound.Allowed != nil || pb.Bound.Min == nil {
				return settings.Bound{}, errors.New("higher_is_stricter bounds use min")
			}
			raw = pb.Bound.Min
		}
		if raw != nil {
			if weakest, err = parseValue(d, raw); err != nil {
				return settings.Bound{}, fmt.Errorf("bound: %w", err)
			}
		} else {
			var vals []any
			for _, a := range pb.Bound.Allowed {
				v, err := parseValue(d, a)
				if err != nil {
					return settings.Bound{}, fmt.Errorf("bound: %w", err)
				}
				vals = append(vals, v)
			}
			if !slices.ContainsFunc(vals, func(v any) bool { return v == def }) {
				return settings.Bound{}, fmt.Errorf("allowed %v does not include the default %v", vals, def)
			}
			weakest = vals[0]
			for _, v := range vals[1:] {
				if c, _ := d.Compare(v, weakest); c < 0 {
					weakest = v
				}
			}
		}
	}
	return settings.Bound{Default: def, Weakest: weakest}, nil
}

// parseValue converts a YAML scalar to the Go value pkg/settings expects.
func parseValue(d settings.Def, raw any) (any, error) {
	var v any
	switch d.Kind {
	case settings.KindDuration:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%v is not a duration", raw)
		}
		dur, err := parseDuration(s)
		if err != nil {
			return nil, err
		}
		v = dur
	case settings.KindInt:
		n, ok := raw.(int)
		if !ok {
			return nil, fmt.Errorf("%v is not an integer", raw)
		}
		v = n
	case settings.KindBool:
		bv, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("%v is not a bool", raw)
		}
		v = bv
	case settings.KindEnum:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%v is not a string", raw)
		}
		v = s
	}
	if err := d.Validate(v); err != nil {
		return nil, err
	}
	return v, nil
}

// parseDuration accepts Go durations plus a day suffix ("90d").
func parseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
