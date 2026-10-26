package profilegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/settings"
)

var testProfiles = map[string]settings.Family{
	settings.ProfileFedRAMPModerate:    settings.FamilyFedRAMP,
	settings.ProfileCMMCL2R2:           settings.FamilyCMMC,
	settings.ProfileEnterpriseBaseline: settings.FamilyEnterprise,
}

var bindingCtx Context

// testContext builds the validation context once: registered F-001 defs,
// the NIST catalog's parameters, and the resolved FedRAMP Moderate catalog.
func testContext(t *testing.T) Context {
	t.Helper()
	if bindingCtx.Resolved != nil {
		return bindingCtx
	}
	l := loader(t)
	nist, err := l.Load(source(t, l, "nist/sp800-53r5/NIST_SP-800-53_rev5_catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	fedramp, err := Resolve(l, source(t, l, "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline_profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	bindingCtx = Context{
		Defs:     settings.F001Defs(),
		Profiles: testProfiles,
		HasParam: func(catalog, param string) bool {
			_, ok := findParam(nist, param)
			return catalog == CatalogNIST80053r5 && ok
		},
		Resolved: map[string]map[string]any{settings.ProfileFedRAMPModerate: fedramp},
	}
	return bindingCtx
}

const idleTimeout = `setting: session.idle_timeout
type: duration
direction: lower_is_stricter
bu_scopable: false
params:
  - catalog: nist-sp-800-53-r5
    param: ac-11_odp.02
profiles:
  fedramp-moderate:
    default: 15m
    bound: { max: 15m }
    source: { param: ac-11_odp.02, constraint: "fifteen (15) minutes" }
  cmmc-l2-r2:
    default: 15m
    bound: { max: 15m }
    platform_choice: "800-171 3.1.10 leaves the period open; matches FedRAMP Moderate"
  enterprise-baseline:
    default: 15m
    bound: { max: 30m }
    platform_choice: "Enterprise Baseline relaxation, see profile notes"
`

func validate(t *testing.T, yamlText string) []error {
	t.Helper()
	b, err := ParseBinding([]byte(yamlText))
	if err != nil {
		return []error{err}
	}
	return testContext(t).Validate(b)
}

func TestValidBinding(t *testing.T) {
	if errs := validate(t, idleTimeout); len(errs) != 0 {
		t.Fatalf("valid binding rejected: %v", errs)
	}
	b, _ := ParseBinding([]byte(idleTimeout))
	bound, err := b.Bound(settings.ProfileEnterpriseBaseline)
	if err != nil || bound.Default != 15*time.Minute || bound.Weakest != 30*time.Minute {
		t.Fatalf("enterprise bound = %+v %v", bound, err)
	}
}

// Verification for T-03: each way a binding can go wrong fails the build
// with a message naming the problem.
func TestBindingRejects(t *testing.T) {
	swap := func(old, repl string) string {
		if !strings.Contains(idleTimeout, old) {
			t.Fatalf("test setup: %q not in the base binding", old)
		}
		return strings.Replace(idleTimeout, old, repl, 1)
	}
	lockout := `setting: auth.lockout_threshold
type: int
direction: lower_is_stricter
params: [{ catalog: nist-sp-800-53-r5, param: ac-07_odp.01 }]
profiles:
  fedramp-moderate:    { default: 3, source: { param: ac-07_odp.01, constraint: "three" } }
  cmmc-l2-r2:          { default: 3, platform_choice: "x" }
  enterprise-baseline: { default: 5, platform_choice: "x" }
`
	mfa := `setting: auth.mfa_required_privileged
type: bool
direction: true_is_stricter
hard_floor: true
profiles:
  fedramp-moderate:    { default: true, platform_choice: "IA-2(1)" }
  cmmc-l2-r2:          { default: true, platform_choice: "3.5.3" }
  enterprise-baseline: { default: true, bound: { allowed: [true, false] }, platform_choice: "relaxed" }
`
	cases := map[string]struct{ yaml, want string }{
		// The T-03 verification column:
		"missing param in catalog":   {swap("param: ac-11_odp.02\nprofiles", "param: ac-11_odp.99\nprofiles"), "not in nist-sp-800-53-r5"},
		"missing param in profile":   {swap("source: { param: ac-11_odp.02,", "source: { param: ac-11_odp.99,"), "not one of the binding's params"},
		"changed constraint text":    {swap(`"fifteen (15) minutes"`, `"fifteen minutes"`), "constraint for ac-11_odp.02 changed"},
		"unconstrained param":        {lockout, "leaves ac-07_odp.01 unconstrained; use platform_choice"},
		"weaker than the hard floor": {mfa, "weaker than the hard floor"},
		// Further invalid bindings:
		"no value origin":           {swap(`    platform_choice: "Enterprise Baseline relaxation, see profile notes"`+"\n", ""), "say where the value comes from"},
		"both origins":              {swap(`    platform_choice: "800-171`, `    source: { param: ac-11_odp.02, constraint: "x" }`+"\n"+`    platform_choice: "800-171`), "either source or platform_choice"},
		"source without catalog":    {swap(`    platform_choice: "800-171 3.1.10 leaves the period open; matches FedRAMP Moderate"`, `    source: { param: ac-11_odp.02, constraint: "x" }`), "no resolved catalog for cmmc-l2-r2"},
		"default weaker than bound": {swap("default: 15m\n    bound: { max: 30m }", "default: 45m\n    bound: { max: 30m }"), "weaker than its bound"},
		"wrong bound form":          {swap("bound: { max: 30m }", "bound: { min: 30m }"), "lower_is_stricter bounds use max"},
		"missing profile":           {idleTimeout[:strings.Index(idleTimeout, "  enterprise-baseline:")], "no entry for profile enterprise-baseline"},
		"unknown profile":           {swap("  enterprise-baseline:", "  fedramp-high:"), "unknown profile fedramp-high"},
		"unknown key":               {swap("bu_scopable: false", "bu_scopable: false\nbu_scoped: true"), "field bu_scoped not found"},
		"type disagrees":            {swap("type: duration", "type: int"), "is not an integer"},
		"direction disagrees":       {swap("lower_is_stricter\nbu", "higher_is_stricter\nbu"), "disagree with the registered definition"},
		"set type":                  {swap("type: duration", "type: set"), `type "set" is not supported`},
		"unknown catalog":           {swap("catalog: nist-sp-800-53-r5", "catalog: iso-27001"), `unknown catalog "iso-27001"`},
		"bad duration":              {swap("default: 15m\n    bound: { max: 15m }\n    source", "default: fifteen\n    bound: { max: 15m }\n    source"), "invalid duration"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			errs := validate(t, c.yaml)
			for _, err := range errs {
				if strings.Contains(err.Error(), c.want) {
					return
				}
			}
			t.Fatalf("want an error containing %q, got %v", c.want, errs)
		})
	}
}

func TestDurationsAndEnums(t *testing.T) {
	d := settings.Def{Kind: settings.KindDuration, Direction: settings.LowerIsStricter}
	if v, err := parseValue(d, "90d"); err != nil || v != 90*24*time.Hour {
		t.Fatalf("90d = %v %v", v, err)
	}
	b, err := ParseBinding([]byte(`setting: session.network_binding
type: enum
direction: ordered
order: [off, flag, reauthenticate]
profiles:
  fedramp-moderate: { default: reauthenticate, bound: { allowed: [reauthenticate, flag] }, platform_choice: x }
`))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := b.Bound(settings.ProfileFedRAMPModerate)
	if err != nil || bound.Weakest != "flag" {
		t.Fatalf("enum bound = %+v %v (weakest of allowed should be flag)", bound, err)
	}
}

func TestLoadBindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "session.idle_timeout.yaml"), []byte(idleTimeout), 0o600); err != nil {
		t.Fatal(err)
	}
	bs, err := LoadBindings(dir)
	if err != nil || len(bs) != 1 || bs[0].Setting != settings.KeySessionIdleTimeout {
		t.Fatalf("loaded %v %v", bs, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("setting: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBindings(dir); err == nil || !strings.Contains(err.Error(), "broken.yaml") {
		t.Fatalf("broken file: %v", err)
	}
}
