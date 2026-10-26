package profilegen

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/pkg/settings"
)

const bindingsDir = "../../bindings"

// resolvedProfiles resolves the three built-in profiles' catalogs.
func resolvedProfiles(t *testing.T) map[string]map[string]any {
	t.Helper()
	l := loader(t)
	fed, err := Resolve(l, source(t, l, "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline_profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]map[string]any{
		settings.ProfileFedRAMPModerate:    fed,
		settings.ProfileCMMCL2R2:           resolveInRepo(t, "cmmc-l2-r2/profile.json"),
		settings.ProfileEnterpriseBaseline: resolveInRepo(t, "enterprise-baseline/profile.json"),
	}
}

// Verification for T-05: every F-001 key has a binding that validates and
// resolves in all three profiles.
func TestF001BindingsResolveInAllProfiles(t *testing.T) {
	bindings, err := LoadBindings(bindingsDir)
	if err != nil {
		t.Fatal(err)
	}
	defs := settings.F001Defs()
	resolved := resolvedProfiles(t)
	ctx := testContext(t)
	ctx.Resolved = resolved

	byKey := map[string]Binding{}
	for _, b := range bindings {
		if _, dup := byKey[b.Setting]; dup {
			t.Errorf("%s has two binding files", b.Setting)
		}
		byKey[b.Setting] = b
		if b.file != b.Setting+".yaml" {
			t.Errorf("%s: file must be named %s.yaml", b.file, b.Setting)
		}
	}
	for _, d := range defs {
		if _, ok := byKey[d.Key]; !ok {
			t.Errorf("F-001 setting %s has no binding", d.Key)
		}
	}
	if len(bindings) != len(defs) {
		t.Errorf("%d bindings for %d F-001 settings", len(bindings), len(defs))
	}

	builtin := map[string]settings.Profile{}
	for _, p := range settings.BuiltinProfiles() {
		builtin[p.ID] = p
	}
	fromBindings := map[string]settings.Profile{}
	for id, p := range builtin {
		fromBindings[id] = settings.Profile{ID: id, Title: p.Title, Family: p.Family, Version: p.Version, Settings: map[string]settings.Bound{}}
	}

	for _, d := range defs {
		b, ok := byKey[d.Key]
		if !ok {
			continue
		}
		for _, err := range ctx.Validate(b) {
			t.Error(err)
		}
		var params []string
		for _, p := range b.Params {
			params = append(params, p.Param)
		}
		if !slices.Equal(params, d.Params) {
			t.Errorf("%s: binding params %v, pkg/settings says %v", d.Key, params, d.Params)
		}
		// Each parameter is present in every profile's resolved catalog (the
		// control is selected).
		for _, p := range params {
			for id, cat := range resolved {
				if _, found := findParam(cat, p); !found {
					t.Errorf("%s: parameter %s is not in the resolved %s profile", d.Key, p, id)
				}
			}
		}
		for id := range builtin {
			bound, err := b.Bound(id)
			if err != nil {
				t.Errorf("%s/%s: %v", d.Key, id, err)
				continue
			}
			fromBindings[id].Settings[d.Key] = bound
			if want := builtin[id].Settings[d.Key]; bound != want {
				t.Errorf("%s/%s: binding gives %+v, pkg/settings stand-in has %+v", d.Key, id, bound, want)
			}
		}
	}
	for id, p := range fromBindings {
		if err := settings.ValidateProfile(p, defs); err != nil {
			t.Errorf("profile %s built from bindings: %v", id, err)
		}
	}
}

// The FedRAMP sources really are drift-checked: changing FedRAMP's text in
// the resolved catalog breaks the build.
func TestF001BindingsDriftCheck(t *testing.T) {
	bindings, err := LoadBindings(bindingsDir)
	if err != nil {
		t.Fatal(err)
	}
	resolved := resolvedProfiles(t)
	b, _ := json.Marshal(resolved[settings.ProfileFedRAMPModerate])
	tampered := map[string]any{}
	_ = json.Unmarshal([]byte(strings.Replace(string(b), "fifteen (15) minutes", "thirty (30) minutes", 1)), &tampered)
	resolved[settings.ProfileFedRAMPModerate] = tampered
	ctx := testContext(t)
	ctx.Resolved = resolved
	var sources int
	for _, bd := range bindings {
		for _, pb := range bd.Profiles {
			if pb.Source != nil {
				sources++
			}
		}
		errs := ctx.Validate(bd)
		if bd.Setting == settings.KeySessionIdleTimeout {
			if len(errs) == 0 || !strings.Contains(errs[0].Error(), "constraint for ac-11_odp.02 changed") {
				t.Fatalf("idle timeout after FedRAMP text change: %v", errs)
			}
		} else if len(errs) != 0 {
			t.Errorf("%s: %v", bd.Setting, errs)
		}
	}
	if sources != 3 {
		t.Fatalf("%d drift-checked sources, want 3 (AC-11, AC-2(3), SC-13)", sources)
	}
}
