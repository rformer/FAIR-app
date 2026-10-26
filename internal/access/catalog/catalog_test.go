package catalog

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func load(t *testing.T, name string) *Catalog {
	t.Helper()
	c, err := Load("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func keys(ps []Permission) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Key
	}
	return out
}

func TestLoadSortsByKey(t *testing.T) {
	c := load(t, "v1.json")
	if c.Version != 1 {
		t.Fatalf("version = %d", c.Version)
	}
	got := keys(c.Permissions)
	if !slices.IsSorted(got) {
		t.Fatalf("permissions not sorted: %v", got)
	}
	p, ok := c.Lookup("acceptance.approve")
	if !ok || p.Action != ActionApprove || !p.Privileged {
		t.Fatalf("lookup acceptance.approve = %+v, %v", p, ok)
	}
	if _, ok := c.Lookup("nope.nope"); ok {
		t.Fatal("lookup of unknown key succeeded")
	}
}

// Verification for T-03: catalog diff across two versions (AC-51, AC-57).
func TestDiffAcrossVersions(t *testing.T) {
	v1, v2 := load(t, "v1.json"), load(t, "v2.json")
	d, err := Upgrade(v1, v2)
	if err != nil {
		t.Fatal(err)
	}
	if d.FromVersion != 1 || d.ToVersion != 2 {
		t.Fatalf("versions = %d → %d", d.FromVersion, d.ToVersion)
	}
	if got, want := keys(d.Added), []string{"posture.view", "settings.approve"}; !slices.Equal(got, want) {
		t.Errorf("added = %v, want %v", got, want)
	}
	if got, want := keys(d.Removed), []string{"register.draft"}; !slices.Equal(got, want) {
		t.Errorf("removed = %v, want %v", got, want)
	}
	if len(d.Changed) != 1 || d.Changed[0].New.Key != "analysis.view" || d.Changed[0].Old.Privileged || !d.Changed[0].New.Privileged {
		t.Errorf("changed = %+v, want analysis.view reclassified as privileged", d.Changed)
	}

	// Reverse direction is a valid diff but not a valid upgrade.
	back := Compare(v2, v1)
	if !slices.Equal(keys(back.Added), keys(d.Removed)) || !slices.Equal(keys(back.Removed), keys(d.Added)) {
		t.Errorf("reverse diff not symmetric: %+v", back)
	}
	if _, err := Upgrade(v2, v1); !errors.Is(err, ErrVersion) {
		t.Errorf("downgrade: err = %v, want ErrVersion", err)
	}
	if d := Compare(v1, v1); !d.Empty() {
		t.Errorf("self diff not empty: %+v", d)
	}
}

func TestUpgradeVersionRules(t *testing.T) {
	v1 := load(t, "v1.json")
	mk := func(version int, extra ...Permission) *Catalog {
		c := &Catalog{Version: version, Permissions: append(slices.Clone(v1.Permissions), extra...)}
		slices.SortFunc(c.Permissions, func(a, b Permission) int { return strings.Compare(a.Key, b.Key) })
		return c
	}
	newPerm := Permission{Key: "posture.view", ResourceType: "posture", Action: ActionRead, IntroducedIn: 1}

	if _, err := Upgrade(v1, mk(1)); err != nil {
		t.Errorf("identical catalog at same version: %v", err)
	}
	if _, err := Upgrade(v1, mk(1, newPerm)); !errors.Is(err, ErrVersion) {
		t.Errorf("change without version bump: err = %v", err)
	}
	if _, err := Upgrade(v1, mk(2, newPerm)); !errors.Is(err, ErrVersion) {
		t.Errorf("new key stamped with old version: err = %v", err)
	}
	newPerm.IntroducedIn = 2
	if _, err := Upgrade(v1, mk(2, newPerm)); err != nil {
		t.Errorf("valid upgrade: %v", err)
	}

	restamped := mk(2)
	restamped.Permissions[0].IntroducedIn = 2
	if _, err := Upgrade(v1, restamped); !errors.Is(err, ErrVersion) {
		t.Errorf("existing key restamped: err = %v", err)
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	perm := func(s string) string { return `{"version": 2, "permissions": [` + s + `]}` }
	cases := map[string]string{
		"zero version":         `{"version": 0, "permissions": []}`,
		"unknown field":        `{"version": 1, "permissions": [], "extra": true}`,
		"trailing data":        `{"version": 1, "permissions": []} {}`,
		"bad key":              perm(`{"key": "Analysis.Edit", "resource_type": "Analysis", "action": "write", "introduced_in": 1}`),
		"key without dot":      perm(`{"key": "analysis", "resource_type": "analysis", "action": "write", "introduced_in": 1}`),
		"resource mismatch":    perm(`{"key": "analysis.edit", "resource_type": "register", "action": "write", "introduced_in": 1}`),
		"unknown action":       perm(`{"key": "analysis.edit", "resource_type": "analysis", "action": "delete", "introduced_in": 1}`),
		"unprivileged admin":   perm(`{"key": "access.assign", "resource_type": "access", "action": "admin", "introduced_in": 1}`),
		"unprivileged export":  perm(`{"key": "analysis.export", "resource_type": "analysis", "action": "export", "introduced_in": 1}`),
		"unprivileged approve": perm(`{"key": "acceptance.approve", "resource_type": "acceptance", "action": "approve", "introduced_in": 1}`),
		"introduced in future": perm(`{"key": "analysis.edit", "resource_type": "analysis", "action": "write", "introduced_in": 3}`),
		"introduced zero":      perm(`{"key": "analysis.edit", "resource_type": "analysis", "action": "write", "introduced_in": 0}`),
		"duplicate key": perm(`{"key": "analysis.edit", "resource_type": "analysis", "action": "write", "introduced_in": 1},
			{"key": "analysis.edit", "resource_type": "analysis", "action": "read", "introduced_in": 1}`),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(in)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}
