package catalog

import (
	"errors"
	"fmt"
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
	cat := func(perms ...string) string {
		return `{"version": 2, "permissions": [` + strings.Join(perms, ",") + `]}`
	}
	// perm builds a complete, valid entry and then applies overrides, so each
	// case below has exactly one defect.
	perm := func(key, resource, action string, privileged bool, extra string) string {
		return fmt.Sprintf(`{"key": %q, "resource_type": %q, "action": %q, "privileged": %t, "risk_data": false, "introduced_in": 1%s}`,
			key, resource, action, privileged, extra)
	}
	if _, err := Parse(strings.NewReader(cat(perm("analysis.edit", "analysis", "write", false, "")))); err != nil {
		t.Fatalf("baseline entry must be valid: %v", err)
	}
	cases := map[string]struct{ in, want string }{
		"zero version":         {`{"version": 0, "permissions": []}`, "version must be >= 1"},
		"unknown field":        {`{"version": 1, "permissions": [], "extra": true}`, "unknown field"},
		"unknown perm field":   {cat(perm("analysis.edit", "analysis", "write", false, `, "extra": 1`)), "unknown field"},
		"trailing data":        {`{"version": 1, "permissions": []} {}`, "trailing data"},
		"missing privileged":   {cat(`{"key": "analysis.edit", "resource_type": "analysis", "action": "write", "risk_data": true, "introduced_in": 1}`), "are required"},
		"missing risk_data":    {cat(`{"key": "analysis.edit", "resource_type": "analysis", "action": "write", "privileged": false, "introduced_in": 1}`), "are required"},
		"bad key":              {cat(perm("Analysis.Edit", "Analysis", "write", false, "")), "lower snake case"},
		"key without dot":      {cat(perm("analysis", "analysis", "write", false, "")), "lower snake case"},
		"resource mismatch":    {cat(perm("analysis.edit", "register", "write", false, "")), "does not match key prefix"},
		"unknown action":       {cat(perm("analysis.edit", "analysis", "delete", false, "")), "must be one of"},
		"unprivileged admin":   {cat(perm("access.assign", "access", "admin", false, "")), "must be privileged"},
		"unprivileged export":  {cat(perm("analysis.export", "analysis", "export", false, "")), "must be privileged"},
		"unprivileged approve": {cat(perm("acceptance.approve", "acceptance", "approve", false, "")), "must be privileged"},
		"admin risk data":      {cat(`{"key": "access.assign", "resource_type": "access", "action": "admin", "privileged": true, "risk_data": true, "introduced_in": 1}`), "cannot be risk data"},
		"introduced in future": {cat(`{"key": "analysis.edit", "resource_type": "analysis", "action": "write", "privileged": false, "risk_data": false, "introduced_in": 3}`), "introduced_in 3"},
		"introduced zero":      {cat(`{"key": "analysis.edit", "resource_type": "analysis", "action": "write", "privileged": false, "risk_data": false, "introduced_in": 0}`), "introduced_in 0"},
		"duplicate key":        {cat(perm("analysis.edit", "analysis", "write", false, ""), perm("analysis.edit", "analysis", "read", false, "")), "duplicate key"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(c.in))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want ErrInvalid containing %q", err, c.want)
			}
		})
	}
}
