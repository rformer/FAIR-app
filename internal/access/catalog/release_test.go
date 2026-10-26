package catalog

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// specPath is the approved permission catalog (D-OQ4).
const specPath = "../../../specs/features/F-001-identity-bu-rbac/permission-catalog.md"

func TestReleaseLoads(t *testing.T) {
	c, br, err := Release()
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || len(c.Permissions) != 56 || len(br.Roles) != 8 {
		t.Fatalf("release = v%d, %d permissions, %d roles", c.Version, len(c.Permissions), len(br.Roles))
	}
}

// The shipped JSON must match the approved spec exactly: same keys, actions,
// privileged and risk-data flags, and the same built-in role contents.
func TestReleaseMatchesApprovedSpec(t *testing.T) {
	md, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	c, br, err := Release()
	if err != nil {
		t.Fatal(err)
	}

	permRow := regexp.MustCompile("^\\| `([a-z_.]+)` \\| (\\w+) \\| (\\*\\*yes\\*\\*|no) \\|")
	roleRow := regexp.MustCompile(`^\| ([A-Z][A-Za-z ]+) \| (.*) \|$`)
	keyRef := regexp.MustCompile("`([a-z_.]+)`")
	var want []Permission
	wantRoles := map[string][]string{}
	section := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(md), "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "### "), strings.HasPrefix(line, "## "):
			section = line
		case strings.HasPrefix(section, "## Built-in role"):
			if m := roleRow.FindStringSubmatch(line); m != nil && m[1] != "Role" {
				var ks []string
				for _, k := range keyRef.FindAllStringSubmatch(m[2], -1) {
					ks = append(ks, k[1])
				}
				slices.Sort(ks)
				wantRoles[m[1]] = ks
			}
		default:
			if m := permRow.FindStringSubmatch(line); m != nil {
				res, _, _ := strings.Cut(m[1], ".")
				want = append(want, Permission{
					Key: m[1], ResourceType: res, Action: Action(m[2]), Privileged: m[3] != "no",
					RiskData: strings.HasPrefix(section, "### Risk data"), IntroducedIn: 1,
				})
			}
		}
	}
	slices.SortFunc(want, func(a, b Permission) int { return strings.Compare(a.Key, b.Key) })
	if !slices.Equal(c.Permissions, want) {
		t.Errorf("release/catalog.json differs from %s: %d vs %d permissions; diff %+v", specPath, len(c.Permissions), len(want), Compare(&Catalog{Version: 1, Permissions: want}, c))
	}
	if len(wantRoles) != len(br.Roles) {
		t.Errorf("spec has %d roles, release has %d", len(wantRoles), len(br.Roles))
	}
	for _, r := range br.Roles {
		if !slices.Equal(r.Permissions, wantRoles[r.Name]) {
			t.Errorf("role %s differs from the spec:\n got %v\nwant %v", r.Name, r.Permissions, wantRoles[r.Name])
		}
	}
}

func TestBuiltinRoleInvariants(t *testing.T) {
	c, br, err := Release()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range br.Roles {
		// AC-29 default SoD pair.
		if slices.Contains(r.Permissions, "analysis.edit") && slices.Contains(r.Permissions, "acceptance.approve") {
			t.Errorf("%s holds both halves of the default SoD pair", r.Name)
		}
		if r.Name == "Platform Admin" { // AC-44: break-glass accounts get no risk data
			for _, k := range r.Permissions {
				if p, _ := c.Lookup(k); p.RiskData {
					t.Errorf("Platform Admin holds risk-data permission %s", k)
				}
			}
		}
		if r.Name == "Service Account" && len(r.Permissions) != 0 { // AC-36: API scopes only
			t.Errorf("Service Account role has permissions %v", r.Permissions)
		}
	}
}

func TestParseRolesRejectsInvalid(t *testing.T) {
	c, _, err := Release()
	if err != nil {
		t.Fatal(err)
	}
	doc := func(version int, roles ...BuiltinRole) string {
		b, _ := json.Marshal(BuiltinRoles{CatalogVersion: version, Roles: roles})
		return string(b)
	}
	cases := map[string]struct{ in, want string }{
		"version mismatch":    {doc(2), "target catalog 2"},
		"unknown permission":  {doc(1, BuiltinRole{"X", []string{"nope.nope"}}), "unknown permission"},
		"admin with risk":     {doc(1, BuiltinRole{"X", []string{"access.assign", "analysis.view"}}), "combines admin"},
		"duplicate perm":      {doc(1, BuiltinRole{"X", []string{"bu.view", "bu.view"}}), "twice"},
		"duplicate role name": {doc(1, BuiltinRole{"X", nil}, BuiltinRole{"X", nil}), "duplicated"},
		"empty name":          {doc(1, BuiltinRole{"", nil}), "duplicated"},
		"unknown field":       {`{"catalog_version": 1, "roles": [], "x": 1}`, "unknown field"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRoles(strings.NewReader(tc.in), c)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrInvalid containing %q", err, tc.want)
			}
		})
	}
}
