package framework

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-2-3"
)

// The pinned NIST content (third_party/oscal, MANIFEST.json): the 800-53r5
// catalog, its moderate baseline and NIST's profile-resolution examples
// with their expected resolved catalogs.
func pinned(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "third_party", "oscal", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// resolvedIDs is every control id of a resolved-profile catalog, in order.
func resolvedIDs(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc struct {
		Catalog oscaltypes.Catalog `json:"catalog"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var ids []string
	var controls func(cs *[]oscaltypes.Control)
	controls = func(cs *[]oscaltypes.Control) {
		if cs == nil {
			return
		}
		for _, c := range *cs {
			ids = append(ids, c.ID)
			controls(c.Controls)
		}
	}
	var groups func(gs *[]oscaltypes.Group)
	groups = func(gs *[]oscaltypes.Group) {
		if gs == nil {
			return
		}
		for _, g := range *gs {
			controls(g.Controls)
			groups(g.Groups)
		}
	}
	controls(doc.Catalog.Controls)
	groups(doc.Catalog.Groups)
	return ids
}

// F-013 T-03 (AC-01, NFR): the shipped 800-53r5 catalog reads whole, in
// well under the import budget.
func TestNISTCatalog(t *testing.T) {
	t0 := time.Now()
	v, err := ParseCatalog(pinned(t, "nist/sp800-53r5/NIST_SP-800-53_rev5_catalog.json"), Family{Key: "nist-800-53", Title: "NIST SP 800-53", Publisher: "NIST"})
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(t0)
	if v.Label != "5.2.0" || len(v.Requirements) < 1100 || len(v.Requirements) > MaxRequirements {
		t.Fatalf("%s: %d requirements", v.Label, len(v.Requirements))
	}
	withdrawn, statements := 0, 0
	for _, r := range v.Requirements {
		if r.Withdrawn {
			withdrawn++
		} else if r.Statement != "" {
			statements++
		}
		if strings.Contains(r.Statement, "{{") {
			t.Fatalf("%s keeps a parameter insertion: %q", r.Identifier, r.Statement)
		}
	}
	if withdrawn < 100 || statements < 900 {
		t.Errorf("%d withdrawn, %d with statements", withdrawn, statements)
	}
	ac21 := find(v, "ac-2.1")
	if ac21 == nil || ac21.Label != "AC-2(1)" || ac21.Parent != "ac-2" || !strings.Contains(ac21.Statement, "[Assignment:") {
		t.Errorf("ac-2.1 %+v", ac21)
	}
	t.Logf("800-53r5 %s: %d requirements (%d withdrawn) in %v", v.Label, len(v.Requirements), withdrawn, took.Round(time.Millisecond))
}

// AC-02: profile resolution agrees with NIST's resolved catalogs: the
// examples (include by id, by pattern) and the moderate baseline.
func TestNISTProfiles(t *testing.T) {
	for _, c := range []struct {
		catalog, profile, resolved string
	}{
		{"examples/catalog/basic_catalog.json", "examples/profile/basic_select_with_id_profile.json", "examples/profile/basic_select_with_id-resolved-profile_catalog.json"},
		{"examples/catalog/basic_catalog.json", "examples/profile/basic_select_with_match_profile.json", "examples/profile/basic_select_with_match-resolved-profile_catalog.json"},
		{"nist/sp800-53r5/NIST_SP-800-53_rev5_catalog.json", "nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
			"nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json"},
	} {
		cat, err := ParseCatalog(pinned(t, c.catalog), Family{Key: "nist", Title: "NIST"})
		if err != nil {
			t.Fatalf("%s: %v", c.catalog, err)
		}
		lookup := func(string, *oscaltypes.Resource) (*Import, error) { return &Import{Catalog: cat}, nil }
		b, _, err := ParseProfile(pinned(t, c.profile), "baseline", lookup)
		if err != nil {
			t.Fatalf("%s: %v", c.profile, err)
		}
		want := resolvedIDs(t, pinned(t, c.resolved))
		got := slices.Clone(b.Selected)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: %d selected, NIST resolves %d; first differences: %v", c.profile, len(got), len(want), firstDiff(got, want))
		}
	}
}

func firstDiff(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, "+"+x)
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			out = append(out, "-"+x)
		}
	}
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}
