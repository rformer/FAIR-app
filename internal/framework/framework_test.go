package framework

import (
	"errors"
	"os"
	"strings"
	"testing"

	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-2-3"
)

var testFamily = Family{Key: "test-fw", Title: "Test framework", Publisher: "Test"}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name) // #nosec G304 -- test fixtures
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func find(v *Version, id string) *Requirement {
	for i := range v.Requirements {
		if v.Requirements[i].Identifier == id {
			return &v.Requirements[i]
		}
	}
	return nil
}

// F-013 T-03 (AC-01): an OSCAL catalog's controls and enhancements as
// requirements: labels, statements flattened with parameters, parents,
// withdrawn controls and what they were incorporated into.
func TestParseCatalog(t *testing.T) {
	v, err := ParseCatalog(readFile(t, "catalog.json"), testFamily)
	if err != nil {
		t.Fatal(err)
	}
	if v.Label != "1.0" || v.Title != "Test Catalog" || v.Published != "2026-01-15" || v.Format != "oscal" || len(v.Requirements) != 4 {
		t.Fatalf("version %+v", v)
	}
	ac1 := find(v, "ac-1")
	want := "a. Develop, document, and disseminate to [Assignment: organization-defined personnel or roles]:\n  1. [Selection (one or more): organization-level; system-level] access control policy; and"
	if ac1.Label != "AC-1" || ac1.Statement != want || strings.Contains(ac1.Statement, "Guidance") {
		t.Errorf("ac-1 %q", ac1.Statement)
	}
	if e := find(v, "ac-2.1"); e == nil || e.Parent != "ac-2" || e.Label != "AC-2(1)" {
		t.Errorf("the enhancement %+v", e)
	}
	if w := find(v, "ac-3"); w == nil || !w.Withdrawn || strings.Join(w.IncorporatedInto, ",") != "ac-2" {
		t.Errorf("the withdrawn control %+v", w)
	}
	// Refused whole: not OSCAL, another model, an invalid document.
	for name, raw := range map[string]string{
		"not JSON":      "{",
		"a profile":     string(readFile(t, "profile.json")),
		"invalid OSCAL": `{"catalog": {"uuid": "x"}}`,
	} {
		var p Problems
		if _, err := ParseCatalog([]byte(raw), testFamily); !errors.As(err, &p) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseCatalog(readFile(t, "catalog.json"), Family{Key: "Bad Key", Title: "x"}); err == nil || !strings.Contains(err.Error(), "/family/key") {
		t.Errorf("a bad family key: %v", err)
	}
}

// AC-02: a profile resolved to its selection; set-parameters recorded,
// alters reported as not applied; nothing fetched.
func TestParseProfile(t *testing.T) {
	cat, err := ParseCatalog(readFile(t, "catalog.json"), testFamily)
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	lookup := func(href string, res *oscaltypes.Resource) (*Import, error) {
		asked = append(asked, href)
		if res != nil && res.Title == "Test Catalog" {
			return &Import{Catalog: cat}, nil
		}
		return nil, errors.New("no such catalog in the platform")
	}
	b, of, err := ParseProfile(readFile(t, "profile.json"), "test-moderate", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if of != cat || strings.Join(b.Selected, ",") != "ac-1,ac-2" || b.Parameters["ac-01_odp.01"] != "the CISO" || len(b.Notes) != 1 || b.Title != "Test Moderate Baseline" {
		t.Fatalf("baseline %+v", b)
	}
	if strings.Join(asked, ",") != "#5e7a9c3d-1b2f-4d6e-8a0c-7f9b1e3d5a22" {
		t.Errorf("lookups %v", asked)
	}
	// A catalog that is not in the platform refuses the profile.
	if _, _, err := ParseProfile(readFile(t, "profile.json"), "test-moderate", func(string, *oscaltypes.Resource) (*Import, error) {
		return nil, errors.New("no such catalog in the platform")
	}); err == nil || !strings.Contains(err.Error(), "no such catalog") {
		t.Errorf("a missing catalog: %v", err)
	}
	// A with-id the catalog lacks is named.
	bad := strings.Replace(string(readFile(t, "profile.json")), `"ac-1", "ac-2"`, `"ac-1", "zz-9"`, 1)
	if _, _, err := ParseProfile([]byte(bad), "test-moderate", lookup); err == nil || !strings.Contains(err.Error(), "zz-9") {
		t.Errorf("an unknown id: %v", err)
	}
	// Profiles nested deeper than the limit are refused.
	loop := Lookup(func(string, *oscaltypes.Resource) (*Import, error) {
		return &Import{Profile: readFile(t, "profile.json")}, nil
	})
	if _, _, err := ParseProfile(readFile(t, "profile.json"), "deep", loop); err == nil || !strings.Contains(err.Error(), "deep") {
		t.Errorf("a profile loop: %v", err)
	}
}

// AC-03: the simple format, JSON and CSV, as strict as OSCAL.
func TestParseSimple(t *testing.T) {
	ok := `{"format": "fair.framework.v1", "family": {"key": "iso-27001", "title": "ISO/IEC 27001"}, "version": {"label": "2022", "title": "ISO/IEC 27001:2022", "published": "2022-10-25"},
		"requirements": [{"identifier": "A.5", "title": "Organizational controls"}, {"identifier": "A.5.1", "title": "Policies for information security", "parent": "A.5"}]}`
	v, err := ParseSimple([]byte(ok))
	if err != nil || len(v.Requirements) != 2 || v.Format != "simple" {
		t.Fatalf("%+v %v", v, err)
	}
	for name, raw := range map[string]string{
		"an unknown member": strings.Replace(ok, `"title": "Organizational controls"`, `"title": "x", "score": 3`, 1),
		"a missing parent":  strings.Replace(ok, `"parent": "A.5"`, `"parent": "A.9"`, 1),
		"a duplicate":       strings.Replace(ok, `"identifier": "A.5.1"`, `"identifier": "A.5"`, 1),
		"a cycle":           strings.Replace(ok, `{"identifier": "A.5", "title": "Organizational controls"}`, `{"identifier": "A.5", "title": "x", "parent": "A.5.1"}`, 1),
		"another format":    strings.Replace(ok, "fair.framework.v1", "fair.framework.v2", 1),
		"a NUL":             strings.Replace(ok, "Organizational controls", `Org\u0000`, 1),
		"withdrawn":         strings.Replace(ok, `"title": "Organizational controls"`, `"title": "x", "withdrawn": true`, 1),
	} {
		if _, err := ParseSimple([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	meta := Meta{Family: Family{Key: "soc2", Title: "SOC 2"}, Label: "2017", Title: "Trust Services Criteria (2017)"}
	csvOK := "Identifier,Title,Parent,Statement\nCC6,Logical and Physical Access,,\nCC6.1,Logical access security,CC6,\"The entity implements, ...\"\n"
	if v, err := ParseSimpleCSV([]byte(csvOK), meta); err != nil || len(v.Requirements) != 2 || v.Requirements[1].Parent != "CC6" {
		t.Fatalf("CSV: %+v %v", v, err)
	}
	if _, err := ParseSimpleCSV([]byte("identifier,score\nx,3\n"), meta); err == nil || !strings.Contains(err.Error(), "score") {
		t.Errorf("an unknown column: %v", err)
	}
	if _, err := ParseSimpleCSV([]byte("identifier\nx\n"), meta); err == nil || !strings.Contains(err.Error(), "title") {
		t.Errorf("no title column: %v", err)
	}
}

// AC-10: crosswalks with the NIST IR 8278 relationships only.
func TestParseCrosswalk(t *testing.T) {
	ok := `{"format": "fair.crosswalk.v1", "title": "800-171 to 800-53", "label": "r3", "source": {"family": "nist-800-171", "version": "3.0.0"},
		"target": {"family": "nist-800-53", "version": "5.1.1"}, "relationships": [{"source": "03.01.01", "target": "ac-2", "relationship": "subset_of"}]}`
	if x, err := ParseCrosswalk([]byte(ok)); err != nil || len(x.Relationships) != 1 {
		t.Fatalf("%+v %v", x, err)
	}
	for name, raw := range map[string]string{
		"a relationship":  strings.Replace(ok, "subset_of", "related", 1),
		"the same target": strings.Replace(ok, `"family": "nist-800-171", "version": "3.0.0"`, `"family": "nist-800-53", "version": "5.1.1"`, 1),
		"no relationship": strings.Replace(ok, `[{"source": "03.01.01", "target": "ac-2", "relationship": "subset_of"}]`, `[]`, 1),
	} {
		if _, err := ParseCrosswalk([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	head := Crosswalk{Title: "x", Label: "1", Source: Ref{"a", "1"}, Target: Ref{"b", "1"}}
	if x, err := ParseCrosswalkCSV([]byte("source,target,relationship\na-1,b-1,EQUAL\na-2,b-1,intersects\n"), head); err != nil || x.Relationships[0].Relationship != "equal" {
		t.Fatalf("CSV: %+v %v", x, err)
	}
}

// AC-05: what changed between two versions.
func TestCompare(t *testing.T) {
	prev := &Version{Requirements: []Requirement{{Identifier: "a", Title: "A"}, {Identifier: "b", Title: "B"}, {Identifier: "c", Title: "C"}, {Identifier: "d", Title: "D"}}}
	next := &Version{Requirements: []Requirement{{Identifier: "a", Title: "A"}, {Identifier: "b", Title: "B, revised"},
		{Identifier: "c", Title: "C", Withdrawn: true, IncorporatedInto: []string{"a"}}, {Identifier: "e", Title: "E"}}}
	d := Compare(prev, next)
	if strings.Join(d.Added, ",") != "e" || strings.Join(d.Changed, ",") != "b" || strings.Join(d.Withdrawn, ",") != "c,d" || d.Renumbered["c"] != "a" {
		t.Errorf("%+v", d)
	}
}
