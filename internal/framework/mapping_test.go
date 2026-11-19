package framework

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// F-013 T-07 (F-013-AC-10): an OSCAL mapping collection read as a
// crosswalk: OSCAL relationships become NIST IR 8278 ones, each map relates
// every source to every target, no-relationship maps are left out, and
// statements or unknown relationships are refused by pointer.
func TestParseMappingCollection(t *testing.T) {
	raw, err := os.ReadFile("testdata/mapping-collection.json")
	if err != nil {
		t.Fatal(err)
	}
	head := Crosswalk{Source: Ref{Family: "nist-800-171", Version: "Rev 3 (1.1.0)"}, Target: Ref{Family: "nist-800-53", Version: "5.1.1+u4"}}
	x, err := ParseMappingCollection(raw, head)
	if err != nil {
		t.Fatal(err)
	}
	if x.Title != "SP 800-171r3 to SP 800-53r5 (test)" || x.Label != "test-1" || x.Format != CrosswalkFormat {
		t.Errorf("header %+v", x)
	}
	var got []string
	for _, l := range x.Relationships {
		got = append(got, l.Source+" "+l.Relationship+" "+l.Target)
	}
	want := "SP_800_171_03.01.01 equal ac-2,SP_800_171_03.01.02 superset_of ac-3,SP_800_171_03.01.02 superset_of ac-14,SP_800_171_03.01.03 intersects ac-4"
	if strings.Join(got, ",") != want {
		t.Errorf("relationships\n got %s\nwant %s", strings.Join(got, ","), want)
	}
	// The query's title and label win over the file's.
	head.Title, head.Label = "Mine", "v2"
	if x, err := ParseMappingCollection(raw, head); err != nil || x.Title != "Mine" || x.Label != "v2" {
		t.Errorf("header from the request: %v %+v", err, x)
	}

	for name, c := range map[string]struct {
		from, to, pointer string
	}{
		"a statement":             {`"type": "control", "id-ref": "ac-4"`, `"type": "statement", "id-ref": "ac-4_smt"`, "/mapping-collection/mappings/0/maps/2"},
		"an unknown relationship": {`"relationship": "intersects-with"`, `"relationship": "near"`, "/mapping-collection/mappings/0/maps/2/relationship"},
	} {
		_, err := ParseMappingCollection([]byte(strings.Replace(string(raw), c.from, c.to, 1)), head)
		var p Problems
		if !errors.As(err, &p) || p[0].Pointer != c.pointer {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Not OSCAL, or another model.
	for name, b := range map[string]string{"not a mapping": `{"catalog": {}}`, "not JSON": `x`} {
		var p Problems
		if _, err := ParseMappingCollection([]byte(b), head); !errors.As(err, &p) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
