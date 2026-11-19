package content

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-2-3"
)

var pinDir = filepath.Join("..", "..", "..", "third_party", "oscal")

// F-013 T-04 (AC-04; design §2): the embedded content is exactly what the
// pinned files build, so a pin change cannot ship stale frameworks.
// FAIR_UPDATE_GOLDEN=1 rewrites shipped.json.gz.
func TestShippedUpToDate(t *testing.T) {
	s, err := Build(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("FAIR_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile("shipped.json.gz", enc, 0o644); err != nil { // #nosec G306 -- a committed source file
			t.Fatal(err)
		}
		t.Logf("wrote shipped.json.gz (%d bytes)", len(enc))
		return
	}
	got, err := SyncPayload()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(s)
	if !bytes.Equal(got, want) {
		t.Fatal("shipped.json.gz is stale: run FAIR_UPDATE_GOLDEN=1 go test ./internal/framework/content/")
	}
}

// What ships (OQ1, OQ2): two 800-53 versions, 800-171r3, eight baselines,
// one crosswalk; FedRAMP's selections equal FedRAMP's resolved catalog.
func TestShippedContent(t *testing.T) {
	s, err := Build(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	var labels []string
	for _, v := range s.Versions {
		labels = append(labels, v.Family.Key+" "+v.Label)
		if len(v.SHA256) != 64 || v.Origin == "" {
			t.Errorf("%s %s: no digest or origin", v.Family.Key, v.Label)
		}
	}
	if !slices.Equal(labels, []string{"nist-800-53 5.2.0", "nist-800-53 5.1.1+u4", "nist-800-171 Rev 3 (1.1.0)"}) {
		t.Fatalf("versions %v", labels)
	}
	byKey := map[string]Baseline{}
	for _, b := range s.Baselines {
		byKey[b.Key] = b
	}
	for key, version := range map[string]string{"nist-low": "5.2.0", "nist-moderate": "5.2.0", "nist-high": "5.2.0", "nist-privacy": "5.2.0",
		"fedramp-low": "5.1.1+u4", "fedramp-moderate": "5.1.1+u4", "fedramp-high": "5.1.1+u4", "fedramp-li-saas": "5.1.1+u4"} {
		b, ok := byKey[key]
		if !ok || b.Version.Version != version || len(b.Selected) == 0 {
			t.Errorf("baseline %s: %+v", key, b.Version)
		}
	}
	if l, m, h := len(byKey["nist-low"].Selected), len(byKey["nist-moderate"].Selected), len(byKey["nist-high"].Selected); !(l < m && m < h) {
		t.Errorf("low %d, moderate %d, high %d", l, m, h)
	}
	// FedRAMP moderate equals FedRAMP's own resolved catalog.
	raw, err := os.ReadFile(filepath.Join(pinDir, "fedramp", "rev5", "FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := resolvedIDs(t, raw)
	got := slices.Clone(byKey["fedramp-moderate"].Selected)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("FedRAMP moderate: %d selected, FedRAMP resolves %d", len(got), len(want))
	}
	if len(s.Crosswalks) != 1 || len(s.Crosswalks[0].Relationships) < 150 { // 157 at the pin: the other references cite publications, not controls
		t.Fatalf("crosswalks %d, relationships %d", len(s.Crosswalks), len(s.Crosswalks[0].Relationships))
	}
	x := s.Crosswalks[0]
	if x.Source.Family != "nist-800-171" || x.Target.Version != "5.1.1+u4" {
		t.Errorf("crosswalk %+v to %+v", x.Source, x.Target)
	}
	found := false
	for _, l := range x.Relationships {
		if l.Relationship != "intersects" {
			t.Fatalf("relationship %+v", l)
		}
		if l.Source == "SP_800_171_03.01.01" && l.Target == "ac-2" {
			found = true
		}
	}
	if !found {
		t.Error("03.01.01 does not reach AC-2")
	}
	enc, _ := Encode(s)
	zr, _ := gzip.NewReader(bytes.NewReader(enc))
	plain, _ := io.ReadAll(zr)
	t.Logf("shipped: %d bytes, %d compressed; %d relationships", len(plain), len(enc), len(x.Relationships))
}

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
