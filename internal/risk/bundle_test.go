package risk

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/canon"
)

func pinOf(ptr, kind, id string, v int64, doc string) BundlePin {
	b, _ := canon.Canonicalize([]byte(doc))
	return BundlePin{Pointer: ptr, Kind: kind, ID: id, Version: v, Digest: canon.Digest(b), Document: b}
}

// The same inputs give the same bytes and digest, in any pin order; any
// change of the scenario, a pin, the currency or the set of pins changes
// the digest; a document that does not match its digest is refused.
func TestBuildBundle(t *testing.T) {
	sd, _ := canon.Canonicalize([]byte(`{"kind": "scenario", "name": "S"}`))
	s := BundleScenario{ID: "s1", Version: 2, Digest: canon.Digest(sd), Document: sd}
	pins := []BundlePin{
		pinOf("/threat_community", "threat_community", "t1", 1, `{"name": "TC"}`),
		pinOf("/asset", "asset_group", "g1", 3, `{"name": "G"}`),
		pinOf("/asset/members/0", "asset", "a1", 1, `{"name": "A"}`),
	}
	pins[2].MemberOf = "/asset"
	base, err := BuildBundle("USD", s, pins)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := BuildBundle("USD", s, []BundlePin{pins[2], pins[0], pins[1]}); !bytes.Equal(again.Canonical, base.Canonical) || again.Digest != base.Digest {
		t.Fatal("pin order changed the bundle")
	}
	if c, _ := canon.Canonicalize(base.Canonical); !bytes.Equal(c, base.Canonical) {
		t.Fatal("not canonical")
	}
	for _, want := range []string{`"format":"fair.scenario-input.v1"`, `"currency":"USD"`, `"member_of":"/asset"`, `"pointer":"/asset/members/0"`} {
		if !strings.Contains(string(base.Canonical), want) {
			t.Errorf("missing %s in %s", want, base.Canonical)
		}
	}
	changed := map[string]func() (Bundle, error){
		"currency":    func() (Bundle, error) { return BuildBundle("EUR", s, pins) },
		"no currency": func() (Bundle, error) { return BuildBundle("", s, pins) },
		"scenario version": func() (Bundle, error) {
			s2 := s
			s2.Version = 3
			return BuildBundle("USD", s2, pins)
		},
		"a pin's version": func() (Bundle, error) {
			p := append([]BundlePin(nil), pins...)
			p[0] = pinOf("/threat_community", "threat_community", "t1", 2, `{"name": "TC"}`)
			return BuildBundle("USD", s, p)
		},
		"a pin's document": func() (Bundle, error) {
			p := append([]BundlePin(nil), pins...)
			p[0] = pinOf("/threat_community", "threat_community", "t1", 1, `{"name": "TC2"}`)
			return BuildBundle("USD", s, p)
		},
		"a pin fewer": func() (Bundle, error) { return BuildBundle("USD", s, pins[:2]) },
	}
	for name, f := range changed {
		b, err := f()
		if err != nil || b.Digest == base.Digest {
			t.Errorf("%s: digest unchanged (%v)", name, err)
		}
	}
	// Integrity: a document that is not what its digest says, or two pins
	// at one place, is refused.
	bad := append([]BundlePin(nil), pins...)
	bad[1].Document = []byte(`{"name":"X"}`)
	if _, err := BuildBundle("USD", s, bad); err == nil {
		t.Error("a pin that does not match its digest")
	}
	s3 := s
	s3.Digest = strings.Repeat("0", 64)
	if _, err := BuildBundle("USD", s3, pins); err == nil {
		t.Error("a scenario that does not match its digest")
	}
	if _, err := BuildBundle("USD", s, append(pins, pins[0])); err == nil {
		t.Error("two pins at one place")
	}
}
