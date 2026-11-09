package risk

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// BundleFormat names the input bundle's format.
const BundleFormat = "fair.scenario-input.v1"

// BundlePin is one pinned version, as a scenario version's pin rows hold it.
type BundlePin struct {
	Pointer  string
	Kind     string
	ID       string
	Version  int64
	Digest   string
	Document []byte // canonical
	MemberOf string // an asset group member: the group pin's pointer
}

// BundleScenario is the scenario version a bundle is for.
type BundleScenario struct {
	ID       string
	Version  int64
	Digest   string
	Document []byte // canonical
}

// Bundle is the frozen, self-contained input of a simulation (F-003 AC-16;
// design §1): a scenario version with every library and control version it
// uses, and the installation currency, in canonical form. Its digest
// changes whenever any of them does.
type Bundle struct {
	Canonical []byte
	Digest    string
}

// BuildBundle assembles a bundle. Every document must match its digest
// (they were copied when the version was saved; a mismatch means the
// store was changed and the bundle is refused).
func BuildBundle(currency string, s BundleScenario, pins []BundlePin) (Bundle, error) {
	doc := func(what string, b []byte, digest string) (any, error) {
		if canon.Digest(b) != digest {
			return nil, fmt.Errorf("risk: bundle: %s does not match its digest", what)
		}
		v, err := canon.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("risk: bundle: %s: %w", what, err)
		}
		return v, nil
	}
	sd, err := doc("the scenario version", s.Document, s.Digest)
	if err != nil {
		return Bundle{}, err
	}
	sorted := slices.Clone(pins)
	slices.SortFunc(sorted, func(a, b BundlePin) int { return strings.Compare(a.Pointer, b.Pointer) })
	out := make([]any, 0, len(sorted))
	for i, p := range sorted {
		if i > 0 && sorted[i-1].Pointer == p.Pointer {
			return Bundle{}, fmt.Errorf("risk: bundle: two pins at %s", p.Pointer)
		}
		pd, err := doc("the pin at "+p.Pointer, p.Document, p.Digest)
		if err != nil {
			return Bundle{}, err
		}
		m := map[string]any{"pointer": p.Pointer, "kind": p.Kind, "id": p.ID, "version": p.Version, "digest": p.Digest, "document": pd}
		if p.MemberOf != "" {
			m["member_of"] = p.MemberOf
		}
		out = append(out, m)
	}
	var cur any
	if currency != "" {
		cur = currency
	}
	b, err := canon.Marshal(map[string]any{
		"format":   BundleFormat,
		"currency": cur,
		"scenario": map[string]any{"id": s.ID, "version": s.Version, "digest": s.Digest, "document": sd},
		"pins":     out,
	})
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Canonical: b, Digest: canon.Digest(b)}, nil
}
