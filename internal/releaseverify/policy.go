package releaseverify

import (
	"encoding/json"
	"regexp"
)

// ProvenancePolicy is what a release image's SLSA provenance must name
// (design §3.5): the builder and the source F-012's admission policy
// requires (deploy/fleet/policy/release.yaml; a test holds them equal).
type ProvenancePolicy struct {
	Builder    *regexp.Regexp // predicate.builder.id
	Source     *regexp.Regexp // predicate.invocation.configSource.uri
	EntryPoint string         // predicate.invocation.configSource.entryPoint
}

// The release policy's values, as deploy/fleet/policy/release.yaml has them.
const (
	ReleaseBuilder    = `^https://github\.com/slsa-framework/slsa-github-generator/\.github/workflows/generator_container_slsa3\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`
	ReleaseSource     = `^git\+https://github\.com/rformer/FAIR-app@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`
	ReleaseEntryPoint = ".github/workflows/release.yml"
)

// ReleasePolicy is the provenance policy of FAIR releases: built by the SLSA
// generator's container workflow from this repository's release workflow at
// a v* tag.
func ReleasePolicy() *ProvenancePolicy {
	return &ProvenancePolicy{
		Builder:    regexp.MustCompile(ReleaseBuilder),
		Source:     regexp.MustCompile(ReleaseSource),
		EntryPoint: ReleaseEntryPoint,
	}
}

// Allows reports whether a SLSA v0.2 provenance statement names the
// policy's builder and source.
func (p *ProvenancePolicy) Allows(st Statement) bool {
	var pred struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		Invocation struct {
			ConfigSource struct {
				URI        string `json:"uri"`
				EntryPoint string `json:"entryPoint"`
			} `json:"configSource"`
		} `json:"invocation"`
	}
	if st.PredicateType != PredicateSLSA || json.Unmarshal(st.Predicate, &pred) != nil {
		return false
	}
	return p.Builder.MatchString(pred.Builder.ID) &&
		p.Source.MatchString(pred.Invocation.ConfigSource.URI) &&
		pred.Invocation.ConfigSource.EntryPoint == p.EntryPoint
}
