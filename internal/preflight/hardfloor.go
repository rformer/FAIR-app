package preflight

import (
	"encoding/json"
	"strings"

	"github.com/rformer/fair-app/pkg/settings"
)

// Context is what the hard floor depends on besides the finding.
type Context struct {
	Mode    string
	Profile string // a posture profile identifier
}

// fipsProfile reports whether the profile requires FIPS on the hard floor:
// a FedRAMP- or CMMC-derived built-in profile, or one this release does not
// know (an unknown profile is treated as the strictest).
func (c Context) fipsProfile() bool {
	for _, p := range settings.BuiltinProfiles() {
		if p.ID == c.Profile {
			return p.Family == settings.FamilyFedRAMP || p.Family == settings.FamilyCMMC
		}
	}
	return true
}

// HardFloor reports whether a finding of a check is on the hard floor
// (AC-19; design §3.7), classified by finding, not by check: such a
// finding refuses the install or upgrade with no override in any mode.
func HardFloor(check string, f Finding, c Context) bool {
	for _, k := range Checks() {
		if k.ID == check {
			return k.floor != nil && k.floor(f, c)
		}
	}
	return false
}

// driftFloor classifies the drift checks' findings (design §3.7): plaintext
// or TLS below 1.2 on a platform connection; node FIPS under a FedRAMP- or
// CMMC-derived profile; key material in plaintext values. The other drift
// checks' findings are above the floor (overridable outside SaaS).
var driftFloor = map[string]func(Finding, Context) bool{
	"tls_endpoints": func(f Finding, _ Context) bool {
		for _, p := range detailStrings(f.Detail, "problems") {
			if p == "plaintext (not TLS)" || strings.HasPrefix(p, "no TLS 1.2+ handshake") || p == "accepts TLS 1.0" || p == "accepts TLS 1.1" {
				return true
			}
		}
		return false
	},
	"node_fips": func(_ Finding, c Context) bool { return c.fipsProfile() },
	"plaintext_secrets": func(f Finding, _ Context) bool {
		return len(detailStrings(f.Detail, "plaintext")) > 0 // not the low "not from the secrets store" finding
	},
}

// detailStrings returns the strings of a detail's array field.
func detailStrings(detail json.RawMessage, field string) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(detail, &m) != nil {
		return nil
	}
	var out []string
	_ = json.Unmarshal(m[field], &out)
	return out
}
