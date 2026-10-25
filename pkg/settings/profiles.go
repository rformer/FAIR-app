package settings

import "fmt"

// Built-in profile IDs (ADR-006). FedRAMP Moderate is the install default.
const (
	ProfileFedRAMPModerate    = "fedramp-moderate"
	ProfileCMMCL2             = "cmmc-l2-r2"
	ProfileEnterpriseBaseline = "enterprise-baseline"
	DefaultProfile            = ProfileFedRAMPModerate
)

// Value is one setting's default and bound within a profile. Bound is the
// weakest value the profile allows without an exception.
type Value struct {
	Default string
	Bound   string
	// Floor, if set, raises the setting's hard floor under this profile
	// (e.g. FIPS required under FedRAMP- and CMMC-derived profiles).
	Floor string
}

// Profile is a named set of defaults and bounds.
type Profile struct {
	ID     string
	Title  string
	Values map[string]Value
}

// Profile values below are hand-written stand-ins. F-015 replaces them with
// packages generated from OSCAL (e.g. FedRAMP AC-11 lock time -> 15m).
const (
	days90  = "2160h0m0s"
	days180 = "4320h0m0s"
	days365 = "8760h0m0s"
)

// F001Defs are the security settings F-001 registers.
var F001Defs = []Def{
	{Key: "session.idle_timeout", Type: TypeDuration, Direction: LowerIsStricter, Controls: []string{"AC-11", "AC-12"}, Owner: "F-001"},
	{Key: "session.absolute_timeout", Type: TypeDuration, Direction: LowerIsStricter, Controls: []string{"AC-12"}, Owner: "F-001"},
	{Key: "session.network_binding", Type: TypeEnum, Enum: []string{"off", "flag", "reauthenticate"}, Controls: []string{"SC-23", "AC-12"}, Owner: "F-001"},
	{Key: "auth.mfa_required", Type: TypeBool, StrictBool: true, Controls: []string{"IA-2(2)"}, Owner: "F-001"},
	{Key: "auth.mfa_required_privileged", Type: TypeBool, StrictBool: true, Floor: "true", Controls: []string{"IA-2(1)"}, Owner: "F-001"},
	{Key: "auth.jit_provisioning", Type: TypeBool, StrictBool: false, Controls: []string{"AC-2"}, Owner: "F-001"},
	{Key: "auth.totp_enabled", Type: TypeBool, StrictBool: false, Controls: []string{"IA-2(8)"}, Owner: "F-001"},
	{Key: "auth.banner_enabled", Type: TypeBool, StrictBool: true, Controls: []string{"AC-8"}, Owner: "F-001"},
	{Key: "auth.lockout_threshold", Type: TypeInt, Direction: LowerIsStricter, Controls: []string{"AC-7"}, Owner: "F-001"},
	{Key: "auth.lockout_window", Type: TypeDuration, Direction: HigherIsStricter, Controls: []string{"AC-7"}, Owner: "F-001"},
	{Key: "account.inactivity_disable_after", Type: TypeDuration, Direction: LowerIsStricter, Controls: []string{"AC-2(3)"}, Owner: "F-001"},
	{Key: "token.max_lifetime", Type: TypeDuration, Direction: LowerIsStricter, Controls: []string{"IA-5"}, Owner: "F-001"},
	{Key: "bu.new_restricted", Type: TypeBool, StrictBool: true, Controls: []string{"AC-3", "AC-6"}, Owner: "F-001"},
	{Key: "bu.restricted_rollup_default", Type: TypeEnum, Enum: []string{"full", "aggregate", "excluded"}, AlwaysDualApproveLoosen: true, Controls: []string{"AC-3", "AC-6"}, Owner: "F-001"},
	{Key: "breakglass.enabled", Type: TypeBool, StrictBool: false, AlwaysDualApproveLoosen: true, Controls: []string{"AC-2", "AC-6(5)"}, Owner: "F-001"},
}

// PlatformDefs are hard-floor settings from ADR-006 that every profile carries.
var PlatformDefs = []Def{
	{Key: "tls.min_version", Type: TypeEnum, Enum: []string{"1.2", "1.3"}, Floor: "1.2", Controls: []string{"SC-8", "SC-13"}, Owner: "platform"},
	{Key: "audit.enabled", Type: TypeBool, StrictBool: true, Floor: "true", Controls: []string{"AU-2", "AU-12"}, Owner: "platform"},
	{Key: "crypto.fips_required", Type: TypeBool, StrictBool: true, Controls: []string{"SC-13"}, Owner: "platform"},
}

// AllDefs returns every setting registered in Phase 0.
func AllDefs() []Def { return append(append([]Def{}, PlatformDefs...), F001Defs...) }

func common(strict bool) map[string]Value {
	// Shared defaults; bounds differ per profile below.
	return map[string]Value{
		"session.idle_timeout":             {Default: "15m0s", Bound: "15m0s"},
		"session.absolute_timeout":         {Default: "12h0m0s", Bound: "12h0m0s"},
		"session.network_binding":          {Default: "reauthenticate", Bound: "reauthenticate"},
		"auth.mfa_required":                {Default: "true", Bound: "true"},
		"auth.mfa_required_privileged":     {Default: "true", Bound: "true"},
		"auth.jit_provisioning":            {Default: "false", Bound: "true"},
		"auth.totp_enabled":                {Default: "false", Bound: "true"},
		"auth.banner_enabled":              {Default: "true", Bound: "true"},
		"auth.lockout_threshold":           {Default: "3", Bound: "3"},
		"auth.lockout_window":              {Default: "15m0s", Bound: "15m0s"},
		"account.inactivity_disable_after": {Default: days90, Bound: days90},
		"token.max_lifetime":               {Default: days90, Bound: days90},
		"bu.new_restricted":                {Default: "true", Bound: "false"},
		"bu.restricted_rollup_default":     {Default: "excluded", Bound: "full"},
		"breakglass.enabled":               {Default: "false", Bound: "true"},
		"tls.min_version":                  {Default: "1.2", Bound: "1.2"},
		"audit.enabled":                    {Default: "true", Bound: "true"},
		"crypto.fips_required":             fips(strict),
	}
}

func fips(strict bool) Value {
	if strict {
		return Value{Default: "true", Bound: "true", Floor: "true"}
	}
	return Value{Default: "true", Bound: "false"}
}

// BuiltinProfiles returns the three v1 profiles.
func BuiltinProfiles() map[string]Profile {
	fed := common(true)

	cmmc := common(true)
	cmmc["auth.lockout_threshold"] = Value{Default: "3", Bound: "5"}

	ent := common(false)
	ent["session.idle_timeout"] = Value{Default: "15m0s", Bound: "30m0s"}
	ent["session.absolute_timeout"] = Value{Default: "12h0m0s", Bound: "24h0m0s"}
	ent["session.network_binding"] = Value{Default: "off", Bound: "off"}
	ent["auth.mfa_required"] = Value{Default: "true", Bound: "false"}
	ent["auth.banner_enabled"] = Value{Default: "true", Bound: "false"}
	ent["auth.lockout_threshold"] = Value{Default: "3", Bound: "10"}
	ent["auth.lockout_window"] = Value{Default: "15m0s", Bound: "5m0s"}
	ent["account.inactivity_disable_after"] = Value{Default: days90, Bound: days180}
	ent["token.max_lifetime"] = Value{Default: days90, Bound: days365}

	return map[string]Profile{
		ProfileFedRAMPModerate:    {ID: ProfileFedRAMPModerate, Title: "FedRAMP Moderate", Values: fed},
		ProfileCMMCL2:             {ID: ProfileCMMCL2, Title: "CMMC Level 2 (NIST SP 800-171 Rev 2)", Values: cmmc},
		ProfileEnterpriseBaseline: {ID: ProfileEnterpriseBaseline, Title: "Enterprise Baseline", Values: ent},
	}
}

// LookupProfile returns a built-in profile by ID.
func LookupProfile(id string) (Profile, error) {
	p, ok := BuiltinProfiles()[id]
	if !ok {
		return Profile{}, fmt.Errorf("settings: unknown profile %q", id)
	}
	return p, nil
}
