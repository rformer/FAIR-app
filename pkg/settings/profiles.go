package settings

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Family groups profiles for conditional hard floors (e.g. FIPS).
type Family string

const (
	FamilyFedRAMP    Family = "fedramp"
	FamilyCMMC       Family = "cmmc"
	FamilyEnterprise Family = "enterprise"
)

// Bound is a profile's default and weakest allowed value for one setting.
type Bound struct {
	Default any
	Weakest any // values weaker than this are out of bounds
}

// Profile is a named set of defaults and bounds (F-015 R-02).
type Profile struct {
	ID       string
	Title    string
	Family   Family
	Version  string
	Settings map[string]Bound
}

// Built-in profile IDs.
const (
	ProfileFedRAMPModerate    = "fedramp-moderate"
	ProfileCMMCL2R2           = "cmmc-l2-r2"
	ProfileEnterpriseBaseline = "enterprise-baseline"
)

// F-001 setting keys.
const (
	KeySessionIdleTimeout     = "session.idle_timeout"
	KeySessionAbsoluteTimeout = "session.absolute_timeout"
	KeySessionNetworkBinding  = "session.network_binding"
	KeyAuthMFAPrivileged      = "auth.mfa_required_privileged"
	KeyAuthMFAAll             = "auth.mfa_required_all"
	KeyAuthJIT                = "auth.jit_provisioning"
	KeyAuthTOTP               = "auth.totp_enabled"
	KeyAuthLockoutThreshold   = "auth.lockout_threshold"
	KeyAuthLockoutWindow      = "auth.lockout_window"
	KeyAuthInactiveDisable    = "auth.inactive_disable_after"
	KeyBannerEnabled          = "banner.enabled"
	KeyTokenMaxLifetime       = "token.max_lifetime"
	KeyBUNewRestricted        = "bu.new_restricted_default"
	KeyBreakGlassEnabled      = "breakglass.enabled"
	KeyExceptionMaxDuration   = "exception.max_duration"
	KeyTLSMinVersion          = "tls.min_version"
	KeyAuditEnabled           = "audit.enabled"
	KeyRLSEnforced            = "rls.enforced"
	KeyFIPSEnabled            = "fips.enabled"
)

const day = 24 * time.Hour

// F001Defs returns the F-001 setting definitions. Parameter IDs follow the
// OSCAL 800-53r5 catalog naming; profilegen (F-015 T-02/T-05) will verify them.
func F001Defs() []Def {
	return []Def{
		{Key: KeySessionIdleTimeout, Kind: KindDuration, Direction: LowerIsStricter, Params: []string{"ac-11_odp.01"}, Controls: []string{"AC-11"}, BUScopable: false, Description: "Idle session timeout"},
		{Key: KeySessionAbsoluteTimeout, Kind: KindDuration, Direction: LowerIsStricter, Params: []string{"ac-12_odp"}, Controls: []string{"AC-12"}, Description: "Absolute session lifetime"},
		{Key: KeySessionNetworkBinding, Kind: KindEnum, Direction: OrderedEnum, Order: []string{"off", "flag", "reauthenticate"}, Controls: []string{"AC-12", "SC-23"}, BUScopable: true, Description: "Behavior when a session's client network changes"},
		{Key: KeyAuthMFAPrivileged, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"IA-2(1)"}, Floor: true, Description: "MFA required for privileged permissions"},
		{Key: KeyAuthMFAAll, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"IA-2(2)"}, Description: "MFA required for all users"},
		{Key: KeyAuthJIT, Kind: KindBool, Direction: FalseIsStricter, Controls: []string{"AC-2"}, Description: "Just-in-time user provisioning"},
		{Key: KeyAuthTOTP, Kind: KindBool, Direction: FalseIsStricter, Controls: []string{"IA-2(8)"}, Description: "TOTP allowed for non-privileged users (bundled Keycloak)"},
		{Key: KeyAuthLockoutThreshold, Kind: KindInt, Direction: LowerIsStricter, Params: []string{"ac-07_odp.01"}, Controls: []string{"AC-7"}, Description: "Consecutive failed logins before lockout (local accounts)"},
		{Key: KeyAuthLockoutWindow, Kind: KindDuration, Direction: HigherIsStricter, Params: []string{"ac-07_odp.02"}, Controls: []string{"AC-7"}, Description: "Window in which failures are counted"},
		{Key: KeyAuthInactiveDisable, Kind: KindDuration, Direction: LowerIsStricter, Params: []string{"ac-02.03_odp.01"}, Controls: []string{"AC-2(3)"}, Description: "Disable accounts after this much inactivity"},
		{Key: KeyBannerEnabled, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"AC-8"}, Description: "System use notification banner"},
		{Key: KeyTokenMaxLifetime, Kind: KindDuration, Direction: LowerIsStricter, Controls: []string{"IA-5"}, Description: "Maximum API token lifetime"},
		{Key: KeyBUNewRestricted, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"AC-3", "AC-6"}, Description: "New business units are restricted by default"},
		{Key: KeyBreakGlassEnabled, Kind: KindBool, Direction: FalseIsStricter, Controls: []string{"AC-2", "AC-6"}, Description: "Break-glass local admin accounts enabled"},
		{Key: KeyExceptionMaxDuration, Kind: KindDuration, Direction: LowerIsStricter, Controls: []string{"CA-5", "CM-6"}, Description: "Maximum exception duration before automatic revert"},
		{Key: KeyTLSMinVersion, Kind: KindEnum, Direction: OrderedEnum, Order: []string{"1.0", "1.1", "1.2", "1.3"}, Controls: []string{"SC-8", "SC-13"}, Floor: "1.2", Description: "Minimum TLS version"},
		{Key: KeyAuditEnabled, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"AU-2", "AU-12"}, Floor: true, Description: "Security audit logging"},
		{Key: KeyRLSEnforced, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"AC-3"}, Floor: true, Description: "Row-level security enforced"},
		{Key: KeyFIPSEnabled, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"SC-13"}, Floor: true, FloorFamilies: []Family{FamilyFedRAMP, FamilyCMMC}, Description: "FIPS 140-validated cryptography"},
	}
}

// BuiltinProfiles returns the three v1 built-in profiles for F-001 settings.
// Values are placeholders pending profilegen (F-015 Phase A), which derives
// them from the OSCAL baselines; tests assert they respect the hard floor.
func BuiltinProfiles() []Profile {
	strict := func(def any) Bound { return Bound{Default: def, Weakest: def} }
	common := func() map[string]Bound {
		return map[string]Bound{
			KeySessionIdleTimeout:     strict(15 * time.Minute),
			KeySessionAbsoluteTimeout: strict(12 * time.Hour),
			KeySessionNetworkBinding:  strict("reauthenticate"),
			KeyAuthMFAPrivileged:      strict(true),
			KeyAuthMFAAll:             strict(true),
			KeyAuthJIT:                strict(false),
			KeyAuthTOTP:               strict(false),
			KeyAuthLockoutThreshold:   strict(3),
			KeyAuthLockoutWindow:      strict(15 * time.Minute),
			KeyAuthInactiveDisable:    strict(90 * day),
			KeyBannerEnabled:          strict(true),
			KeyTokenMaxLifetime:       strict(90 * day),
			KeyBUNewRestricted:        strict(true),
			KeyBreakGlassEnabled:      strict(false), // enabling always needs approval
			KeyExceptionMaxDuration:   strict(90 * day),
			KeyTLSMinVersion:          {Default: "1.2", Weakest: "1.2"},
			KeyAuditEnabled:           strict(true),
			KeyRLSEnforced:            strict(true),
			KeyFIPSEnabled:            strict(true),
		}
	}

	fed := common()
	cmmc := common()

	ent := common()
	ent[KeySessionIdleTimeout] = Bound{Default: 15 * time.Minute, Weakest: 30 * time.Minute}
	ent[KeySessionAbsoluteTimeout] = Bound{Default: 12 * time.Hour, Weakest: 24 * time.Hour}
	ent[KeySessionNetworkBinding] = Bound{Default: "off", Weakest: "off"}
	ent[KeyAuthJIT] = Bound{Default: false, Weakest: true}
	ent[KeyAuthTOTP] = Bound{Default: false, Weakest: true}
	ent[KeyAuthLockoutThreshold] = Bound{Default: 5, Weakest: 10}
	ent[KeyAuthInactiveDisable] = Bound{Default: 90 * day, Weakest: 180 * day}
	ent[KeyBUNewRestricted] = Bound{Default: true, Weakest: false}
	ent[KeyFIPSEnabled] = Bound{Default: true, Weakest: false}

	return []Profile{
		{ID: ProfileFedRAMPModerate, Title: "FedRAMP Moderate", Family: FamilyFedRAMP, Version: "0.1.0-stub", Settings: fed},
		{ID: ProfileCMMCL2R2, Title: "CMMC Level 2 (NIST SP 800-171 Rev 2)", Family: FamilyCMMC, Version: "0.1.0-stub", Settings: cmmc},
		{ID: ProfileEnterpriseBaseline, Title: "Enterprise Baseline", Family: FamilyEnterprise, Version: "0.1.0-stub", Settings: ent},
	}
}

// floorApplies reports whether d's hard floor applies under profile p.
func (d Def) floorApplies(p Profile) bool {
	if d.Floor == nil {
		return false
	}
	return len(d.FloorFamilies) == 0 || slices.Contains(d.FloorFamilies, p.Family)
}

// belowFloor reports whether v is weaker than d's floor under profile p.
func (d Def) belowFloor(p Profile, v any) (bool, error) {
	if !d.floorApplies(p) {
		return false, nil
	}
	c, err := d.Compare(v, d.Floor)
	return c < 0, err
}

// ValidateProfile checks that a profile binds every definition, that values
// are well-typed, that defaults are within bounds, and that no bound is weaker
// than the hard floor (F-015 AC-01, AC-31).
func ValidateProfile(p Profile, defs []Def) error {
	var errs []error
	for _, d := range defs {
		b, ok := p.Settings[d.Key]
		if !ok {
			errs = append(errs, fmt.Errorf("profile %s: missing binding for %s", p.ID, d.Key))
			continue
		}
		if err := d.Validate(b.Default); err != nil {
			errs = append(errs, fmt.Errorf("profile %s default: %w", p.ID, err))
			continue
		}
		if err := d.Validate(b.Weakest); err != nil {
			errs = append(errs, fmt.Errorf("profile %s bound: %w", p.ID, err))
			continue
		}
		if c, _ := d.Compare(b.Default, b.Weakest); c < 0 {
			errs = append(errs, fmt.Errorf("profile %s: %s default is weaker than its own bound", p.ID, d.Key))
		}
		if below, _ := d.belowFloor(p, b.Weakest); below {
			errs = append(errs, fmt.Errorf("profile %s: %s bound is weaker than the hard floor", p.ID, d.Key))
		}
	}
	return errors.Join(errs...)
}
