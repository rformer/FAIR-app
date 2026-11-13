package settings

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Family groups profiles for conditional hard floors (e.g. FIPS).
type Family string

// The profile families.
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
	KeyBUReauthMaxAge         = "bu.reauth_max_age"
	KeyBreakGlassEnabled      = "breakglass.enabled"
	KeyExceptionMaxDuration   = "exception.max_duration"
	KeyTLSMinVersion          = "tls.min_version"
	KeyAuditEnabled           = "audit.enabled"
	KeyRLSEnforced            = "rls.enforced"
	KeyFIPSEnabled            = "fips.enabled"
)

// F-002 setting keys (design §4.4).
const (
	KeyAuditRetentionOnline   = "audit.retention_online"
	KeyAuditRetentionTotal    = "audit.retention_total"
	KeyAuditMaxClockSkew      = "audit.max_clock_skew"
	KeyAuditBacklogRecords    = "audit.forward_backlog_records"
	KeyAuditBacklogAge        = "audit.forward_backlog_age"
	KeyAuditSyslogDestination = "audit.syslog_destination"
	KeyAuditOTLPDestination   = "audit.otlp_destination"
)

// F-004 setting keys (design §7).
const (
	KeyEstimateReminderLead    = "estimate.reminder_lead"
	KeyCalibrationExerciseSize = "calibration.exercise_size"
	KeyCalibrationReusePeriod  = "calibration.reuse_period"
	KeyCalibrationWindow       = "calibration.window"
	KeyCalibrationMinAnswers   = "calibration.min_answers"
	KeyCalibrationRetention    = "calibration.retention"
)

// F-005 setting keys (design §7).
const (
	KeySimulationIterationsDefault = "simulation.iterations_default"
	KeySimulationIterationsMin     = "simulation.iterations_min"
	KeySimulationIterationsMax     = "simulation.iterations_max"
	KeySimulationMaxActiveRuns     = "simulation.max_active_runs"
	KeySimulationConvergenceBP     = "simulation.convergence_threshold_bp"
)

// F-007 setting keys (design §4).
const (
	KeyRegisterIterations     = "register.iterations"
	KeyRegisterAnalysisMaxAge = "register.analysis_max_age_days"
)

// F007Defs returns the F-007 (risk register) setting definitions,
// registered by the risk service. The profiles bound the loosening side;
// the service keeps the other limits (design §4): the register's iteration
// count within the simulation bounds, the maximum age at least 30 days.
func F007Defs() []Def {
	return []Def{
		{Key: KeyRegisterIterations, Kind: KindInt, Direction: HigherIsStricter, Controls: []string{"RA-3"},
			Description: "Iterations a run must have to be pinned as a register risk's analysis"},
		{Key: KeyRegisterAnalysisMaxAge, Kind: KindInt, Direction: LowerIsStricter, Controls: []string{"RA-3"},
			Description: "Days after which a register risk's pinned analysis is stale"},
	}
}

// F005Defs returns the F-005 (simulation) setting definitions, registered by
// the risk service. The profiles bound the loosening side; the service
// keeps the other limits (design §4.3, §7): iterations_min at least 1,000,
// the default between the minimum and the maximum, the convergence
// threshold at least 10 basis points.
func F005Defs() []Def {
	return []Def{
		{Key: KeySimulationIterationsDefault, Kind: KindInt, Direction: HigherIsStricter, Controls: []string{"RA-3"},
			Description: "Iterations of a simulation run when the analyst does not choose"},
		{Key: KeySimulationIterationsMin, Kind: KindInt, Direction: HigherIsStricter, Controls: []string{"RA-3"},
			Description: "The fewest iterations a simulation run may have"},
		{Key: KeySimulationIterationsMax, Kind: KindInt, Direction: LowerIsStricter, Controls: []string{"SC-5"},
			Description: "The most iterations a simulation run may have"},
		{Key: KeySimulationMaxActiveRuns, Kind: KindInt, Direction: LowerIsStricter, Controls: []string{"SC-5"},
			Description: "Simulation runs a person may have queued or running at once"},
		{Key: KeySimulationConvergenceBP, Kind: KindInt, Direction: LowerIsStricter, Controls: []string{"RA-3"},
			Description: "Relative standard error of the mean annualized loss, in basis points, above which a run is flagged as not converged"},
	}
}

// F004Defs returns the F-004 (estimate capture and calibration) setting
// definitions, registered by the risk service. Only the loosening side is
// bounded by the profiles; the other limits (an exercise of at most 50
// questions) are the service's (design §4.4).
func F004Defs() []Def {
	return []Def{
		{Key: KeyEstimateReminderLead, Kind: KindDuration, Direction: HigherIsStricter, Controls: []string{"RA-3"},
			Description: "How long before an estimate request's due date its estimators are reminded"},
		{Key: KeyCalibrationExerciseSize, Kind: KindInt, Direction: HigherIsStricter, Controls: []string{"RA-3"},
			Description: "Questions in a calibration exercise (at most 50)"},
		{Key: KeyCalibrationReusePeriod, Kind: KindDuration, Direction: HigherIsStricter, Controls: []string{"RA-3"},
			Description: "How long before a person may be given a calibration question they answered again"},
		{Key: KeyCalibrationWindow, Kind: KindDuration, Direction: HigherIsStricter, Controls: []string{"RA-3"},
			Description: "How far back calibration answers count towards a person's score"},
		{Key: KeyCalibrationMinAnswers, Kind: KindInt, Direction: HigherIsStricter, Controls: []string{"RA-3"},
			Description: "Answers of a kind (range or binary) needed before calibration is measured"},
		{Key: KeyCalibrationRetention, Kind: KindDuration, Direction: LowerIsStricter, Controls: []string{"SI-12", "PT-2"},
			Description: "How long calibration exercises and score history are kept (personal data)"},
	}
}

// F002Defs returns the F-002 (audit trail) setting definitions, registered
// by the audit service and bound in bindings/ like F-001's.
func F002Defs() []Def {
	return []Def{
		{Key: KeyAuditRetentionOnline, Kind: KindDuration, Direction: HigherIsStricter, Params: []string{"au-11_odp"}, Controls: []string{"AU-11"},
			Floor: 90 * day, LooseningNeedsApproval: true, Description: "How long audit records stay searchable (online retention)"},
		{Key: KeyAuditRetentionTotal, Kind: KindDuration, Direction: HigherIsStricter, Params: []string{"au-11_odp"}, Controls: []string{"AU-11"},
			LooseningNeedsApproval: true, Description: "How long audit records are kept in all, online and archived (at least the online retention)"},
		{Key: KeyAuditMaxClockSkew, Kind: KindDuration, Direction: LowerIsStricter, Controls: []string{"AU-8"},
			Description: "Difference between an event's time and its receipt beyond which the record is flagged"},
		{Key: KeyAuditBacklogRecords, Kind: KindInt, Direction: LowerIsStricter, Controls: []string{"AU-5", "AU-6"},
			Description: "Records waiting for a SIEM destination before a backlog alert"},
		{Key: KeyAuditBacklogAge, Kind: KindDuration, Direction: LowerIsStricter, Controls: []string{"AU-5", "AU-6"},
			Description: "Age of the oldest record waiting for a SIEM destination before a backlog alert"},
		{Key: KeyAuditSyslogDestination, Kind: KindString, Direction: NonEmptyIsStricter, Controls: []string{"AU-6", "SI-4"},
			LooseningNeedsApproval: true, Description: "Syslog over TLS destination for the audit trail (host:port; empty: none)"},
		{Key: KeyAuditOTLPDestination, Kind: KindString, Direction: NonEmptyIsStricter, Controls: []string{"AU-6", "SI-4"},
			LooseningNeedsApproval: true, Description: "OTLP over TLS destination for the audit trail (host:port; empty: none)"},
	}
}

// ReleaseDefs are the setting definitions a release binds: F-001's,
// F-002's, F-004's, F-005's and F-007's. Profile packages cover exactly these
// (internal/profilegen).
func ReleaseDefs() []Def {
	return append(append(append(append(F001Defs(), F002Defs()...), F004Defs()...), F005Defs()...), F007Defs()...)
}

const day = 24 * time.Hour

// F001Defs returns the F-001 setting definitions. Parameter IDs follow the
// OSCAL 800-53r5 catalog naming and must match the binding files in
// bindings/ (F-015 T-05; checked by internal/profilegen tests).
func F001Defs() []Def {
	return []Def{
		{Key: KeySessionIdleTimeout, Kind: KindDuration, Direction: LowerIsStricter, Params: []string{"ac-11_odp.02"}, Controls: []string{"AC-11"}, BUScopable: false, Description: "Idle session timeout"},
		{Key: KeySessionAbsoluteTimeout, Kind: KindDuration, Direction: LowerIsStricter, Params: []string{"ac-12_odp"}, Controls: []string{"AC-12"}, Description: "Absolute session lifetime"},
		{Key: KeySessionNetworkBinding, Kind: KindEnum, Direction: OrderedEnum, Order: []string{"off", "flag", "reauthenticate"}, Controls: []string{"AC-12", "SC-23"}, BUScopable: true, Description: "Behavior when a session's client network changes"},
		{Key: KeyAuthMFAPrivileged, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"IA-2(1)"}, Floor: true, Description: "MFA required for privileged permissions"},
		{Key: KeyAuthMFAAll, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"IA-2(2)"}, Description: "MFA required for all users"},
		{Key: KeyAuthJIT, Kind: KindBool, Direction: FalseIsStricter, Controls: []string{"AC-2"}, Description: "Just-in-time user provisioning"},
		{Key: KeyAuthTOTP, Kind: KindBool, Direction: FalseIsStricter, Params: []string{"ia-02.08_odp"}, Controls: []string{"IA-2(8)"}, Description: "TOTP allowed for non-privileged users (bundled Keycloak)"},
		{Key: KeyAuthLockoutThreshold, Kind: KindInt, Direction: LowerIsStricter, Params: []string{"ac-07_odp.01"}, Controls: []string{"AC-7"}, Description: "Consecutive failed logins before lockout (local accounts)"},
		{Key: KeyAuthLockoutWindow, Kind: KindDuration, Direction: HigherIsStricter, Params: []string{"ac-07_odp.02"}, Controls: []string{"AC-7"}, Description: "Window in which failures are counted"},
		{Key: KeyAuthInactiveDisable, Kind: KindDuration, Direction: LowerIsStricter, Params: []string{"ac-02.03_odp.02"}, Controls: []string{"AC-2(3)"}, Description: "Disable accounts after this much inactivity"},
		{Key: KeyBannerEnabled, Kind: KindBool, Direction: TrueIsStricter, Params: []string{"ac-08_odp.01"}, Controls: []string{"AC-8"}, Description: "System use notification banner"},
		{Key: KeyTokenMaxLifetime, Kind: KindDuration, Direction: LowerIsStricter, Params: []string{"ia-05_odp.01"}, Controls: []string{"IA-5"}, Description: "Maximum API token lifetime"},
		{Key: KeyBUNewRestricted, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"AC-3", "AC-6"}, Description: "New business units are restricted by default"},
		{Key: KeyBUReauthMaxAge, Kind: KindDuration, Direction: LowerIsStricter, Controls: []string{"IA-11"}, BUScopable: true, Description: "Re-authentication required when the sign-in is older than this, before accessing a BU's data (step-up)"},
		{Key: KeyBreakGlassEnabled, Kind: KindBool, Direction: FalseIsStricter, Controls: []string{"AC-2", "AC-6"}, Description: "Break-glass local admin accounts enabled"},
		{Key: KeyExceptionMaxDuration, Kind: KindDuration, Direction: LowerIsStricter, Controls: []string{"CA-5", "CM-6"}, Description: "Maximum exception duration before automatic revert"},
		{Key: KeyTLSMinVersion, Kind: KindEnum, Direction: OrderedEnum, Order: []string{"1.0", "1.1", "1.2", "1.3"}, Controls: []string{"SC-8", "SC-13"}, Floor: "1.2", Description: "Minimum TLS version"},
		{Key: KeyAuditEnabled, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"AU-2", "AU-12"}, Floor: true, Description: "Security audit logging"},
		{Key: KeyRLSEnforced, Kind: KindBool, Direction: TrueIsStricter, Controls: []string{"AC-3"}, Floor: true, Description: "Row-level security enforced"},
		{Key: KeyFIPSEnabled, Kind: KindBool, Direction: TrueIsStricter, Params: []string{"sc-13_odp.02"}, Controls: []string{"SC-13"}, Floor: true, FloorFamilies: []Family{FamilyFedRAMP, FamilyCMMC}, Description: "FIPS 140-validated cryptography"},
	}
}

// BuiltinProfiles returns the three v1 built-in profiles for F-001 settings.
// The values are those of the binding files in bindings/ (F-015 T-05), which
// record where each comes from; internal/profilegen tests keep the two equal
// until signed profile packages (T-06) and the posture service (T-16)
// replace this stand-in.
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
			KeyBUReauthMaxAge:         strict(12 * time.Hour), // the session absolute timeout: no step-up outside restricted BUs
			KeyBreakGlassEnabled:      strict(false),          // enabling always needs approval
			KeyExceptionMaxDuration:   strict(90 * day),
			KeyTLSMinVersion:          {Default: "1.2", Weakest: "1.2"},
			KeyAuditEnabled:           strict(true),
			KeyRLSEnforced:            strict(true),
			KeyFIPSEnabled:            strict(true),
			// F-002 (design §4.4).
			KeyAuditRetentionOnline:   {Default: 365 * day, Weakest: 365 * day},
			KeyAuditRetentionTotal:    {Default: 2557 * day, Weakest: 913 * day}, // 30 months (OMB M-21-31)
			KeyAuditMaxClockSkew:      strict(5 * time.Minute),
			KeyAuditBacklogRecords:    strict(10000),
			KeyAuditBacklogAge:        strict(15 * time.Minute),
			KeyAuditSyslogDestination: strict(""),
			KeyAuditOTLPDestination:   strict(""),
			// F-004 (design §7): the same in every family.
			KeyEstimateReminderLead:    {Default: 48 * time.Hour, Weakest: time.Hour},
			KeyCalibrationExerciseSize: {Default: 20, Weakest: 10},
			KeyCalibrationReusePeriod:  {Default: 180 * day, Weakest: 30 * day},
			KeyCalibrationWindow:       {Default: 365 * day, Weakest: 30 * day},
			KeyCalibrationMinAnswers:   {Default: 20, Weakest: 10},
			KeyCalibrationRetention:    {Default: 1095 * day, Weakest: 2557 * day},
			// F-005 (design §7): the same in every family.
			KeySimulationIterationsDefault: {Default: 100_000, Weakest: 10_000},
			KeySimulationIterationsMin:     {Default: 10_000, Weakest: 1_000},
			KeySimulationIterationsMax:     {Default: 1_000_000, Weakest: 2_000_000},
			KeySimulationMaxActiveRuns:     {Default: 5, Weakest: 50},
			KeySimulationConvergenceBP:     {Default: 100, Weakest: 500},
			// F-007 (design §4): the same in every family.
			KeyRegisterIterations:     {Default: 100_000, Weakest: 10_000},
			KeyRegisterAnalysisMaxAge: {Default: 365, Weakest: 730},
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
	ent[KeyBUReauthMaxAge] = Bound{Default: 12 * time.Hour, Weakest: 24 * time.Hour}
	ent[KeyFIPSEnabled] = Bound{Default: true, Weakest: false}
	ent[KeyAuditRetentionOnline] = Bound{Default: 365 * day, Weakest: 90 * day}
	ent[KeyAuditRetentionTotal] = Bound{Default: 2557 * day, Weakest: 365 * day}
	ent[KeyAuditMaxClockSkew] = Bound{Default: 5 * time.Minute, Weakest: 15 * time.Minute}
	ent[KeyAuditBacklogRecords] = Bound{Default: 10000, Weakest: 100000}
	ent[KeyAuditBacklogAge] = Bound{Default: 15 * time.Minute, Weakest: time.Hour}

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
