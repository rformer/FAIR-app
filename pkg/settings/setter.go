package settings

import (
	"context"
	"errors"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
)

// Setter is the settings.Set contract of F-001 design §8: every write to a
// security setting is evaluated against the active profile and takes one of
// the F-015 paths (applied; applied with a warning; dual approval; refused
// at the hard floor).
//
// posture.Setter is the implementation (F-015 T-16): the change evaluator
// embedded in the calling service, acting for p through p's signed database
// context. Approvals are decided through the approvals module and applied
// with posture.Setter.ApplyApproved; renewal and automatic revert are in
// package posture too (T-17, T-18).
type Setter interface {
	Set(ctx context.Context, p authz.Principal, req Request) (Result, error)
}

// Errors returned by Setter (and the settings client).
var (
	ErrUnknownKey          = errors.New("settings: unknown key")
	ErrHardFloor           = errors.New("settings: change would weaken a hard-floor setting")
	ErrExplanationRequired = errors.New("settings: a written explanation is required to loosen beyond the profile bound")
	ErrExpiryTooLong       = errors.New("settings: requested exception expiry exceeds the maximum duration")
)

// Outcome of a change request.
type Outcome string

// Outcomes.
const (
	Applied         Outcome = "applied"
	PendingApproval Outcome = "pending_approval"
	Refused         Outcome = "refused"
)

// Warning is shown before an out-of-bounds change is submitted (F-015 AC-21).
type Warning struct {
	Key      string
	Bound    any
	Controls []string
	Message  string
}

// Request asks to change a setting. The requester is the principal passed
// to Set, never a field.
type Request struct {
	Key         string
	Value       any // time.Duration, int, bool or string, per the setting's kind
	Explanation string
	BUID        string // BU override ("" = instance-wide)
	// ExceptionDuration: how long the exception lasts if the change is out
	// of bounds and approved; 0 = the maximum in force (AC-24).
	ExceptionDuration time.Duration
}

// Result describes what happened to a request.
type Result struct {
	Outcome    Outcome
	ApprovalID string
	ChangeID   string // the recorded change, applied with ApplyApproved once approved
	Warning    *Warning
}
