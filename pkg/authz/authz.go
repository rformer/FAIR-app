// Package authz is the in-process authorization library embedded by every Go
// service (F-001 design §2, ADR-007, ADR-008).
//
// Cache implements Checker over a per-user grant snapshot (T-12), MintDBContext
// builds the signed database context (T-09), and WithDBContext runs a
// transaction under it.
package authz

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Permission is a catalog permission key such as "analysis.edit".
type Permission string

// Principal identifies the caller.
type Principal struct {
	UserID       string
	ScopeVersion int64
	ServiceAcct  bool
	// DBToken is the signed database context the gateway minted for this
	// request (MintDBContext). Snapshots are loaded through it, and services
	// pass it to WithDBContext.
	DBToken string
	// AuthTime is when the user last authenticated at the IdP (the session's
	// auth_time, F-015 T-24b). Zero means unknown, which fails any step-up
	// check.
	AuthTime time.Time
}

var (
	// ErrDenied means the principal lacks the permission at the BU. Callers
	// must surface out-of-scope resources as 404 (F-001 AC-25), not 403.
	ErrDenied = errors.New("authz: denied")

	// ErrStepUpRequired means the BU requires fresher authentication
	// (F-015 Restricted BU overlay; F-015 T-24). Check returns it as a
	// *StepUpError, which carries the maximum age to re-authenticate within.
	ErrStepUpRequired = errors.New("authz: step-up authentication required")

	// ErrStaleScope means the principal's scope version is older than current.
	ErrStaleScope = errors.New("authz: stale scope version")
)

// StepUpError is ErrStepUpRequired with the BU's maximum authentication age
// (bu.reauth_max_age), for the IdP re-authentication (max_age).
type StepUpError struct {
	MaxAge time.Duration
}

func (e *StepUpError) Error() string {
	return fmt.Sprintf("%s (re-authenticate within %s)", ErrStepUpRequired, e.MaxAge)
}

// Is makes errors.Is(err, ErrStepUpRequired) hold.
func (e *StepUpError) Is(target error) bool { return target == ErrStepUpRequired }

// Checker answers action-level authorization questions.
type Checker interface {
	Check(ctx context.Context, p Principal, perm Permission, buID string) error
}
