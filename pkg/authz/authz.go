// Package authz is the in-process authorization library embedded by every Go
// service (F-001 design §2, ADR-007, ADR-008).
//
// Phase 0 defines the public contract only. The implementation — grant snapshot
// cache, scope invalidation on iam.scope.changed, and the signed database
// context helper — is delivered in F-001 Phase 1 (T-09, T-12).
package authz

import (
	"context"
	"errors"
)

// Permission is a catalog permission key such as "analysis.edit".
type Permission string

// Principal identifies the caller.
type Principal struct {
	UserID       string
	ScopeVersion int64
	ServiceAcct  bool
}

var (
	// ErrDenied means the principal lacks the permission at the BU. Callers
	// must surface out-of-scope resources as 404 (F-001 AC-25), not 403.
	ErrDenied = errors.New("authz: denied")

	// ErrStepUpRequired means the BU requires fresher authentication
	// (F-015 Restricted BU overlay; tracked as F-015 T-24).
	ErrStepUpRequired = errors.New("authz: step-up authentication required")

	// ErrStaleScope means the principal's scope version is older than current.
	ErrStaleScope = errors.New("authz: stale scope version")
)

// Checker answers action-level authorization questions.
type Checker interface {
	Check(ctx context.Context, p Principal, perm Permission, buID string) error
}
