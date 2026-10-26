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
