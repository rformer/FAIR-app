// Package authz is the authorization library every Go service embeds
// (F-001 design §2, ADR-008).
//
// Phase 0 (T-01) provides the public surface and fail-closed defaults:
//   - Checker / Check(principal, permission, buID): the action layer.
//   - BeginScoped: starts a transaction carrying the signed DB context that
//     PostgreSQL RLS verifies (the data layer, ADR-007).
//
// The grant-snapshot checker arrives in T-12 and the signed-context
// verification functions in T-09. Until then the only Checker is DenyAll.
package authz

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// PrincipalKind distinguishes human users from service accounts.
type PrincipalKind string

const (
	PrincipalUser           PrincipalKind = "user"
	PrincipalServiceAccount PrincipalKind = "service_account"
	PrincipalBreakGlass     PrincipalKind = "breakglass"
)

// Principal is the authenticated caller, taken from the internal JWT.
type Principal struct {
	ID           string
	Kind         PrincipalKind
	ScopeVersion int64
}

// Permission is a catalog permission key such as "analysis.edit".
type Permission string

var permRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Valid reports whether p is syntactically a catalog key.
func (p Permission) Valid() bool { return permRe.MatchString(string(p)) }

// ErrDenied is returned when the caller lacks the permission at the BU.
// Handlers translate it to 404 for out-of-scope records (AC-25) or 403
// for in-scope actions the caller may not perform.
var ErrDenied = errors.New("authz: denied")

// ErrInvalidRequest is returned for malformed checks; it is also a denial.
var ErrInvalidRequest = fmt.Errorf("%w: invalid request", ErrDenied)

// Checker decides whether a principal may perform an action in a BU.
type Checker interface {
	Check(ctx context.Context, p Principal, perm Permission, buID string) error
}

// DenyAll is the fail-closed Checker used until the grant snapshot (T-12)
// is wired in. A service that forgets to configure a Checker denies everything.
type DenyAll struct{}

// Check implements Checker.
func (DenyAll) Check(_ context.Context, p Principal, perm Permission, buID string) error {
	if err := validate(p, perm, buID); err != nil {
		return err
	}
	return ErrDenied
}

func validate(p Principal, perm Permission, buID string) error {
	if p.ID == "" || !perm.Valid() || buID == "" {
		return ErrInvalidRequest
	}
	return nil
}

// Check is a convenience that treats a nil Checker as DenyAll.
func Check(ctx context.Context, c Checker, p Principal, perm Permission, buID string) error {
	if c == nil {
		c = DenyAll{}
	}
	return c.Check(ctx, p, perm, buID)
}
