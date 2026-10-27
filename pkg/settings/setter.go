package settings

import (
	"context"

	"github.com/rformer/fair-app/pkg/authz"
)

// Setter is the settings.Set contract of F-001 design §8: every write to a
// security setting is evaluated against the active profile and takes one of
// the F-015 paths (applied; applied with a warning; dual approval; refused
// at the hard floor).
//
// posture.Setter is the real implementation (F-015 T-16): the change
// evaluator embedded in the calling service, acting for p through p's signed
// database context. It returns ErrHardFloor or ErrExplanationRequired (with
// Result.Warning) like the T-00b Registry. Approvals are decided through
// the approvals module and applied with posture.Setter.ApplyApproved.
//
// Registry, the T-00b stand-in, remains for the exception lifecycle until
// F-015 T-17 and T-18 move renewal and automatic revert to the posture
// service.
type Setter interface {
	Set(ctx context.Context, p authz.Principal, req Request) (Result, error)
}
