package posture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// Setter implements settings.Setter with the change evaluator (F-015 T-16):
// the registry that replaces the F-001 T-00b stand-in. Embed it in any
// service with a pool connected as app_rw.
type Setter struct {
	Evaluator Evaluator
}

var _ settings.Setter = Setter{}

// Set implements settings.Setter. Values are Go values as the settings
// client returns them (time.Duration, int, bool, string).
func (s Setter) Set(ctx context.Context, p authz.Principal, req settings.Request) (settings.Result, error) {
	v := req.Value
	if d, ok := v.(time.Duration); ok {
		v = d.String()
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return settings.Result{Outcome: settings.Refused}, fmt.Errorf("%w: %w", settings.ErrType, err)
	}
	res, err := s.Evaluator.Change(ctx, p, ChangeRequest{Key: req.Key, BUID: req.BUID, Value: raw, Explanation: req.Explanation,
		ExceptionDuration: req.ExceptionDuration})
	out := settings.Result{ApprovalID: res.ApprovalID, ChangeID: res.ChangeID, Warning: warning(res.Warning)}
	switch {
	case errors.Is(err, ErrHardFloor):
		out.Outcome = settings.Refused
		return out, fmt.Errorf("%w: %w", settings.ErrHardFloor, err)
	case errors.Is(err, ErrExplanationRequired):
		out.Outcome = settings.Refused
		return out, fmt.Errorf("%w: %w", settings.ErrExplanationRequired, err)
	case errors.Is(err, ErrExpiryOutOfRange):
		out.Outcome = settings.Refused
		return out, fmt.Errorf("%w: %w", settings.ErrExpiryTooLong, err)
	case errors.Is(err, ErrInvalidValue):
		out.Outcome = settings.Refused
		return out, fmt.Errorf("%w: %w", settings.ErrType, err)
	case err != nil:
		out.Outcome = settings.Refused
		return out, err
	case res.Outcome == PendingApproval:
		out.Outcome = settings.PendingApproval
	default:
		out.Outcome = settings.Applied
	}
	return out, nil
}

// ApplyApproved applies a change once its approval has been granted.
func (s Setter) ApplyApproved(ctx context.Context, changeID string) (Exception, error) {
	return s.Evaluator.ApplyApproved(ctx, changeID)
}

func warning(w *Warning) *settings.Warning {
	if w == nil {
		return nil
	}
	var bound any
	_ = json.Unmarshal(w.Bound, &bound)
	return &settings.Warning{Key: w.Key, Bound: bound, Controls: w.Controls, Message: w.Message}
}
