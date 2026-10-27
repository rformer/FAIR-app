package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Profile switch (F-015 T-21; AC-07, AC-16 - AC-19; design §6.4; migration
// 0025). The database computes the conflicts, enforces their resolution and
// the approvals, and activates in one transaction.

// SubjectProfileActivated announces an activated profile.
const SubjectProfileActivated = "posture.profile.activated"

// Switches manages profile switches for a signed-in user.
type Switches struct {
	DB      *pgxpool.Pool
	Audit   audit.Emitter
	Publish Publisher // optional; caches also poll
}

// SwitchRequest is a requested switch.
type SwitchRequest struct {
	ID         string
	Loosening  bool   // the target has a weaker bound: justification and dual approval (AC-19)
	Conflicts  int    // values outside the target's bounds (AC-16)
	ApprovalID string // the loosening's approval request
}

// Request asks to switch to an approved profile version. A loosening
// switch needs a justification.
func (s Switches) Request(ctx context.Context, p authz.Principal, targetID, targetVersion, justification string) (SwitchRequest, error) {
	var r SwitchRequest
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		var approval *string
		if err := tx.QueryRow(ctx, "SELECT switch_id, loosening, conflicts, approval_request_id FROM posture.request_switch($1, $2, $3)",
			targetID, targetVersion, nullable(justification)).Scan(&r.ID, &r.Loosening, &r.Conflicts, &approval); err != nil {
			return err
		}
		if approval != nil {
			r.ApprovalID = *approval
		}
		sev := audit.SeverityInfo
		if r.Loosening {
			sev = audit.SeverityHigh // AC-19
		}
		return s.Audit.Emit(ctx, audit.Event{Type: "profile.switch_requested", Severity: sev, Actor: p.UserID,
			Target: "profile:" + targetID + "@" + targetVersion, Reason: justification, Attributes: map[string]string{
				"switch_id": r.ID, "loosening": strconv.FormatBool(r.Loosening), "conflicts": strconv.Itoa(r.Conflicts), "approval_id": r.ApprovalID}})
	})
	return r, mapErr(err)
}

// Resolution of a conflict.
const (
	Conform       = "conform"
	ExceptionAsIs = "exception"
)

// Resolve resolves one conflict (buID "" = the instance value): Conform, or
// ExceptionAsIs with a reason (and optional duration), which opens a dual
// approval and is refused below the target's hard floor (AC-17). It
// returns the exception's approval request id.
func (s Switches) Resolve(ctx context.Context, p authz.Principal, switchID, key, buID, resolution, reason string, d time.Duration) (string, error) {
	var approval *string
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT posture.resolve_conflict($1, $2, $3, $4, $5, $6)",
			switchID, key, nullable(buID), resolution, nullable(reason), durationArg(d)).Scan(&approval); err != nil {
			return err
		}
		return s.Audit.Emit(ctx, audit.Event{Type: "profile.conflict_resolved", Severity: audit.SeverityInfo, Actor: p.UserID,
			Target: "setting:" + key, Reason: reason, Attributes: map[string]string{"switch_id": switchID, "key": key, "bu_id": buID, "resolution": resolution}})
	})
	if approval == nil {
		return "", mapErr(err)
	}
	return *approval, mapErr(err)
}

// Activate activates a switch in one transaction: refused while any
// conflict is unresolved or any approval is missing; nothing changes then.
// It returns how many values changed.
func (s Switches) Activate(ctx context.Context, p authz.Principal, switchID string) (int, error) {
	var changed int
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT posture.activate_switch($1)", switchID).Scan(&changed); err != nil {
			return err
		}
		return s.Audit.Emit(ctx, audit.Event{Type: "profile.activated", Severity: audit.SeverityHigh, Actor: p.UserID,
			Target: "switch:" + switchID, Attributes: map[string]string{"switch_id": switchID, "changed": strconv.Itoa(changed)}})
	})
	if err != nil {
		return 0, mapErr(err)
	}
	if s.Publish != nil {
		b, _ := json.Marshal(map[string]string{"switch_id": switchID})
		_ = s.Publish.Publish(ctx, SubjectProfileActivated, "posture-switch-"+switchID, b)
		_ = PublishChanged(ctx, s.DB, s.Publish, "", "") // every setting may have changed; caches also poll
	}
	return changed, nil
}

// Cancel cancels a pending switch; nothing changes.
func (s Switches) Cancel(ctx context.Context, p authz.Principal, switchID string) error {
	return mapErr(authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT posture.cancel_switch($1)", switchID); err != nil {
			return err
		}
		return s.Audit.Emit(ctx, audit.Event{Type: "profile.switch_cancelled", Severity: audit.SeverityInfo, Actor: p.UserID,
			Target: "switch:" + switchID, Attributes: map[string]string{"switch_id": switchID}})
	}))
}

// Conflict is one value outside the target profile's bounds.
type Conflict struct {
	Key, BUID         string
	Current, NewBound json.RawMessage
	BelowFloor        bool   // conform only
	Resolution        string // unresolved, conform or exception
}

// PendingSwitch is the pending switch as the Posture page shows it (AC-18).
type PendingSwitch struct {
	ID, From, Target string
	Loosening        bool
	ApprovalID       string
	Conflicts        []Conflict
}

// Unresolved counts the conflicts still blocking activation.
func (ps PendingSwitch) Unresolved() int {
	n := 0
	for _, c := range ps.Conflicts {
		if c.Resolution == "unresolved" {
			n++
		}
	}
	return n
}

// Pending returns the pending switch, or nil.
func (s Switches) Pending(ctx context.Context, p authz.Principal) (*PendingSwitch, error) {
	var ps *PendingSwitch
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT switch_id::text, from_profile, target_profile, loosening, coalesce(approval_request_id::text, ''),
			key, bu_id::text, current_value, new_bound, below_floor, resolution FROM posture.pending_switch()`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sw PendingSwitch
			var key, bu, resolution *string
			var c Conflict
			var floor *bool
			if err := rows.Scan(&sw.ID, &sw.From, &sw.Target, &sw.Loosening, &sw.ApprovalID, &key, &bu, &c.Current, &c.NewBound, &floor, &resolution); err != nil {
				return err
			}
			if ps == nil {
				ps = &sw
			}
			if key != nil {
				c.Key, c.Resolution = *key, *resolution
				if bu != nil {
					c.BUID = *bu
				}
				c.BelowFloor = floor != nil && *floor
				ps.Conflicts = append(ps.Conflicts, c)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("pending switch: %w", mapErr(err))
	}
	return ps, nil
}
