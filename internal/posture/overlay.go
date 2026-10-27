package posture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Restricted BU overlay (F-015 T-23; AC-33, AC-34; design §6.6; migration
// 0027). The database applies the overlay to every BU in a restricted
// subtree and enforces its edits: tightening applies at once, and anything
// weaker than the AC-33 default needs an explanation and dual approval and
// becomes an expiring overlay exception (R-07).

// Overlay manages the Restricted BU overlay for a signed-in user.
type Overlay struct {
	DB      *pgxpool.Pool // app_posture
	Audit   audit.Emitter
	Publish Publisher // optional; caches also poll
}

// OverlayEntry is one overlay setting as GET /overlay shows it.
type OverlayEntry struct {
	Key         string
	Default     json.RawMessage // the AC-33 default, and the overlay's bound
	Value       json.RawMessage // in force
	Source      string          // default, change or exception
	ExceptionID string
	ExpiresAt   *time.Time
	Applies     bool     // the setting is registered as BU-scopable
	Params      []string // OSCAL parameters of the setting
}

// View returns the overlay.
func (o Overlay) View(ctx context.Context) ([]OverlayEntry, error) {
	rows, err := o.DB.Query(ctx, "SELECT key, default_value, value, source, coalesce(exception_id::text, ''), expires_at, applies, params FROM posture.overlay()")
	if err != nil {
		return nil, mapErr(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (OverlayEntry, error) {
		var x OverlayEntry
		err := r.Scan(&x.Key, &x.Default, &x.Value, &x.Source, &x.ExceptionID, &x.ExpiresAt, &x.Applies, &x.Params)
		return x, err
	})
}

// Change requests an overlay edit by p and applies it when no approval is
// needed. A value weaker than the default needs an explanation (with a
// warning naming the affected controls) and returns PendingApproval. Every
// outcome is audited inside its transaction.
func (o Overlay) Change(ctx context.Context, p authz.Principal, key string, value json.RawMessage, explanation string, d time.Duration) (ChangeResult, error) {
	var res ChangeResult
	var current, def json.RawMessage
	var params []string
	err := authz.WithDBContext(ctx, o.DB, p.DBToken, func(tx pgx.Tx) error {
		var approval *string
		if err := tx.QueryRow(ctx, `SELECT change_id, direction, state, approval_request_id, current_value, overlay_default, params
			FROM posture.request_overlay_change($1, $2, $3, $4)`, key, []byte(value), explanation, durationArg(d)).
			Scan(&res.ChangeID, &res.Direction, &res.Outcome, &approval, &current, &def, &params); err != nil {
			return err
		}
		attrs := map[string]string{"key": key, "value": string(value), "previous": string(current), "default": string(def),
			"direction": res.Direction, "change_id": res.ChangeID}
		if res.Outcome == PendingApproval {
			res.ApprovalID = *approval
			res.Warning = overlayWarning(key, current, value, def, params)
			attrs["approval_id"] = res.ApprovalID
			attrs["controls"] = strings.Join(res.Warning.Controls, ",")
			return o.Audit.Emit(ctx, audit.Event{Type: "overlay.change_requested", Severity: audit.SeverityHigh, Actor: p.UserID,
				Target: "overlay:" + key, Reason: explanation, Attributes: attrs})
		}
		var exc *string
		if err := tx.QueryRow(ctx, "SELECT posture.apply_overlay_change($1)", res.ChangeID).Scan(&exc); err != nil {
			return err
		}
		res.Outcome = Applied
		sev := audit.SeverityInfo
		if res.Direction == "loosen" {
			sev = audit.SeverityLow // back towards the default: audited and flagged
		}
		return o.Audit.Emit(ctx, audit.Event{Type: "overlay.changed", Severity: sev, Actor: p.UserID,
			Target: "overlay:" + key, Reason: explanation, Attributes: attrs})
	})
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "PF002" {
		// Weaker than the default without an explanation: say what it affects.
		res.Warning = o.warningFor(ctx, key, value)
	}
	if err != nil {
		if errors.As(err, &pg) && pg.Code == "PF001" {
			return res, o.refuseFloor(ctx, p, key, value, mapErr(err))
		}
		return res, mapErr(err)
	}
	if res.Outcome == Applied && o.Publish != nil {
		res.PublishErr = PublishChanged(ctx, o.DB, o.Publish, key, "")
	}
	return res, nil
}

func overlayWarning(key string, current, proposed, def json.RawMessage, params []string) *Warning {
	controls := ControlsForParams(params)
	return &Warning{Key: key, Current: current, Proposed: proposed, Bound: def, Params: params, Controls: controls,
		Message: fmt.Sprintf("Restricted BU overlay %s = %s is weaker than its default (%s). It affects %s on every restricted BU and needs a written explanation and a second approver; on approval it applies as a time-limited exception.",
			key, proposed, def, strings.Join(controls, ", "))}
}

// warningFor builds the warning for a refused request from the overlay view.
func (o Overlay) warningFor(ctx context.Context, key string, value json.RawMessage) *Warning {
	var current, def json.RawMessage
	var params []string
	if err := o.DB.QueryRow(ctx, "SELECT value, default_value, params FROM posture.overlay() WHERE key = $1", key).Scan(&current, &def, &params); err != nil {
		return nil
	}
	return overlayWarning(key, current, value, def, params)
}

func (o Overlay) refuseFloor(ctx context.Context, p authz.Principal, key string, value json.RawMessage, err error) error {
	if aerr := o.Audit.Emit(ctx, audit.Event{Type: "setting.hard_floor_refused", Severity: audit.SeverityHigh, Actor: p.UserID,
		Target: "overlay:" + key, Attributes: map[string]string{"key": key, "overlay": "true", "value": string(value)}}); aerr != nil {
		return fmt.Errorf("%w (and the refusal could not be audited: %w)", err, aerr)
	}
	return err
}

// ApplyApproved applies an approved overlay edit as an overlay exception,
// with overlay.exception_created (high) audited inside the transaction.
func (o Overlay) ApplyApproved(ctx context.Context, changeID string) (Exception, error) {
	var x Exception
	err := pgx.BeginFunc(ctx, o.DB, func(tx pgx.Tx) error {
		var id *string
		if err := tx.QueryRow(ctx, "SELECT posture.apply_overlay_change($1)", changeID).Scan(&id); err != nil {
			return err
		}
		if id == nil {
			return fmt.Errorf("%w: overlay change %s needed no approval", ErrNotApplicable, changeID)
		}
		x.ID = *id
		if err := tx.QueryRow(ctx, "SELECT key, value, owner_id::text, approved_by::text, expires_at FROM posture.exception_summary($1)", x.ID).
			Scan(&x.Key, &x.Value, &x.OwnerID, &x.ApprovedBy, &x.ExpiresAt); err != nil {
			return err
		}
		return o.Audit.Emit(ctx, audit.Event{Type: "overlay.exception_created", Severity: audit.SeverityHigh, Actor: x.ApprovedBy,
			Target: "overlay:" + x.Key, Attributes: map[string]string{
				"key": x.Key, "value": string(x.Value), "change_id": changeID, "exception_id": x.ID,
				"owner": x.OwnerID, "approved_by": x.ApprovedBy, "expires_at": x.ExpiresAt.UTC().Format(time.RFC3339)}})
	})
	if err != nil {
		return Exception{}, mapErr(err)
	}
	if o.Publish != nil {
		_ = PublishChanged(ctx, o.DB, o.Publish, x.Key, "") // caches also poll
	}
	return x, nil
}
