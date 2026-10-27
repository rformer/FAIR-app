package posture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Evaluator applies setting changes (F-015 T-14; design §6.2): hard-floor
// refusal, tightening and in-bounds changes applied at once, and
// out-of-bounds changes routed through an explanation, a warning naming the
// affected controls, and dual approval, then applied as an exception. The
// database enforces every rule (migrations 0012 and 0018); the evaluator
// adds the warning, the audit events and the change announcement.
type Evaluator struct {
	DB      *pgxpool.Pool // app_posture in the posture service; app_rw where a service embeds settings.Set (T-16)
	Audit   audit.Emitter
	Publish Publisher // optional: posture.setting.changed; caches also poll
}

// ChangeRequest is a requested value for a setting, in package encoding
// (durations as Go duration strings).
type ChangeRequest struct {
	Key         string
	BUID        string // "" = instance-wide
	Value       json.RawMessage
	Explanation string // required when out of bounds
}

// Outcome of a change request.
type Outcome string

// Outcomes.
const (
	Applied         Outcome = "applied"
	PendingApproval Outcome = "pending_approval"
)

// Warning is the out-of-bounds warning (AC-21): the change is weaker than
// the active profile allows, and these controls and parameters are affected.
type Warning struct {
	Key      string          `json:"key"`
	Current  json.RawMessage `json:"current"`
	Proposed json.RawMessage `json:"proposed"`
	Bound    json.RawMessage `json:"bound"`
	Params   []string        `json:"params"`
	Controls []string        `json:"controls"`
	Message  string          `json:"message"`
}

// ChangeResult reports a change request.
type ChangeResult struct {
	Outcome    Outcome
	ChangeID   string
	Direction  string // tighten, neutral or loosen
	ApprovalID string // pending approvals
	Warning    *Warning
	// PublishErr is a failure to announce an applied change. The change is
	// committed; caches still pick it up through their poll.
	PublishErr error
}

// Errors returned by the evaluator.
var (
	ErrHardFloor           = errors.New("posture: the change would weaken a hard-floor setting")
	ErrExplanationRequired = errors.New("posture: the change is outside the active profile's bounds; a written explanation and dual approval are required")
	ErrInvalidValue        = errors.New("posture: invalid setting or value")
	ErrNoContext           = errors.New("posture: a valid signed database context is required")
	ErrNotPermitted        = errors.New("posture: settings.change is required")
	ErrNotApplicable       = errors.New("posture: the change cannot be applied in its current state")
	ErrNotApproved         = errors.New("posture: the change has not been approved, or its approval has expired or been used")
	ErrConfiguration       = errors.New("posture: posture is not configured for this setting")
)

type preview struct {
	direction               string
	belowFloor, outOfBounds bool
	current, bound, floor   json.RawMessage
	params                  []string
	covered                 bool // out of bounds, but a tightening under an active exception (AC-22)
}

// Change evaluates and, where the rules allow, applies a change requested by
// p. A hard-floor refusal is audited (high) even though nothing is written;
// if that audit fails, the error says so. Applied changes and requests for
// approval are audited inside their transaction: no audit, no change.
func (ev Evaluator) Change(ctx context.Context, p authz.Principal, r ChangeRequest) (ChangeResult, error) {
	var res ChangeResult
	bu := nullable(r.BUID)
	var pv preview
	err := ev.DB.QueryRow(ctx, `SELECT direction, below_floor, out_of_bounds, current_value, bound, hard_floor, params, covered
		FROM posture.preview_change($1, $2, $3)`, r.Key, bu, []byte(r.Value)).
		Scan(&pv.direction, &pv.belowFloor, &pv.outOfBounds, &pv.current, &pv.bound, &pv.floor, &pv.params, &pv.covered)
	if err != nil {
		return res, mapErr(err)
	}
	res.Direction = pv.direction
	if pv.belowFloor {
		return res, ev.refuseFloor(ctx, p, r, pv.floor)
	}
	if pv.outOfBounds && !pv.covered {
		res.Warning = &Warning{Key: r.Key, Current: pv.current, Proposed: r.Value, Bound: pv.bound, Params: pv.params,
			Controls: ControlsForParams(pv.params),
			Message: fmt.Sprintf("%s = %s is weaker than the active profile allows (%s). It affects %s and needs a written explanation and a second approver; on approval it applies as a time-limited exception.",
				r.Key, r.Value, pv.bound, strings.Join(ControlsForParams(pv.params), ", "))}
		if strings.TrimSpace(r.Explanation) == "" {
			return res, ErrExplanationRequired
		}
	}

	err = authz.WithDBContext(ctx, ev.DB, p.DBToken, func(tx pgx.Tx) error {
		var approval *string
		if err := tx.QueryRow(ctx, "SELECT change_id, direction, state, approval_request_id FROM posture.request_change($1, $2, $3, $4)",
			r.Key, bu, []byte(r.Value), r.Explanation).Scan(&res.ChangeID, &res.Direction, &res.Outcome, &approval); err != nil {
			return err
		}
		attrs := map[string]string{"key": r.Key, "bu_id": r.BUID, "value": string(r.Value), "previous": string(pv.current),
			"direction": res.Direction, "change_id": res.ChangeID}
		if res.Outcome == PendingApproval {
			res.ApprovalID = *approval
			attrs["approval_id"] = res.ApprovalID
			attrs["bound"] = string(pv.bound)
			attrs["controls"] = strings.Join(res.Warning.Controls, ",")
			return ev.Audit.Emit(ctx, audit.Event{Type: "setting.change_requested", Severity: audit.SeverityHigh, Actor: p.UserID,
				Target: "setting:" + r.Key, Reason: r.Explanation, Attributes: attrs})
		}
		var exc *string
		if err := tx.QueryRow(ctx, "SELECT posture.apply_change($1)", res.ChangeID).Scan(&exc); err != nil {
			return err
		}
		res.Outcome = Applied
		sev := audit.SeverityInfo
		if res.Direction == "loosen" {
			sev = audit.SeverityLow // a loosening within bounds: audited and flagged (AC-20)
		}
		return ev.Audit.Emit(ctx, audit.Event{Type: "setting.changed", Severity: sev, Actor: p.UserID,
			Target: "setting:" + r.Key, Reason: r.Explanation, Attributes: attrs})
	})
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "PF001" { // the floor or profile moved since the preview
		return ChangeResult{}, ev.refuseFloor(ctx, p, r, pv.floor)
	}
	if err != nil {
		return ChangeResult{}, mapErr(err)
	}
	if res.Outcome == Applied && ev.Publish != nil {
		res.PublishErr = PublishChanged(ctx, ev.DB, ev.Publish, r.Key, r.BUID)
	}
	return res, nil
}

func (ev Evaluator) refuseFloor(ctx context.Context, p authz.Principal, r ChangeRequest, floor json.RawMessage) error {
	if err := ev.Audit.Emit(ctx, audit.Event{Type: "setting.hard_floor_refused", Severity: audit.SeverityHigh, Actor: p.UserID,
		Target: "setting:" + r.Key, Attributes: map[string]string{"key": r.Key, "bu_id": r.BUID, "value": string(r.Value), "hard_floor": string(floor)}}); err != nil {
		return fmt.Errorf("%w (and the refusal could not be audited: %w)", ErrHardFloor, err)
	}
	return ErrHardFloor
}

// Exception is an applied out-of-bounds change.
type Exception struct {
	ID, Key, BUID, OwnerID, ApprovedBy string
	Value                              json.RawMessage
	ExpiresAt                          time.Time
}

// ApplyApproved applies an approved out-of-bounds change as an exception
// (AC-21): the approval is consumed once, the floor re-checked, and
// setting.exception_created emitted (high) inside the transaction.
func (ev Evaluator) ApplyApproved(ctx context.Context, changeID string) (Exception, error) {
	var x Exception
	err := pgx.BeginFunc(ctx, ev.DB, func(tx pgx.Tx) error {
		var id *string
		if err := tx.QueryRow(ctx, "SELECT posture.apply_change($1)", changeID).Scan(&id); err != nil {
			return err
		}
		if id == nil {
			return fmt.Errorf("%w: change %s needed no approval", ErrNotApplicable, changeID)
		}
		x.ID = *id
		var bu *string
		if err := tx.QueryRow(ctx, "SELECT key, bu_id::text, value, owner_id::text, approved_by::text, expires_at FROM posture.exception_summary($1)", x.ID).
			Scan(&x.Key, &bu, &x.Value, &x.OwnerID, &x.ApprovedBy, &x.ExpiresAt); err != nil {
			return err
		}
		if bu != nil {
			x.BUID = *bu
		}
		return ev.Audit.Emit(ctx, audit.Event{Type: "setting.exception_created", Severity: audit.SeverityHigh, Actor: x.ApprovedBy,
			Target: "setting:" + x.Key, Attributes: map[string]string{
				"key": x.Key, "bu_id": x.BUID, "value": string(x.Value), "change_id": changeID, "exception_id": x.ID,
				"owner": x.OwnerID, "approved_by": x.ApprovedBy, "expires_at": x.ExpiresAt.UTC().Format(time.RFC3339)}})
	})
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "AP004" {
			return Exception{}, fmt.Errorf("%w: %s", ErrNotApproved, pg.Message)
		}
		return Exception{}, mapErr(err)
	}
	if ev.Publish != nil {
		_ = PublishChanged(ctx, ev.DB, ev.Publish, x.Key, x.BUID) // caches also poll
	}
	return x, nil
}

func mapErr(err error) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		if errors.Is(err, authz.ErrNoDBContext) {
			return fmt.Errorf("%w: %w", ErrNoContext, err)
		}
		return err
	}
	sentinel := map[string]error{
		"PF001": ErrHardFloor, "PF002": ErrExplanationRequired, "PF003": ErrNotApplicable, "PF004": ErrInvalidValue,
		"PF006": ErrConfiguration, "PF007": ErrNoContext, "PF008": ErrNotPermitted, "AP004": ErrNotApproved,
	}[pg.Code]
	if sentinel == nil {
		return err
	}
	return fmt.Errorf("%w: %s", sentinel, pg.Message)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

var paramRE = regexp.MustCompile(`^([a-z]{2})-(\d+)(?:\.(\d+))?_odp`)

// ControlsForParams names the 800-53r5 controls of OSCAL parameter ids, for
// warnings: "ac-02.03_odp.02" is AC-2(3), "ac-11_odp.02" is AC-11.
func ControlsForParams(params []string) []string {
	var out []string
	for _, p := range params {
		m := paramRE.FindStringSubmatch(p)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		c := fmt.Sprintf("%s-%d", strings.ToUpper(m[1]), n)
		if m[3] != "" {
			e, _ := strconv.Atoi(m[3])
			c += fmt.Sprintf("(%d)", e)
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}
