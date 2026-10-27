// Package approvals is the iam approvals module: generic dual approval
// (F-001 T-26, design §5.5). The rules live in the database (migration
// 0017): the acting user always comes from the caller's signed database
// context, a request cannot be decided by its requester, and only holders of
// the kind's approve permission may decide. This package adds the API-side
// checks and maps database errors to sentinel errors.
package approvals

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/pkg/authz"
)

// Kinds of approval (iam.approval_kind).
const (
	KindAdminRiskCombination = "access.admin_risk_combination" // F-001 AC-30
	KindBreakGlassEnable     = "breakglass.enable"             // F-001 AC-41
	KindSoDException         = "sod.exception"                 // F-001 AC-53
	KindBUUnrestrict         = "bu.unrestrict"                 // F-001 AC-63
	KindBURollupLoosen       = "bu.rollup_loosen"              // F-001 AC-63
	KindSettingsOutOfBounds  = "settings.out_of_bounds"        // F-015 AC-21
)

// Status of a request.
type Status string

// Request statuses.
const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Rejected Status = "rejected"
	Expired  Status = "expired"
)

// Errors returned by the module.
var (
	ErrNoContext     = errors.New("approvals: a valid signed database context for an active user is required")
	ErrSelfApproval  = errors.New("approvals: the approver must be a different person than the requester")
	ErrNotAuthorized = errors.New("approvals: not permitted to decide this kind of request")
	ErrNotApplicable = errors.New("approvals: request is not pending, has expired, or does not exist")
	ErrInvalid       = errors.New("approvals: invalid request")
	ErrNotFound      = errors.New("approvals: request not found")
)

// Request is an approval request as its requester or an approver sees it.
type Request struct {
	ID, Kind, TargetRef, Reason string
	Payload                     []byte // JSON
	BUID                        string // "" = root
	RequestedBy                 string
	Status                      Status
	DecidedBy, DecisionReason   string
	CreatedAt, ExpiresAt        time.Time
	DecidedAt, ConsumedAt       *time.Time
}

// NewRequest describes a change that needs a second person's approval.
type NewRequest struct {
	Kind      string
	TargetRef string // what is approved, e.g. a change or assignment id
	Reason    string // stated reason (required)
	Payload   []byte // optional JSON detail for the approver
	BUID      string // where approver authority is checked; "" = root
}

// Service runs approval operations as the calling user.
type Service struct {
	DB authz.TxBeginner
}

// Request asks for approval as p. It returns the request id.
func (s Service) Request(ctx context.Context, p authz.Principal, r NewRequest) (string, error) {
	payload := r.Payload
	if payload == nil {
		payload = []byte("{}")
	}
	var id string
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT iam.request_approval($1, $2, $3, $4::jsonb, $5)",
			r.Kind, r.TargetRef, r.Reason, string(payload), nullable(r.BUID)).Scan(&id)
	})
	return id, mapErr(err)
}

// Get returns a request if p requested it or may decide it.
func (s Service) Get(ctx context.Context, p authz.Principal, id string) (Request, error) {
	var r Request
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		var bu, decidedBy, decisionReason *string
		err := tx.QueryRow(ctx, `SELECT id::text, kind, target_ref, reason, payload::text, bu_id::text, requested_by::text,
			status, decided_by::text, decision_reason, created_at, expires_at, decided_at, consumed_at FROM iam.approval($1)`, id).
			Scan(&r.ID, &r.Kind, &r.TargetRef, &r.Reason, &r.Payload, &bu, &r.RequestedBy, &r.Status, &decidedBy,
				&decisionReason, &r.CreatedAt, &r.ExpiresAt, &r.DecidedAt, &r.ConsumedAt)
		r.BUID, r.DecidedBy, r.DecisionReason = deref(bu), deref(decidedBy), deref(decisionReason)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	return r, mapErr(err)
}

// Decide approves or rejects a request as p. Self-approval is refused here
// before the database refuses it too.
func (s Service) Decide(ctx context.Context, p authz.Principal, id string, approve bool, reason string) (Status, error) {
	r, err := s.Get(ctx, p, id)
	if err != nil {
		return "", err
	}
	if r.RequestedBy == p.UserID {
		return "", ErrSelfApproval
	}
	var st Status
	err = authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT iam.decide_approval($1, $2, $3)", id, approve, reason).Scan(&st)
	})
	return st, mapErr(err)
}

// Querier runs a query (a pool or connection as app_rw).
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ExpireDue marks overdue pending requests expired (scheduled job). It
// returns how many expired.
func ExpireDue(ctx context.Context, db Querier) (int, error) {
	var n int
	err := db.QueryRow(ctx, "SELECT iam.expire_approvals()").Scan(&n)
	return n, mapErr(err)
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
		"AP001": ErrNoContext, "AP002": ErrSelfApproval, "AP003": ErrNotAuthorized,
		"AP004": ErrNotApplicable, "AP005": ErrInvalid, "23514": ErrInvalid,
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

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
