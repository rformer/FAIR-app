package posture

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Exception lifecycle (F-015 T-17; design §6.3): renewal before expiry with
// a new justification and dual approval (AC-26), and the 14-, 7- and 1-day
// expiry notices (AC-25). The database enforces the rules (migration 0021).

// Renewal is a pending renewal request.
type Renewal struct {
	ID, ApprovalID string
}

// RequestRenewal asks, as p, to renew an active exception before it expires.
// The approval request goes to the holders of settings.approve.
func (ev Evaluator) RequestRenewal(ctx context.Context, p authz.Principal, exceptionID, justification string, duration time.Duration) (Renewal, error) {
	var r Renewal
	err := authz.WithDBContext(ctx, ev.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT renewal_id, approval_request_id FROM posture.request_renewal($1, $2, $3)",
			exceptionID, justification, durationArg(duration)).Scan(&r.ID, &r.ApprovalID); err != nil {
			return err
		}
		return ev.Audit.Emit(ctx, audit.Event{Type: "setting.exception_renewal_requested", Severity: audit.SeverityHigh, Actor: p.UserID,
			Target: "exception:" + exceptionID, Reason: justification,
			Attributes: map[string]string{"exception_id": exceptionID, "renewal_id": r.ID, "approval_id": r.ApprovalID}})
	})
	return r, mapErr(err)
}

// ApplyRenewal applies an approved renewal: a new exception linked to the
// old one, which becomes renewed. setting.exception_renewed (high) is
// audited inside the transaction.
func (ev Evaluator) ApplyRenewal(ctx context.Context, renewalID string) (Exception, error) {
	var x Exception
	err := pgx.BeginFunc(ctx, ev.DB, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT posture.apply_renewal($1)", renewalID).Scan(&x.ID); err != nil {
			return err
		}
		var bu *string
		if err := tx.QueryRow(ctx, "SELECT key, bu_id::text, value, owner_id::text, approved_by::text, expires_at FROM posture.exception_summary($1)", x.ID).
			Scan(&x.Key, &bu, &x.Value, &x.OwnerID, &x.ApprovedBy, &x.ExpiresAt); err != nil {
			return err
		}
		if bu != nil {
			x.BUID = *bu
		}
		return ev.Audit.Emit(ctx, audit.Event{Type: "setting.exception_renewed", Severity: audit.SeverityHigh, Actor: x.ApprovedBy,
			Target: "setting:" + x.Key, Attributes: map[string]string{
				"key": x.Key, "bu_id": x.BUID, "renewal_id": renewalID, "exception_id": x.ID, "owner": x.OwnerID,
				"approved_by": x.ApprovedBy, "expires_at": x.ExpiresAt.UTC().Format(time.RFC3339)}})
	})
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "AP004" {
			return Exception{}, fmt.Errorf("%w: %s", ErrNotApproved, pg.Message)
		}
		return Exception{}, mapErr(err)
	}
	if ev.Publish != nil {
		_ = PublishChanged(ctx, ev.DB, ev.Publish, x.Key, x.BUID) // the value's exception changed; caches also poll
	}
	return x, nil
}

// Notice is one expiry notice (AC-25).
type Notice struct {
	ExceptionID, Key, BUID, OwnerID string
	DaysBefore                      int
	ExpiresAt                       time.Time
}

// ExceptionNotices records and audits the expiry notices now due. Each is
// audited inside the transaction that records it: if the audit fails,
// nothing is recorded and the next run tries again.
func ExceptionNotices(ctx context.Context, db *pgxpool.Pool, em audit.Emitter) ([]Notice, error) {
	var out []Notice
	err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT exception_id::text, days_before, key, bu_id::text, owner_id::text, expires_at FROM posture.exception_notices()")
		if err != nil {
			return err
		}
		for rows.Next() {
			var n Notice
			var bu *string
			if err := rows.Scan(&n.ExceptionID, &n.DaysBefore, &n.Key, &bu, &n.OwnerID, &n.ExpiresAt); err != nil {
				rows.Close()
				return err
			}
			if bu != nil {
				n.BUID = *bu
			}
			out = append(out, n)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, n := range out {
			sev := audit.SeverityInfo
			switch n.DaysBefore {
			case 7:
				sev = audit.SeverityLow
			case 1:
				sev = audit.SeverityHigh
			}
			if err := em.Emit(ctx, audit.Event{Type: "setting.exception_expiring", Severity: sev, Actor: "system:posture",
				Target: "exception:" + n.ExceptionID, Attributes: map[string]string{
					"exception_id": n.ExceptionID, "key": n.Key, "bu_id": n.BUID, "owner": n.OwnerID,
					"days_before": strconv.Itoa(n.DaysBefore), "expires_at": n.ExpiresAt.UTC().Format(time.RFC3339)}}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RunNotices runs ExceptionNotices every interval until ctx ends.
func RunNotices(ctx context.Context, db *pgxpool.Pool, em audit.Emitter, every time.Duration, onError func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := ExceptionNotices(ctx, db, em); err != nil && ctx.Err() == nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
