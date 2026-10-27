package posture

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/audit"
)

// Automatic revert (F-015 T-18; AC-27 - AC-29; design §6.3). Expired
// exceptions are reverted as system:posture: the instance value returns to
// the active profile default, a BU override is removed so the BU inherits.
// A failed revert is retried with backoff and keeps a critical revert_failed
// finding open until a revert succeeds; escalations repeat hourly
// (migration 0022).

// RevertActor is the audit actor of automatic reverts.
const RevertActor = "system:posture"

// RevertOutcome reports one revert attempt.
type RevertOutcome struct {
	ExceptionID, Key, BUID string
	Err                    error // nil: reverted
	Escalated              bool  // a failure that sent the (hourly) escalation
}

// RevertDue reverts the exceptions that are due, each in its own
// transaction with setting.exception_reverted (high) audited inside it, and
// records failures. pub, if set, announces each revert to the caches.
func RevertDue(ctx context.Context, db *pgxpool.Pool, em audit.Emitter, pub Publisher) ([]RevertOutcome, error) {
	type due struct {
		id, key  string
		bu       *string
		owner    string
		attempts int
	}
	rows, err := db.Query(ctx, "SELECT exception_id::text, key, bu_id::text, owner_id::text, attempts FROM posture.due_reverts(50)")
	if err != nil {
		return nil, err
	}
	var batch []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.key, &d.bu, &d.owner, &d.attempts); err != nil {
			rows.Close()
			return nil, err
		}
		batch = append(batch, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []RevertOutcome
	for _, d := range batch {
		o := RevertOutcome{ExceptionID: d.id, Key: d.key}
		if d.bu != nil {
			o.BUID = *d.bu
		}
		attrs := map[string]string{"exception_id": d.id, "key": d.key, "bu_id": o.BUID, "owner": d.owner}
		o.Err = pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT posture.apply_revert($1)", d.id); err != nil {
				return err
			}
			return em.Emit(ctx, audit.Event{Type: "setting.exception_reverted", Severity: audit.SeverityHigh, Actor: RevertActor,
				Target: "setting:" + d.key, Attributes: attrs})
		})
		if o.Err == nil {
			if pub != nil {
				_ = PublishChanged(ctx, db, pub, d.key, o.BUID) // caches also poll
			}
			out = append(out, o)
			continue
		}
		// The revert rolled back: record the failure, keep the finding open.
		var attempts int
		if err := db.QueryRow(ctx, "SELECT escalate, attempts FROM posture.record_revert_failure($1, $2)", d.id, o.Err.Error()).
			Scan(&o.Escalated, &attempts); err != nil {
			return out, fmt.Errorf("recording failed revert of %s: %w (revert: %w)", d.id, err, o.Err)
		}
		attrs["attempts"] = strconv.Itoa(attempts)
		attrs["error"] = o.Err.Error()
		typ := "setting.revert_failed"
		if o.Escalated {
			typ = "setting.revert_failed_escalation"
		}
		if err := em.Emit(ctx, audit.Event{Type: typ, Severity: audit.SeverityCritical, Actor: RevertActor,
			Target: "setting:" + d.key, Attributes: attrs}); err != nil {
			o.Err = fmt.Errorf("%w (and the failure could not be audited: %w)", o.Err, err)
		}
		out = append(out, o)
	}
	return out, nil
}

// RunReverts runs RevertDue every interval until ctx ends. Every failure is
// reported to onError; the failures themselves are retried by the schedule
// recorded in the database.
func RunReverts(ctx context.Context, db *pgxpool.Pool, em audit.Emitter, pub Publisher, every time.Duration, onError func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		out, err := RevertDue(ctx, db, em, pub)
		if err != nil && ctx.Err() == nil {
			onError(err)
		}
		for _, o := range out {
			if o.Err != nil {
				onError(fmt.Errorf("revert of exception %s (%s) failed: %w", o.ExceptionID, o.Key, o.Err))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
