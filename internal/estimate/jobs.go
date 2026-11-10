package estimate

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RiskLeaderLockKey is the advisory lock of the risk service's leader,
// which runs the estimate jobs (design §6.7).
const RiskLeaderLockKey int64 = 0x0FA1_0004_0000_0001

// Jobs are the leader's estimate jobs (design §6.7): every minute, close
// requests past their due date and queue reminders a lead time before it.
type Jobs struct {
	DB           *pgxpool.Pool        // app_rw
	ReminderLead func() time.Duration // the setting estimate.reminder_lead
	Every        time.Duration        // default one minute
	OnError      func(error)
}

// Step runs the jobs once and says how many requests closed and how many
// reminders were queued.
func (j Jobs) Step(ctx context.Context) (closed, reminded int, err error) {
	if err = j.DB.QueryRow(ctx, "SELECT estimate.close_due()").Scan(&closed); err != nil {
		return 0, 0, fmt.Errorf("estimate: closing due requests: %w", err)
	}
	lead := 48 * time.Hour
	if j.ReminderLead != nil {
		lead = j.ReminderLead()
	}
	if err = j.DB.QueryRow(ctx, "SELECT estimate.queue_reminders(make_interval(secs => $1))", lead.Seconds()).Scan(&reminded); err != nil {
		return closed, 0, fmt.Errorf("estimate: queueing reminders: %w", err)
	}
	return closed, reminded, nil
}

// Run steps until ctx ends (while this replica leads).
func (j Jobs) Run(ctx context.Context) error {
	every := j.Every
	if every <= 0 {
		every = time.Minute
	}
	for {
		if _, _, err := j.Step(ctx); err != nil && ctx.Err() == nil && j.OnError != nil {
			j.OnError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
