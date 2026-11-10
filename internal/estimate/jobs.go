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
	// The daily calibration jobs (design §4.3, §6.7): rescoring as the
	// window moves, and the retention purge. Each returns the setting, or
	// the built-in default.
	Window     func() time.Duration // calibration.window
	MinAnswers func() int           // calibration.min_answers
	Retention  func() time.Duration // calibration.retention
}

// Daily rescores and purges once, and says how many scores changed and how
// many exercises and scores were deleted.
func (j Jobs) Daily(ctx context.Context) (rescored, exercises, scores int, err error) {
	window, minAnswers, retention := 365*24*time.Hour, 20, 3*365*24*time.Hour
	if j.Window != nil {
		window = j.Window()
	}
	if j.MinAnswers != nil {
		minAnswers = j.MinAnswers()
	}
	if j.Retention != nil {
		retention = j.Retention()
	}
	secs := func(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d/time.Second)) }
	if err = j.DB.QueryRow(ctx, "SELECT estimate.rescore($1::interval, $2)", secs(window), minAnswers).Scan(&rescored); err != nil {
		return 0, 0, 0, fmt.Errorf("estimate: rescoring: %w", err)
	}
	if err = j.DB.QueryRow(ctx, "SELECT (r->>'exercises')::int, (r->>'scores')::int FROM estimate.purge_calibration($1::interval) r",
		secs(retention)).Scan(&exercises, &scores); err != nil {
		return rescored, 0, 0, fmt.Errorf("estimate: purging calibration records: %w", err)
	}
	return rescored, exercises, scores, nil
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
	var lastDaily time.Time
	for {
		if _, _, err := j.Step(ctx); err != nil && ctx.Err() == nil && j.OnError != nil {
			j.OnError(err)
		}
		if time.Since(lastDaily) >= 24*time.Hour {
			if _, _, _, err := j.Daily(ctx); err != nil && ctx.Err() == nil && j.OnError != nil {
				j.OnError(err)
			} else if err == nil {
				lastDaily = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
