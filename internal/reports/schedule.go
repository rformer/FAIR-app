package reports

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// F-010 T-16 (F-010-AC-19 to AC-21; design §3.7): the leader's due
// schedules. Every minute report.due_schedules turns each due schedule into
// a queued run (its owner re-checked) or suspends it, and moves it to its
// next time after now (one catch-up run after an outage); the runs' jobs
// are queued in the same transaction.

// ScheduleBatch bounds the schedules one Step handles.
const ScheduleBatch = 100

// ScheduleJob is the leader's schedule job.
type ScheduleJob struct {
	DB      *pgxpool.Pool // app_rw
	Enqueue func(context.Context, pgx.Tx, GenerateArgs) error
	Batch   int
	Every   time.Duration // default a minute
	OnError func(error)
}

// Step handles at most one batch of due schedules: the runs queued and the
// schedules suspended.
func (j *ScheduleJob) Step(ctx context.Context) (runs, suspended int, err error) {
	batch := j.Batch
	if batch <= 0 {
		batch = ScheduleBatch
	}
	err = pgx.BeginFunc(ctx, j.DB, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT report.due_schedules($1)", batch).Scan(&raw); err != nil {
			return err
		}
		var out struct {
			Runs      []string `json:"runs"`
			Suspended int      `json:"suspended"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return err
		}
		for _, id := range out.Runs {
			if err := j.Enqueue(ctx, tx, GenerateArgs{RunID: id}); err != nil {
				return fmt.Errorf("reports: queue scheduled run %s: %w", id, err)
			}
		}
		runs, suspended = len(out.Runs), out.Suspended
		return nil
	})
	return runs, suspended, err
}

// Run steps every Every (and again at once after a full batch) until ctx
// ends.
func (j *ScheduleJob) Run(ctx context.Context) error {
	every := j.Every
	if every <= 0 {
		every = time.Minute
	}
	batch := j.Batch
	if batch <= 0 {
		batch = ScheduleBatch
	}
	for {
		n, s, err := j.Step(ctx)
		if err != nil && j.OnError != nil && ctx.Err() == nil {
			j.OnError(err)
		}
		wait := every
		if err == nil && n+s >= batch {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}
