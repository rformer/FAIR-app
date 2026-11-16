package register

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// F-009 T-12 (F-009-AC-20; F-009 design §3.7): the notices nobody queued
// before. Every 15 minutes the risk service's leader runs
// register.notice_sweep: a risk whose exposure becomes stale, or one of
// whose treatment actions becomes overdue, queues one notice to its owner;
// it notifies again only after the condition clears and returns.

// NoticeJob runs register.notice_sweep.
type NoticeJob struct {
	DB      *pgxpool.Pool // app_rw
	Every   time.Duration // default 15 minutes
	Batch   int           // changes of each kind per sweep; default 500
	OnError func(error)
}

// Sweep runs register.notice_sweep once.
func (j NoticeJob) Sweep(ctx context.Context) (opened, cleared int, err error) {
	batch := j.Batch
	if batch <= 0 {
		batch = 500
	}
	if err := j.DB.QueryRow(ctx, "SELECT (r->>'opened')::int, (r->>'cleared')::int FROM register.notice_sweep($1) r", batch).Scan(&opened, &cleared); err != nil {
		return 0, 0, fmt.Errorf("register: notice sweep: %w", err)
	}
	return opened, cleared, nil
}

// Run sweeps until ctx ends (while this replica leads).
func (j NoticeJob) Run(ctx context.Context) error {
	every := j.Every
	if every <= 0 {
		every = 15 * time.Minute
	}
	for {
		if _, _, err := j.Sweep(ctx); err != nil && ctx.Err() == nil && j.OnError != nil {
			j.OnError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
