// Package audit is the audit service (F-002 design §2): leader election and
// install checks (T-05); the sequencer, checkpoints, verification,
// forwarding, retention and the audit API arrive with later tasks. The
// integrity primitives are in internal/audit/integrity.
package audit

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// LeaderLockKey is the PostgreSQL advisory lock the leader holds: one
// replica sequences, checkpoints and verifies at a time (design §2).
const LeaderLockKey int64 = 0x0FA1_0002_0000_0001

// Leader runs work on whichever replica holds the leader lock. The lock is
// a session lock on one dedicated connection: if that connection fails or
// the database restarts, the lock is gone and the work is cancelled, so
// two replicas never lead at once for longer than the check interval.
type Leader struct {
	Pool  *pgxpool.Pool
	Key   int64         // default LeaderLockKey
	Every time.Duration // how often to try for the lock and to check it is held; default 5 s
	// OnChange, when set, is told when this replica gains (true) or loses
	// (false) the lead.
	OnChange func(leading bool)
}

// Run tries for the lock until ctx ends. While it holds the lock it runs
// work with a context that is cancelled when the lock is lost or ctx ends;
// when work returns, the lock is released and Run tries again after Every.
// Errors from work or from the database are passed to onErr (may be nil).
func (l Leader) Run(ctx context.Context, work func(ctx context.Context) error, onErr func(error)) {
	if l.Key == 0 {
		l.Key = LeaderLockKey
	}
	if l.Every <= 0 {
		l.Every = 5 * time.Second
	}
	report := func(err error) {
		if err != nil && onErr != nil && !errors.Is(err, context.Canceled) {
			onErr(err)
		}
	}
	for {
		report(l.lead(ctx, work))
		select {
		case <-ctx.Done():
			return
		case <-time.After(l.Every):
		}
	}
}

// lead makes one attempt: take the lock if it is free, and run work while
// it is held.
func (l Leader) lead(ctx context.Context, work func(ctx context.Context) error) error {
	conn, err := l.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	// The session lock lives on this connection; never return it to the
	// pool holding the lock.
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", l.Key).Scan(&got); err != nil {
		return err
	}
	if !got {
		return nil
	}
	defer func() {
		// Released with the connection if this fails (the pool closes broken
		// connections); unlock explicitly so a healthy one is reusable.
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", l.Key)
	}()
	if l.OnChange != nil {
		l.OnChange(true)
		defer l.OnChange(false)
	}

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- work(wctx) }()
	tick := time.NewTicker(l.Every)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-tick.C:
			// Still ours? A lost connection loses the lock.
			var held bool
			err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()
				AND granted AND objsubid = 1 AND ((classid::bigint << 32) | objid::bigint) = $1)`, l.Key).Scan(&held)
			if err != nil || !held {
				cancel()
				werr := <-done
				if err == nil {
					err = errors.New("audit: the leader lock was lost")
				}
				if werr != nil && !errors.Is(werr, context.Canceled) {
					err = errors.Join(err, werr)
				}
				return err
			}
		}
	}
}
