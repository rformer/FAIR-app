package reports

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/objstore"
)

// F-010 T-13 (F-010-AC-15; OQ8; design §3.6): retention. The risk
// service's leader deletes report files older than report.retention_days
// from the report store, every version of each object, then marks them
// purged (report.mark_purged: purged_at, report.files_purged as the
// system). The run and its files' digests stay.

// PurgeStore is the report store as the purge uses it (objstore.Store).
type PurgeStore interface {
	List(ctx context.Context, prefix string) ([]objstore.Object, error)
	Delete(ctx context.Context, v objstore.Version) error
}

// Purger is the retention job.
type Purger struct {
	DB    *pgxpool.Pool // app_rw: report_definer's functions
	Store PurgeStore
	// Retention gives report.retention_days in force.
	Retention func() (int, error)
	// Batch bounds the files one Step purges (default 200).
	Batch   int
	Every   time.Duration // default an hour
	OnError func(error)
}

// PurgeBatch is the default batch.
const PurgeBatch = 200

type due struct {
	run, format, key string
}

// Step purges at most one batch of files past retention; it returns how
// many it purged. A file whose versions cannot all be deleted stays
// unpurged (retried next time).
func (p *Purger) Step(ctx context.Context) (int, error) {
	days, err := p.Retention()
	if err != nil {
		return 0, fmt.Errorf("reports: report.retention_days: %w", err)
	}
	if days < 1 || days > 365 {
		return 0, fmt.Errorf("reports: report.retention_days %d is outside 1 to 365", days)
	}
	batch := p.Batch
	if batch <= 0 {
		batch = PurgeBatch
	}
	rows, err := p.DB.Query(ctx, "SELECT run_id::text, format, object_key FROM report.files_due($1, $2)", days, batch)
	if err != nil {
		return 0, err
	}
	var files []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.run, &d.format, &d.key); err != nil {
			rows.Close()
			return 0, err
		}
		files = append(files, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// Delete each object's every version, then mark the run's deleted
	// files purged together.
	done := map[string][]string{}
	var order []string
	var errs []error
	for _, f := range files {
		if err := p.deleteAll(ctx, f.key); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, ok := done[f.run]; !ok {
			order = append(order, f.run)
		}
		done[f.run] = append(done[f.run], f.format)
	}
	n := 0
	for _, run := range order {
		var marked int
		if err := p.DB.QueryRow(ctx, "SELECT report.mark_purged($1, $2)", run, done[run]).Scan(&marked); err != nil {
			errs = append(errs, err)
			continue
		}
		n += marked
	}
	return n, errors.Join(errs...)
}

// deleteAll deletes every version of key.
func (p *Purger) deleteAll(ctx context.Context, key string) error {
	objs, err := p.Store.List(ctx, key)
	if err != nil {
		return err
	}
	for _, o := range objs {
		if o.Key != key {
			continue // a longer key with the same prefix
		}
		if err := p.Store.Delete(ctx, o.Version); err != nil {
			return err
		}
	}
	return nil
}

// Run steps every Every (and at once while a batch was full) until ctx ends.
func (p *Purger) Run(ctx context.Context) error {
	every := p.Every
	if every <= 0 {
		every = time.Hour
	}
	batch := p.Batch
	if batch <= 0 {
		batch = PurgeBatch
	}
	for {
		n, err := p.Step(ctx)
		if err != nil && p.OnError != nil && ctx.Err() == nil {
			p.OnError(err)
		}
		wait := every
		if err == nil && n >= batch {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}
