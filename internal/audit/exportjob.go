package audit

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// River for the audit service (F-002 T-15, design §6.6): its own schema
// (migrations 0076 and 0077, granted to app_audit only) and queue.
const (
	RiverSchema    = "audit_river"
	ExportQueue    = "audit_export"
	ExportAttempts = 5
	// ExportTimeout bounds one attempt (the target is 1 million records in
	// 5 minutes).
	ExportTimeout = 30 * time.Minute
)

// ExportArgs is the export job: make export ID.
type ExportArgs struct {
	ID string `json:"id"`
}

// Kind implements river.JobArgs.
func (ExportArgs) Kind() string { return "audit_export" }

// InsertOpts implements river.JobArgsWithInsertOpts.
func (ExportArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: ExportQueue, MaxAttempts: ExportAttempts}
}

type exportWorker struct {
	river.WorkerDefaults[ExportArgs]
	x      *Exporter
	logger *slog.Logger
}

func (w *exportWorker) Work(ctx context.Context, job *river.Job[ExportArgs]) error {
	res, err := RunExportAttempt(ctx, w.x, job.Args.ID, job.Attempt, job.MaxAttempts)
	if err == nil && res.Created && w.logger != nil {
		w.logger.Info("audit export ready", "export", res.ID, "records", res.Records, "segment", res.Segment, "digest", res.Digest.String())
	}
	return err
}

// RunExportAttempt is one attempt of the export job: it makes export id; an
// export that no longer exists is cancelled; on the last attempt a failure
// marks the export failed (recorded in the trail) and cancels the job.
// Other failures are returned for River to retry.
func RunExportAttempt(ctx context.Context, x *Exporter, id string, attempt, maxAttempts int) (ExportResult, error) {
	res, err := x.Run(ctx, id)
	switch {
	case err == nil:
		return res, nil
	case errors.Is(err, ErrExportGone):
		return res, river.JobCancel(err)
	case attempt >= maxAttempts:
		if _, ferr := x.Fail(ctx, id, err); ferr != nil {
			return res, errors.Join(err, ferr)
		}
		return res, river.JobCancel(err)
	}
	return res, err
}

func (w *exportWorker) Timeout(*river.Job[ExportArgs]) time.Duration { return ExportTimeout }

// NewExportClient is the audit service's River client: it runs export jobs
// with x (every replica works the queue). The caller starts and stops it.
func NewExportClient(pool *pgxpool.Pool, x *Exporter, logger *slog.Logger) (*river.Client[pgx.Tx], error) {
	workers := river.NewWorkers()
	river.AddWorker(workers, &exportWorker{x: x, logger: logger})
	return river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:  map[string]river.QueueConfig{ExportQueue: {MaxWorkers: 2}},
		Workers: workers,
		Schema:  RiverSchema,
		Logger:  logger,
	})
}

// Enqueuer returns the function the Audit API uses to queue an export job
// in the request's transaction.
func Enqueuer(c *river.Client[pgx.Tx]) func(ctx context.Context, tx pgx.Tx, id string) error {
	return func(ctx context.Context, tx pgx.Tx, id string) error {
		_, err := c.InsertTx(ctx, tx, ExportArgs{ID: id}, nil)
		return err
	}
}
