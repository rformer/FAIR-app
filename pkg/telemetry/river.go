package telemetry

import (
	"context"
	"errors"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// River is a River worker middleware recording every job's queue, kind,
// outcome and duration (F-012 T-09; AC-22: job queues). Add it to each
// client's river.Config.Middleware.
type River struct{ river.MiddlewareDefaults }

// Work implements rivertype.WorkerMiddleware.
func (*River) Work(ctx context.Context, job *rivertype.JobRow, doInner func(context.Context) error) error {
	start := time.Now()
	err := doInner(ctx)
	Job(ctx, job.Queue, job.Kind, JobOutcome(err), time.Since(start))
	return err
}

// JobOutcome names a job's result: completed, snoozed, cancelled or failed.
func JobOutcome(err error) string {
	var snooze *rivertype.JobSnoozeError
	var cancel *rivertype.JobCancelError
	switch {
	case err == nil:
		return "completed"
	case errors.As(err, &snooze):
		return "snoozed"
	case errors.As(err, &cancel):
		return "cancelled"
	}
	return "failed"
}

var _ rivertype.WorkerMiddleware = &River{}
