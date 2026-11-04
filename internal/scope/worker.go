// Package scope runs the scope worker (F-001 T-08; design §2 "Scope worker",
// §5.4). It is a River client with two periodic jobs:
//
//   - scope.drain, every few seconds: calls authz.drain_outbox until the
//     access-change outbox is empty, then delivers queued events;
//   - scope.reconcile, nightly: calls authz.reconcile_scopes, which repairs
//     drift and queues a high-severity audit event per drifted user.
//
// The recomputation itself happens in the database (migration 0006); the
// worker only schedules it and delivers events at least once:
// iam.scope.changed to NATS JetStream, audit events to the audit emitter.
// An event is marked delivered only after the sink accepted it, so audit
// failures fail closed (ADR-006): the event stays queued and is retried.
package scope

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// SubjectScopeChanged is published for every user whose scope changed.
const SubjectScopeChanged = "iam.scope.changed"

// Subjects the worker publishes events to (every non-audit topic of
// iam.event_outbox); the installer provisions JetStream streams capturing
// them all, and the worker refuses to start otherwise: an event it cannot
// publish would hold back every later one, audit events included.
var Subjects = []string{
	SubjectScopeChanged,
	"iam.session.revoked",  // F-001 T-13: a session ended early
	"iam.user.deactivated", // F-001 T-22: a user stopped being active
	"iam.breakglass.login", // F-001 T-34: a break-glass account signed in (AC-43)
}

// RiverSchema holds River's tables (migrations 0007, 0008).
const RiverSchema = "river"

// Publisher stores a message on a JetStream subject; msgID de-duplicates
// redeliveries. natspub.Publisher implements it.
type Publisher interface {
	Publish(ctx context.Context, subject, msgID string, data []byte) error
}

// Options configures a Worker.
type Options struct {
	Pool      *pgxpool.Pool // connected as app_rw
	Publisher Publisher
	Logger    *slog.Logger

	DrainEvery     time.Duration // default 2s; at least 1s (River's unique-period minimum)
	ReconcileAtUTC time.Duration // time of day for reconciliation, default 02:00 UTC
}

// Worker drains the access-change outbox, reconciles scope and delivers
// events.
type Worker struct {
	o Options
}

// New returns a Worker with defaults applied.
func New(o Options) *Worker {
	if o.DrainEvery <= 0 {
		o.DrainEvery = 2 * time.Second
	}
	o.DrainEvery = max(o.DrainEvery, time.Second)
	if o.ReconcileAtUTC <= 0 {
		o.ReconcileAtUTC = 2 * time.Hour
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Worker{o: o}
}

// Drain processes the outbox until it is empty (or another drain holds the
// lock), then delivers events. It returns how many users' scope changed.
func (w *Worker) Drain(ctx context.Context) (int, error) {
	total := 0
	for {
		var drained, changed int
		if err := w.o.Pool.QueryRow(ctx, "SELECT drained, changed FROM authz.drain_outbox($1)", 1000).Scan(&drained, &changed); err != nil {
			return total, fmt.Errorf("scope: drain: %w", err)
		}
		total += changed
		if drained <= 0 {
			break
		}
	}
	return total, w.Deliver(ctx)
}

// Reconcile recomputes every user's scope and returns how many had drifted.
func (w *Worker) Reconcile(ctx context.Context) (int, error) {
	var n int
	if err := w.o.Pool.QueryRow(ctx, "SELECT count(*) FROM authz.reconcile_scopes()").Scan(&n); err != nil {
		return 0, fmt.Errorf("scope: reconcile: %w", err)
	}
	if n > 0 {
		w.o.Logger.Warn("scope drift repaired", "users", n)
	}
	return n, w.Deliver(ctx)
}

type event struct {
	id      int64
	topic   string
	payload []byte
	created time.Time
}

// msgID identifies one event for JetStream de-duplication. The id alone is
// not enough: ids restart in a new or restored database.
func (e event) msgID() string {
	return fmt.Sprintf("fair-event-%d-%d", e.id, e.created.UnixNano())
}

// Deliver sends queued events in order and marks each one delivered after
// its sink accepted it. It stops at the first failure, leaving the rest
// queued for the next run.
func (w *Worker) Deliver(ctx context.Context) error {
	for {
		rows, err := w.o.Pool.Query(ctx, "SELECT id, topic, payload, created_at FROM authz.pending_events($1)", 500)
		if err != nil {
			return fmt.Errorf("scope: pending events: %w", err)
		}
		events, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (event, error) {
			var e event
			return e, r.Scan(&e.id, &e.topic, &e.payload, &e.created)
		})
		if err != nil {
			return fmt.Errorf("scope: pending events: %w", err)
		}
		if len(events) == 0 {
			return nil
		}
		var done []int64
		var sendErr error
		for _, e := range events {
			if sendErr = w.send(ctx, e); sendErr != nil {
				break
			}
			done = append(done, e.id)
		}
		if len(done) > 0 {
			if _, err := w.o.Pool.Exec(ctx, "SELECT authz.mark_events_published($1)", done); err != nil {
				return fmt.Errorf("scope: mark delivered: %w", err)
			}
		}
		if sendErr != nil {
			return sendErr
		}
	}
}

func (w *Worker) send(ctx context.Context, e event) error {
	if e.topic == "audit" {
		// Since F-002 T-06 audit rows never reach the outbox: a trigger hands
		// them to the audit trail in the producer's transaction.
		return fmt.Errorf("scope: event %d has topic audit; audit events go to the trail (iam.event_outbox trigger)", e.id)
	}
	if err := w.o.Publisher.Publish(ctx, e.topic, e.msgID(), e.payload); err != nil {
		return fmt.Errorf("scope: publish event %d to %s: %w", e.id, e.topic, err)
	}
	return nil
}

// DrainArgs is the periodic outbox drain job.
type DrainArgs struct{}

// Kind implements river.JobArgs.
func (DrainArgs) Kind() string { return "scope.drain" }

// InactivityArgs is the hourly inactivity sweep (F-001 T-23, AC-11).
type InactivityArgs struct{}

// Kind implements river.JobArgs.
func (InactivityArgs) Kind() string { return "iam.inactivity_sweep" }

// SweepInactive disables users inactive longer than
// auth.inactive_disable_after (iam.inactivity_sweep) and returns how many.
func (w *Worker) SweepInactive(ctx context.Context) (int, error) {
	var n int
	if err := w.o.Pool.QueryRow(ctx, "SELECT iam.inactivity_sweep()").Scan(&n); err != nil {
		return 0, fmt.Errorf("scope: inactivity sweep: %w", err)
	}
	if n > 0 {
		w.o.Logger.Info("inactive accounts disabled", "count", n)
	}
	return n, nil
}

type inactivityWorker struct {
	river.WorkerDefaults[InactivityArgs]
	w *Worker
}

func (r *inactivityWorker) Work(ctx context.Context, _ *river.Job[InactivityArgs]) error {
	_, err := r.w.SweepInactive(ctx)
	return err
}

// ExpiryArgs is the assignment expiry sweep (F-001 T-32, AC-23), every
// minute.
type ExpiryArgs struct{}

// Kind implements river.JobArgs.
func (ExpiryArgs) Kind() string { return "iam.assignment_expiry" }

// SweepExpired revokes expired assignments as the system
// (iam.assignment_expiry_sweep), which queues the scope recompute, and
// returns how many.
func (w *Worker) SweepExpired(ctx context.Context) (int, error) {
	var n int
	if err := w.o.Pool.QueryRow(ctx, "SELECT iam.assignment_expiry_sweep()").Scan(&n); err != nil {
		return 0, fmt.Errorf("scope: assignment expiry: %w", err)
	}
	if n > 0 {
		w.o.Logger.Info("expired assignments revoked", "count", n)
	}
	return n, nil
}

type expiryWorker struct {
	river.WorkerDefaults[ExpiryArgs]
	w *Worker
}

func (r *expiryWorker) Work(ctx context.Context, _ *river.Job[ExpiryArgs]) error {
	_, err := r.w.SweepExpired(ctx)
	return err
}

// ReviewArgs is the access review due-date sweep (F-001 T-39, AC-49), every
// minute.
type ReviewArgs struct{}

// Kind implements river.JobArgs.
func (ReviewArgs) Kind() string { return "iam.access_review_sweep" }

// SweepReviews closes access review campaigns past their due date
// (iam.access_review_sweep): undecided items are kept or revoked by each
// campaign's policy. Returns how many campaigns closed.
func (w *Worker) SweepReviews(ctx context.Context) (int, error) {
	var n int
	if err := w.o.Pool.QueryRow(ctx, "SELECT iam.access_review_sweep()").Scan(&n); err != nil {
		return 0, fmt.Errorf("scope: access review sweep: %w", err)
	}
	if n > 0 {
		w.o.Logger.Info("access review campaigns closed", "count", n)
	}
	return n, nil
}

type reviewWorker struct {
	river.WorkerDefaults[ReviewArgs]
	w *Worker
}

func (r *reviewWorker) Work(ctx context.Context, _ *river.Job[ReviewArgs]) error {
	_, err := r.w.SweepReviews(ctx)
	return err
}

// SoDArgs is the hourly separation-of-duties exception sweep (F-001 T-27,
// AC-53), with the expiry of pending approval requests (T-26).
type SoDArgs struct{}

// Kind implements river.JobArgs.
func (SoDArgs) Kind() string { return "iam.sod_sweep" }

// SweepSoD ends expired SoD exceptions, suspending custom roles that still
// break a rule (iam.sod_exception_sweep), and expires overdue approval
// requests. It returns how many roles were suspended.
func (w *Worker) SweepSoD(ctx context.Context) (int, error) {
	var n, expired int
	if err := w.o.Pool.QueryRow(ctx, "SELECT iam.sod_exception_sweep()").Scan(&n); err != nil {
		return 0, fmt.Errorf("scope: SoD sweep: %w", err)
	}
	if err := w.o.Pool.QueryRow(ctx, "SELECT iam.expire_approvals()").Scan(&expired); err != nil {
		return n, fmt.Errorf("scope: approval expiry: %w", err)
	}
	if n > 0 || expired > 0 {
		w.o.Logger.Info("SoD sweep", "roles_suspended", n, "approvals_expired", expired)
	}
	return n, nil
}

type sodWorker struct {
	river.WorkerDefaults[SoDArgs]
	w *Worker
}

func (r *sodWorker) Work(ctx context.Context, _ *river.Job[SoDArgs]) error {
	_, err := r.w.SweepSoD(ctx)
	return err
}

// ReconcileArgs is the nightly reconciliation job.
type ReconcileArgs struct{}

// Kind implements river.JobArgs.
func (ReconcileArgs) Kind() string { return "scope.reconcile" }

type drainWorker struct {
	river.WorkerDefaults[DrainArgs]
	w *Worker
}

func (d *drainWorker) Work(ctx context.Context, _ *river.Job[DrainArgs]) error {
	_, err := d.w.Drain(ctx)
	return err
}

type reconcileWorker struct {
	river.WorkerDefaults[ReconcileArgs]
	w *Worker
}

func (r *reconcileWorker) Work(ctx context.Context, _ *river.Job[ReconcileArgs]) error {
	_, err := r.w.Reconcile(ctx)
	return err
}

func (r *reconcileWorker) Timeout(*river.Job[ReconcileArgs]) time.Duration { return 30 * time.Minute }

// dailyAt fires once a day at a fixed UTC time of day.
type dailyAt time.Duration

func (d dailyAt) Next(t time.Time) time.Time {
	t = t.UTC()
	next := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).Add(time.Duration(d))
	if !next.After(t) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// RiverClient builds the River client that schedules and runs the jobs. The
// caller starts and stops it.
func (w *Worker) RiverClient() (*river.Client[pgx.Tx], error) {
	workers := river.NewWorkers()
	river.AddWorker(workers, &drainWorker{w: w})
	river.AddWorker(workers, &reconcileWorker{w: w})
	river.AddWorker(workers, &inactivityWorker{w: w})
	river.AddWorker(workers, &sodWorker{w: w})
	river.AddWorker(workers, &expiryWorker{w: w})
	river.AddWorker(workers, &reviewWorker{w: w})
	every := w.o.DrainEvery
	periodic := []*river.PeriodicJob{
		// A failed drain is not retried: the next tick drains again.
		river.NewPeriodicJob(river.PeriodicInterval(every), func() (river.JobArgs, *river.InsertOpts) {
			return DrainArgs{}, &river.InsertOpts{MaxAttempts: 1, UniqueOpts: river.UniqueOpts{ByPeriod: every}}
		}, &river.PeriodicJobOpts{RunOnStart: true}),
		river.NewPeriodicJob(dailyAt(w.o.ReconcileAtUTC), func() (river.JobArgs, *river.InsertOpts) {
			return ReconcileArgs{}, &river.InsertOpts{MaxAttempts: 5, UniqueOpts: river.UniqueOpts{ByPeriod: 24 * time.Hour}}
		}, nil),
		// Inactive accounts (T-23): hourly, so an account is disabled within
		// an hour of crossing auth.inactive_disable_after.
		river.NewPeriodicJob(river.PeriodicInterval(time.Hour), func() (river.JobArgs, *river.InsertOpts) {
			return InactivityArgs{}, &river.InsertOpts{MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByPeriod: time.Hour}}
		}, &river.PeriodicJobOpts{RunOnStart: true}),
		// Expired assignments (T-32): every minute, so an expired grant's
		// scope is recomputed within a minute or so (the drain follows).
		river.NewPeriodicJob(river.PeriodicInterval(time.Minute), func() (river.JobArgs, *river.InsertOpts) {
			return ExpiryArgs{}, &river.InsertOpts{MaxAttempts: 1, UniqueOpts: river.UniqueOpts{ByPeriod: time.Minute}}
		}, &river.PeriodicJobOpts{RunOnStart: true}),
		// Access review campaigns past their due date (T-39): every minute.
		river.NewPeriodicJob(river.PeriodicInterval(time.Minute), func() (river.JobArgs, *river.InsertOpts) {
			return ReviewArgs{}, &river.InsertOpts{MaxAttempts: 1, UniqueOpts: river.UniqueOpts{ByPeriod: time.Minute}}
		}, &river.PeriodicJobOpts{RunOnStart: true}),
		// SoD exceptions and approval requests (T-27, T-26): hourly.
		river.NewPeriodicJob(river.PeriodicInterval(time.Hour), func() (river.JobArgs, *river.InsertOpts) {
			return SoDArgs{}, &river.InsertOpts{MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByPeriod: time.Hour}}
		}, &river.PeriodicJobOpts{RunOnStart: true}),
	}
	return river.NewClient(riverpgxv5.New(w.o.Pool), &river.Config{
		Queues:       map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 2}},
		Workers:      workers,
		PeriodicJobs: periodic,
		Schema:       RiverSchema,
		Logger:       w.o.Logger,
	})
}
