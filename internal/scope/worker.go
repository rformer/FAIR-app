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
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/rformer/fair-app/pkg/audit"
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
	Audit     audit.Emitter
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
	if e.topic != "audit" {
		if err := w.o.Publisher.Publish(ctx, e.topic, e.msgID(), e.payload); err != nil {
			return fmt.Errorf("scope: publish event %d to %s: %w", e.id, e.topic, err)
		}
		return nil
	}
	var p struct {
		Type       string         `json:"type"`
		Severity   string         `json:"severity"`
		Actor      string         `json:"actor"`
		Attributes map[string]any `json:"attributes"`
	}
	if err := json.Unmarshal(e.payload, &p); err != nil {
		return fmt.Errorf("scope: audit event %d: %w", e.id, err)
	}
	attrs := make(map[string]string, len(p.Attributes)+1)
	for k, v := range p.Attributes {
		if v != nil {
			attrs[k] = fmt.Sprint(v)
		}
	}
	attrs["event_id"] = fmt.Sprint(e.id)
	if err := w.o.Audit.Emit(ctx, audit.Event{
		Type: p.Type, Severity: audit.Severity(p.Severity), Actor: p.Actor, Attributes: attrs,
	}); err != nil {
		return fmt.Errorf("scope: audit event %d: %w", e.id, err)
	}
	return nil
}

// DrainArgs is the periodic outbox drain job.
type DrainArgs struct{}

// Kind implements river.JobArgs.
func (DrainArgs) Kind() string { return "scope.drain" }

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
	every := w.o.DrainEvery
	periodic := []*river.PeriodicJob{
		// A failed drain is not retried: the next tick drains again.
		river.NewPeriodicJob(river.PeriodicInterval(every), func() (river.JobArgs, *river.InsertOpts) {
			return DrainArgs{}, &river.InsertOpts{MaxAttempts: 1, UniqueOpts: river.UniqueOpts{ByPeriod: every}}
		}, &river.PeriodicJobOpts{RunOnStart: true}),
		river.NewPeriodicJob(dailyAt(w.o.ReconcileAtUTC), func() (river.JobArgs, *river.InsertOpts) {
			return ReconcileArgs{}, &river.InsertOpts{MaxAttempts: 5, UniqueOpts: river.UniqueOpts{ByPeriod: 24 * time.Hour}}
		}, nil),
	}
	return river.NewClient(riverpgxv5.New(w.o.Pool), &river.Config{
		Queues:       map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 2}},
		Workers:      workers,
		PeriodicJobs: periodic,
		Schema:       RiverSchema,
		Logger:       w.o.Logger,
	})
}
