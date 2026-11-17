package reports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/rformer/fair-app/internal/objstore"
	"github.com/rformer/fair-app/internal/reports/doc"
	"github.com/rformer/fair-app/internal/risk"
	"github.com/rformer/fair-app/pkg/authz"
)

// Failure codes recorded on a failed run (the text after the code is
// detail).
const (
	FailNoPermission  = "no_permission" // the database's (report.start_run)
	FailLimitExceeded = "limit_exceeded"
	FailUnknownKind   = "unknown_kind"
	FailInvalid       = "invalid_document"
	FailGeneration    = "generation_failed"
)

// RunTimeout bounds one attempt.
const RunTimeout = 15 * time.Minute

// Store is the report store (objstore.Store; a fake in tests).
type Store interface {
	PutStream(ctx context.Context, key string, r io.Reader, size int64, retainUntil time.Time) (objstore.Version, error)
	Open(ctx context.Context, v objstore.Version) (io.ReadCloser, error)
}

// Worker generates reports (River kind report.generate).
type Worker struct {
	river.WorkerDefaults[GenerateArgs]
	DB *pgxpool.Pool // app_rw: report_definer's functions, and reads under the delegated context
	// Key is the report context key (risk/report-context, purpose report).
	Key   authz.ContextKey
	Store Store
	Kinds map[string]Kind
	// Marking gives report.marking at run time.
	Marking func() (string, error)
	Logger  *slog.Logger
	// Now is the clock (tests).
	Now func() time.Time
}

// Timeout implements river.Worker.
func (w *Worker) Timeout(*river.Job[GenerateArgs]) time.Duration { return RunTimeout }

// Work implements river.Worker.
func (w *Worker) Work(ctx context.Context, job *river.Job[GenerateArgs]) error {
	return w.Attempt(ctx, job.Args.RunID, job.Attempt, job.MaxAttempts)
}

// errFinal is a failure another attempt would repeat.
type errFinal struct{ code, detail string }

func (e errFinal) Error() string { return e.code + ": " + e.detail }

// errGone: the run finished, or another attempt took it over.
var errGone = errors.New("reports: the run is no longer this attempt's")

type spec struct {
	ID            string          `json:"id"`
	State         string          `json:"state"`
	RequestedBy   string          `json:"requested_by"`
	RequesterName string          `json:"requester_name"`
	ScopeVersion  *int64          `json:"scope_version"`
	BU            doc.Ref         `json:"bu"`
	Kind          string          `json:"kind"`
	Params        json.RawMessage `json:"params"`
	Formats       []string        `json:"formats"`
	Reason        *string         `json:"reason"`
	ScheduleID    *string         `json:"schedule_id"`
	Instance      string          `json:"instance"`
}

// Attempt is one attempt of run id (the job's body; tests call it). It
// returns nil when the run succeeded, failed for good or is no longer
// runnable; an error for River to retry; river.JobCancel after marking the
// run failed.
func (w *Worker) Attempt(ctx context.Context, id string, attempt, maxAttempts int) error {
	var raw []byte
	if err := w.DB.QueryRow(ctx, "SELECT report.run_spec($1)", id).Scan(&raw); err != nil {
		return err
	}
	if raw == nil {
		return nil // no such run
	}
	var sp spec
	if err := json.Unmarshal(raw, &sp); err != nil {
		return err
	}
	if sp.State != "queued" && sp.State != "running" {
		return nil
	}
	var version int64
	if sp.ScopeVersion != nil {
		version = *sp.ScopeVersion
	}
	tok, err := authz.MintDBContext(w.Key, sp.RequestedBy, version, authz.MaxContextTTL, w.now())
	if err != nil {
		return err
	}
	nonce := strings.Split(tok, ".")[5]
	var started string
	if err := w.DB.QueryRow(ctx, "SELECT report.start_run($1, $2)", id, nonce).Scan(&started); err != nil {
		return err
	}
	if started != "started" {
		w.log("report not started", "run", id, "outcome", started)
		return nil
	}
	err = w.run(ctx, sp, tok, nonce)
	var final errFinal
	switch {
	case err == nil, errors.Is(err, errGone):
		return nil
	case errors.As(err, &final):
		return w.fail(ctx, id, nonce, final.Error(), err)
	case attempt < maxAttempts:
		w.log("report attempt failed; retrying", "run", id, "attempt", attempt, "error", err.Error())
		return err
	}
	return w.fail(ctx, id, nonce, FailGeneration+": "+err.Error(), err)
}

func (w *Worker) fail(ctx context.Context, id, nonce, failure string, cause error) error {
	if _, err := w.DB.Exec(context.WithoutCancel(ctx), "SELECT report.fail_run($1, $2, $3)", id, nonce, failure); err != nil {
		if gone(err) {
			return nil
		}
		return errors.Join(cause, err)
	}
	w.log("report failed", "run", id, "failure", strings.SplitN(failure, ":", 2)[0])
	return river.JobCancel(cause)
}

// gone: P0002 not_running from report.running.
func gone(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "P0002" && pg.Hint == "not_running"
}

func (w *Worker) progress(ctx context.Context, id, nonce string, pct int) error {
	if _, err := w.DB.Exec(ctx, "SELECT report.progress($1, $2, $3)", id, nonce, pct); err != nil {
		if gone(err) {
			return errGone
		}
		return err
	}
	return nil
}

type stored struct {
	Format    string `json:"format"`
	ObjectKey string `json:"object_key"`
	VersionID string `json:"version_id"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

func (w *Worker) run(ctx context.Context, sp spec, tok, nonce string) error {
	k, ok := w.Kinds[sp.Kind]
	if !ok || k.Read == nil {
		return errFinal{FailUnknownKind, "no reader for " + sp.Kind}
	}
	run := Run{ID: sp.ID, RequestedBy: sp.RequestedBy, RequesterName: sp.RequesterName, BU: sp.BU, Kind: sp.Kind, Params: sp.Params,
		Formats: sp.Formats}
	if sp.Reason != nil {
		run.Reason = *sp.Reason
	}
	if sp.ScheduleID != nil {
		run.ScheduleID = *sp.ScheduleID
	}
	marking, err := w.Marking()
	if err != nil {
		return fmt.Errorf("reports: report.marking: %w", err)
	}
	// One consistent read as the requester (design §3.3): the delegated
	// token is honoured only in this read-only transaction, while the run
	// runs with its nonce.
	var built Built
	var asOf time.Time
	var currency string
	err = authz.WithDBSnapshot(ctx, w.DB, tok, func(tx pgx.Tx) error {
		var reader *string
		if err := tx.QueryRow(ctx, "SELECT report.reader()::text, now()").Scan(&reader, &asOf); err != nil {
			return err
		}
		if reader == nil || *reader != sp.RequestedBy {
			return errors.New("reports: the delegated context was not honoured (the requester's scope changed); retrying")
		}
		var err error
		if currency, err = risk.Currency(ctx, tx); err != nil {
			return err
		}
		built, err = k.Read(ctx, tx, run)
		return err
	})
	if err != nil {
		return err
	}
	// The scope limit holds for every run, scheduled ones included (their
	// scope is counted here, as they have no request).
	if built.Risks > MaxRisks {
		return errFinal{FailLimitExceeded, fmt.Sprintf("the report covers %d risks; at most %d", built.Risks, MaxRisks)}
	}
	d := built.Doc
	if d.Metadata.Title == "" {
		d.Metadata.Title = k.Title
	}
	d.Metadata.RunID, d.Metadata.Kind, d.Metadata.BU = sp.ID, sp.Kind, sp.BU
	d.Metadata.GeneratedAt, d.Metadata.GeneratedBy, d.Metadata.DataAsOf = w.now().UTC(), sp.RequesterName, asOf.UTC()
	d.Metadata.Currency, d.Metadata.Marking = currency, marking
	if err := d.Validate(); err != nil {
		return errFinal{FailInvalid, err.Error()}
	}
	if err := w.progress(ctx, sp.ID, nonce, 40); err != nil {
		return err
	}
	var files []stored
	for i, f := range sp.Formats {
		var b []byte
		switch f {
		case "pdf":
			b, err = PDF(d)
		case "csv":
			b, err = d.CSV()
		case "json":
			b, err = d.JSON()
		default:
			err = errFinal{FailInvalid, "format " + f}
		}
		if err != nil {
			var final errFinal
			if errors.As(err, &final) {
				return err
			}
			return errFinal{FailInvalid, err.Error()}
		}
		if len(b) > MaxFile {
			return errFinal{FailLimitExceeded, fmt.Sprintf("%s is %d bytes; files are at most %d", FileName(f), len(b), MaxFile)}
		}
		// The digest is computed from the bytes as they stream to the store.
		h := sha256.New()
		key := fmt.Sprintf("reports/%s/%s/%s", sp.Instance, sp.ID, FileName(f))
		v, err := w.Store.PutStream(ctx, key, io.TeeReader(bytes.NewReader(b), h), int64(len(b)), time.Time{})
		if err != nil {
			return fmt.Errorf("reports: store %s: %w", key, err)
		}
		files = append(files, stored{Format: f, ObjectKey: v.Key, VersionID: v.VersionID, Size: int64(len(b)), SHA256: hex.EncodeToString(h.Sum(nil))})
		if err := w.progress(ctx, sp.ID, nonce, 40+60*(i+1)/len(sp.Formats)); err != nil {
			return err
		}
	}
	fj, _ := json.Marshal(files)
	lo := d.Metadata.LeftOut
	if lo == nil {
		lo = map[string]int{}
	}
	lj, _ := json.Marshal(lo)
	if _, err := w.DB.Exec(ctx, "SELECT report.complete_run($1, $2, $3, $4, $5, $6)", sp.ID, nonce, fj, asOf, built.Risks, lj); err != nil {
		if gone(err) {
			return errGone
		}
		return err
	}
	w.log("report generated", "run", sp.ID, "kind", sp.Kind, "formats", strings.Join(sp.Formats, " "))
	return nil
}

func (w *Worker) log(msg string, args ...any) {
	if w.Logger != nil {
		w.Logger.Info(msg, args...)
	}
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// NewClient is the risk service's River client for report jobs: every
// replica works the queue (workers jobs at once). The caller starts and
// stops it.
func NewClient(pool *pgxpool.Pool, w *Worker, workers int, logger *slog.Logger) (*river.Client[pgx.Tx], error) {
	ws := river.NewWorkers()
	river.AddWorker(ws, w)
	return river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:  map[string]river.QueueConfig{Queue: {MaxWorkers: workers}},
		Workers: ws,
		Schema:  RiverSchema,
		Logger:  logger,
	})
}
