package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rformer/fair-app/internal/api/enginev1"
)

// Failure codes recorded on a failed run.
const (
	FailInvalidBundle  = "invalid_bundle"
	FailNotValidated   = "engine_not_validated"
	FailUnavailable    = "engine_unavailable"
	FailInvalidResults = "invalid_results"
	FailInternal       = "engine_internal"
)

// Worker runs simulate jobs.
type Worker struct {
	river.WorkerDefaults[SimulateArgs]
	DB     *pgxpool.Pool // app_rw: the worker uses analysis_definer's functions only
	Engine enginev1.EngineClient
	// ThresholdBP gives simulation.convergence_threshold_bp at run time.
	ThresholdBP func() int
	// ImageDigest is the engine image's digest from the release manifest
	// (sha256:<hex>), recorded on every run; empty when not known.
	ImageDigest string
	Logger      *slog.Logger
	// Now is the clock (tests).
	Now func() time.Time
}

// Timeout implements river.Worker.
func (w *Worker) Timeout(*river.Job[SimulateArgs]) time.Duration { return RunTimeout }

// errTransient marks a failure worth another attempt: the engine was
// unreachable or the stream broke.
type errTransient struct{ err error }

func (e errTransient) Error() string { return "engine unavailable: " + e.err.Error() }
func (e errTransient) Unwrap() error { return e.err }

// errModel is a failure another attempt would repeat.
type errModel struct{ code, detail string }

func (e errModel) Error() string { return e.code + ": " + e.detail }

type spec struct {
	ID           string   `json:"id"`
	BUID         string   `json:"bu_id"`
	ScenarioID   string   `json:"scenario_id"`
	Version      int64    `json:"scenario_version"`
	BundleDigest string   `json:"bundle_digest"`
	Seed         string   `json:"seed"`
	Iterations   int      `json:"iterations"`
	ControlSets  []string `json:"control_sets"`
}

// Work implements river.Worker: one attempt of a run.
func (w *Worker) Work(ctx context.Context, job *river.Job[SimulateArgs]) error {
	return w.Attempt(ctx, job.Args.RunID, job.Attempt, job.MaxAttempts)
}

// Attempt is one attempt of run id (the worker's body; tests call it).
// It returns nil when the run succeeded, failed for good, was cancelled or
// is no longer runnable; an error for River to retry; river.JobCancel when
// it marked the run failed.
func (w *Worker) Attempt(ctx context.Context, id string, attempt, maxAttempts int) error {
	var token string
	err := w.DB.QueryRow(ctx, "SELECT analysis.start_run($1)", id).Scan(&token)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "PF024" {
			return nil // cancelled or finished meanwhile
		}
		return err
	}
	err = w.run(ctx, id, token)
	var tr errTransient
	var me errModel
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errStopped):
		return nil
	case errors.As(err, &me):
		return w.fail(ctx, id, token, me.code, me.detail, err)
	case errors.As(err, &tr) && attempt < maxAttempts:
		w.log("simulation attempt failed; retrying", "run", id, "attempt", attempt, "error", err.Error())
		return err
	case errors.As(err, &tr):
		return w.fail(ctx, id, token, FailUnavailable, err.Error(), err)
	}
	return err // a database error: River retries, and the rescuer restarts a lost attempt
}

var errStopped = errors.New("analysis: the run is no longer running")

func (w *Worker) fail(ctx context.Context, id, token, code, detail string, cause error) error {
	if _, err := w.DB.Exec(context.WithoutCancel(ctx), "SELECT analysis.fail_run($1, $2, $3, $4)", id, token, code, detail); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "PF024" {
			return nil // cancelled meanwhile
		}
		return errors.Join(cause, err)
	}
	w.log("simulation failed", "run", id, "failure", code)
	return river.JobCancel(cause)
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

var codeRE = regexp.MustCompile(`^[a-z_]{1,64}$`)

func (w *Worker) run(ctx context.Context, id, token string) error {
	var raw []byte
	if err := w.DB.QueryRow(ctx, "SELECT analysis.run_spec($1, $2)", id, token).Scan(&raw); err != nil {
		return err
	}
	var sp spec
	if err := json.Unmarshal(raw, &sp); err != nil {
		return err
	}
	var bundle []byte
	if err := w.DB.QueryRow(ctx, "SELECT analysis.run_bundle($1, $2)", id, token).Scan(&bundle); err != nil {
		return err
	}
	seed, err := strconv.ParseUint(sp.Seed, 10, 64)
	if err != nil {
		return fmt.Errorf("analysis: the run's seed %q: %w", sp.Seed, err)
	}

	info, err := w.Engine.Info(ctx, &enginev1.InfoRequest{})
	if err != nil {
		return transient(err)
	}
	if !info.GetValidation().GetPassed() {
		return errModel{FailNotValidated, "the engine's validation record did not pass (suite " + info.GetValidation().GetSuiteVersion() + ")"}
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	threshold := 100
	if w.ThresholdBP != nil {
		threshold = w.ThresholdBP()
	}
	stream, err := w.Engine.Simulate(sctx, &enginev1.SimulateRequest{
		Bundle: bundle, Seed: seed, Iterations: uint32(sp.Iterations), // #nosec G115 -- bounded by the run's CHECK (at most 2,000,000)
		ControlSets: sp.ControlSets, ConvergenceThresholdBp: uint32(threshold), RunId: id, // #nosec G115 -- the setting's bounds (10 to 500)
	})
	if err != nil {
		return transient(err)
	}
	summaries := map[string][]byte{}
	series := map[string][]byte{}
	want := map[string]bool{}
	for _, s := range sp.ControlSets {
		want[s] = true
	}
	var warnings []map[string]string
	last := time.Time{}
	done := false
	for !done {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return errTransient{errors.New("the stream ended without done")}
		}
		if err != nil {
			return transient(err)
		}
		switch e := ev.GetEvent().(type) {
		case *enginev1.SimulateEvent_Progress:
			if t := w.now(); t.Sub(last) >= ProgressGap && e.Progress.GetTotal() > 0 {
				last = t
				var state string
				p := float64(e.Progress.GetDone()) / float64(e.Progress.GetTotal())
				if err := w.DB.QueryRow(ctx, "SELECT analysis.progress($1, $2, $3)", id, token, p).Scan(&state); err != nil {
					return err
				}
				if state != "running" {
					cancel() // cancelled: the engine stops at its next chunk
					w.log("simulation stopped", "run", id, "state", state)
					return errStopped
				}
			}
		case *enginev1.SimulateEvent_Result:
			set := e.Result.GetControlSet()
			if !want[set] || summaries[set] != nil {
				return errModel{FailInvalidResults, fmt.Sprintf("an unexpected or repeated result for control set %q", set)}
			}
			if err := checkSummary([]byte(e.Result.GetSummaryJson())); err != nil {
				return errModel{FailInvalidResults, fmt.Sprintf("the summary of %q: %v", set, err)}
			}
			summaries[set] = []byte(e.Result.GetSummaryJson())
		case *enginev1.SimulateEvent_Series:
			set := e.Series.GetControlSet()
			if !want[set] || summaries[set] == nil {
				return errModel{FailInvalidResults, fmt.Sprintf("a series chunk for %q before its result", set)}
			}
			if e.Series.GetOffset() != uint64(len(series[set])/8) || len(e.Series.GetValues())%8 != 0 ||
				len(series[set])+len(e.Series.GetValues()) > sp.Iterations*8 {
				return errModel{FailInvalidResults, fmt.Sprintf("a series chunk of %q out of order or too long", set)}
			}
			series[set] = append(series[set], e.Series.GetValues()...)
		case *enginev1.SimulateEvent_Done:
			for _, x := range e.Done.GetWarnings() {
				warnings = append(warnings, map[string]string{"code": x.GetCode(), "pointer": x.GetPointer(), "control_set": x.GetControlSet(), "detail": x.GetDetail()})
			}
			done = true
		case *enginev1.SimulateEvent_Failure:
			code := e.Failure.GetCode()
			if code == "internal" || !codeRE.MatchString(code) {
				code = FailInternal
			}
			return errModel{code, e.Failure.GetDetail()}
		}
	}
	results := make([]SetResult, 0, len(sp.ControlSets))
	for _, s := range sp.ControlSets {
		if summaries[s] == nil {
			return errModel{FailInvalidResults, fmt.Sprintf("no result for control set %q", s)}
		}
		if err := checkSeries(series[s], sp.Iterations); err != nil {
			return errModel{FailInvalidResults, fmt.Sprintf("the series of %q: %v", s, err)}
		}
		results = append(results, SetResult{ControlSet: s, Summary: summaries[s], Series: series[s]})
	}
	digest, err := Digest(RunInputs{ScenarioID: sp.ScenarioID, Version: sp.Version, BundleDigest: sp.BundleDigest, Seed: sp.Seed,
		Iterations: sp.Iterations, ControlSets: sp.ControlSets}, info.GetVersion(), info.GetArchitecture(), results)
	if err != nil {
		return errModel{FailInvalidResults, err.Error()}
	}
	return w.store(ctx, id, token, info, warnings, results, digest)
}

// store puts every series and finishes the run (results, engine record,
// warnings, digest, analysis.run_succeeded) in one transaction.
func (w *Worker) store(ctx context.Context, id, token string, info *enginev1.EngineInfo, warnings []map[string]string, results []SetResult, digest string) error {
	v := info.GetValidation()
	eng := map[string]any{"version": info.GetVersion(), "architecture": info.GetArchitecture(),
		"validation": map[string]any{"suite_version": v.GetSuiteVersion(), "passed": v.GetPassed(), "run_at_unix_ms": v.GetRunAtUnixMs()}}
	if w.ImageDigest != "" {
		eng["image_digest"] = w.ImageDigest
	}
	engJSON, _ := json.Marshal(eng)
	if warnings == nil {
		warnings = []map[string]string{}
	}
	warnJSON, _ := json.Marshal(warnings)
	sums := map[string]json.RawMessage{}
	for _, r := range results {
		sums[r.ControlSet] = r.Summary
	}
	sumJSON, _ := json.Marshal(sums)
	tx, err := w.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	for _, r := range results {
		if _, err := tx.Exec(ctx, "SELECT analysis.put_series($1, $2, $3, $4)", id, token, r.ControlSet, r.Series); err != nil {
			return stopped(err)
		}
	}
	var outcome string
	if err := tx.QueryRow(ctx, "SELECT analysis.finish_run($1, $2, $3, $4, $5, $6)", id, token, engJSON, warnJSON, sumJSON, digest).Scan(&outcome); err != nil {
		return stopped(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	w.log("simulation succeeded", "run", id, "result_digest", digest, "outcome", outcome)
	return nil
}

// stopped: a run cancelled while its results were being stored.
func stopped(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "PF024" && strings.HasSuffix(pg.Message, "is not running") {
		return errStopped
	}
	return err
}

// transient classifies a gRPC error: unreachable, unavailable, cut or
// timed out is worth another attempt; anything else the engine answered is
// a model error.
func transient(err error) error {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Aborted, codes.ResourceExhausted, codes.Canceled, codes.Unknown, codes.Internal:
		return errTransient{err}
	}
	return errModel{FailInternal, status.Convert(err).Message()}
}

// NewClient is the risk service's River client for analysis jobs (runs and
// aggregates): every replica works the queue (workers jobs at once). The caller starts
// and stops it.
func NewClient(pool *pgxpool.Pool, w *Worker, aw *AggregateWorker, workers int, logger *slog.Logger) (*river.Client[pgx.Tx], error) {
	ws := river.NewWorkers()
	river.AddWorker(ws, w)
	river.AddWorker(ws, aw)
	return river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:  map[string]river.QueueConfig{Queue: {MaxWorkers: workers}},
		Workers: ws,
		Schema:  RiverSchema,
		Logger:  logger,
	})
}

// Enqueuer queues a simulate job in the request's transaction.
func Enqueuer(c *river.Client[pgx.Tx]) func(context.Context, pgx.Tx, SimulateArgs) error {
	return func(ctx context.Context, tx pgx.Tx, args SimulateArgs) error {
		_, err := c.InsertTx(ctx, tx, args, nil)
		return err
	}
}
