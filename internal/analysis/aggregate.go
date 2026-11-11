package analysis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/rformer/fair-app/internal/api/enginev1"
	"github.com/rformer/fair-app/internal/risk/canon"
)

// F-005 T-12 (AC-18, AC-19; design §3.5, §6.4): aggregates of runs.

// AggregateArgs is the aggregate job: aggregate AggregateID.
type AggregateArgs struct {
	AggregateID string `json:"aggregate_id"`
}

// Kind implements river.JobArgs.
func (AggregateArgs) Kind() string { return "analysis.aggregate" }

// InsertOpts implements river.JobArgsWithInsertOpts.
func (AggregateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: Queue, MaxAttempts: Attempts}
}

// MemberRef names a member: one control set of a succeeded run.
type MemberRef struct {
	RunID      string `json:"run_id"`
	ControlSet string `json:"control_set"`
}

// AggregateRequest is what an analyst asks for (design §5).
type AggregateRequest struct {
	BU      string
	Name    string
	Seed    *uint64 // nil: random
	Members []MemberRef
}

// RequestAggregate records an aggregate and its members, and queues its
// job, in tx (under the caller's DB context). The caller has checked
// analysis.run at the BU; the database checks each member (visible to the
// caller, succeeded, in the BU's subtree, of equal iterations) and records
// analysis.aggregate_created.
func RequestAggregate(ctx context.Context, tx pgx.Tx, ins func(context.Context, pgx.Tx, AggregateArgs) error, in AggregateRequest) (string, error) {
	var seed uint64
	if in.Seed != nil {
		seed = *in.Seed
	} else {
		var buf [8]byte
		_, _ = rand.Read(buf[:]) // crypto/rand.Read never fails
		seed = binary.BigEndian.Uint64(buf[:])
	}
	members, err := json.Marshal(in.Members)
	if err != nil {
		return "", err
	}
	var id string
	if err := tx.QueryRow(ctx, "SELECT analysis.request_aggregate($1, $2, $3::numeric, $4)::text", in.BU, in.Name, strconv.FormatUint(seed, 10), members).
		Scan(&id); err != nil {
		return "", err
	}
	if err := ins(ctx, tx, AggregateArgs{AggregateID: id}); err != nil {
		return "", fmt.Errorf("analysis: queue the aggregate: %w", err)
	}
	return id, nil
}

// AggregateWorker runs aggregate jobs.
type AggregateWorker struct {
	river.WorkerDefaults[AggregateArgs]
	DB     *pgxpool.Pool // app_rw: analysis_definer's functions only
	Engine enginev1.EngineClient
	Logger *slog.Logger
}

// Timeout implements river.Worker.
func (w *AggregateWorker) Timeout(*river.Job[AggregateArgs]) time.Duration { return RunTimeout }

// Work implements river.Worker.
func (w *AggregateWorker) Work(ctx context.Context, job *river.Job[AggregateArgs]) error {
	return w.Attempt(ctx, job.Args.AggregateID, job.Attempt, job.MaxAttempts)
}

type aggregateSpec struct {
	Seed       string `json:"seed"`
	Iterations int    `json:"iterations"`
	Members    []struct {
		Position     int    `json:"position"`
		RunID        string `json:"run_id"`
		ControlSet   string `json:"control_set"`
		ResultDigest string `json:"result_digest"`
	} `json:"members"`
}

// Attempt is one attempt of aggregate id, as Worker.Attempt for a run.
func (w *AggregateWorker) Attempt(ctx context.Context, id string, attempt, maxAttempts int) error {
	var token string
	if err := w.DB.QueryRow(ctx, "SELECT analysis.start_aggregate($1)", id).Scan(&token); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "PF024" {
			return nil // finished meanwhile
		}
		return err
	}
	err := w.run(ctx, id, token)
	var tr errTransient
	var me errModel
	switch {
	case err == nil:
		return nil
	case errors.As(err, &me):
		return w.fail(ctx, id, token, me.code, me.detail, err)
	case errors.As(err, &tr) && attempt < maxAttempts:
		return err
	case errors.As(err, &tr):
		return w.fail(ctx, id, token, FailUnavailable, err.Error(), err)
	}
	return err
}

func (w *AggregateWorker) fail(ctx context.Context, id, token, code, detail string, cause error) error {
	if _, err := w.DB.Exec(context.WithoutCancel(ctx), "SELECT analysis.fail_aggregate($1, $2, $3, $4)", id, token, code, detail); err != nil {
		return errors.Join(cause, err)
	}
	if w.Logger != nil {
		w.Logger.Info("aggregate failed", "aggregate", id, "failure", code)
	}
	return river.JobCancel(cause)
}

func (w *AggregateWorker) run(ctx context.Context, id, token string) error {
	var raw []byte
	if err := w.DB.QueryRow(ctx, "SELECT analysis.aggregate_spec($1, $2)", id, token).Scan(&raw); err != nil {
		return err
	}
	var sp aggregateSpec
	if err := json.Unmarshal(raw, &sp); err != nil {
		return err
	}
	seed, err := strconv.ParseUint(sp.Seed, 10, 64)
	if err != nil {
		return fmt.Errorf("analysis: the aggregate's seed %q: %w", sp.Seed, err)
	}
	info, err := w.Engine.Info(ctx, &enginev1.InfoRequest{})
	if err != nil {
		return transient(err)
	}
	if !info.GetValidation().GetPassed() {
		return errModel{FailNotValidated, "the engine's validation record did not pass"}
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := w.Engine.Aggregate(sctx)
	if err != nil {
		return transient(err)
	}
	header := &enginev1.AggregateHeader{AggregateId: id, Seed: seed, Iterations: uint32(sp.Iterations)} // #nosec G115 -- the aggregate's CHECK bounds it
	for _, m := range sp.Members {
		header.Members = append(header.Members, &enginev1.Member{Position: uint32(m.Position), RunId: m.RunID, ControlSet: m.ControlSet}) // #nosec G115 -- 0 to 199
	}
	if err := stream.Send(&enginev1.AggregateInput{Input: &enginev1.AggregateInput_Header{Header: header}}); err != nil {
		return transient(err)
	}
	// One member's series at a time: memory stays one series.
	const chunk = 1 << 20
	for _, m := range sp.Members {
		var ale []byte
		if err := w.DB.QueryRow(ctx, "SELECT analysis.member_series($1, $2, $3)", id, token, m.Position).Scan(&ale); err != nil {
			return err
		}
		for off := 0; off < len(ale); off += chunk {
			end := min(off+chunk, len(ale))
			if err := stream.Send(&enginev1.AggregateInput{Input: &enginev1.AggregateInput_Series{Series: &enginev1.MemberChunk{
				Position: uint32(m.Position), Offset: uint64(off / 8), Values: ale[off:end]}}}); err != nil { // #nosec G115 -- 0 to 199
				return transient(err)
			}
		}
	}
	if err := stream.CloseSend(); err != nil {
		return transient(err)
	}
	var summary, series []byte
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return errTransient{errors.New("the stream ended without done")}
		}
		if err != nil {
			return transient(err)
		}
		switch e := ev.GetEvent().(type) {
		case *enginev1.AggregateEvent_Result:
			if summary != nil {
				return errModel{FailInvalidResults, "a repeated result"}
			}
			if err := checkSummary([]byte(e.Result.GetSummaryJson())); err != nil {
				return errModel{FailInvalidResults, "the summary: " + err.Error()}
			}
			summary = []byte(e.Result.GetSummaryJson())
		case *enginev1.AggregateEvent_Series:
			if e.Series.GetOffset() != uint64(len(series)/8) || len(series)+len(e.Series.GetValues()) > sp.Iterations*8 {
				return errModel{FailInvalidResults, "a series chunk out of order or too long"}
			}
			series = append(series, e.Series.GetValues()...)
		case *enginev1.AggregateEvent_Failure:
			code := e.Failure.GetCode()
			if code == "internal" || !codeRE.MatchString(code) {
				code = FailInternal
			}
			return errModel{code, e.Failure.GetDetail()}
		case *enginev1.AggregateEvent_Done:
			if summary == nil {
				return errModel{FailInvalidResults, "no result"}
			}
			if err := checkSeries(series, sp.Iterations); err != nil {
				return errModel{FailInvalidResults, "the series: " + err.Error()}
			}
			digest, err := AggregateDigest(sp, info.GetVersion(), info.GetArchitecture(), summary, series)
			if err != nil {
				return errModel{FailInvalidResults, err.Error()}
			}
			eng, _ := json.Marshal(map[string]string{"version": info.GetVersion(), "architecture": info.GetArchitecture()})
			if _, err := w.DB.Exec(ctx, "SELECT analysis.finish_aggregate($1, $2, $3, $4, $5, $6)", id, token, eng, summary, series, digest); err != nil {
				return err
			}
			if w.Logger != nil {
				w.Logger.Info("aggregate succeeded", "aggregate", id, "result_digest", digest)
			}
			return nil
		}
	}
}

// AggregateDigest is an aggregate's results digest, as Digest for a run:
// SHA-256 of the canonical {inputs (seed, iterations, members with their
// runs' results digests), engine, summary, SHA-256 of the series}.
func AggregateDigest(sp aggregateSpec, engineVersion, architecture string, summary, series []byte) (string, error) {
	v, err := canon.Parse(summary)
	if err != nil {
		return "", err
	}
	norm, err := normalize(v)
	if err != nil {
		return "", err
	}
	members := make([]any, 0, len(sp.Members))
	for _, m := range sp.Members {
		members = append(members, map[string]any{"position": int64(m.Position), "run_id": m.RunID, "control_set": m.ControlSet, "result_digest": m.ResultDigest})
	}
	sum := sha256.Sum256(series)
	b, err := canon.Marshal(map[string]any{
		"format":    "fair.analysis-aggregate.v1",
		"aggregate": map[string]any{"seed": sp.Seed, "iterations": int64(sp.Iterations), "members": members},
		"engine":    map[string]any{"version": engineVersion, "architecture": architecture},
		"summary":   norm, "series_sha256": hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return "", err
	}
	return canon.Digest(b), nil
}

// AggregateEnqueuer queues an aggregate job in the request's transaction.
func AggregateEnqueuer(c *river.Client[pgx.Tx]) func(context.Context, pgx.Tx, AggregateArgs) error {
	return func(ctx context.Context, tx pgx.Tx, args AggregateArgs) error {
		_, err := c.InsertTx(ctx, tx, args, nil)
		return err
	}
}
