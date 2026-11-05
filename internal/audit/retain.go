package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/objstore"
	events "github.com/rformer/fair-app/pkg/audit"
)

// RetainStore is what retention needs of the audit store (objstore.Store):
// reading archives, S3 legal holds and deleting a version.
type RetainStore interface {
	ArchiveSource
	SetLegalHold(ctx context.Context, v objstore.Version, on bool) error
	Delete(ctx context.Context, v objstore.Version) error
}

// RetainEvery is how often the leader applies holds and destroys what is
// due (holds reach the store's legal holds within this; design §6.7 asks
// for daily destruction at least).
const RetainEvery = time.Hour

// Retainer applies legal holds to the archive and destroys archived
// segments past the total retention (F-002 T-19, AC-27, AC-29; design
// §6.7). Each Step:
//  1. checks every new hold against the archived segments, reading their
//     objects (a hold's filter over their bodies, as search applies it), and
//     marks the hold checked; until then nothing is destroyed;
//  2. sets the S3 legal hold on every archive an active hold covers and
//     clears it on the others;
//  3. destroys each archive whose lock has ended, whose newest record is
//     older than the total retention in force and that no active hold
//     covers: the destruction is recorded with audit.records_destroyed,
//     then the object is deleted (retried until it is gone).
//
// Checkpoints are never destroyed, so verification continues from the
// first retained record. Run it on the leader.
type Retainer struct {
	DB    *pgxpool.Pool // app_audit
	Store RetainStore
	Audit events.Emitter
	// Retention is audit.retention_online and audit.retention_total; the
	// total used is the longer of the two.
	Retention func() (online, total time.Duration)
	Now       func() time.Time
}

// RetainResult is what one Step did.
type RetainResult struct {
	HoldsChecked    int
	LegalHoldsSet   int
	LegalHoldsClear int
	Destroyed       []uint64
	ObjectsRemoved  int
}

func (r Retainer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r Retainer) total() time.Duration {
	online, total := 365*24*time.Hour, 2557*24*time.Hour
	if r.Retention != nil {
		online, total = r.Retention()
	}
	return max(total, online)
}

// Step runs the three stages once; it stops at the first failure.
func (r Retainer) Step(ctx context.Context) (RetainResult, error) {
	var res RetainResult
	if r.Store == nil || r.Audit == nil {
		return res, errors.New("audit retention: no store or audit emitter")
	}
	n, err := r.checkHolds(ctx)
	res.HoldsChecked = n
	if err != nil {
		return res, err
	}
	if res.LegalHoldsSet, res.LegalHoldsClear, err = r.syncLegalHolds(ctx); err != nil {
		return res, err
	}
	if res.Destroyed, err = r.destroy(ctx); err != nil {
		return res, err
	}
	res.ObjectsRemoved, err = r.removeObjects(ctx)
	return res, err
}

// checkHolds checks every unchecked active hold against the live archives.
func (r Retainer) checkHolds(ctx context.Context) (int, error) {
	rows, err := r.DB.Query(ctx, "SELECT id::text FROM audit.holds_unchecked()")
	if err != nil {
		return 0, fmt.Errorf("audit holds: %w", err)
	}
	holds, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(holds) == 0 {
		return 0, err
	}
	rows, err = r.DB.Query(ctx, "SELECT segment, object_key, version_id, digest FROM audit.verify_archives() WHERE NOT destroyed")
	if err != nil {
		return 0, fmt.Errorf("audit holds: archives: %w", err)
	}
	type arc struct {
		Segment      int64
		Key, Version string
		Digest       []byte
	}
	archives, err := pgx.CollectRows(rows, pgx.RowToStructByPos[arc])
	if err != nil {
		return 0, fmt.Errorf("audit holds: archives: %w", err)
	}
	for _, a := range archives {
		seqs, bodies, err := r.readArchive(ctx, objstore.Version{Key: a.Key, VersionID: a.Version}, a.Digest)
		if err != nil {
			return 0, fmt.Errorf("audit holds: segment %d: %w", a.Segment, err)
		}
		for _, h := range holds {
			if _, err := r.DB.Exec(ctx, "SELECT audit.hold_match_archived($1, $2, $3, $4)", h, a.Segment, seqs, bodies); err != nil {
				return 0, fmt.Errorf("audit holds: hold %s, segment %d: %w", h, a.Segment, err)
			}
		}
	}
	for _, h := range holds {
		if _, err := r.DB.Exec(ctx, "SELECT audit.hold_checked($1)", h); err != nil {
			return 0, fmt.Errorf("audit holds: %w", err)
		}
	}
	return len(holds), nil
}

// readArchive reads an archive by version, checks its recorded digest and
// returns its records' positions and bodies.
func (r Retainer) readArchive(ctx context.Context, v objstore.Version, digest []byte) ([]int64, [][]byte, error) {
	rc, err := r.Store.Open(ctx, v)
	if err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return nil, nil, err
	}
	if sum := sha256.Sum256(data); !bytes.Equal(sum[:], digest) {
		return nil, nil, errors.New("the archive does not match its recorded digest")
	}
	seg, err := evidence.ReadSegment(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	seqs := make([]int64, len(seg.Records))
	bodies := make([][]byte, len(seg.Records))
	for i, rec := range seg.Records {
		seqs[i], bodies[i] = int64(rec.Seq), rec.Body // #nosec G115 -- positions
	}
	return seqs, bodies, nil
}

// syncLegalHolds makes each archive's S3 legal hold what the active holds
// say.
func (r Retainer) syncLegalHolds(ctx context.Context) (set, cleared int, err error) {
	rows, err := r.DB.Query(ctx, "SELECT segment, object_key, version_id, want FROM audit.legal_hold_drift()")
	if err != nil {
		return 0, 0, fmt.Errorf("audit legal holds: %w", err)
	}
	type drift struct {
		Segment      int64
		Key, Version string
		Want         bool
	}
	ds, err := pgx.CollectRows(rows, pgx.RowToStructByPos[drift])
	if err != nil {
		return 0, 0, fmt.Errorf("audit legal holds: %w", err)
	}
	for _, d := range ds {
		if err := r.Store.SetLegalHold(ctx, objstore.Version{Key: d.Key, VersionID: d.Version}, d.Want); err != nil {
			return set, cleared, fmt.Errorf("audit legal hold on segment %d: %w", d.Segment, err)
		}
		if _, err := r.DB.Exec(ctx, "SELECT audit.legal_hold_set($1, $2)", d.Segment, d.Want); err != nil {
			return set, cleared, fmt.Errorf("audit legal hold on segment %d: %w", d.Segment, err)
		}
		if d.Want {
			set++
		} else {
			cleared++
		}
	}
	return set, cleared, nil
}

// destroy records the destruction of every archive that is due.
func (r Retainer) destroy(ctx context.Context) ([]uint64, error) {
	olderThan := r.now().Add(-r.total())
	rows, err := r.DB.Query(ctx, "SELECT segment, seq_from, seq_to, object_key, version_id, record_count FROM audit.destroy_candidates($1, 100)", olderThan)
	if err != nil {
		return nil, fmt.Errorf("audit destruction: %w", err)
	}
	type cand struct {
		Segment, From, To int64
		Key, Version      string
		Count             int64
	}
	cs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[cand])
	if err != nil {
		return nil, fmt.Errorf("audit destruction: %w", err)
	}
	var out []uint64
	for _, c := range cs {
		err := pgx.BeginFunc(ctx, r.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT audit.destroy_segment($1, $2)", c.Segment, olderThan); err != nil {
				return err
			}
			return r.Audit.Emit(events.WithTx(ctx, tx), events.Event{Type: "audit.records_destroyed", Severity: events.SeverityHigh, Actor: "system:audit",
				Target: "segment:" + strconv.FormatInt(c.Segment, 10), Attributes: map[string]string{
					"segment": strconv.FormatInt(c.Segment, 10), "seq_from": strconv.FormatInt(c.From, 10), "seq_to": strconv.FormatInt(c.To, 10),
					"record_count": strconv.FormatInt(c.Count, 10), "object_key": c.Key, "version_id": c.Version}})
		})
		if err != nil {
			return out, fmt.Errorf("audit destruction of segment %d: %w", c.Segment, err)
		}
		out = append(out, uint64(c.Segment)) // #nosec G115
	}
	return out, nil
}

// removeObjects deletes the objects of destroyed archives.
func (r Retainer) removeObjects(ctx context.Context) (int, error) {
	rows, err := r.DB.Query(ctx, "SELECT segment, object_key, version_id FROM audit.destroy_pending()")
	if err != nil {
		return 0, fmt.Errorf("audit destruction: %w", err)
	}
	type pend struct {
		Segment      int64
		Key, Version string
	}
	ps, err := pgx.CollectRows(rows, pgx.RowToStructByPos[pend])
	if err != nil {
		return 0, fmt.Errorf("audit destruction: %w", err)
	}
	n := 0
	for _, p := range ps {
		if err := r.Store.Delete(ctx, objstore.Version{Key: p.Key, VersionID: p.Version}); err != nil {
			return n, fmt.Errorf("audit destruction: deleting segment %d: %w", p.Segment, err)
		}
		if _, err := r.DB.Exec(ctx, "SELECT audit.object_removed($1)", p.Segment); err != nil {
			return n, fmt.Errorf("audit destruction: %w", err)
		}
		n++
	}
	return n, nil
}

// Run applies holds and destroys what is due at start and then every
// interval (RetainEvery when zero), until ctx ends. Errors go to onErr.
func (r Retainer) Run(ctx context.Context, every time.Duration, onErr func(error)) error {
	if every <= 0 {
		every = RetainEvery
	}
	for {
		if _, err := r.Step(ctx); err != nil && onErr != nil && ctx.Err() == nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
