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
	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/internal/objstore"
	events "github.com/rformer/fair-app/pkg/audit"
)

// ArchiveSource reads archived segments by version (objstore.Store).
type ArchiveSource interface {
	Digest(ctx context.Context, v objstore.Version) ([32]byte, error)
	Open(ctx context.Context, v objstore.Version) (io.ReadCloser, error)
}

// ArchiveStore keeps archived segments (objstore.Store: the audit store,
// with Object Lock).
type ArchiveStore interface {
	ArchiveSource
	PutStream(ctx context.Context, key string, r io.Reader, size int64, retainUntil time.Time) (objstore.Version, error)
}

// ArchiveEvery is how often the leader archives (design §6.7: daily).
const ArchiveEvery = 24 * time.Hour

// MinArchiveLock is the shortest lock an archive gets, when the total
// retention is not longer than the online one.
const MinArchiveLock = 24 * time.Hour

// Archiver moves segments past the online retention to the archive (F-002
// T-18, AC-25, AC-26; design §6.7). For each closed segment whose newest
// record is older than audit.retention_online, it checks the segment
// against its signed checkpoint, writes it (evidence.WriteSegment: the
// checkpoint and every record's exact body with its hashes) to
// segments/<instance>/<n>.jsonl.gz, locked until destroy_after (archived
// time plus the total retention less the online one), reads it back and
// checks its digest, and only then removes the segment's rows and records
// audit.records_archived in one transaction (audit.archive_segment). A
// failure at any step removes nothing. Run it on the leader.
type Archiver struct {
	DB    *pgxpool.Pool // app_audit
	Store ArchiveStore
	Audit events.Emitter
	// Retention is audit.retention_online and audit.retention_total; the
	// total used is the longer of the two (design §4.4).
	Retention func() (online, total time.Duration)
	Now       func() time.Time
}

// ArchiveResult describes one archived segment.
type ArchiveResult struct {
	Segment      uint64
	Records      int
	Object       objstore.Version
	Digest       integrity.Hash
	DestroyAfter time.Time
}

func (a Archiver) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a Archiver) retention() (time.Duration, time.Duration) {
	online, total := 365*24*time.Hour, 2557*24*time.Hour // the built-in profiles' defaults
	if a.Retention != nil {
		online, total = a.Retention()
	}
	return online, max(total, online)
}

// Step archives every segment that is due, oldest first, and returns what
// it archived. It stops at the first failure.
func (a Archiver) Step(ctx context.Context) ([]ArchiveResult, error) {
	if a.Store == nil || a.Audit == nil {
		return nil, errors.New("audit archive: no store or audit emitter")
	}
	online, _ := a.retention()
	var out []ArchiveResult
	for {
		rows, err := a.DB.Query(ctx, "SELECT segment, seq_from, seq_to FROM audit.archive_candidates($1, 10)", a.now().Add(-online))
		if err != nil {
			return out, fmt.Errorf("audit archive: candidates: %w", err)
		}
		type cand struct{ Segment, From, To int64 }
		cs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[cand])
		if err != nil {
			return out, fmt.Errorf("audit archive: candidates: %w", err)
		}
		if len(cs) == 0 {
			return out, nil
		}
		for _, c := range cs {
			r, err := a.archive(ctx, c.Segment, c.From, c.To)
			if err != nil {
				return out, err
			}
			out = append(out, r)
		}
	}
}

// archive moves one segment.
func (a Archiver) archive(ctx context.Context, segment, from, to int64) (ArchiveResult, error) {
	res := ArchiveResult{Segment: uint64(segment)} // #nosec G115 -- positions
	fail := func(err error) (ArchiveResult, error) {
		return res, fmt.Errorf("audit archive: segment %d: %w", segment, err)
	}
	// The segment and what proves it.
	cp, st, err := a.checkpoint(ctx, segment)
	if err != nil {
		return fail(err)
	}
	prev := integrity.Genesis(st.Instance)
	if segment > 1 {
		_, ps, err := a.checkpoint(ctx, segment-1)
		if err != nil {
			return fail(err)
		}
		prev = ps.ChainHash
	}
	var recs []integrity.Record
	for next := from; next <= to; {
		rows, err := a.DB.Query(ctx, "SELECT seq, segment, body, leaf_hash, chain_hash FROM audit.verify_records($1, $2, 50000)", next, to)
		if err != nil {
			return fail(err)
		}
		batch, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ForwardRecord])
		if err != nil {
			return fail(err)
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			rec := integrity.Record{Seq: uint64(r.Seq), Body: r.Body} // #nosec G115
			copy(rec.Leaf[:], r.Leaf)
			copy(rec.Chain[:], r.Chain)
			recs = append(recs, rec)
		}
		next = batch[len(batch)-1].Seq + 1
	}
	// Never archive (and so delete) a segment that does not verify: the
	// verifier reports it, and it stays where it is.
	if err := integrity.VerifySegment(st, prev, recs); err != nil {
		return fail(err)
	}
	var buf bytes.Buffer
	if err := evidence.WriteSegment(&buf, evidence.Segment{Checkpoint: cp, Records: recs}); err != nil {
		return fail(err)
	}
	digest := sha256.Sum256(buf.Bytes())
	online, total := a.retention()
	now := a.now()
	until := now.Add(max(total-online, MinArchiveLock)).UTC().Truncate(time.Second)
	key := evidence.SegmentKey(st.Instance, uint64(segment)) // #nosec G115
	ver, err := a.Store.PutStream(ctx, key, bytes.NewReader(buf.Bytes()), int64(buf.Len()), until)
	if err != nil {
		return fail(fmt.Errorf("store: %w", err))
	}
	// Read back and check before anything is removed.
	got, err := a.Store.Digest(ctx, ver)
	if err != nil {
		return fail(fmt.Errorf("read back: %w", err))
	}
	// The same digest is the same bytes: what was checked against the
	// checkpoint above.
	if got != digest {
		return fail(errors.New("the stored object does not match what was written"))
	}
	// Record the archive and remove the rows, with the event.
	err = pgx.BeginFunc(ctx, a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT audit.archive_segment($1, $2, $3, $4, $5, $6)",
			segment, ver.Key, ver.VersionID, digest[:], int64(len(recs)), until); err != nil {
			return err
		}
		return a.Audit.Emit(events.WithTx(ctx, tx), events.Event{Type: "audit.records_archived", Severity: events.SeverityInfo, Actor: "system:audit",
			Target: "segment:" + strconv.FormatInt(segment, 10), Attributes: map[string]string{
				"segment": strconv.FormatInt(segment, 10), "seq_from": strconv.FormatInt(from, 10), "seq_to": strconv.FormatInt(to, 10),
				"record_count": strconv.Itoa(len(recs)), "object_key": ver.Key, "version_id": ver.VersionID,
				"digest": integrity.Hash(digest).String(), "destroy_after": until.Format(time.RFC3339)}})
	})
	if err != nil {
		return fail(err)
	}
	res.Records, res.Object, res.Digest, res.DestroyAfter = len(recs), ver, digest, until
	return res, nil
}

func (a Archiver) checkpoint(ctx context.Context, segment int64) (integrity.Checkpoint, integrity.Statement, error) {
	var cp integrity.Checkpoint
	var seg int64
	if err := a.DB.QueryRow(ctx, "SELECT segment, statement, signature FROM audit.verify_checkpoints($1, 1)", segment).
		Scan(&seg, &cp.Statement, &cp.Signature); err != nil {
		return cp, integrity.Statement{}, fmt.Errorf("checkpoint %d: %w", segment, err)
	}
	if seg != segment {
		return cp, integrity.Statement{}, fmt.Errorf("checkpoint %d is missing", segment)
	}
	st, err := integrity.ParseStatement(cp.Statement)
	return cp, st, err
}

// Run archives at start and then every interval (ArchiveEvery when zero),
// until ctx ends. Errors go to onErr.
func (a Archiver) Run(ctx context.Context, every time.Duration, onErr func(error)) error {
	if every <= 0 {
		every = ArchiveEvery
	}
	for {
		if _, err := a.Step(ctx); err != nil && onErr != nil && ctx.Err() == nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
