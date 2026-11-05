package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/internal/objstore"
	events "github.com/rformer/fair-app/pkg/audit"
)

// The verification cadence (design §6.5; constants, AC-12: neither may be
// lengthened).
const (
	IncrementalEvery = 15 * time.Minute
	FullEvery        = 24 * time.Hour
)

// Verifier checks the trail continuously (F-002 T-11, AC-12 to AC-14;
// design §6.5) with the primitives fair-audit-verify uses. Run it on the
// leader.
type Verifier struct {
	DB    *pgxpool.Pool // app_audit
	Audit events.Emitter
	// WORM, when set (SaaS), holds the write-once checkpoint copies that
	// full runs compare with the platform's checkpoints.
	WORM *objstore.Store
	// Archive holds archived segments (T-18). A full run needs it once
	// segments have been archived.
	Archive ArchiveSource
	Batch   int // records per read; default 5000
}

// Run kinds.
const (
	KindIncremental = "incremental"
	KindFull        = "full"
)

// VerifyResult is a run's outcome.
type VerifyResult struct {
	ID        int64
	Kind      string
	OK        bool
	FromSeq   uint64
	ToSeq     uint64
	ToSegment uint64
	// The first failure, when !OK: a record (Seq) or a segment (Segment),
	// or neither when the trail as a whole is wrong (Reason says how).
	FailedSeq, FailedSegment uint64
	Reason                   string
	// Finding is what happened to the audit_integrity finding: opened,
	// refreshed, resolved or unchanged.
	Finding string
}

// errIncomplete marks a run that could not finish for an operational
// reason (the database or a store unreachable): it is not a verdict on the
// trail, and it is not recorded as one.
var errIncomplete = errors.New("audit verification incomplete")

// Incremental verifies what was added since the last passed run.
func (v Verifier) Incremental(ctx context.Context) (VerifyResult, error) {
	return v.run(ctx, KindIncremental)
}

// Full verifies the whole retained trail.
func (v Verifier) Full(ctx context.Context) (VerifyResult, error) { return v.run(ctx, KindFull) }

func (v Verifier) batch() int {
	if v.Batch <= 0 {
		return 5000
	}
	return v.Batch
}

func (v Verifier) run(ctx context.Context, kind string) (VerifyResult, error) {
	res := VerifyResult{Kind: kind}
	var verified int64
	if err := v.DB.QueryRow(ctx, "SELECT verified_segment FROM audit.verification_resume()").Scan(&verified); err != nil {
		return res, fmt.Errorf("%w: %w", errIncomplete, err)
	}
	from := uint64(0)
	if kind == KindIncremental {
		from = uint64(verified) // #nosec G115 -- a segment number
	}
	if err := v.DB.QueryRow(ctx, "SELECT audit.verification_begin($1, 0)", kind).Scan(&res.ID); err != nil {
		return res, fmt.Errorf("%w: %w", errIncomplete, err)
	}
	// One snapshot: the head, the checkpoints and the records agree.
	var checkErr error
	err := pgx.BeginTxFunc(ctx, v.DB, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		checkErr = v.check(ctx, tx, from, kind == KindFull, &res)
		if errors.Is(checkErr, errIncomplete) {
			return checkErr
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, errIncomplete) {
			err = fmt.Errorf("%w: %w", errIncomplete, err)
		}
		return res, err // the run stays unfinished; the tile shows it overdue if this persists
	}
	res.OK = checkErr == nil
	if !res.OK {
		var f *integrity.Failure
		var d *evidence.Difference
		switch {
		case errors.As(checkErr, &f):
			res.FailedSeq, res.FailedSegment, res.Reason = f.Seq, f.Segment, f.Reason
		case errors.As(checkErr, &d):
			res.FailedSegment, res.Reason = d.Segment, d.Reason
		default:
			res.Reason = checkErr.Error()
		}
	}
	return res, v.record(ctx, &res)
}

// record ends the run and acts on its outcome in one transaction: a failure
// opens or refreshes the finding and is reported; a passed full run
// resolves the finding.
func (v Verifier) record(ctx context.Context, res *VerifyResult) error {
	if v.Audit == nil {
		return errors.New("audit verification: no audit emitter")
	}
	nullable := func(n uint64) any {
		if n == 0 {
			return nil
		}
		return int64(n) // #nosec G115 -- positions
	}
	return pgx.BeginFunc(ctx, v.DB, func(tx pgx.Tx) error {
		var toSeq, toSegment any // a failed run verified no range
		if res.OK {
			toSeq, toSegment = int64(res.ToSeq), int64(res.ToSegment) // #nosec G115 -- positions
		}
		if _, err := tx.Exec(ctx, "SELECT audit.verification_end($1, $2, $3, $4, $5, $6, $7, $8)", res.ID, res.OK, int64(res.FromSeq), // #nosec G115
			toSeq, toSegment, nullable(res.FailedSeq), nullable(res.FailedSegment), res.Reason); err != nil {
			return err
		}
		id := strconv.FormatInt(res.ID, 10)
		ectx := events.WithTx(ctx, tx)
		if !res.OK {
			detail, _ := json.Marshal(map[string]any{"verification_id": res.ID, "kind": res.Kind, "failed_at_seq": nullable(res.FailedSeq),
				"failed_at_segment": nullable(res.FailedSegment), "reason": res.Reason})
			if err := tx.QueryRow(ctx, "SELECT posture.audit_finding(true, $1)", detail).Scan(&res.Finding); err != nil {
				return err
			}
			return v.Audit.Emit(ectx, events.Event{Type: "audit.verification_failed", Severity: events.SeverityCritical, Actor: "system:audit",
				Target: "audit-trail", Attributes: map[string]string{"verification_id": id, "kind": res.Kind, "reason": res.Reason,
					"failed_at_seq": position(res.FailedSeq), "failed_at_segment": position(res.FailedSegment)}})
		}
		if res.Kind != KindFull {
			res.Finding = "unchanged"
			return nil
		}
		if err := tx.QueryRow(ctx, "SELECT posture.audit_finding(false, NULL)").Scan(&res.Finding); err != nil {
			return err
		}
		if res.Finding != "resolved" {
			return nil
		}
		return v.Audit.Emit(ectx, events.Event{Type: "audit.verification_recovered", Severity: events.SeverityHigh, Actor: "system:audit",
			Target: "audit-trail", Attributes: map[string]string{"verification_id": id, "kind": res.Kind,
				"to_seq": strconv.FormatUint(res.ToSeq, 10), "to_segment": strconv.FormatUint(res.ToSegment, 10)}})
	})
}

func position(n uint64) string {
	if n == 0 {
		return ""
	}
	return strconv.FormatUint(n, 10)
}

// trail is what one run reads.
type trail struct {
	instance  string
	headSeq   uint64
	headChain integrity.Hash
	open      uint64 // the open segment
	cps       []integrity.Checkpoint
	wormKeys  map[uint64]string
	archived  map[uint64]archived
}

type archived struct {
	version   objstore.Version
	digest    integrity.Hash
	count     uint64
	destroyed bool
}

// check verifies the trail in tx from checkpoint from (0: from the start).
// Integrity failures are *integrity.Failure, *evidence.Difference or
// evidence.ErrInvalid; anything else is errIncomplete.
func (v Verifier) check(ctx context.Context, tx pgx.Tx, from uint64, full bool, res *VerifyResult) error {
	t, keys, err := v.read(ctx, tx, from)
	if err != nil {
		return err
	}
	if t.instance == "" { // nothing recorded yet
		return nil
	}
	// The checkpoints: signed, linked, contiguous; the last one is the
	// segment before the open one.
	var chain evidence.Chain
	if len(t.cps) > 0 {
		if from > 0 {
			if s, err := integrity.ParseStatement(t.cps[0].Statement); err != nil || s.Segment != from {
				return &integrity.Failure{Segment: from, Reason: "the last verified checkpoint is missing or changed"}
			}
		}
		if chain, err = evidence.VerifyChain(t.cps, keys); err != nil {
			return err
		}
		if first := chain.Statements[0]; from == 0 && first.Segment != 1 {
			return &integrity.Failure{Segment: 1, Reason: "missing"}
		}
	} else if from > 0 {
		return &integrity.Failure{Segment: from, Reason: "the last verified checkpoint is missing"}
	}
	var last integrity.Statement
	if n := len(chain.Statements); n > 0 {
		last = chain.Statements[n-1]
		if chain.Instance() != t.instance {
			return fmt.Errorf("%w: the checkpoints belong to instance %q, the head to %q", evidence.ErrInvalid, chain.Instance(), t.instance)
		}
	}
	if last.Segment+1 != t.open {
		return &integrity.Failure{Segment: last.Segment + 1, Reason: fmt.Sprintf("missing (the open segment is %d)", t.open)}
	}
	res.ToSegment = last.Segment

	// Each newly verified segment's records, or its archive.
	for _, s := range chain.Statements {
		if s.Segment <= from {
			continue
		}
		prev, ok := chain.PrevChain(s.Segment)
		if !ok {
			return &integrity.Failure{Segment: s.Segment - 1, Reason: "missing"}
		}
		if res.FromSeq == 0 {
			res.FromSeq = s.SeqFrom
		}
		if a, ok := t.archived[s.Segment]; ok {
			if full {
				if err := v.checkArchive(ctx, s, prev, a, t.cps, chain); err != nil {
					return err
				}
			}
			continue
		}
		if err := v.checkSegment(ctx, tx, s, prev); err != nil {
			return err
		}
	}

	// The open segment, up to the head.
	prev, firstSeq := integrity.Genesis(t.instance), uint64(1)
	if last.Segment > 0 {
		prev, firstSeq = last.ChainHash, last.SeqTo+1
	}
	if res.FromSeq == 0 {
		res.FromSeq = firstSeq
	}
	if t.headSeq+1 < firstSeq {
		return &integrity.Failure{Segment: last.Segment, Reason: fmt.Sprintf("the head (record %d) is behind the checkpoint", t.headSeq)}
	}
	end, _, err := v.replay(ctx, tx, firstSeq, t.headSeq, t.open, prev, false)
	if err != nil {
		return err
	}
	if end != t.headChain {
		return &integrity.Failure{Seq: t.headSeq, Reason: "the head's chain hash does not match the records"}
	}
	// Nothing past the head.
	var beyond int64
	switch err := tx.QueryRow(ctx, "SELECT seq FROM audit.verify_records($1, 9223372036854775807, 1)", int64(t.headSeq)+1).Scan(&beyond); // #nosec G115
	{
	case err == nil:
		return &integrity.Failure{Seq: uint64(beyond), Reason: fmt.Sprintf("recorded beyond the head (record %d)", t.headSeq)} // #nosec G115
	case !errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("%w: %w", errIncomplete, err)
	}
	res.ToSeq = t.headSeq
	if full && v.WORM != nil {
		return v.compareCopies(ctx, t)
	}
	return nil
}

func (v Verifier) read(ctx context.Context, tx pgx.Tx, from uint64) (trail, evidence.Keys, error) {
	var t trail
	incomplete := func(err error) (trail, evidence.Keys, error) { return t, nil, fmt.Errorf("%w: %w", errIncomplete, err) }
	var seq, open int64
	var chain []byte
	err := tx.QueryRow(ctx, "SELECT instance, seq, chain_hash, open_segment FROM audit.verify_head()").Scan(&t.instance, &seq, &chain, &open)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, nil, nil
	}
	if err != nil {
		return incomplete(err)
	}
	t.headSeq, t.open = uint64(seq), uint64(open) // #nosec G115 -- positions
	copy(t.headChain[:], chain)

	keys := evidence.Keys{}
	rows, err := tx.Query(ctx, "SELECT key_id, public_pem FROM audit.verify_keys()")
	if err != nil {
		return incomplete(err)
	}
	type keyRow struct{ ID, PEM string }
	krs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[keyRow])
	if err != nil {
		return incomplete(err)
	}
	for _, k := range krs {
		parsed, err := evidence.ParseKeys([]byte(k.PEM))
		if err != nil || parsed[k.ID] == nil {
			return t, nil, fmt.Errorf("%w: signing key %s does not match its id", evidence.ErrInvalid, k.ID)
		}
		keys[k.ID] = parsed[k.ID]
	}

	t.wormKeys = map[uint64]string{}
	next := max(from, 1)
	for {
		rows, err := tx.Query(ctx, "SELECT segment, statement, signature, coalesce(worm_key, '') FROM audit.verify_checkpoints($1, 1000)", int64(next)) // #nosec G115
		if err != nil {
			return incomplete(err)
		}
		n := 0
		for rows.Next() {
			var seg int64
			var cp integrity.Checkpoint
			var wk string
			if err := rows.Scan(&seg, &cp.Statement, &cp.Signature, &wk); err != nil {
				rows.Close()
				return incomplete(err)
			}
			t.cps = append(t.cps, cp)
			if wk != "" {
				t.wormKeys[uint64(seg)] = wk // #nosec G115
			}
			next = uint64(seg) + 1 // #nosec G115
			n++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return incomplete(err)
		}
		if n < 1000 {
			break
		}
	}

	t.archived = map[uint64]archived{}
	rows, err = tx.Query(ctx, "SELECT segment, object_key, version_id, digest, record_count, destroyed FROM audit.verify_archives()")
	if err != nil {
		return incomplete(err)
	}
	for rows.Next() {
		var seg, count int64
		var a archived
		var digest []byte
		if err := rows.Scan(&seg, &a.version.Key, &a.version.VersionID, &digest, &count, &a.destroyed); err != nil {
			rows.Close()
			return incomplete(err)
		}
		copy(a.digest[:], digest)
		a.count = uint64(count)     // #nosec G115
		t.archived[uint64(seg)] = a // #nosec G115
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return incomplete(err)
	}
	return t, keys, nil
}

// replay checks records first..last (all in segment seg) from the chain
// hash prev: present, in order, in their segment, each body matching its
// leaf and each chain hash following. It returns the chain hash after the
// last record and, when leaves is true, the leaf hashes.
func (v Verifier) replay(ctx context.Context, tx pgx.Tx, first, last, seg uint64, prev integrity.Hash, leaves bool) (integrity.Hash, []integrity.Hash, error) {
	var out []integrity.Hash
	want := first
	for want <= last {
		rows, err := tx.Query(ctx, "SELECT seq, segment, body, leaf_hash, chain_hash FROM audit.verify_records($1, $2, $3)",
			int64(want), int64(last), v.batch()) // #nosec G115 -- positions
		if err != nil {
			return prev, nil, fmt.Errorf("%w: %w", errIncomplete, err)
		}
		n := 0
		for rows.Next() {
			var s, sg int64
			var body, leaf, chain []byte
			if err := rows.Scan(&s, &sg, &body, &leaf, &chain); err != nil {
				rows.Close()
				return prev, nil, fmt.Errorf("%w: %w", errIncomplete, err)
			}
			n++
			var f *integrity.Failure
			l := integrity.Leaf(body)
			switch {
			case uint64(s) != want: // #nosec G115
				f = &integrity.Failure{Seq: want, Reason: fmt.Sprintf("missing (the next record is %d)", s)}
			case uint64(sg) != seg: // #nosec G115
				f = &integrity.Failure{Seq: want, Reason: fmt.Sprintf("recorded in segment %d, which its position says is %d", sg, seg)}
			case !bytes.Equal(l[:], leaf):
				f = &integrity.Failure{Seq: want, Reason: "body does not match its leaf hash"}
			}
			if f == nil {
				c := integrity.Chain(prev, want, l)
				if !bytes.Equal(c[:], chain) {
					f = &integrity.Failure{Seq: want, Reason: "chain hash does not follow the previous record"}
				}
				prev = c
			}
			if f != nil {
				rows.Close()
				return prev, nil, f
			}
			if leaves {
				out = append(out, l)
			}
			want++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return prev, nil, fmt.Errorf("%w: %w", errIncomplete, err)
		}
		if n == 0 {
			return prev, nil, &integrity.Failure{Seq: want, Reason: "missing"}
		}
	}
	return prev, out, nil
}

// checkSegment checks a closed segment's online records against its
// statement.
func (v Verifier) checkSegment(ctx context.Context, tx pgx.Tx, s integrity.Statement, prev integrity.Hash) error {
	end, leaves, err := v.replay(ctx, tx, s.SeqFrom, s.SeqTo, s.Segment, prev, true)
	if err != nil {
		return err
	}
	if end != s.ChainHash {
		return &integrity.Failure{Segment: s.Segment, Reason: "chain does not end at the checkpoint's chain hash"}
	}
	if integrity.Root(leaves) != s.MerkleRoot {
		return &integrity.Failure{Segment: s.Segment, Reason: "Merkle root does not match the checkpoint"}
	}
	return nil
}

// checkArchive checks an archived segment's object: its digest as recorded
// at archive time, its checkpoint the platform's, and its records against
// the statement. A destroyed archive is past retention: only its checkpoint
// remains.
func (v Verifier) checkArchive(ctx context.Context, s integrity.Statement, prev integrity.Hash, a archived, cps []integrity.Checkpoint, chain evidence.Chain) error {
	if a.destroyed {
		return nil
	}
	if v.Archive == nil {
		return fmt.Errorf("%w: segment %d is archived but no archive store is configured", errIncomplete, s.Segment)
	}
	ver := a.version
	digest, err := v.Archive.Digest(ctx, ver)
	if err != nil {
		return fmt.Errorf("%w: archive of segment %d: %w", errIncomplete, s.Segment, err)
	}
	if digest != a.digest {
		return &integrity.Failure{Segment: s.Segment, Reason: "the archived object does not match its recorded digest"}
	}
	rc, err := v.Archive.Open(ctx, ver)
	if err != nil {
		return fmt.Errorf("%w: archive of segment %d: %w", errIncomplete, s.Segment, err)
	}
	defer func() { _ = rc.Close() }()
	seg, err := evidence.ReadSegment(rc)
	if err != nil {
		return &integrity.Failure{Segment: s.Segment, Reason: "the archived object is unreadable: " + err.Error()}
	}
	want := cps[segmentIndex(chain, s.Segment)].Statement
	if !bytes.Equal(seg.Checkpoint.Statement, want) {
		return &integrity.Failure{Segment: s.Segment, Reason: "the archived object holds another checkpoint"}
	}
	if uint64(len(seg.Records)) != a.count {
		return &integrity.Failure{Segment: s.Segment, Reason: "the archived object's record count differs from the archive record"}
	}
	return integrity.VerifySegment(s, prev, seg.Records)
}

func segmentIndex(c evidence.Chain, segment uint64) int {
	for i, s := range c.Statements {
		if s.Segment == segment {
			return i
		}
	}
	return -1
}

// compareCopies compares the platform's checkpoints with every version of
// the write-once copies: each saved copy is there and identical, and every
// copy matches a platform checkpoint (a copy beyond the platform's last
// checkpoint means the platform's trail was cut back).
func (v Verifier) compareCopies(ctx context.Context, t trail) error {
	platform := map[uint64][]integrity.Checkpoint{}
	for _, cp := range t.cps {
		s, err := integrity.ParseStatement(cp.Statement)
		if err != nil {
			return err
		}
		platform[s.Segment] = append(platform[s.Segment], cp)
	}
	prefix := "checkpoints/" + t.instance + "/"
	objs, err := v.WORM.List(ctx, prefix)
	if err != nil {
		return fmt.Errorf("%w: write-once copies: %w", errIncomplete, err)
	}
	seen := map[string]bool{}
	for _, o := range objs {
		data, err := v.WORM.Get(ctx, o.Version)
		if err != nil {
			return fmt.Errorf("%w: write-once copy %s: %w", errIncomplete, o.Key, err)
		}
		var cp integrity.Checkpoint
		if err := json.Unmarshal(data, &cp); err != nil {
			return &evidence.Difference{Reason: fmt.Sprintf("the write-once copy %s is not a checkpoint", o.Key)}
		}
		s, err := integrity.ParseStatement(cp.Statement)
		if err != nil {
			return &evidence.Difference{Reason: fmt.Sprintf("the write-once copy %s: %v", o.Key, err)}
		}
		if o.Key != CopyKey(t.instance, int64(s.Segment)) { // #nosec G115
			return &evidence.Difference{Segment: s.Segment, Reason: fmt.Sprintf("the write-once copy %s holds segment %d", o.Key, s.Segment)}
		}
		p := platform[s.Segment]
		if len(p) == 0 {
			return &evidence.Difference{Segment: s.Segment, Reason: "a write-once copy exists, the platform's checkpoint does not"}
		}
		if !bytes.Equal(p[0].Statement, cp.Statement) || !bytes.Equal(p[0].Signature, cp.Signature) {
			return &evidence.Difference{Segment: s.Segment, Reason: "the write-once copy differs from the platform's checkpoint"}
		}
		seen[o.Key] = true
	}
	for seg, key := range t.wormKeys {
		if !seen[key] {
			return &evidence.Difference{Segment: seg, Reason: "the write-once copy recorded for this checkpoint is missing"}
		}
	}
	return nil
}

// Run verifies until ctx ends: a full run first when the last one is
// missing or older than FullEvery, then an incremental run every
// IncrementalEvery and a full run every FullEvery. Results and errors go
// to the callbacks (either may be nil).
func (v Verifier) Run(ctx context.Context, every, fullEvery time.Duration, onResult func(VerifyResult), onErr func(error)) error {
	if every <= 0 {
		every = IncrementalEvery
	}
	if fullEvery <= 0 {
		fullEvery = FullEvery
	}
	var lastFull time.Time
	var at *time.Time
	if err := v.DB.QueryRow(ctx, "SELECT last_full_at FROM audit.verification_resume()").Scan(&at); err == nil && at != nil {
		lastFull = *at
	}
	once := func() {
		kind := KindIncremental
		if time.Since(lastFull) >= fullEvery {
			kind = KindFull
		}
		res, err := v.run(ctx, kind)
		if err != nil {
			if onErr != nil && ctx.Err() == nil {
				onErr(err)
			}
			return
		}
		if kind == KindFull {
			lastFull = time.Now()
		}
		if onResult != nil {
			onResult(res)
		}
	}
	once()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			once()
		}
	}
}
