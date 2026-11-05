package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-002 T-11 (F-002-AC-12, AC-13, AC-14; design §6.5): continuous
// verification.

// verifyFixture builds a trail of closed segments (a key rotation among
// them) and an open segment with records.
func verifyFixture(t *testing.T) (*env, *pgxpool.Pool, auditsvc.Sequencer, auditsvc.Checkpointer, auditsvc.Verifier) {
	t.Helper()
	e := setup(t)
	ctx := context.Background()
	pool := e.auditPool()
	seq := auditsvc.Sequencer{DB: pool}
	c := checkpointer(t, pool, newCheckpointKey(t))
	for i, n := range []int{4, 0, 5} {
		submitN(t, e, fmt.Sprintf("v%d", i), n)
		drainTrail(t, seq)
		if i == 2 {
			c = checkpointer(t, pool, newCheckpointKey(t))
		}
		if _, err := c.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	submitN(t, e, "open", 3)
	drainTrail(t, seq)
	v := auditsvc.Verifier{DB: pool, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool}), Batch: 4}
	return e, pool, seq, c, v
}

func mustVerify(t *testing.T, v auditsvc.Verifier, kind string) auditsvc.VerifyResult {
	t.Helper()
	run := v.Incremental
	if kind == auditsvc.KindFull {
		run = v.Full
	}
	res, err := run(context.Background())
	if err != nil {
		t.Fatalf("%s run: %v", kind, err)
	}
	return res
}

// tamper changes the trail as a database superuser would: without the
// append-only triggers.
func (e *env) tamper(sql string) {
	e.t.Helper()
	e.admin(e.db, "SET session_replication_role = replica; "+sql)
}

type auditStatus struct {
	State   string `json:"state"`
	LastRun *struct {
		Kind            string `json:"kind"`
		OK              bool   `json:"ok"`
		FailedAtSeq     *int64 `json:"failed_at_seq"`
		FailedAtSegment *int64 `json:"failed_at_segment"`
		Detail          string `json:"detail"`
	} `json:"last_run"`
	LastVerifiedAt     *time.Time `json:"last_verified_at"`
	VerifiedThroughSeq *int64     `json:"verified_through_seq"`
	HeadSeq            int64      `json:"head_seq"`
}

// status reads audit.status() as the posture service does.
func (e *env) auditStatus() auditStatus {
	e.t.Helper()
	out, err := e.as("app_posture", "SELECT audit.status()")
	if err != nil {
		e.t.Fatalf("audit.status as app_posture: %v %s", err, out)
	}
	var s auditStatus
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		e.t.Fatalf("%v: %s", err, out)
	}
	return s
}

func (e *env) integrityFinding() string {
	e.t.Helper()
	return e.adminQuery("SELECT coalesce(string_agg(status || ':' || severity || ':' || array_to_string(controls, '|'), ','), 'none') FROM posture.drift_finding WHERE check_id = 'audit_integrity'")
}

func TestAuditVerification(t *testing.T) {
	e, _, seq, c, v := verifyFixture(t)
	ctx := context.Background()
	if st := e.auditStatus(); st.State != "never" || st.LastRun != nil {
		t.Fatalf("before any run: %+v", st)
	}
	// A full run verifies everything: 3 closed segments and the open one.
	res := mustVerify(t, v, auditsvc.KindFull)
	head := e.adminQuery("SELECT seq FROM audit.head")
	if !res.OK || res.FromSeq != 1 || fmt.Sprint(res.ToSeq) != head || res.ToSegment != 3 || res.Finding != "unchanged" {
		t.Fatalf("full: %+v (head %s)", res, head)
	}
	// Incremental runs start after the last verified checkpoint.
	submitN(t, e, "more", 6)
	drainTrail(t, seq)
	if _, err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	drainTrail(t, seq)
	res = mustVerify(t, v, auditsvc.KindIncremental)
	if from := e.adminQuery("SELECT seq_from FROM audit.checkpoint WHERE segment = 4"); !res.OK || res.ToSegment != 4 || fmt.Sprint(res.FromSeq) != from {
		t.Fatalf("incremental: %+v", res)
	}
	// Nothing new: an empty incremental run passes.
	res = mustVerify(t, v, auditsvc.KindIncremental)
	if !res.OK || res.ToSegment != 4 {
		t.Fatalf("empty incremental: %+v", res)
	}
	st := e.auditStatus()
	if st.State != "ok" || st.LastRun == nil || !st.LastRun.OK || st.LastVerifiedAt == nil || st.VerifiedThroughSeq == nil || fmt.Sprint(*st.VerifiedThroughSeq) != fmt.Sprint(res.ToSeq) {
		t.Fatalf("status: %+v", st)
	}
	if e.integrityFinding() != "none" {
		t.Fatal("a finding without a failure")
	}
	// Overdue: no passed run for over 30 minutes.
	e.tamper("UPDATE audit.verification SET started_at = started_at - interval '1 hour', finished_at = finished_at - interval '1 hour'")
	if st := e.auditStatus(); st.State != "overdue" {
		t.Fatalf("overdue: %s", st.State)
	}
	// Other application roles cannot read the trail through these functions.
	for _, role := range []string{"app_rw", "app_gateway", "app_posture"} {
		e.mustFail(role, "SELECT * FROM audit.verify_records(1, 10, 10)", "permission denied")
		e.mustFail(role, "SELECT audit.verification_begin('full', 0)", "permission denied")
		e.mustFail(role, "SELECT posture.audit_finding(false, NULL)", "permission denied")
	}
	e.mustFail("app_rw", "SELECT audit.status()", "permission denied")
}

// Tampering as a superuser is found by the next run (AC-13), named at its
// first position, and opens the critical audit_integrity finding; only a
// passed full run resolves it.
func TestAuditVerificationFindsTampering(t *testing.T) {
	cases := []struct {
		name     string
		tamper   string
		kind     string // the first run that must find it
		seq, seg string // expected failure position ("" = not given)
	}{
		{"altered body in a closed segment", "UPDATE audit.record SET body = convert_to(replace(convert_from(body, 'UTF8'), '\"actor\":\"x\"', '\"actor\":\"y\"'), 'UTF8') WHERE seq = 2",
			auditsvc.KindFull, "2", ""},
		{"altered body in the open segment", "UPDATE audit.record SET body = convert_to(replace(convert_from(body, 'UTF8'), '\"actor\":\"x\"', '\"actor\":\"y\"'), 'UTF8') WHERE seq = (SELECT max(seq) - 1 FROM audit.record)",
			auditsvc.KindIncremental, "head-1", ""},
		{"removed record", "DELETE FROM audit.record WHERE seq = (SELECT max(seq) - 1 FROM audit.record)", auditsvc.KindIncremental, "head-1", ""},
		{"truncated tail", "DELETE FROM audit.record WHERE seq = (SELECT max(seq) FROM audit.record)", auditsvc.KindIncremental, "head", ""},
		{"head moved back", "UPDATE audit.head SET seq = seq - 1", auditsvc.KindIncremental, "head-1", ""},
		// The body changed and its leaf hash recomputed: the chain no longer follows.
		{"altered body with its leaf rehashed", "UPDATE audit.record SET body = convert_to(replace(convert_from(body, 'UTF8'), '\"actor\":\"x\"', '\"actor\":\"w\"'), 'UTF8'), " +
			"leaf_hash = sha256('\\x00'::bytea || convert_to(replace(convert_from(body, 'UTF8'), '\"actor\":\"x\"', '\"actor\":\"w\"'), 'UTF8')) WHERE seq = 3",
			auditsvc.KindFull, "3", ""},
		{"newest checkpoint removed", "DELETE FROM audit.checkpoint WHERE segment = 3", auditsvc.KindIncremental, "", "3"},
		{"checkpoint statement changed", "UPDATE audit.checkpoint SET statement = convert_to(replace(convert_from(statement, 'UTF8'), '\"v\":1', '\"v\":1 '), 'UTF8') WHERE segment = 2",
			auditsvc.KindFull, "", "2"},
		{"record moved to another segment", "UPDATE audit.record SET segment = 9 WHERE seq = 5", auditsvc.KindFull, "5", ""},
		{"signing key swapped", "UPDATE audit.signing_key SET public_pem = (SELECT public_pem FROM audit.signing_key ORDER BY active_from DESC LIMIT 1) WHERE retired_at IS NOT NULL",
			auditsvc.KindFull, "", ""},
		// A key no checkpoint uses, filed under an id that is not its own.
		{"signing key under another id", "INSERT INTO audit.signing_key (key_id, public_pem, active_from, retired_at) " +
			"SELECT repeat('ab', 32), public_pem, now() - interval '1 day', now() FROM audit.signing_key LIMIT 1", auditsvc.KindFull, "", ""},
		// The stored leaf hash alone changed (the body and chain still agree).
		{"stored leaf hash altered", "UPDATE audit.record SET leaf_hash = sha256('x'::bytea) WHERE seq = 3", auditsvc.KindFull, "3", ""},
		// A record added past the head, which still matches its records.
		{"record beyond the head", "WITH r AS (SELECT * FROM audit.record WHERE seq = (SELECT max(seq) FROM audit.record)) " +
			"INSERT INTO audit.record SELECT (jsonb_populate_record(NULL::audit.record, to_jsonb(r) || jsonb_build_object('seq', r.seq + 1, 'event_id', r.event_id || '-x'))).* FROM r",
			auditsvc.KindIncremental, "head+1", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, _, _, _, v := verifyFixture(t)
			if res := mustVerify(t, v, auditsvc.KindFull); !res.OK {
				t.Fatalf("before tampering: %+v", res)
			}
			head := e.adminQuery("SELECT seq FROM audit.head")
			saved := e.adminQuery("SELECT count(*) FROM audit.record")
			e.tamper(c.tamper)
			if c.name == "altered body in a closed segment" {
				// An incremental run does not reach back into verified
				// segments; the daily full run does.
				if inc := mustVerify(t, v, auditsvc.KindIncremental); !inc.OK {
					t.Fatalf("incremental reached a verified segment: %+v", inc)
				}
			}
			res := mustVerify(t, v, c.kind)
			if res.OK {
				t.Fatalf("not found (%s run; %s records before)", c.kind, saved)
			}
			want := func(w string) string {
				switch w {
				case "head":
					return head
				case "head-1":
					return e.adminQuery("SELECT " + head + " - 1")
				case "head+1":
					return e.adminQuery("SELECT " + head + " + 1")
				}
				return w
			}
			if c.seq != "" && fmt.Sprint(res.FailedSeq) != want(c.seq) {
				t.Errorf("failed at record %d, want %s (%s)", res.FailedSeq, want(c.seq), res.Reason)
			}
			if c.seg != "" && fmt.Sprint(res.FailedSegment) != c.seg {
				t.Errorf("failed at segment %d, want %s (%s)", res.FailedSegment, c.seg, res.Reason)
			}
			if res.Finding != "opened" || e.integrityFinding() != "open:critical:AU-9|AU-6" {
				t.Fatalf("finding %s: %s", res.Finding, e.integrityFinding())
			}
			// The failure is in the trail, with its position.
			ev := e.adminQuery("SELECT body::text FROM audit.intake WHERE body->>'type' = 'audit.verification_failed'")
			if !strings.Contains(ev, `"severity": "critical"`) || !strings.Contains(ev, res.Reason) {
				t.Fatalf("event: %s", ev)
			}
			if st := e.auditStatus(); st.State != "failed" || st.LastRun == nil || st.LastRun.OK {
				t.Fatalf("status: %+v", st)
			}
			// Self-hosted: no SecOps alert.
			if n := e.adminQuery("SELECT count(*) FROM posture.secops_outbox WHERE event->>'type' = 'audit.verification_failed'"); n != "0" {
				t.Fatalf("%s SecOps alerts in self-hosted", n)
			}
		})
	}
}

func TestAuditVerificationRecovery(t *testing.T) {
	e, _, seq, _, v := verifyFixture(t)
	original := e.adminQuery("SELECT encode(body, 'hex') FROM audit.record WHERE seq = 2")
	e.mustOwner("SELECT posture.set_deployment_mode('saas')")
	e.tamper("UPDATE audit.record SET body = convert_to(replace(convert_from(body, 'UTF8'), '\"actor\":\"x\"', '\"actor\":\"z\"'), 'UTF8') WHERE seq = 2")
	res := mustVerify(t, v, auditsvc.KindFull)
	if res.OK || res.Finding != "opened" {
		t.Fatalf("%+v", res)
	}
	// SaaS: one SecOps alert, when the finding opens; a repeat failure
	// refreshes the finding without another alert.
	if res := mustVerify(t, v, auditsvc.KindFull); res.OK || res.Finding != "refreshed" {
		t.Fatalf("repeat: %+v", res)
	}
	if n := e.adminQuery("SELECT count(*) FROM posture.secops_outbox WHERE event->>'type' = 'audit.verification_failed'"); n != "1" {
		t.Fatalf("%s SecOps alerts", n)
	}
	if n := e.adminQuery("SELECT count(*) FROM audit.intake WHERE body->>'type' = 'audit.verification_failed'"); n != "2" {
		t.Fatalf("%s failure events, one per failed run", n)
	}
	// The record restored: an incremental pass does not resolve the
	// finding; a full one does.
	e.tamper("UPDATE audit.record SET body = decode('" + original + "', 'hex') WHERE seq = 2")
	drainTrail(t, seq)
	if res := mustVerify(t, v, auditsvc.KindIncremental); !res.OK || res.Finding != "unchanged" || !strings.HasPrefix(e.integrityFinding(), "open:") {
		t.Fatalf("incremental: %+v %s", res, e.integrityFinding())
	}
	if st := e.auditStatus(); st.State != "failed" {
		t.Fatalf("status before the full run: %s", st.State)
	}
	res = mustVerify(t, v, auditsvc.KindFull)
	if !res.OK || res.Finding != "resolved" || !strings.HasPrefix(e.integrityFinding(), "resolved:") {
		t.Fatalf("full: %+v %s", res, e.integrityFinding())
	}
	if ev := e.adminQuery("SELECT body->>'severity' FROM audit.intake WHERE body->>'type' = 'audit.verification_recovered'"); ev != "high" {
		t.Fatalf("recovered event: %q", ev)
	}
	if st := e.auditStatus(); st.State != "ok" {
		t.Fatalf("status after recovery: %s", st.State)
	}
	// The drift engine never resolves it: it is not one of its checks.
	if out := e.adminQuery("SELECT count(*) FROM posture.drift_finding WHERE check_id = 'audit_integrity' AND status <> 'resolved'"); out != "0" {
		t.Fatal(out)
	}
}

// The verifier's own records of runs are append-only in effect: a run is
// ended once, and its outcome must be consistent.
func TestAuditVerificationBookkeeping(t *testing.T) {
	e := setup(t)
	pool := e.auditPool()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx, "SELECT audit.verification_begin('full', 0)").Scan(&id); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string]string{
		"passed with a failure":  fmt.Sprintf("%d, true, 1, 5, 1, 3, NULL, NULL", id),
		"passed without a range": fmt.Sprintf("%d, true, 1, NULL, NULL, NULL, NULL, NULL", id),
		"failed with a range":    fmt.Sprintf("%d, false, 1, 5, 1, 3, NULL, 'x'", id),
		"no result":              fmt.Sprintf("%d, NULL, 1, 5, 1, NULL, NULL, NULL", id),
		"a range that runs back": fmt.Sprintf("%d, true, 5, 2, 1, NULL, NULL, NULL", id),
	} {
		if _, err := pool.Exec(ctx, "SELECT audit.verification_end("+args+")"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := pool.Exec(ctx, "SELECT audit.verification_end($1, true, 1, 5, 1, NULL, NULL, NULL)", id); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "SELECT audit.verification_end($1, false, 1, NULL, NULL, 3, NULL, 'later')", id); err == nil || !strings.Contains(err.Error(), "PF003") {
		t.Fatalf("ended twice: %v", err)
	}
	for _, kind := range []string{"partial", ""} {
		if _, err := pool.Exec(ctx, "SELECT audit.verification_begin($1, 0)", kind); err == nil {
			t.Errorf("kind %q accepted", kind)
		}
	}
}

// The loop: a full run first (none yet), then incremental runs, and a full
// run again once the full interval has passed.
func TestAuditVerificationRun(t *testing.T) {
	e, _, _, _, v := verifyFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	var kinds []string
	var errs []error
	_ = v.Run(ctx, 250*time.Millisecond, 700*time.Millisecond, func(r auditsvc.VerifyResult) {
		if !r.OK {
			errs = append(errs, fmt.Errorf("%+v", r))
		}
		kinds = append(kinds, r.Kind)
	}, func(err error) { errs = append(errs, err) })
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	got := strings.Join(kinds, ",")
	if !strings.HasPrefix(got, "full,incremental,incremental") || !strings.Contains(got[5:], "full") {
		t.Fatalf("runs %s", got)
	}
	if n := e.adminQuery("SELECT count(*) FROM audit.verification WHERE finished_at IS NULL"); n != "0" {
		t.Fatalf("%s unfinished runs", n)
	}
	if auditsvc.IncrementalEvery != 15*time.Minute || auditsvc.FullEvery != 24*time.Hour {
		t.Fatal("cadence differs from design §6.5")
	}
}

// Full runs compare the write-once copies (SaaS) and check archived
// segments (FAIR_TEST_S3=1).
func TestAuditVerificationCopiesAndArchives(t *testing.T) {
	e, pool, _, c, v := verifyFixture(t)
	ctx := context.Background()
	worm, _, _ := testWORM(t)
	c.WORM = worm
	if n, err := c.SaveCopies(ctx); err != nil || n != 3 {
		t.Fatalf("copies: %d %v", n, err)
	}
	v.WORM = worm
	if res := mustVerify(t, v, auditsvc.KindFull); !res.OK {
		t.Fatalf("with copies: %+v", res)
	}
	instance := e.adminQuery("SELECT instance FROM audit.head")

	// An archived segment: verified from its object version, not online.
	archive, _, _ := testWORM(t)
	stored := e.checkpoints()
	var recs []integrity.Record
	for _, r := range e.trailRecords() {
		if s, _ := integrity.ParseStatement(stored[0].statement); r.seq >= s.SeqFrom && r.seq <= s.SeqTo {
			var l, ch integrity.Hash
			copy(l[:], r.leaf)
			copy(ch[:], r.chain)
			recs = append(recs, integrity.Record{Seq: r.seq, Body: r.body, Leaf: l, Chain: ch})
		}
	}
	var buf bytes.Buffer
	if err := evidence.WriteSegment(&buf, evidence.Segment{Checkpoint: integrity.Checkpoint{Statement: stored[0].statement, Signature: stored[0].signature}, Records: recs}); err != nil {
		t.Fatal(err)
	}
	key := evidence.SegmentKey(instance, 1)
	ver, err := archive.Put(ctx, key, buf.Bytes(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(buf.Bytes())
	e.adminQuery(fmt.Sprintf("INSERT INTO audit.archive (segment, object_key, version_id, digest, record_count, destroy_after) VALUES (1, '%s', '%s', decode('%x', 'hex'), %d, now() + interval '1 day')",
		key, ver.VersionID, digest, len(recs)))
	// Without the archive store a full run cannot finish: no verdict.
	if _, err := v.Full(ctx); err == nil || !strings.Contains(err.Error(), "no archive store") {
		t.Fatalf("no store: %v", err)
	}
	v.Archive = archive
	if res := mustVerify(t, v, auditsvc.KindFull); !res.OK {
		t.Fatalf("archive: %+v", res)
	}
	// The archived records are checked from the object: altering them
	// online changes nothing; a newer version written over the key is
	// ignored (the archive is the recorded version).
	e.tamper("UPDATE audit.record SET body = convert_to('{}', 'UTF8') WHERE seq = 1")
	if _, err := archive.Put(ctx, key, []byte("forged"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if res := mustVerify(t, v, auditsvc.KindFull); !res.OK {
		t.Fatalf("archived segment read online or from the newer version: %+v", res)
	}
	// A wrong recorded digest is found.
	e.tamper("UPDATE audit.archive SET digest = sha256('x') WHERE segment = 1")
	if res := mustVerify(t, v, auditsvc.KindFull); res.OK || res.FailedSegment != 1 || !strings.Contains(res.Reason, "digest") {
		t.Fatalf("digest: %+v", res)
	}
	e.tamper(fmt.Sprintf("UPDATE audit.archive SET digest = decode('%x', 'hex') WHERE segment = 1", digest))
	if res := mustVerify(t, v, auditsvc.KindFull); !res.OK || res.Finding != "resolved" {
		t.Fatalf("restored: %+v", res)
	}

	// The write-once copies: a copy recorded but missing, another version
	// over a copy, and a copy beyond the platform's checkpoints.
	e.tamper("UPDATE audit.checkpoint SET worm_key = 'checkpoints/elsewhere/2.json' WHERE segment = 2")
	if res := mustVerify(t, v, auditsvc.KindFull); res.OK || res.FailedSegment != 2 || !strings.Contains(res.Reason, "missing") {
		t.Fatalf("missing copy: %+v", res)
	}
	e.tamper(fmt.Sprintf("UPDATE audit.checkpoint SET worm_key = '%s' WHERE segment = 2", auditsvc.CopyKey(instance, 2)))
	if res := mustVerify(t, v, auditsvc.KindFull); !res.OK {
		t.Fatalf("restored copy key: %+v", res)
	}
	st, _ := integrity.ParseStatement(stored[1].statement)
	other := newCheckpointKey(t)
	resigned, _ := integrity.Sign(other, stored[1].statement)
	forged, _ := json.Marshal(integrity.Checkpoint{Statement: stored[1].statement, Signature: resigned})
	worm2, _, _ := testWORM(t)
	c.WORM, v.WORM = worm2, worm2
	e.tamper("UPDATE audit.checkpoint SET worm_key = NULL")
	if n, err := c.SaveCopies(ctx); err != nil || n != 3 {
		t.Fatalf("copies: %d %v", n, err)
	}
	if _, err := worm2.Put(ctx, auditsvc.CopyKey(instance, int64(st.Segment)), forged, time.Now().Add(time.Hour)); err != nil { // #nosec G115
		t.Fatal(err)
	}
	if res := mustVerify(t, v, auditsvc.KindFull); res.OK || res.FailedSegment != 2 || !strings.Contains(res.Reason, "differs") {
		t.Fatalf("another version: %+v", res)
	}
	// A copy filed under another segment's key (a new version of 3.json
	// holding segment 2).
	worm4, _, _ := testWORM(t)
	c.WORM, v.WORM = worm4, worm4
	e.tamper("UPDATE audit.checkpoint SET worm_key = NULL")
	if _, err := c.SaveCopies(ctx); err != nil {
		t.Fatal(err)
	}
	misfiled, _ := json.Marshal(integrity.Checkpoint{Statement: stored[1].statement, Signature: stored[1].signature})
	if _, err := worm4.Put(ctx, auditsvc.CopyKey(instance, 3), misfiled, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if res := mustVerify(t, v, auditsvc.KindFull); res.OK || res.FailedSegment != 2 || !strings.Contains(res.Reason, "holds segment 2") {
		t.Fatalf("misfiled copy: %+v", res)
	}
	worm3, _, _ := testWORM(t)
	c.WORM, v.WORM = worm3, worm3
	e.tamper("UPDATE audit.checkpoint SET worm_key = NULL")
	if _, err := c.SaveCopies(ctx); err != nil {
		t.Fatal(err)
	}
	beyond := st
	beyond.Segment, beyond.SeqFrom, beyond.SeqTo = 99, 1000, 999
	bb, _ := beyond.Marshal()
	cut, _ := json.Marshal(integrity.Checkpoint{Statement: bb, Signature: resigned})
	if _, err := worm3.Put(ctx, auditsvc.CopyKey(instance, 99), cut, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if res := mustVerify(t, v, auditsvc.KindFull); res.OK || res.FailedSegment != 99 || !strings.Contains(res.Reason, "platform's checkpoint does not") {
		t.Fatalf("cut back: %+v", res)
	}
	_ = pool
}

// An empty segment's checkpoint removed: no records are missing, but the
// checkpoints no longer reach the segment before the open one.
func TestAuditVerificationEmptyCheckpointRemoved(t *testing.T) {
	e, _, _, c, v := verifyFixture(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ { // the second close: an empty segment (the first close's event is still in intake)
		if _, err := c.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if res := mustVerify(t, v, auditsvc.KindFull); !res.OK || res.ToSegment != 5 {
		t.Fatalf("before: %+v", res)
	}
	e.tamper("DELETE FROM audit.checkpoint WHERE segment = 5")
	if res := mustVerify(t, v, auditsvc.KindFull); res.OK || res.FailedSegment != 5 {
		t.Fatalf("after: %+v", res)
	}
}

// A checkpoint signed by a registered key that does not match its records
// (a compromised key, or a signer's mistake) is found at that segment.
func TestAuditVerificationSignedButWrong(t *testing.T) {
	for name, mut := range map[string]func(s *integrity.Statement){
		"Merkle root does not match": func(s *integrity.Statement) { s.MerkleRoot[0] ^= 1 },
		"chain does not end":         func(s *integrity.Statement) { s.ChainHash[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			e, _, _, c, v := verifyFixture(t)
			stored := e.checkpoints()
			st, err := integrity.ParseStatement(stored[2].statement)
			if err != nil {
				t.Fatal(err)
			}
			mut(&st)
			b, _ := st.Marshal()
			sig, err := integrity.Sign(c.Key, b) // the key that signed segment 3
			if err != nil {
				t.Fatal(err)
			}
			e.tamper(fmt.Sprintf("UPDATE audit.checkpoint SET statement = decode('%x', 'hex'), signature = decode('%x', 'hex') WHERE segment = 3", b, sig))
			if res := mustVerify(t, v, auditsvc.KindFull); res.OK || res.FailedSegment != 3 || !strings.Contains(res.Reason, name) {
				t.Fatalf("%+v", res)
			}
		})
	}
}
