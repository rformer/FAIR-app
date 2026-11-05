package tests

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-002 T-18 (F-002-AC-25, AC-26; design §6.7): archiving segments past the
// online retention.

const (
	testOnline = 365 * 24 * time.Hour
	testTotal  = 2557 * 24 * time.Hour
)

// archiver archives as if now were later than the fixture's records by
// more than the online retention.
func (xe *exportEnv) archiver(store *memStore) auditsvc.Archiver {
	return auditsvc.Archiver{DB: xe.pool, Store: store, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: xe.pool}),
		Retention: func() (time.Duration, time.Duration) { return testOnline, testTotal },
		Now:       func() time.Time { return time.Now().Add(testOnline + time.Hour) }}
}

// closeSegment closes the open segment with the fixture's checkpointer.
func (xe *exportEnv) closeSegment(t *testing.T) {
	t.Helper()
	drainTrail(t, xe.seq)
	if _, err := xe.exporter.Checkpointer.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	drainTrail(t, xe.seq)
}

// AC-25, AC-26: a segment past the online retention moves to the archive,
// signed and locked; its records leave search and stay verifiable and
// exportable, in the requester's scope.
func TestAuditArchive(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	e := xe.e
	ctx := context.Background()
	xe.closeSegment(t) // the fixture's records, and the reads so far
	seg := e.adminQuery("SELECT segment FROM audit.record WHERE event_id = 'a1'")
	a := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")
	submitAs(t, e, "app_rw", map[string]any{"id": "a-online", "type": "setting.change_requested", "severity": "high", "actor": "x", "bu_id": a, "target": "test:a"})
	drainTrail(t, xe.seq)

	// Not yet due: nothing moves.
	early := xe.archiver(xe.store)
	early.Now = time.Now
	if got, err := early.Step(ctx); err != nil || len(got) != 0 {
		t.Fatalf("archived before the online retention ended: %+v %v", got, err)
	}
	early.Now = func() time.Time { return time.Now().Add(testOnline - time.Hour) }
	if got, err := early.Step(ctx); err != nil || len(got) != 0 {
		t.Fatalf("archived an hour before the online retention ended: %+v %v", got, err)
	}

	// Due: the closed segments with records move; the open one stays.
	got, err := xe.archiver(xe.store).Step(ctx)
	if err != nil || len(got) == 0 {
		t.Fatalf("archive: %+v %v", got, err)
	}
	if fmt.Sprint(got[0].Segment) != seg {
		t.Fatalf("first archived segment %d, want %s", got[0].Segment, seg)
	}
	if n := e.adminQuery("SELECT count(*) FROM audit.record WHERE segment = " + seg); n != "0" {
		t.Fatalf("%s records of the archived segment left online", n)
	}
	if n := e.adminQuery("SELECT count(*) FROM audit.record WHERE event_id = 'a-online'"); n != "1" {
		t.Fatal("a record of the open segment was archived")
	}
	row := e.adminQuery("SELECT object_key || '|' || record_count || '|' || encode(digest, 'hex') || '|' || (destroy_after > now() + interval '6 years') FROM audit.archive WHERE segment = " + seg)
	instance := e.adminQuery("SELECT instance FROM audit.head")
	if want := evidence.SegmentKey(instance, got[0].Segment) + "|" + fmt.Sprint(got[0].Records) + "|" + got[0].Digest.String() + "|true"; row != want {
		t.Fatalf("archive row %s, want %s", row, want)
	}
	// Locked until destroy_after: archived time plus total less online.
	if lock := xe.store.locks[got[0].Object]; !lock.Equal(got[0].DestroyAfter) || lock.Sub(time.Now().Add(testOnline)) < testTotal-testOnline-2*time.Hour {
		t.Fatalf("locked until %v, destroy after %v", lock, got[0].DestroyAfter)
	}
	// The object holds the signed checkpoint and every record.
	rc, _ := xe.store.Open(ctx, got[0].Object)
	archived, err := evidence.ReadSegment(rc)
	_ = rc.Close()
	if err != nil || len(archived.Records) != got[0].Records || len(archived.Checkpoint.Signature) == 0 {
		t.Fatalf("archive object: %d records %v", len(archived.Records), err)
	}
	evs := trailEvents(t, xe.auditAPIEnv, "audit.records_archived")
	if len(evs) != len(got) || attrs(evs[0])["segment"] != seg || attrs(evs[0])["digest"] != got[0].Digest.String() || evs[0]["severity"] != "info" {
		t.Fatalf("audit.records_archived %v", evs)
	}

	// Gone from search and the record view.
	if r := xe.get(t, "rootaud", "/records?type=setting.change_requested&limit=200"); sortedIDs(r) != "a-online" {
		t.Fatalf("search after archiving: %s", sortedIDs(r))
	}
	a1 := e.adminQuery(fmt.Sprintf("SELECT %d", archived.Records[0].Seq))
	if r := xe.get(t, "rootaud", "/records/"+a1); r.code != http.StatusNotFound {
		t.Fatalf("an archived record's view: %d", r.code)
	}

	// Verifiable: a full run reads the archive.
	ver := auditsvc.Verifier{DB: xe.pool, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: xe.pool}), Archive: xe.store}
	if r, err := ver.Full(ctx); err != nil || !r.OK {
		t.Fatalf("full verification after archiving: %+v %v", r, err)
	}
	// Without the archive store a full run cannot finish.
	if r, err := (auditsvc.Verifier{DB: xe.pool, Audit: ver.Audit}).Full(ctx); err == nil && r.OK {
		t.Fatal("a full run passed without reading the archive")
	}

	// Exportable, in order with the online records, in the requester's
	// scope, as CSV too (skew is not known for archived records).
	id := xe.request(t, "rootaud", map[string]string{"type": "setting.change_requested"}, "csv")
	res, files, _ := xe.run(t, "rootaud", id)
	if ids := bodyIDs(t, files[evidence.FileBodies]); ids != "a1,root1,a2,a-online" {
		t.Fatalf("export across the archive: %s", ids)
	}
	if !strings.Contains(res.Manifest.Filter.Description, "online or archived") {
		t.Fatalf("filter description %q", res.Manifest.Filter.Description)
	}
	rows, _ := csv.NewReader(bytes.NewReader(files[evidence.FileRecordsCSV])).ReadAll()
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	if rows[1][col["skew"]] != "" || rows[4][col["skew"]] != "false" || rows[1][col["category"]] != "configuration" || rows[1][col["source_ip"]] != "10.0.0.1" {
		t.Fatalf("csv %q", rows)
	}
	idA := xe.request(t, "aaud", map[string]string{}, "jsonl")
	_, filesA, _ := xe.run(t, "aaud", idA)
	if ids := bodyIDs(t, filesA[evidence.FileRecords]); !strings.HasPrefix(ids, "a1,a2,") || strings.Contains(ids, "root1") || strings.Contains(ids, "r1") {
		t.Fatalf("A's export across the archive: %s", ids)
	}
	// An archive that no longer matches its digest is not exported.
	xe.store.corrupt = true
	bad := xe.request(t, "rootaud", map[string]string{}, "jsonl")
	if _, err := xe.exporter.Run(ctx, bad); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("export from a changed archive: %v", err)
	}
	xe.store.corrupt = false

	// Nothing is archived twice: later runs take only segments closed since
	// (the exports closed some), and then nothing.
	done := map[uint64]bool{}
	for _, r := range got {
		done[r.Segment] = true
	}
	for run := 0; run < 2; run++ {
		again, err := xe.archiver(xe.store).Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range again {
			if done[r.Segment] {
				t.Fatalf("segment %d archived twice", r.Segment)
			}
			done[r.Segment] = true
		}
		if run == 1 && len(again) != 0 {
			t.Fatalf("a third run archived %+v", again)
		}
	}
}

// A failed upload, or an object that does not read back as written,
// removes nothing; a segment that does not verify is not archived.
func TestAuditArchiveFailures(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	e := xe.e
	ctx := context.Background()
	xe.closeSegment(t)
	before := e.adminQuery("SELECT count(*) FROM audit.record")
	unchanged := func(what string) {
		t.Helper()
		if got := e.adminQuery("SELECT count(*) FROM audit.record"); got != before {
			t.Fatalf("%s: %s records online, was %s", what, got, before)
		}
		if got := e.adminQuery("SELECT count(*) FROM audit.archive"); got != "0" {
			t.Fatalf("%s: %s archives recorded", what, got)
		}
		if n := len(trailEventsOf(t, e, "audit.records_archived")); n != 0 {
			t.Fatalf("%s: %d archive events", what, n)
		}
	}

	store := newMemStore()
	store.fail = errors.New("bucket unreachable")
	if _, err := xe.archiver(store).Step(ctx); err == nil || !strings.Contains(err.Error(), "bucket unreachable") {
		t.Fatalf("upload failure: %v", err)
	}
	unchanged("a failed upload")

	store = newMemStore()
	store.corrupt = true
	if _, err := xe.archiver(store).Step(ctx); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("read-back mismatch: %v", err)
	}
	unchanged("a bad read-back")

	bad := e.adminQuery("SELECT seq FROM audit.record WHERE event_id = 'a2'")
	e.tamper("UPDATE audit.record SET body = convert_to('{}', 'UTF8') WHERE seq = " + bad)
	store = newMemStore()
	if _, err := xe.archiver(store).Step(ctx); err == nil || !strings.Contains(err.Error(), "record "+bad) {
		t.Fatalf("an altered segment: %v", err)
	}
	unchanged("an altered segment")
	// Nothing was written: a bad segment is never locked in the store.
	if len(store.objects) != 0 {
		t.Fatalf("%d objects written for an altered segment", len(store.objects))
	}
}

// The database removes a segment's rows only through audit.archive_segment,
// once, with the segment's exact count and a future destruction time.
func TestAuditArchiveSegmentGuards(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	e := xe.e
	xe.closeSegment(t)
	seg := e.adminQuery("SELECT segment FROM audit.record WHERE event_id = 'a1'")
	n := e.adminQuery("SELECT seq_to - seq_from + 1 FROM audit.checkpoint WHERE segment = " + seg)
	call := func(count, until string) string {
		return fmt.Sprintf(`SELECT audit.archive_segment(%s, 'k', 'v', decode(repeat('ab', 32), 'hex'), %s, %s)`, seg, count, until)
	}
	e.mustFail("app_audit", call(n+"+1", "now() + interval '1 day'"), "holds")
	e.mustFail("app_audit", call(n, "now() - interval '1 day'"), "future destruction time")
	e.mustFail("app_audit", "SELECT audit.archive_segment(999999, 'k', 'v', decode(repeat('ab', 32), 'hex'), 1, now() + interval '1 day')", "not closed")
	e.mustFail("app_rw", call(n, "now() + interval '1 day'"), "permission denied")
	e.mustFail("app_audit", "DELETE FROM audit.record WHERE segment = "+seg, "permission denied")
	if got, err := e.as("app_audit", call(n, "now() + interval '1 day'")); err != nil || got != n {
		t.Fatalf("archive_segment removed %s, want %s: %v", got, n, err)
	}
	e.mustFail("app_audit", call(n, "now() + interval '1 day'"), "already archived")
}

// The audit store (FAIR_TEST_S3): the archive is locked in compliance mode
// until destroy_after, cannot be deleted, and full verification reads it.
func TestAuditArchiveS3(t *testing.T) {
	st, _, _ := testWORM(t)
	xe := newExportEnv(t, auditAPIFixture(t))
	ctx := context.Background()
	xe.closeSegment(t)
	arc := auditsvc.Archiver{DB: xe.pool, Store: st, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: xe.pool}),
		Retention: func() (time.Duration, time.Duration) { return testOnline, testTotal },
		Now:       func() time.Time { return time.Now().Add(testOnline + time.Hour) }}
	got, err := arc.Step(ctx)
	if err != nil || len(got) == 0 {
		t.Fatalf("archive: %+v %v", got, err)
	}
	until, err := st.RetainedUntil(ctx, got[0].Object)
	if err != nil || !until.Equal(got[0].DestroyAfter) {
		t.Fatalf("retained until %v (want %v): %v", until, got[0].DestroyAfter, err)
	}
	if err := st.Delete(ctx, got[0].Object); err == nil {
		t.Fatal("a locked archive was deleted")
	}
	ver := auditsvc.Verifier{DB: xe.pool, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: xe.pool}), Archive: st}
	if r, err := ver.Full(ctx); err != nil || !r.OK {
		t.Fatalf("full verification from the store: %+v %v", r, err)
	}
}

// A segment with rows missing (removed behind the database's back) is not
// archived with what is left: the count must be the segment's.
func TestAuditArchiveSegmentMissingRows(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	e := xe.e
	xe.closeSegment(t)
	seg := e.adminQuery("SELECT segment FROM audit.record WHERE event_id = 'a1'")
	n := atoi(e.adminQuery("SELECT seq_to - seq_from + 1 FROM audit.checkpoint WHERE segment = " + seg))
	last := e.adminQuery("SELECT seq_to FROM audit.checkpoint WHERE segment = " + seg)
	e.tamper("DELETE FROM audit.record WHERE seq = " + last)
	e.mustFail("app_audit", fmt.Sprintf(`SELECT audit.archive_segment(%s, 'k', 'v', decode(repeat('ab', 32), 'hex'), %d, now() + interval '1 day')`, seg, n-1), "holds")
	if got := e.adminQuery("SELECT count(*) FROM audit.archive"); got != "0" {
		t.Fatalf("%s archives", got)
	}
}
