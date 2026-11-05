package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/objstore"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-002 T-19 (F-002-AC-27, AC-29; design §6.7): legal holds and destruction.

func (xe *exportEnv) retainer(store *memStore, total time.Duration) auditsvc.Retainer {
	return auditsvc.Retainer{DB: xe.pool, Store: store, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: xe.pool}),
		Retention: func() (time.Duration, time.Duration) { return testOnline, total }}
}

// placeHold places a hold as user and returns its id.
func (xe *exportEnv) placeHold(t *testing.T, user string, filter map[string]string) string {
	t.Helper()
	r := xe.do(t, user, "POST", "/holds", idem(), map[string]any{"filter": filter, "reason": "litigation ACME v. Example"})
	if r.code != http.StatusCreated || r.body["status"] != "active" {
		t.Fatalf("place hold: %d %s", r.code, r.raw)
	}
	return fmt.Sprint(r.body["hold_id"])
}

// lapse makes every archive past its lock and its records older than the
// total retention (time passing, without waiting for it), in the database
// and in the store.
func (xe *exportEnv) lapse() {
	xe.e.tamper("UPDATE audit.archive SET destroy_after = now() - interval '1 day', newest_at = now() - interval '8 years' WHERE destroyed_at IS NULL")
	xe.store.clock = func() time.Time { return time.Now().Add(20 * 365 * 24 * time.Hour) }
}

func archiveRow(e *env, seg string) string {
	return e.adminQuery("SELECT (destroyed_at IS NOT NULL) || '/' || (object_removed_at IS NOT NULL) || '/' || legal_hold FROM audit.archive WHERE segment = " + seg)
}

// AC-29: only holders of audit.hold at the root place and release holds;
// both are recorded at high severity with the reason.
func TestAuditHoldAPI(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	e := xe.e
	xe.closeSegment(t)
	body := map[string]any{"filter": map[string]string{"target": "test:a"}, "reason": "litigation"}
	for user, code := range map[string]int{"rootaud": 403, "aaud": 403, "nobody": 404} {
		if r := xe.do(t, user, "POST", "/holds", idem(), body); r.code != code {
			t.Errorf("%s placing a hold: %d %s", user, r.code, r.raw)
		}
		if r := xe.do(t, user, "GET", "/holds", "", nil); r.code != code {
			t.Errorf("%s listing holds: %d", user, r.code)
		}
	}
	for name, b := range map[string]map[string]any{
		"no reason":      {"filter": map[string]string{}, "reason": " "},
		"unknown filter": {"filter": map[string]string{"colour": "red"}, "reason": "x"},
		"unknown field":  {"reason": "x", "scope": "all"},
		"long reason":    {"reason": strings.Repeat("r", 1001)},
	} {
		if r := xe.do(t, "admin", "POST", "/holds", idem(), b); r.code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if r := xe.do(t, "admin", "POST", "/holds", "", body); r.code != http.StatusBadRequest {
		t.Errorf("without Idempotency-Key: %d", r.code)
	}

	// A closed segment without matching records is not held.
	submitAs(t, e, "app_rw", map[string]any{"id": "unrelated", "type": "db.migrated", "severity": "info", "actor": "x", "target": "test:unrelated"})
	xe.closeSegment(t)
	id := xe.placeHold(t, "admin", map[string]string{"target": "test:a"})
	admin := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin@example.test'")
	l := xe.do(t, "admin", "GET", "/holds", "", nil)
	holds, _ := l.body["holds"].([]any)
	if l.code != 200 || len(holds) != 1 {
		t.Fatalf("list: %d %s", l.code, l.raw)
	}
	h := holds[0].(map[string]any)
	if h["hold_id"] != id || h["placed_by"] != admin || fmt.Sprint(h["segments"]) != "1" || h["archives_checked_at"] != nil ||
		h["names"].(map[string]any)[admin] == nil || h["reason"] != "litigation ACME v. Example" {
		t.Fatalf("hold %v", h)
	}
	placed := trailEvents(t, xe.auditAPIEnv, "audit.hold_placed")
	if len(placed) != 1 || placed[0]["severity"] != "high" || placed[0]["actor"] != admin || placed[0]["reason"] != "litigation ACME v. Example" ||
		attrs(placed[0])["hold_id"] != id || attrs(placed[0])["online_segments"] != "1" {
		t.Fatalf("audit.hold_placed %v", placed)
	}

	// Release, once; with a reason.
	if r := xe.do(t, "admin", "POST", "/holds/"+id+"/release", idem(), map[string]any{"reason": " "}); r.code != http.StatusBadRequest {
		t.Fatalf("release without reason: %d", r.code)
	}
	if r := xe.do(t, "rootaud", "POST", "/holds/"+id+"/release", idem(), map[string]any{"reason": "x"}); r.code != http.StatusForbidden {
		t.Fatalf("auditor releasing: %d", r.code)
	}
	r := xe.do(t, "admin", "POST", "/holds/"+id+"/release", idem(), map[string]any{"reason": "settled"})
	if r.code != 200 || r.body["status"] != "released" || r.body["release_reason"] != "settled" || r.body["released_by"] != admin {
		t.Fatalf("release: %d %s", r.code, r.raw)
	}
	if r := xe.do(t, "admin", "POST", "/holds/"+id+"/release", idem(), map[string]any{"reason": "again"}); r.code != http.StatusConflict {
		t.Fatalf("second release: %d", r.code)
	}
	for _, path := range []string{"/holds/00000000-0000-0000-0000-000000000000/release", "/holds/nope/release"} {
		if r := xe.do(t, "admin", "POST", path, idem(), map[string]any{"reason": "x"}); r.code != http.StatusNotFound {
			t.Errorf("%s: %d", path, r.code)
		}
	}
	released := trailEvents(t, xe.auditAPIEnv, "audit.hold_released")
	if len(released) != 1 || released[0]["severity"] != "high" || released[0]["reason"] != "settled" || attrs(released[0])["segments_released"] != "1" {
		t.Fatalf("audit.hold_released %v", released)
	}
	// The database refuses what the API would.
	e.mustFail("app_audit", `SELECT audit.hold_place('{}', 'x')`, "valid signed database context")
	e.mustFail("app_rw", `SELECT audit.hold_place('{}', 'x')`, "permission denied")
	rp := e.principal("rootaud")
	e.mustFail("app_audit", fmt.Sprintf(`SELECT set_config('authz.ctx', '%s', false), audit.hold_place('{}', 'x')`, rp.DBToken), "audit.hold at the root")
}

// AC-27, AC-29: held segments survive past their destruction time, also
// for records that arrived after the hold; released, they are destroyed;
// destruction is recorded and verification still passes.
func TestAuditHoldAndDestruction(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	e := xe.e
	ctx := context.Background()
	xe.closeSegment(t) // the fixture's records: a1 and a2 have target test:a
	seg1 := e.adminQuery("SELECT segment FROM audit.record WHERE event_id = 'a1'")
	id := xe.placeHold(t, "admin", map[string]string{"target": "test:a"})

	// A matching record after the hold, in a later segment; and one that
	// does not match, in another.
	a := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")
	submitAs(t, e, "app_rw", map[string]any{"id": "a-later", "type": "setting.change_requested", "severity": "high", "actor": "x", "bu_id": a, "target": "test:a"})
	xe.closeSegment(t)
	seg2 := e.adminQuery("SELECT segment FROM audit.record WHERE event_id = 'a-later'")
	submitAs(t, e, "app_rw", map[string]any{"id": "other", "type": "setting.change_requested", "severity": "high", "actor": "x", "bu_id": a, "target": "test:other"})
	xe.closeSegment(t)
	seg3 := e.adminQuery("SELECT segment FROM audit.record WHERE event_id = 'other'")

	// The hold is checked against the (empty) archive first, so the later
	// record is held by archiving itself, not by that check.
	ret := xe.retainer(xe.store, testTotal)
	if res, err := ret.Step(ctx); err != nil || res.HoldsChecked != 1 {
		t.Fatalf("check before archiving: %+v %v", res, err)
	}
	if got, err := xe.archiver(xe.store).Step(ctx); err != nil || len(got) < 3 {
		t.Fatalf("archive: %+v %v", got, err)
	}

	// Not yet due: nothing is destroyed; the legal holds are set.
	res, err := ret.Step(ctx)
	if err != nil || len(res.Destroyed) != 0 {
		t.Fatalf("before the lock ends: %+v %v", res, err)
	}
	for _, s := range []string{seg1, seg2} {
		if got := archiveRow(e, s); got != "false/false/true" {
			t.Fatalf("held segment %s: %s", s, got)
		}
	}
	if got := archiveRow(e, seg3); got != "false/false/false" {
		t.Fatalf("unheld segment %s: %s", seg3, got)
	}

	// Past the lock and the total retention: only the unheld are destroyed.
	xe.lapse()
	res, err = ret.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := archiveRow(e, seg3); got != "true/true/false" {
		t.Fatalf("unheld segment after its time: %s (%+v)", got, res)
	}
	key := e.adminQuery("SELECT object_key || '|' || version_id FROM audit.archive WHERE segment = " + seg3)
	k, v, _ := strings.Cut(key, "|")
	if _, err := xe.store.Open(ctx, objstore.Version{Key: k, VersionID: v}); err == nil {
		t.Fatal("the destroyed segment's object is still in the store")
	}
	for _, s := range []string{seg1, seg2} {
		if got := archiveRow(e, s); got != "false/false/true" {
			t.Fatalf("held segment %s destroyed: %s", s, got)
		}
	}
	drainTrail(t, xe.seq)
	destroyed := trailEventsOf(t, e, "audit.records_destroyed")
	if len(destroyed) == 0 || destroyed[0]["severity"] != "high" {
		t.Fatalf("audit.records_destroyed %v", destroyed)
	}
	found := false
	for _, ev := range destroyed {
		found = found || attrs(ev)["segment"] == seg3
	}
	if !found {
		t.Fatalf("no audit.records_destroyed for segment %s: %v", seg3, destroyed)
	}
	// Verification continues from the first retained record (AC-27).
	ver := auditsvc.Verifier{DB: xe.pool, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: xe.pool}), Archive: xe.store}
	if r, err := ver.Full(ctx); err != nil || !r.OK {
		t.Fatalf("full verification after destruction: %+v %v", r, err)
	}

	// Released: the legal holds are cleared and the segments destroyed.
	if r := xe.do(t, "admin", "POST", "/holds/"+id+"/release", idem(), map[string]any{"reason": "settled"}); r.code != 200 {
		t.Fatalf("release: %d %s", r.code, r.raw)
	}
	if _, err := ret.Step(ctx); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{seg1, seg2} {
		if got := archiveRow(e, s); got != "true/true/false" {
			t.Fatalf("released segment %s: %s", s, got)
		}
	}
	if r, err := ver.Full(ctx); err != nil || !r.OK {
		t.Fatalf("full verification after every destruction: %+v %v", r, err)
	}
	// Checkpoints stay.
	if n := e.adminQuery("SELECT count(*) FROM audit.checkpoint WHERE segment IN (" + seg1 + "," + seg2 + "," + seg3 + ")"); n != "3" {
		t.Fatalf("%s checkpoints left", n)
	}
}

// A hold placed after segments were archived covers matching archived
// segments once checked, and nothing is destroyed until it has been.
func TestAuditHoldOverArchives(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	e := xe.e
	ctx := context.Background()
	xe.closeSegment(t)
	seg := e.adminQuery("SELECT segment FROM audit.record WHERE event_id = 'r1'")
	if _, err := xe.archiver(xe.store).Step(ctx); err != nil {
		t.Fatal(err)
	}
	xe.lapse()
	id := xe.placeHold(t, "admin", map[string]string{"request_id": "req-r"}) // r2, archived
	if got := e.adminQuery("SELECT count(*) FROM audit.destroy_candidates(now(), 100)"); got != "0" {
		t.Fatalf("%s due while a hold is unchecked", got)
	}
	ret := xe.retainer(xe.store, testTotal)
	// An archive that no longer matches its digest stops the check: the
	// hold stays unchecked and nothing is destroyed.
	xe.store.corrupt = true
	if _, err := ret.Step(ctx); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("check over a changed archive: %v", err)
	}
	if got := e.adminQuery("SELECT archives_checked_at IS NULL FROM audit.hold WHERE id = '" + id + "'"); got != "t" {
		t.Fatal("a hold was marked checked over a changed archive")
	}
	xe.store.corrupt = false
	if res, err := ret.Step(ctx); err != nil || res.HoldsChecked != 1 {
		t.Fatalf("check: %+v %v", res, err)
	}
	if got := archiveRow(e, seg); got != "false/false/true" {
		t.Fatalf("the archived segment with a held record: %s", got)
	}
	if got := e.adminQuery("SELECT archives_checked_at IS NOT NULL FROM audit.hold WHERE id = '" + id + "'"); got != "t" {
		t.Fatal("hold not marked checked")
	}
	// The database refuses to destroy a held segment even when asked.
	e.mustFail("app_audit", "SELECT audit.destroy_segment("+seg+", now())", "not due")
}

// Shortening the retention never shortens a lock; a longer total keeps an
// archive longer than its lock (AC-27, AC-28).
func TestAuditDestructionFollowsRetention(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	e := xe.e
	ctx := context.Background()
	xe.closeSegment(t)
	seg := e.adminQuery("SELECT segment FROM audit.record WHERE event_id = 'a1'")
	if _, err := xe.archiver(xe.store).Step(ctx); err != nil {
		t.Fatal(err)
	}
	// Records eight years old, lock still running: a total of one year does
	// not destroy before the lock ends.
	e.tamper("UPDATE audit.archive SET newest_at = now() - interval '8 years'")
	if res, err := xe.retainer(xe.store, testOnline).Step(ctx); err != nil || len(res.Destroyed) != 0 {
		t.Fatalf("destroyed under its lock: %+v %v", res, err)
	}
	// Lock ended, but the total retention is now ten years.
	e.tamper("UPDATE audit.archive SET destroy_after = now() - interval '1 day'")
	xe.store.clock = func() time.Time { return time.Now().Add(20 * 365 * 24 * time.Hour) }
	if res, err := xe.retainer(xe.store, 10*365*24*time.Hour).Step(ctx); err != nil || len(res.Destroyed) != 0 {
		t.Fatalf("destroyed within a longer total retention: %+v %v", res, err)
	}
	if got := archiveRow(e, seg); got != "false/false/false" {
		t.Fatalf("archive %s", got)
	}
	// Within the seven years: destroyed.
	if res, err := xe.retainer(xe.store, testTotal).Step(ctx); err != nil || len(res.Destroyed) == 0 {
		t.Fatalf("not destroyed: %+v %v", res, err)
	}
	// A failed object deletion is retried; the record stands.
	if got := archiveRow(e, seg); got != "true/true/false" {
		t.Fatalf("archive after destruction %s", got)
	}
}

// The audit store (FAIR_TEST_S3): legal holds are set and cleared on the
// archive objects.
func TestAuditHoldS3(t *testing.T) {
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
	id := xe.placeHold(t, "admin", map[string]string{"target": "test:a"})
	ret := auditsvc.Retainer{DB: xe.pool, Store: st, Audit: arc.Audit, Retention: arc.Retention}
	if _, err := ret.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if on, err := st.LegalHold(ctx, got[0].Object); err != nil || !on {
		t.Fatalf("legal hold after placing: %v %v", on, err)
	}
	if r := xe.do(t, "admin", "POST", "/holds/"+id+"/release", idem(), map[string]any{"reason": "settled"}); r.code != 200 {
		t.Fatalf("release: %d", r.code)
	}
	if _, err := ret.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if on, err := st.LegalHold(ctx, got[0].Object); err != nil || on {
		t.Fatalf("legal hold after release: %v %v", on, err)
	}
	// Still locked until destroy_after: shortening nothing, deleting refused.
	if err := st.Delete(ctx, got[0].Object); err == nil {
		t.Fatal("a locked archive was deleted")
	}
}
