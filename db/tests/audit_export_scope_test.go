package tests

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/evidence"
	"github.com/rformer/fair-app/internal/auditapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-002 T-15 (F-002-AC-32, AC-33): export formats, scope, refusals,
// failures, the closing checkpoint, the River job and the S3 store.

// CSV: a view of the records plus their bodies, which are what verifies.
func TestAuditExportCSV(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	id := xe.request(t, "rootaud", map[string]string{"request_id": "req-1"}, "csv")
	res, files, _ := xe.run(t, "rootaud", id)
	if res.Manifest.RecordFormat != "csv" || files[evidence.FileRecords] != nil {
		t.Fatalf("csv manifest %+v", res.Manifest)
	}
	if got := bodyIDs(t, files[evidence.FileBodies]); got != "a1,root1" {
		t.Fatalf("bodies %s", got)
	}
	rows, err := csv.NewReader(bytes.NewReader(files[evidence.FileRecordsCSV])).ReadAll()
	if err != nil || len(rows) != 3 || strings.Join(rows[0], ",") != strings.Join(auditsvc.ExportCSVHeader, ",") {
		t.Fatalf("csv %q %v", rows, err)
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	if rows[1][col["event_id"]] != "a1" || rows[2][col["event_id"]] != "root1" || rows[1][col["request_id"]] != "req-1" ||
		rows[1][col["source_ip"]] != "10.0.0.1" || rows[1][col["type"]] != "setting.change_requested" {
		t.Fatalf("csv rows %q", rows)
	}
}

// AC-33: an export holds what its requester could see and export when they
// asked for it, whatever changes later; exports need audit.export and are
// visible to their requester and to holders of audit.export at the root.
func TestAuditExportScope(t *testing.T) {
	ae := auditAPIFixture(t)
	e := ae.e
	// Someone at A who may view the trail but not export it.
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Audit Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['audit.view'], 'test' FROM r`)
	e.mustOwner(`INSERT INTO iam.app_user (email, display_name) VALUES ('viewer@example.test', 'Viewer')`)
	e.mustOwner(grant("admin", "user:viewer", "Audit Viewer", "A"))
	e.drain()
	xe := newExportEnv(t, ae)
	a := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")
	r := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'R'")

	idA := xe.request(t, "aaud", map[string]string{}, "jsonl")
	idR := xe.request(t, "raud", map[string]string{"type": "setting.change_requested"}, "jsonl")

	// The scope is captured at the request: A's auditor is then made an
	// auditor at the root too, and their export still holds only A's
	// records.
	e.mustOwner(grant("admin", "user:aaud", "Auditor", "ENTERPRISE"))
	e.drain()
	resA, filesA, _ := xe.run(t, "aaud", idA)
	if strings.Join(resA.Manifest.BUScope, ",") != a {
		t.Fatalf("A's scope %v", resA.Manifest.BUScope)
	}
	for _, l := range bytes.Split(bytes.TrimSpace(filesA[evidence.FileRecords]), []byte("\n")) {
		var b struct {
			BU string `json:"bu_id"`
		}
		_ = json.Unmarshal(l, &b)
		if b.BU != a {
			t.Fatalf("A's export holds a record of %q: %s", b.BU, l)
		}
	}
	if got := bodyIDs(t, filesA[evidence.FileRecords]); !strings.HasPrefix(got, "a1,a2") {
		t.Fatalf("A's records %s", got)
	}
	resR, filesR, _ := xe.run(t, "raud", idR)
	if strings.Join(resR.Manifest.BUScope, ",") != r || bodyIDs(t, filesR[evidence.FileRecords]) != "r1,r2" {
		t.Fatalf("R's export: scope %v, records %s", resR.Manifest.BUScope, bodyIDs(t, filesR[evidence.FileRecords]))
	}

	// Who sees an export: its requester and audit.export at the root.
	for _, c := range []struct {
		user string
		code int
	}{{"aaud", 200}, {"rootaud", 200}, {"raud", 404}, {"viewer", 403}, {"nobody", 404}} {
		if g := xe.do(t, c.user, "GET", "/exports/"+idA, "", nil); g.code != c.code {
			t.Errorf("%s reading A's export: %d %s", c.user, g.code, g.raw)
		}
		if b := xe.do(t, c.user, "GET", "/exports/"+idA+"/bundle", "", nil); b.code != c.code {
			t.Errorf("%s downloading A's export: %d", c.user, b.code)
		}
	}
	if g := xe.do(t, "raud", "GET", "/exports/"+idR, "", nil); g.code != 200 {
		t.Errorf("R's auditor reading their own export: %d", g.code)
	}
	for _, path := range []string{"/exports/not-a-uuid", "/exports/00000000-0000-0000-0000-000000000000"} {
		if g := xe.do(t, "rootaud", "GET", path, "", nil); g.code != 404 {
			t.Errorf("%s: %d", path, g.code)
		}
	}

	// Requests: audit.export is required (403; 404 without audit.view); the
	// filter, format and reason are checked; Idempotency-Key is required,
	// and a retry does not export twice.
	body := map[string]any{"filter": map[string]string{}, "format": "jsonl", "reason": "review"}
	if p := xe.do(t, "viewer", "POST", "/exports", idem(), body); p.code != http.StatusForbidden {
		t.Errorf("viewer: %d %s", p.code, p.raw)
	}
	if p := xe.do(t, "nobody", "POST", "/exports", idem(), body); p.code != http.StatusNotFound {
		t.Errorf("nobody: %d %s", p.code, p.raw)
	}
	if p := xe.do(t, "rootaud", "POST", "/exports", "", body); p.code != http.StatusBadRequest || p.body["error"] != "idempotency_key_required" {
		t.Errorf("no Idempotency-Key: %d %s", p.code, p.raw)
	}
	for name, b := range map[string]map[string]any{
		"unknown filter": {"filter": map[string]string{"colour": "red"}, "format": "jsonl", "reason": "x"},
		"bad time":       {"filter": map[string]string{"from": "yesterday"}, "format": "jsonl", "reason": "x"},
		"bad address":    {"filter": map[string]string{"source_ip": "nowhere"}, "format": "jsonl", "reason": "x"},
		"bad BU":         {"filter": map[string]string{"bu": "nowhere"}, "format": "jsonl", "reason": "x"},
		"bad format":     {"format": "xml", "reason": "x"},
		"no reason":      {"format": "csv", "reason": "  "},
		"long reason":    {"format": "csv", "reason": strings.Repeat("r", 1001)},
		"unknown field":  {"format": "csv", "reason": "x", "scope": "everything"},
	} {
		if p := xe.do(t, "rootaud", "POST", "/exports", idem(), b); p.code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, p.code, p.raw)
		}
	}
	before := atoi(e.adminQuery("SELECT count(*) FROM audit.export"))
	key := idem()
	p1 := xe.do(t, "rootaud", "POST", "/exports", key, body)
	p2 := xe.do(t, "rootaud", "POST", "/exports", key, body)
	if p1.code != 202 || p2.code != 202 || p1.body["export_id"] != p2.body["export_id"] {
		t.Fatalf("retry: %d %s / %d %s", p1.code, p1.raw, p2.code, p2.raw)
	}
	if after := atoi(e.adminQuery("SELECT count(*) FROM audit.export")); after != before+1 {
		t.Fatalf("exports %d -> %d", before, after)
	}

	// The database refuses what the API would: a request without a signed
	// context, or by someone without audit.export.
	e.mustFail("app_audit", `SELECT audit.export_request('{}', 'jsonl', 'x')`, "valid signed database context")
	vp := e.principal("viewer")
	e.mustFail("app_audit", fmt.Sprintf(`SELECT set_config('authz.ctx', '%s', false), audit.export_request('{}', 'jsonl', 'x')`, vp.DBToken),
		"audit.export is required")
	// Exports see what search sees: once R's roll-up mode lets its ancestors
	// read it, the root auditor's search shows R's records, and so does
	// their export (audit.export held at the root reaches R as audit.view
	// does).
	e.mustOwner("UPDATE iam.bu SET rollup_mode = 'full' WHERE code = 'R'")
	e.drain()
	search := xe.get(t, "rootaud", "/records?type=setting.change_requested&limit=200")
	if got := sortedIDs(search); got != "a1,a2,r1,r2,root1" {
		t.Fatalf("root auditor's search with R rolled up: %s", got)
	}
	idFull := xe.request(t, "rootaud", map[string]string{"type": "setting.change_requested"}, "jsonl")
	resFull, filesFull, _ := xe.run(t, "rootaud", idFull)
	if got := bodyIDs(t, filesFull[evidence.FileRecords]); got != "a1,r1,root1,a2,r2" || !strings.Contains(strings.Join(resFull.Manifest.BUScope, ","), r) {
		t.Fatalf("root auditor's export with R rolled up: %s, scope %v", got, resFull.Manifest.BUScope)
	}

	// Other application roles cannot use the export functions.
	e.mustFail("app_rw", "SELECT * FROM audit.export_rows('"+idA+"', 0, 100, 10)", "permission denied")
}

func atoi(s string) int {
	var n int
	_, _ = fmt.Sscan(s, &n)
	return n
}

// An export that cannot be stored is retried; after the last attempt it
// fails, and the trail says so. A failed export is not downloadable.
func TestAuditExportFailure(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	id := xe.request(t, "rootaud", map[string]string{}, "jsonl")
	xe.store.fail = errors.New("bucket unreachable")
	ctx := context.Background()
	// Attempts before the last are retried (the error goes back to River)
	// and leave the export pending.
	for attempt := 1; attempt < auditsvc.ExportAttempts; attempt++ {
		_, err := auditsvc.RunExportAttempt(ctx, xe.exporter, id, attempt, auditsvc.ExportAttempts)
		var cancel *river.JobCancelError
		if err == nil || !strings.Contains(err.Error(), "bucket unreachable") || errors.As(err, &cancel) {
			t.Fatalf("attempt %d with a failing store: %v", attempt, err)
		}
		if got := xe.e.adminQuery("SELECT status FROM audit.export WHERE id = '" + id + "'"); got != "pending" {
			t.Fatalf("after attempt %d: %s", attempt, got)
		}
	}
	if n := len(trailEvents(t, xe.auditAPIEnv, "audit.exported")); n != 0 {
		t.Fatalf("%d audit.exported before the last attempt", n)
	}
	// The last attempt fails the export and cancels the job.
	_, err := auditsvc.RunExportAttempt(ctx, xe.exporter, id, auditsvc.ExportAttempts, auditsvc.ExportAttempts)
	var cancel *river.JobCancelError
	if !errors.As(err, &cancel) || !strings.Contains(err.Error(), "bucket unreachable") {
		t.Fatalf("last attempt: %v", err)
	}
	g := xe.do(t, "rootaud", "GET", "/exports/"+id, "", nil)
	if g.body["status"] != "failed" || !strings.Contains(fmt.Sprint(g.body["failure"]), "bucket unreachable") {
		t.Fatalf("failed export: %s", g.raw)
	}
	if b := xe.do(t, "rootaud", "GET", "/exports/"+id+"/bundle", "", nil); b.code != http.StatusConflict {
		t.Fatalf("a failed bundle: %d", b.code)
	}
	evs := trailEvents(t, xe.auditAPIEnv, "audit.exported")
	if len(evs) != 1 || attrs(evs[0])["status"] != "failed" || evs[0]["severity"] != "high" ||
		!strings.Contains(fmt.Sprint(attrs(evs[0])["failure"]), "bucket unreachable") {
		t.Fatalf("audit.exported %v", evs)
	}
	// Failing again, or running a failed export, does nothing; an export
	// that does not exist cancels its job.
	if failed, err := xe.exporter.Fail(ctx, id, nil); err != nil || failed {
		t.Fatalf("second fail: %v %v", failed, err)
	}
	xe.store.fail = nil
	if res, err := xe.exporter.Run(ctx, id); err != nil || res.Created {
		t.Fatalf("running a failed export: %+v %v", res, err)
	}
	if _, err := auditsvc.RunExportAttempt(ctx, xe.exporter, "00000000-0000-0000-0000-000000000000", 1, 5); !errors.Is(err, auditsvc.ErrExportGone) ||
		!errors.As(err, &cancel) {
		t.Fatalf("no such export: %v", err)
	}
	// Only a pending export completes.
	if _, err := xe.e.as("app_audit", fmt.Sprintf(`SELECT audit.export_complete('%s', 1, decode(repeat('00', 32), 'hex'), 1, 'k', 'v')`, id)); err == nil {
		t.Fatal("a failed export completed")
	}
}

// The export closes a segment: records sequenced into the open segment are
// covered by the checkpoint closed for it.
func TestAuditExportClosesSegment(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	if _, err := xe.exporter.Checkpointer.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := xe.e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")
	late := func(id string) {
		submitAs(t, xe.e, "app_rw", map[string]any{"id": id, "type": "setting.change_requested", "severity": "high", "actor": "x", "bu_id": a, "target": "test:late"})
		drainTrail(t, xe.seq)
	}
	late("late1")
	id := xe.request(t, "rootaud", map[string]string{"target": "test:late"}, "jsonl")
	open := xe.e.adminQuery("SELECT open_segment FROM audit.head")
	res, files, _ := xe.run(t, "rootaud", id)
	if bodyIDs(t, files[evidence.FileRecords]) != "late1" || lastCheckpointSegment(t, files) != open || res.Segments != 1 {
		t.Fatalf("records %s, last checkpoint %s (open was %s), %d checkpoints",
			bodyIDs(t, files[evidence.FileRecords]), lastCheckpointSegment(t, files), open, res.Segments)
	}
	late("late2")
	id2 := xe.request(t, "rootaud", map[string]string{"target": "test:late"}, "jsonl")
	// Rows stop at the export's checkpoint: up to late1's position, only late1.
	late1 := xe.e.adminQuery("SELECT seq FROM audit.record WHERE event_id = 'late1'")
	if got, err := xe.e.as("app_audit", fmt.Sprintf("SELECT string_agg(event_id, ',') FROM audit.export_rows('%s', 0, %s, 100)", id2, late1)); err != nil || got != "late1" {
		t.Fatalf("rows up to %s: %s %v", late1, got, err)
	}
	res2, files2, _ := xe.run(t, "rootaud", id2)
	if got := bodyIDs(t, files2[evidence.FileRecords]); got != "late1,late2" || res2.Segments < 2 {
		t.Fatalf("second export %s over %d checkpoints", got, res2.Segments)
	}
}

// The River job (schema audit_river, as app_audit) runs the export the API
// queued in the request's transaction.
func TestAuditExportRiver(t *testing.T) {
	xe := newExportEnv(t, auditAPIFixture(t))
	rc, err := auditsvc.NewExportClient(xe.pool, xe.exporter, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = rc.Stop(sctx)
	})
	xe.api(t, auditsvc.Enqueuer(rc))
	id := xe.request(t, "rootaud", map[string]string{"type": "breakglass.enabled"}, "jsonl")
	deadline := time.Now().Add(60 * time.Second)
	for {
		g := xe.do(t, "rootaud", "GET", "/exports/"+id, "", nil)
		if g.body["status"] == "ready" {
			if fmt.Sprint(g.body["record_count"]) != "1" {
				t.Fatalf("export %s", g.raw)
			}
			break
		}
		if g.body["status"] == "failed" || time.Now().After(deadline) {
			t.Fatalf("export not ready: %s", g.raw)
		}
		time.Sleep(200 * time.Millisecond)
	}
	b := xe.do(t, "rootaud", "GET", "/exports/"+id+"/bundle", "", nil)
	if v, err := evidence.VerifyExport(strings.NewReader(b.raw), int64(len(b.raw)), evidence.Keys(xe.e.signingKeys())); err != nil || v.Records != 1 {
		t.Fatalf("bundle: %+v %v", v, err)
	}
	// The job lives in audit_river; iam's River and app_rw see nothing of
	// it, and app_audit nothing of iam's jobs.
	if got := xe.e.adminQuery("SELECT count(*) FROM audit_river.river_job WHERE kind = 'audit_export' AND queue = 'audit_export'"); got != "1" {
		t.Fatalf("%s audit export jobs", got)
	}
	if got := xe.e.adminQuery("SELECT count(*) FROM river.river_job WHERE kind = 'audit_export'"); got != "0" {
		t.Fatalf("%s audit jobs in iam's River", got)
	}
	if _, err := xe.e.as("app_rw", "SELECT count(*) FROM audit_river.river_job"); err == nil {
		t.Fatal("app_rw reads the audit service's jobs")
	}
	if _, err := xe.e.as("app_audit", "SELECT count(*) FROM river.river_job"); err == nil {
		t.Fatal("app_audit reads iam's jobs")
	}
}

// The audit store: a bundle written to an Object Lock bucket (FAIR_TEST_S3),
// locked, read back through the API, and verified.
func TestAuditExportS3(t *testing.T) {
	st, _, _ := testWORM(t)
	xe := newExportEnv(t, auditAPIFixture(t))
	xe.exporter.Store = st
	api := &auditapi.API{DB: xe.pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(xe.pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: xe.pool}), Enqueue: func(context.Context, pgx.Tx, string) error { return nil }, Bundles: st}
	srv := httptest.NewServer(api.Handler(xe.keys, nil))
	t.Cleanup(srv.Close)
	xe.url = srv.URL
	id := xe.request(t, "rootaud", map[string]string{}, "csv")
	res, err := xe.exporter.Run(context.Background(), id)
	if err != nil || !res.Created {
		t.Fatalf("export: %+v %v", res, err)
	}
	if res.Object.Key != auditsvc.ExportKey(xe.e.adminQuery("SELECT instance FROM audit.head"), id) {
		t.Fatalf("stored at %s", res.Object.Key)
	}
	until, err := st.RetainedUntil(context.Background(), res.Object)
	if err != nil || time.Until(until) < auditsvc.ExportRetention-time.Hour {
		t.Fatalf("retention until %v: %v", until, err)
	}
	b := xe.do(t, "rootaud", "GET", "/exports/"+id+"/bundle", "", nil)
	if v, err := evidence.VerifyExport(strings.NewReader(b.raw), int64(len(b.raw)), evidence.Keys(xe.e.signingKeys())); err != nil || uint64(v.Records) != res.Records { // #nosec G115 -- a count
		t.Fatalf("bundle from S3: %+v %v", v, err)
	}
}
