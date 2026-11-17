package tests

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/reportapi"
	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-010 T-17: the reports API in the UI harness, mounted beside the risk
// service's other APIs as cmd/risk does, with the report River worker (the
// built-in kinds, files in memory) and the reason rule of a restricted
// subtree (export.reason_required on at R, as F-015's overlay sets it).

// mountHarnessReports mounts the reports API on mux and starts its worker.
func mountHarnessReports(t *testing.T, e *env, mux *http.ServeMux, rp *pgxpool.Pool, keys *authz.LocalKeys, rule reason.Settings) func() {
	t.Helper()
	ctx := context.Background()
	e.mustOwner(fmt.Sprintf("SELECT authz.add_ctx_key('%s', decode('%s', 'hex'), 'report')", reportKey.ID, hex.EncodeToString(reportKey.Secret)))
	store := newMemStore()
	kinds := reports.Kinds()
	w := &reports.Worker{DB: rp, Key: reportKey, Store: store, Kinds: kinds, Marking: func() (string, error) { return "Confidential", nil }}
	rc, err := reports.NewClient(rp, w, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	api := &reportapi.API{DB: rp, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(rp), MaxAge: time.Second}), Kinds: kinds,
		Enqueue: reports.Enqueuer(rc), Store: store, Settings: rule}
	h := api.Handler(keys, nil)
	for _, prefix := range reportapi.Prefixes {
		mux.Handle(prefix, h)
		mux.Handle(prefix+"/", h)
	}
	return func() { _ = rc.Stop(context.Background()) }
}

// seedReports (F-010 T-17): "publisher" (Executive Viewer and Report
// Publisher at the root) with two portfolio snapshots of the root, a week
// apart (the first before their roll-up of the root, the second after), a
// register report generated as PDF, CSV and JSON, and a weekly schedule;
// "investigator" also publishes reports at the restricted R, where a reason
// is required.
func seedReports(t *testing.T, e *env, keys *authz.LocalKeys, url string) {
	t.Helper()
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('publisher@example.test', 'Pat Publisher')")
	e.mustOwner(grant("admin", "user:publisher", "Executive Viewer", "ENTERPRISE"))
	e.mustOwner(grant("admin", "user:publisher", "Report Publisher", "ENTERPRISE"))
	e.mustOwner(grant("admin", "user:investigator", "Report Publisher", "R"))
	e.drain()
	root := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'ENTERPRISE'")
	ea := &riskAPIEnv{riskEnv: riskEnv{e, map[string]string{"ENTERPRISE": root}}, url: url, keys: keys, n: 600000}
	e.adminQuery("SELECT report.snapshot_tick(7, 1095)")
	got := ea.call(t, "POST", "publisher", "/api/v1/register/rollups", map[string]any{"bu_id": root})
	if got.code != 201 && got.code != 202 && got.code != 200 {
		t.Fatalf("seed report roll-up: %d %s", got.code, got.raw)
	}
	rollup := got.body["id"].(string)
	waitAPI(t, ea, "publisher", "/api/v1/register/rollups/"+rollup, "succeeded", "failed")
	e.adminQuery("SET session_replication_role = replica; UPDATE report.snapshot SET taken_at = taken_at - interval '7 days'")
	e.adminQuery("SELECT report.snapshot_tick(7, 1095)")
	got = ea.call(t, "POST", "publisher", "/api/v1/reports", map[string]any{"kind": "register", "bu_id": root, "formats": []string{"pdf", "csv", "json"},
		"reason": "Risk committee pack"}) // the root's subtree holds R, where a reason is required
	if got.code != 202 {
		t.Fatalf("seed report: %d %s", got.code, got.raw)
	}
	waitAPI(t, ea, "publisher", "/api/v1/reports/"+got.body["id"].(string), "succeeded", "failed")
	got = ea.call(t, "POST", "publisher", "/api/v1/reports/schedules", map[string]any{"kind": "portfolio", "bu_id": root, "formats": []string{"pdf"},
		"cadence": "weekly", "weekday": 1, "hour": 6, "params": map[string]any{"period_days": 90}, "reason": "Weekly risk committee"})
	if got.code != 201 {
		t.Fatalf("seed schedule: %d %s", got.code, got.raw)
	}
	t.Log("reports seeded")
}

// waitAPI polls path as user until its state is want (or one of fail).
func waitAPI(t *testing.T, ea *riskAPIEnv, user, path, want string, fail ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		got := ea.call(t, "GET", user, path, nil)
		st, _ := got.body["state"].(string)
		if st == want {
			return
		}
		for _, f := range fail {
			if st == f {
				t.Fatalf("%s: %s (%s)", path, st, got.raw)
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s: not %s in time", path, want)
}
