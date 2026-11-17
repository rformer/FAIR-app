package tests

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/reportapi"
	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-010 T-18 (requirements NFR "Performance"; design §9): the reports gate
// at the F-001 target scale (2,011 BUs, 10,000 users) over the register
// gate's 10,000 open risks (seedRegisterBench), as "benchowner" (Risk Owner,
// Risk Analyst and Report Publisher at the root, who sees them all), with
// a portfolio snapshot taken and 2,000 earlier reports of theirs. Budgets:
//   - the dashboard of the root, p95, through the reports API: <= 2 s;
//   - the list of the requester's reports (newest, a deep page), p95: <= 500 ms;
//   - generation, from the request through the API to the run's files
//     stored and recorded (the worker's attempt: the delegated read, the
//     document, rendering, digests): the register of the root as PDF
//     <= 60 s, as CSV <= 15 s, as JSON <= 15 s; a risk report <= 30 s; the
//     portfolio of the root (PDF) <= 60 s.
//
// The earlier reports are written directly (the functions' checks are not
// what is measured).

const (
	reportDashboardBudget = 2 * time.Second
	reportListBudget      = 500 * time.Millisecond
	reportPDFBudget       = 60 * time.Second
	reportDataBudget      = 15 * time.Second
	reportRiskBudget      = 30 * time.Second
	reportPortfolioBudget = 60 * time.Second
	reportBenchEarlier    = 2_000
)

func TestBenchmarkGateReports(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	ctx := context.Background()
	total := registerBenchRisks
	if n := os.Getenv("FAIR_BENCH_REPORT_RISKS"); n != "" { // a smaller run, by hand
		total, _ = strconv.Atoi(n)
	}
	start := time.Now()
	l1 := seedRegisterBench(t, e, total)
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = 'Report Publisher'), '%s', '%s' FROM iam.app_user u WHERE u.email = 'benchowner@example.test'`, root, granter))
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	e.mustOwner("DELETE FROM iam.outbox")
	owner := e.mustOwner("SELECT id FROM iam.app_user WHERE email = 'benchowner@example.test'")
	e.mustOwner(fmt.Sprintf("SELECT authz.add_ctx_key('%s', decode('%s', 'hex'), 'report')", reportKey.ID, hex.EncodeToString(reportKey.Secret)))

	t0 := time.Now()
	e.adminQuery("SELECT report.snapshot_tick(7, 1095)")
	snapshot := time.Since(t0)

	// The earlier reports: succeeded, a week of them, each with a PDF.
	conn := e.adminConn()
	defer func() { _ = conn.Close(ctx) }()
	for _, q := range []string{
		"SET session_replication_role = replica",
		fmt.Sprintf(`INSERT INTO report.run (requested_by, bu_id, kind, formats, state, progress, attempts, data_as_of, risk_count, left_out, requested_at, started_at, finished_at)
			SELECT '%s', '%s', 'register', '{pdf}', 'succeeded', 100, 1, now() - i * interval '5 minutes', 100, '{}', now() - i * interval '5 minutes',
			  now() - i * interval '5 minutes', now() - i * interval '5 minutes' + interval '10 seconds'
			FROM generate_series(1, %d) i`, owner, l1, reportBenchEarlier),
		`INSERT INTO report.file (run_id, format, object_key, version_id, size, sha256)
			SELECT id, 'pdf', 'reports/bench/' || id || '/report.pdf', 'v1', 123456, repeat('c', 64) FROM report.run`,
		"SET session_replication_role = origin",
		"ANALYZE report.run; ANALYZE report.file",
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q[:min(len(q), 60)], err)
		}
	}
	t.Logf("loaded in %v; the snapshot took %v", time.Since(start).Round(time.Second), snapshot.Round(time.Millisecond))

	api, worker := newBenchReportAPI(t, e)
	var results []benchResult
	failed := false
	for _, c := range []struct {
		name   string
		path   func(int) string
		budget time.Duration
	}{
		{"the dashboard of the root", fixed("/api/v1/reports/dashboard?bu=" + root), reportDashboardBudget},
		{"the dashboard of a level-1 subtree", fixed("/api/v1/reports/dashboard?bu=" + l1), reportDashboardBudget},
		{"my reports, newest", fixed("/api/v1/reports"), reportListBudget},
		{"my reports, a deep page", fixed(fmt.Sprintf("/api/v1/reports?offset=%d", reportBenchEarlier/2)), reportListBudget},
	} {
		r := summarize("reports API: "+c.name, api.time(t, "benchowner", c.path), c.budget)
		results = append(results, r)
		if r.P95ms > r.Budget {
			failed = true
		}
	}

	risk := e.adminQuery(`SELECT r.id FROM register.risk r JOIN register.risk_scenario l ON l.risk_id = r.id AND l.run_id IS NOT NULL
		JOIN iam.bu_closure c ON c.descendant_id = r.bu_id AND c.ancestor_id = '` + l1 + `' ORDER BY r.seq LIMIT 1`)
	for _, c := range []struct {
		name   string
		body   map[string]any
		budget time.Duration
	}{
		{"the register of the root as PDF", map[string]any{"kind": "register", "bu_id": root, "formats": []string{"pdf"}}, reportPDFBudget},
		{"the register of the root as CSV", map[string]any{"kind": "register", "bu_id": root, "formats": []string{"csv"}}, reportDataBudget},
		{"the register of the root as JSON", map[string]any{"kind": "register", "bu_id": root, "formats": []string{"json"}}, reportDataBudget},
		{"a risk report (PDF)", map[string]any{"kind": "risk", "bu_id": l1, "params": map[string]any{"risk": risk}, "formats": []string{"pdf"}}, reportRiskBudget},
		{"the portfolio of the root (PDF)", map[string]any{"kind": "portfolio", "bu_id": root, "formats": []string{"pdf"}}, reportPortfolioBudget},
	} {
		t0 := time.Now()
		id := api.post(t, "benchowner", "/api/v1/reports", c.body)
		if err := worker.Attempt(ctx, id, 1, reports.Attempts); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		took := time.Since(t0)
		got := e.adminQuery("SELECT state || ' ' || coalesce(risk_count::text, '-') || ' ' || coalesce(failure, '') FROM report.run WHERE id = '" + id + "'")
		if !strings.HasPrefix(got, "succeeded ") {
			t.Fatalf("%s: %s", c.name, got)
		}
		size := e.adminQuery("SELECT coalesce(sum(size), 0) FROM report.file WHERE run_id = '" + id + "'")
		ms := float64(took.Milliseconds())
		results = append(results, benchResult{Name: fmt.Sprintf("generate %s (%s risks, %s bytes), request to stored", c.name, strings.Fields(got)[1], size),
			P50ms: ms, P95ms: ms, P99ms: ms, Budget: float64(c.budget.Milliseconds())})
		if took > c.budget {
			failed = true
		}
	}

	var rep strings.Builder
	fmt.Fprintf(&rep, "F-010 reports: %d open risks over the BUs (8 in 10 pinned), as a user who sees them all, %d runs after warm-up for reads\n", total, registerBenchRuns)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.2f | %.2f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("reports over budget")
	}
}

// newBenchReportAPI serves the reports API with every kind (jobs queued,
// worked by the returned worker), files in memory and no reason rule.
func newBenchReportAPI(t *testing.T, e *env) (*benchRegisterAPI, *reports.Worker) {
	t.Helper()
	b := newBenchRiskAPI(t, e) // its keys
	pool := e.appPool()
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: reports.RiverSchema})
	if err != nil {
		t.Fatal(err)
	}
	store := newMemStore()
	kinds := reports.Kinds()
	api := &reportapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), Kinds: kinds,
		Enqueue: reports.Enqueuer(rc), Store: store, Settings: reason.Static{}}
	srv := httptest.NewServer(api.Handler(b.keys, nil))
	t.Cleanup(srv.Close)
	w := &reports.Worker{DB: pool, Key: reportKey, Store: store, Kinds: kinds, Marking: func() (string, error) { return "Confidential", nil }}
	return &benchRegisterAPI{e: e, url: srv.URL, keys: b.keys}, w
}
