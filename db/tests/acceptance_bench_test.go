package tests

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/acceptance"
	"github.com/rformer/fair-app/internal/acceptanceapi"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-008 T-08 (requirements NFR "Performance"; design §9): the acceptance
// gate at the F-001 target scale (2,011 BUs, 10,000 users) over the register
// gate's 10,000 risks (seedRegisterBench), each with one acceptance: 6 in 10
// in force (some past or near their expiry), 2 in 10 pending at tier 1 or
// 2, 1 in 10 expired, 1 in 10 rejected. Budgets, p95, through the
// acceptance API (HTTP, JSON, authorization, the DB context and RLS):
//   - the list (newest, 200 rows, needs review, a subtree, expiring) and the
//     register's list by acceptance, as a user who sees them all: <= 1 s;
//   - the inbox of an approver at the root (2,000 pending): <= 1 s;
//   - an acceptance's page: <= 1 s;
//   - the job's sweeps over them (expiries, notices, the higher-tier check
//     of every acceptance in force; at most acceptance.sweep_batch() handled
//     per sweep, back to back while some are left): each within its
//     one-minute interval.
//
// Acceptances and their steps are written directly (the functions' checks
// are not what is measured).

const (
	acceptanceListBudget  = time.Second
	acceptancePageBudget  = time.Second
	acceptanceSweepBudget = time.Minute
)

func TestBenchmarkGateAcceptances(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	ctx := context.Background()
	total := registerBenchRisks
	if n := os.Getenv("FAIR_BENCH_ACCEPTANCES"); n != "" { // a smaller run, by hand
		total, _ = strconv.Atoi(n)
	}
	start := time.Now()
	l1 := seedRegisterBench(t, e, total)
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('benchapprover@example.test', 'Bench Approver')")
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = 'Approver'), '%s', '%s' FROM iam.app_user u WHERE u.email = 'benchapprover@example.test'`, root, granter))
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	e.mustOwner("DELETE FROM iam.outbox")
	owner := e.mustOwner("SELECT id FROM iam.app_user WHERE email = 'benchowner@example.test'")
	approver := e.mustOwner("SELECT id FROM iam.app_user WHERE email = 'benchapprover@example.test'")

	// One acceptance per risk, by the risk's seq: k 0-5 in force (expiring
	// from 20 days ago to a year on), 6-7 pending (odd seq: tier 2 at the
	// parent), 8 expired, 9 rejected; their steps as the functions leave them.
	conn := e.adminConn()
	defer func() { _ = conn.Close(ctx) }()
	for _, q := range []string{
		"SET session_replication_role = replica",
		fmt.Sprintf(`INSERT INTO acceptance.acceptance (bu_id, risk_id, state, end_reason, tier, tier_bu_id, approvals_needed, mean, expires_on, approved_bu_id,
			requested_by, requested_at, activated_at, ended_at, steps)
			SELECT r.bu_id, r.id, x.state, CASE WHEN x.state = 'ended' THEN 'rejected' END, x.tier,
			  CASE WHEN x.tier = 2 THEN coalesce(b.parent_id, r.bu_id) ELSE r.bu_id END, 1, 50000 + (r.seq %% 997) * 100,
			  CASE WHEN x.state = 'expired' THEN current_date - 1 ELSE current_date + ((r.seq %% 400)::integer - 20) END,
			  CASE WHEN x.state = 'active' THEN r.bu_id END, '%[1]s', now() - interval '30 days',
			  CASE WHEN x.state IN ('active', 'expired') THEN now() - interval '29 days' END,
			  CASE WHEN x.state IN ('ended', 'expired') THEN now() END,
			  CASE x.state WHEN 'active' THEN 3 WHEN 'pending' THEN 1 ELSE 2 END
			FROM register.risk r JOIN iam.bu b ON b.id = r.bu_id,
			  LATERAL (SELECT CASE WHEN r.seq %% 10 < 6 THEN 'active' WHEN r.seq %% 10 < 8 THEN 'pending' WHEN r.seq %% 10 = 8 THEN 'expired' ELSE 'ended' END AS state,
			                  CASE WHEN r.seq %% 10 IN (6, 7) AND r.seq %% 2 = 1 THEN 2 ELSE 1 END AS tier) x`, owner),
		fmt.Sprintf(`INSERT INTO acceptance.step (acceptance_id, n, bu_id, kind, actor, at, reason, data)
			SELECT a.id, 1, a.bu_id, 'requested', a.requested_by, a.requested_at, 'Within appetite',
			  jsonb_build_object('justification', 'Within appetite', 'expires_on', a.expires_on, 'exposure', jsonb_build_object('status', 'current', 'mean', a.mean),
			    'pins', '[]'::jsonb, 'tier', jsonb_build_object('n', a.tier, 'levels_up', a.tier - 1, 'approvals', 1, 'bu_id', a.tier_bu_id))
			FROM acceptance.acceptance a
			UNION ALL
			SELECT a.id, 2, a.bu_id, CASE WHEN a.state = 'ended' THEN 'rejected' ELSE 'approved' END, '%[1]s', a.requested_at + interval '1 day', 'Reviewed', '{}'
			FROM acceptance.acceptance a WHERE a.state <> 'pending'
			UNION ALL
			SELECT a.id, 3, a.bu_id, 'activated', '%[1]s', a.requested_at + interval '1 day', NULL, '{}'
			FROM acceptance.acceptance a WHERE a.state = 'active'`, approver),
		"SET session_replication_role = origin",
		"ANALYZE acceptance.acceptance; ANALYZE acceptance.step",
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q[:min(len(q), 60)], err)
		}
	}
	t.Logf("loaded: %s acceptances (%s pending) in %v", e.adminQuery("SELECT count(*) FROM acceptance.acceptance"),
		e.adminQuery("SELECT count(*) FROM acceptance.acceptance WHERE state = 'pending'"), time.Since(start).Round(time.Second))

	api := newBenchAcceptanceAPI(t, e)
	reg := newBenchRegisterAPI(t, e)
	ids := strings.Split(e.adminQuery("SELECT string_agg(id::text, ',') FROM (SELECT id FROM acceptance.acceptance ORDER BY md5(id::text) LIMIT 23) x"), ",")
	cases := []struct {
		name   string
		api    *benchRegisterAPI
		user   string
		path   func(i int) string
		budget time.Duration
	}{
		{"list, newest", api, "benchowner", fixed("/api/v1/acceptances"), acceptanceListBudget},
		{"list, 200 rows", api, "benchowner", fixed("/api/v1/acceptances?limit=200"), acceptanceListBudget},
		{"list, deep page", api, "benchowner", fixed("/api/v1/acceptances?offset=" + strconv.Itoa(total/2)), acceptanceListBudget},
		{"list, needs review", api, "benchowner", fixed("/api/v1/acceptances?state=needs_review"), acceptanceListBudget},
		{"list, pending", api, "benchowner", fixed("/api/v1/acceptances?state=pending"), acceptanceListBudget},
		{"list, expiring within 30 days", api, "benchowner", fixed("/api/v1/acceptances?expiring_within=30"), acceptanceListBudget},
		{"list, a level-1 subtree", api, "benchowner", fixed("/api/v1/acceptances?bu=" + l1), acceptanceListBudget},
		{"the inbox of an approver at the root", api, "benchapprover", fixed("/api/v1/acceptances/inbox"), acceptanceListBudget},
		{"an acceptance's page", api, "benchowner", func(i int) string { return "/api/v1/acceptances/" + ids[i%len(ids)] }, acceptancePageBudget},
		{"the register, accepted risks", reg, "benchowner", fixed("/api/v1/register/risks?acceptance=active"), acceptanceListBudget},
		{"the register, needing review", reg, "benchowner", fixed("/api/v1/register/risks?acceptance=needs_review"), acceptanceListBudget},
	}
	var results []benchResult
	failed := false
	for _, c := range cases {
		r := summarize("acceptances: "+c.name, c.api.time(t, c.user, c.path), c.budget)
		results = append(results, r)
		if r.P95ms > r.Budget {
			failed = true
		}
	}

	// The sweeps: from the load (every due expiry and notice, and the
	// acceptances whose exposure is above their tier), back to back while a
	// sweep stops at its batch, as Job.Run does; then one with nothing due.
	job := acceptance.Job{DB: e.appPool()}
	sweep := func() (acceptance.Swept, time.Duration) {
		t0 := time.Now()
		s, err := job.Sweep(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return s, time.Since(t0)
	}
	var all acceptance.Swept
	var longest, catchUp time.Duration
	sweeps := 0
	for more := true; more; sweeps++ {
		s, took := sweep()
		all.Expired, all.Notices, all.Suspended = all.Expired+s.Expired, all.Notices+s.Notices, all.Suspended+s.Suspended
		longest, catchUp, more = max(longest, took), catchUp+took, s.More
	}
	t.Logf("catching up: %d sweeps, %+v, %v in all, the longest %v", sweeps, all, catchUp.Round(time.Millisecond), longest.Round(time.Millisecond))
	ms := float64(longest.Milliseconds())
	results = append(results, benchResult{Name: fmt.Sprintf("acceptances: the longest of %d sweeps catching up (%d expired, %d notices, %d suspended in %v)",
		sweeps, all.Expired, all.Notices, all.Suspended, catchUp.Round(time.Second)), P50ms: ms, P95ms: ms, P99ms: ms, Budget: float64(acceptanceSweepBudget.Milliseconds())})
	if longest > acceptanceSweepBudget {
		failed = true
	}
	if s, took := sweep(); s != (acceptance.Swept{}) {
		t.Fatalf("after catching up: %+v", s)
	} else {
		ms := float64(took.Milliseconds())
		results = append(results, benchResult{Name: "acceptances: a sweep with nothing due", P50ms: ms, P95ms: ms, P99ms: ms, Budget: float64(acceptanceSweepBudget.Milliseconds())})
		if took > acceptanceSweepBudget {
			failed = true
		}
	}

	var rep strings.Builder
	fmt.Fprintf(&rep, "F-008 risk acceptance: %d acceptances over the BUs, through the acceptance API, %d runs after warm-up\n", total, registerBenchRuns)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.2f | %.2f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("acceptances over budget")
	}
}

func newBenchAcceptanceAPI(t *testing.T, e *env) *benchRegisterAPI {
	t.Helper()
	b := newBenchRiskAPI(t, e) // its keys
	pool := e.appPool()
	api := &acceptanceapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), Settings: defaultAcceptanceLimits}
	srv := httptest.NewServer(api.Handler(b.keys, nil))
	t.Cleanup(srv.Close)
	return &benchRegisterAPI{e: e, url: srv.URL, keys: b.keys}
}
