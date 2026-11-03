package tests

// F-001 T-11: benchmark gate for authz.visible_bus + RLS at target scale
// (requirements NFR: authorization decisions p95 <= 10 ms; scale 10k users,
// 2k BUs, 50k assignments; design D-OQ3) and for the BU closure rebuild
// (design R1). Runs only with FAIR_BENCH=1.
//
// T-11b: results depend on where a caller's rows sit, so list queries are
// measured for every scope size with the caller's rows spread uniformly, the
// oldest, and the newest (one table per placement), in the shape services
// issue them (authz.NewestQuery, T-11c). The plain query is reported too,
// without a budget.
//
//   - FAIR_BENCH_REPORT=<path>   write the Markdown report there
//   - FAIR_BENCH_BASELINE=<path> compare against this baseline (JSON)
//   - FAIR_BENCH_WRITE_BASELINE=<path> write this run as the new baseline
//
// The gate fails when a request-path p95 exceeds 10 ms, or when any result
// exceeds max(3 x baseline, baseline + 5 ms); CI hardware varies, so the
// regression check is deliberately coarse and the NFR is the hard limit.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/authz"
)

const (
	benchIterations = 300
	requestBudget   = 10 * time.Millisecond // NFR p95 for the request path
	rebuildBudget   = 2 * time.Second       // closure rebuild at 2k BUs (R1)
)

type benchResult struct {
	Name   string  `json:"name"`
	P50ms  float64 `json:"p50_ms"`
	P95ms  float64 `json:"p95_ms"`
	P99ms  float64 `json:"p99_ms"`
	Budget float64 `json:"budget_ms"` // 0 = informative only
}

func percentile(ds []time.Duration, p float64) float64 {
	s := slices.Clone(ds)
	slices.Sort(s)
	i := int(float64(len(s)-1) * p)
	return float64(s[i].Microseconds()) / 1000
}

func summarize(name string, ds []time.Duration, budget time.Duration) benchResult {
	return benchResult{Name: name, P50ms: percentile(ds, .5), P95ms: percentile(ds, .95), P99ms: percentile(ds, .99),
		Budget: float64(budget.Microseconds()) / 1000}
}

// benchTables are the BU-owned tables of the gate, 100 rows per BU each:
// bench_doc spreads every BU's rows uniformly; bench_<scope>_old and _new put
// that profile's visible BUs' rows first (the oldest) or last (the newest).
var benchTables = []string{"bench_doc", "bench_small_old", "bench_small_new", "bench_medium_old", "bench_medium_new", "bench_large_old", "bench_large_new"}

// benchSetup loads the target-scale dataset, materializes every scope and
// adds the BU-owned tables (filled once the profiles are known: benchFill).
func benchSetup(t *testing.T) *env {
	e := setup(t)
	start := time.Now()
	e.mustOwner(scaleLoad)
	dir := t.TempDir()
	copyMigrations(t, e.root, dir)
	var ddl strings.Builder
	for _, tb := range benchTables {
		fmt.Fprintf(&ddl, `CREATE TABLE iam.%[1]s (id bigserial PRIMARY KEY, bu_id uuid NOT NULL, title text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
SELECT authz.apply_bu_rls('iam.%[1]s', 'register');
GRANT SELECT, INSERT, UPDATE, DELETE ON iam.%[1]s TO app_rw;
GRANT USAGE ON SEQUENCE iam.%[1]s_id_seq TO app_rw;
`, tb)
	}
	if err := os.WriteFile(filepath.Join(dir, "9200_bench_doc.sql"), []byte(ddl.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.migrate(dir); err != nil {
		t.Fatal(err)
	}
	// Uniform: one row per BU per round, BUs in a fixed shuffled order.
	e.admin(e.db, `INSERT INTO iam.bench_doc (bu_id, title)
		SELECT b.id, 'doc ' || g FROM generate_series(1, 100) g, iam.bu b ORDER BY g, md5(b.id::text);
		ANALYZE iam.bench_doc`)
	// Materialize every scope; the bulk load's outbox rows are then redundant.
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	e.mustOwner("DELETE FROM iam.outbox")
	e.addCtxKey(ctxKey1)
	t.Logf("setup: %s in %v",
		e.mustOwner("SELECT (SELECT count(*) FROM iam.app_user) || ' users, ' || (SELECT count(*) FROM iam.bu) || ' BUs, ' || (SELECT count(*) FROM iam.assignment) || ' assignments, ' || (SELECT count(*) FROM authz.user_scope) || ' scopes'"),
		time.Since(start).Round(time.Second))
	return e
}

type profile struct {
	name    string
	userID  string
	version int64
	bus     int // register BUs readable
	oneBU   string
	onePK   int64
}

// benchFill fills a profile's placement tables: its visible BUs' rows first
// (_old) or last (_new), each part interleaved across its BUs.
func (e *env) benchFill(p profile) {
	for _, c := range []struct{ suffix, first string }{{"old", "true"}, {"new", "false"}} {
		e.admin(e.db, fmt.Sprintf(`INSERT INTO iam.bench_%[1]s_%[2]s (bu_id, title)
			SELECT b.id, 'doc ' || g FROM generate_series(1, 100) g, iam.bu b
			ORDER BY (b.id::text IN (SELECT jsonb_array_elements_text(s.read_bus->'register') FROM authz.user_scope s WHERE s.user_id = '%[3]s')) = %[4]s DESC,
			         g, md5(b.id::text);
			ANALYZE iam.bench_%[1]s_%[2]s`, p.name, c.suffix, p.userID, c.first))
	}
}

// profiles picks the users with the smallest, median and largest register
// read scope.
func (e *env) profiles(t *testing.T, conn *pgx.Conn) []profile {
	rows, err := conn.Query(context.Background(), `
		WITH s AS (
		  SELECT user_id, scope_version, jsonb_array_length(read_bus->'register') AS n, read_bus->'register'->>0 AS bu,
		         row_number() OVER (ORDER BY jsonb_array_length(read_bus->'register'), user_id) AS r, count(*) OVER () AS c
		  FROM authz.user_scope WHERE read_bus ? 'register')
		SELECT CASE WHEN r = 1 THEN 'small' WHEN r = c THEN 'large' ELSE 'medium' END, user_id::text, scope_version, n, bu,
		       (SELECT max(id) FROM iam.bench_doc d WHERE d.bu_id = s.bu::uuid)
		FROM s WHERE r IN (1, c / 2, c) ORDER BY n`)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (profile, error) {
		var p profile
		return p, r.Scan(&p.name, &p.userID, &p.version, &p.bus, &p.oneBU, &p.onePK)
	})
	if err != nil || len(ps) != 3 {
		t.Fatalf("profiles: %v %v", ps, err)
	}
	return ps
}

// timeTx measures whole request transactions: set the context, run sql, commit.
func timeTx(t *testing.T, pool *pgxpool.Pool, p profile, sql string, args ...any) []time.Duration {
	ctx := context.Background()
	out := make([]time.Duration, 0, benchIterations)
	for i := range benchIterations + 20 {
		tok, err := authz.MintDBContext(ctxKey1, p.userID, p.version, time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('authz.ctx', $1, true)", tok); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, sql, args...)
			if err != nil {
				return err
			}
			for rows.Next() {
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		if i >= 20 { // warm-up
			out = append(out, time.Since(t0))
		}
	}
	return out
}

func TestBenchmarkGate(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the T-11 benchmark gate")
	}
	e := benchSetup(t)
	pool := e.appPool()
	admin := e.adminConn()
	var results []benchResult

	profiles := e.profiles(t, admin)
	for _, p := range profiles {
		e.benchFill(p)
	}
	for _, p := range profiles {
		label := fmt.Sprintf("%s scope (%d BUs)", p.name, p.bus)
		// Sanity: the profile really sees its BUs through RLS.
		var n int
		tok, _ := authz.MintDBContext(ctxKey1, p.userID, p.version, time.Minute, time.Now())
		if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), "SELECT set_config('authz.ctx', $1, true)", tok); err != nil {
				return err
			}
			return tx.QueryRow(context.Background(), "SELECT cardinality(authz.visible_bus('register'))").Scan(&n)
		}); err != nil || n != p.bus {
			t.Fatalf("%s: visible_bus returned %d BUs (%v), want %d", label, n, err, p.bus)
		}
		results = append(results,
			summarize(label+": visible_bus", timeTx(t, pool, p, "SELECT cardinality(authz.visible_bus('register'))"), requestBudget),
			summarize(label+": row by primary key", timeTx(t, pool, p, "SELECT id, title FROM iam.bench_doc WHERE id = $1", p.onePK), requestBudget),
			summarize(label+": count in one BU", timeTx(t, pool, p, "SELECT count(*) FROM iam.bench_doc WHERE bu_id = $1", p.oneBU), requestBudget),
		)
		// Newest 50 rows, by placement: as services list (authz.NewestQuery,
		// budgeted), and the plain query (reported only).
		for _, pl := range []struct{ name, table string }{
			{"spread", "iam.bench_doc"}, {"oldest", "iam.bench_" + p.name + "_old"}, {"newest", "iam.bench_" + p.name + "_new"},
		} {
			q := authz.NewestQuery{Table: pl.table, ResourceType: "register", Columns: []string{"id", "title"}, OrderBy: "id", Limit: 50}
			sql, err := q.SQL()
			if err != nil {
				t.Fatal(err)
			}
			results = append(results,
				summarize(fmt.Sprintf("%s: newest 50 (NewestQuery), rows %s", label, pl.name), timeTx(t, pool, p, sql, nil), requestBudget),
				summarize(fmt.Sprintf("%s: newest 50 (plain query), rows %s", label, pl.name),
					timeTx(t, pool, p, "SELECT id, title FROM "+pl.table+" ORDER BY id DESC LIMIT 50"), 0))
		}
	}

	// The same queries without RLS (superuser), for the overhead column.
	noRLS := func(sql string, args ...any) []time.Duration {
		ds := make([]time.Duration, 0, benchIterations)
		for range benchIterations {
			t0 := time.Now()
			rows, err := admin.Query(context.Background(), sql, args...)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
			}
			rows.Close()
			ds = append(ds, time.Since(t0))
		}
		return ds
	}
	results = append(results,
		summarize("no RLS (superuser): newest 50 rows", noRLS("SELECT id, title FROM iam.bench_doc ORDER BY id DESC LIMIT 50"), 0),
		summarize("no RLS (superuser): row by primary key", noRLS("SELECT id, title FROM iam.bench_doc WHERE id = 1"), 0))

	// Closure rebuild (design R1) on the 2k-BU tree.
	rebuild := func(name, sql string) {
		var ds []time.Duration
		for range 5 {
			t0 := time.Now()
			if _, err := admin.Exec(context.Background(), sql); err != nil {
				t.Fatal(err)
			}
			ds = append(ds, time.Since(t0))
		}
		results = append(results, summarize(name, ds, rebuildBudget))
	}
	rebuild("closure: restrict + unrestrict a level-1 BU (~200 below)",
		"UPDATE iam.bu SET restricted = true WHERE code = 'L1_3'; UPDATE iam.bu SET restricted = false WHERE code = 'L1_3'")
	rebuild("closure: move a level-2 subtree and back",
		`UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code = 'L1_4') WHERE code = 'L2_3_1';
		 UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code = 'L1_3') WHERE code = 'L2_3_1'`)

	report := benchReport(results)
	t.Log("\n" + report)
	if path := os.Getenv("FAIR_BENCH_REPORT"); path != "" {
		if err := os.WriteFile(path, []byte(report), 0o600); err != nil { // #nosec G703 -- operator-chosen output path for a test run
			t.Fatal(err)
		}
	}
	if path := os.Getenv("FAIR_BENCH_WRITE_BASELINE"); path != "" {
		b, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil { // #nosec G703 -- operator-chosen output path for a test run
			t.Fatal(err)
		}
	}

	var baseline map[string]benchResult
	if path := os.Getenv("FAIR_BENCH_BASELINE"); path != "" {
		b, err := os.ReadFile(path) // #nosec G304 G703 -- operator-chosen baseline for a test run
		if err != nil {
			t.Fatal(err)
		}
		var list []benchResult
		if err := json.Unmarshal(b, &list); err != nil {
			t.Fatal(err)
		}
		baseline = map[string]benchResult{}
		for _, r := range list {
			baseline[r.Name] = r
		}
	}
	for _, r := range results {
		if r.Budget > 0 && r.P95ms > r.Budget {
			t.Errorf("%s: p95 %.2f ms exceeds the %.0f ms budget", r.Name, r.P95ms, r.Budget)
		}
		if b, ok := baseline[r.Name]; ok && r.Budget > 0 {
			if limit := max(3*b.P95ms, b.P95ms+5); r.P95ms > limit {
				t.Errorf("%s: p95 %.2f ms regressed past %.2f ms (baseline %.2f ms)", r.Name, r.P95ms, limit, b.P95ms)
			}
		}
	}
}

func benchReport(results []benchResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# F-001 T-11 benchmark report\n\n")
	fmt.Fprintf(&b, "Generated by `TestBenchmarkGate` (db/tests/bench_test.go) on %s.\n\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "Dataset: the T-08 target-scale load (10,001 users, 2,011 BUs, ~52k assignments, all scopes materialized) plus BU-owned tables under `authz.apply_bu_rls`, 201,100 rows each (100 per BU): `iam.bench_doc` spreads every BU's rows uniformly; for each profile, `bench_<scope>_old` and `_new` put that profile's visible BUs' rows first (the oldest) or last (the newest) (T-11b).\n\n")
	fmt.Fprintf(&b, "\"NewestQuery\" rows run `authz.NewestQuery` (T-11c), the way services list BU-owned rows; \"plain query\" rows run `SELECT ... ORDER BY id DESC LIMIT 50` for comparison and have no budget. Policies use the ADR-007 amendment 1 scope forms (T-11d).\n\n")
	fmt.Fprintf(&b, "Request rows time a whole transaction as app_rw over a connection pool: `set_config('authz.ctx', token)`, the query, commit (%d iterations after warm-up). Budget: NFR p95 <= 10 ms. Closure rows time one statement pair as superuser (5 runs).\n\n", benchIterations)
	fmt.Fprintf(&b, "| Measurement | p50 ms | p95 ms | p99 ms | Budget ms |\n|---|---:|---:|---:|---:|\n")
	for _, r := range results {
		budget := "-"
		if r.Budget > 0 {
			budget = fmt.Sprintf("%.0f", r.Budget)
		}
		fmt.Fprintf(&b, "| %s | %.2f | %.2f | %.2f | %s |\n", r.Name, r.P50ms, r.P95ms, r.P99ms, budget)
	}
	return b.String()
}
