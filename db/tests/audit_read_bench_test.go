package tests

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/authz"
)

// F-002 T-12 (NFR: search p95 <= 2 s for indexed filters over the online
// retention period at target scale): 10 million records over 12 monthly
// partitions, filed under the F-001 target-scale tree (2,000 BUs), searched
// through audit.search as app_audit by an auditor at the root and one at a
// single BU (the benchmark scale chosen 2026-11-05; design §5).

const (
	auditBenchRecords = 10_000_000
	auditSearchBudget = 2 * time.Second
	auditSearchRuns   = 20
)

func TestBenchmarkGateAuditSearch(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	start := time.Now()
	n := auditBenchRecords
	if s := os.Getenv("FAIR_BENCH_AUDIT_RECORDS"); s != "" { // a smaller run, by hand
		n, _ = strconv.Atoi(s)
	}
	// Two auditors: at the root, and at one leaf BU.
	leaf := e.mustOwner("SELECT id FROM iam.bu b WHERE NOT EXISTS (SELECT 1 FROM iam.bu c WHERE c.parent_id = b.id) AND NOT b.restricted ORDER BY code LIMIT 1")
	e.mustOwner(`INSERT INTO iam.app_user (email, display_name) VALUES ('benchroot@example.test', 'Bench Root'), ('benchleaf@example.test', 'Bench Leaf')`)
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = 'Auditor'), CASE u.email WHEN 'benchroot@example.test' THEN (SELECT id FROM iam.bu WHERE parent_id IS NULL) ELSE '%s'::uuid END, '%s'
		FROM iam.app_user u WHERE u.email IN ('benchroot@example.test', 'benchleaf@example.test')`, leaf, granter))
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")

	// The records: one every ~3 s over 12 months, cycling through 2,000 BUs,
	// 20 types, 5,000 actors, 100,000 targets; a request per 3 records; a
	// source address on every tenth. Hashes are placeholders: search does
	// not read them.
	for m := 0; m <= 12; m++ {
		e.adminQuery(fmt.Sprintf("SELECT audit.ensure_partition(now() - interval '%d months')", m))
	}
	const batch = 1_000_000
	for lo := 1; lo <= n; lo += batch {
		hi := min(lo+batch-1, n)
		e.admin(e.db, fmt.Sprintf(`SET session_replication_role = replica;
			WITH b AS (SELECT array_agg(id ORDER BY md5(id::text)) AS ids FROM iam.bu)
			INSERT INTO audit.record (seq, event_id, event_time, received_at, producer, type, category, severity, actor, target, bu_id,
			                          request_id, source_ip, approval_id, skew, body, leaf_hash, chain_hash, segment)
			SELECT i, 'ev-' || i, now() - interval '360 days' + ((i::float8 / %[3]d) * interval '360 days'), now() - interval '360 days' + ((i::float8 / %[3]d) * interval '360 days'),
			       'app_rw', 'type.' || (i %% 20), (ARRAY['access','configuration','session','system'])[1 + i %% 4],
			       (ARRAY['info','low','high','critical'])[1 + (i / 7) %% 4], 'actor-' || (i %% 5000), 'target:' || (i %% 100000),
			       b.ids[1 + i %% cardinality(b.ids)], 'req-' || (i / 3),
			       CASE WHEN i %% 10 = 0 THEN ('10.' || (i %% 250) || '.' || ((i / 250) %% 250) || '.1')::inet END, NULL, false,
			       convert_to('{"id":"ev-' || i || '"}', 'UTF8'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), i / 50000 + 1
			FROM generate_series(%[1]d, %[2]d) i, b`, lo, hi, n))
		t.Logf("records to %d: %v", hi, time.Since(start).Round(time.Second))
	}
	e.admin(e.db, "ANALYZE audit.record")
	t.Logf("loaded %d records in %v", n, time.Since(start).Round(time.Second))

	pool := e.auditPool()
	profiles := map[string]profile{}
	for _, email := range []string{"benchroot", "benchleaf"} {
		var p profile
		row := e.mustOwner(fmt.Sprintf("SELECT u.id || '|' || s.scope_version FROM iam.app_user u JOIN authz.user_scope s ON s.user_id = u.id WHERE u.email = '%s@example.test'", email))
		parts := strings.Split(row, "|")
		p.name, p.userID = email, parts[0]
		p.version, _ = strconv.ParseInt(parts[1], 10, 64)
		profiles[email] = p
	}
	mid := n / 2
	leafActor := e.adminQuery("SELECT actor FROM audit.record WHERE bu_id = '" + leaf + "' ORDER BY seq DESC LIMIT 1")
	month := time.Now().AddDate(0, -6, 0).UTC()
	cases := []struct {
		name, user, filter string
		before             *int
	}{
		{"newest, no filter", "benchroot", `{}`, nil},
		{"type", "benchroot", `{"type":"type.7"}`, nil},
		{"category", "benchroot", `{"category":"session"}`, nil},
		{"severity", "benchroot", `{"severity":"critical"}`, nil},
		{"actor", "benchroot", `{"actor":"actor-4242"}`, nil},
		{"target", "benchroot", `{"target":"target:31337"}`, nil},
		{"request", "benchroot", fmt.Sprintf(`{"request_id":"req-%d"}`, mid/3), nil},
		{"source range", "benchroot", `{"source_ip":"10.40.0.0/16"}`, nil},
		{"one month", "benchroot", fmt.Sprintf(`{"from":"%s","to":"%s"}`, month.Format(time.RFC3339), month.AddDate(0, 1, 0).Format(time.RFC3339)), nil},
		{"type and actor", "benchroot", `{"type":"type.2","actor":"actor-1002"}`, nil},
		{"deep page", "benchroot", `{"type":"type.7"}`, &mid},
		{"one BU, no filter", "benchleaf", `{}`, nil},
		{"one BU, type", "benchleaf", `{"type":"type.3"}`, nil},
		{"one BU, actor", "benchleaf", `{"actor":"` + leafActor + `"}`, nil},
	}
	var results []benchResult
	failed := false
	for _, c := range cases {
		p := profiles[c.user]
		var before any
		if c.before != nil {
			before = *c.before
		}
		ds := timeAuditSearch(t, pool, p, c.filter, before)
		r := summarize("audit search: "+c.name, ds, auditSearchBudget)
		results = append(results, r)
		if r.P95ms > r.Budget {
			failed = true
		}
	}
	var rep strings.Builder
	fmt.Fprintf(&rep, "F-002 audit search: %d records over 12 months, 2,011 BUs; audit.search (50 rows) as app_audit in a DB context, %d runs after warm-up\n", n, auditSearchRuns)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.2f | %.2f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("audit search over budget")
	}
}

// timeAuditSearch times audit.search (50 rows) as the API runs it: a
// transaction in the user's DB context, all rows read.
func timeAuditSearch(t *testing.T, pool *pgxpool.Pool, p profile, filter string, before any) []time.Duration {
	t.Helper()
	ctx := context.Background()
	out := make([]time.Duration, 0, auditSearchRuns)
	for i := range auditSearchRuns + 3 {
		tok, err := authz.MintDBContext(ctxKey1, p.userID, p.version, time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		rows := 0
		t0 := time.Now()
		err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('authz.ctx', $1, true)", tok); err != nil {
				return err
			}
			rs, err := tx.Query(ctx, "SELECT seq FROM audit.search($1, $2, 50)", filter, before)
			if err != nil {
				return err
			}
			for rs.Next() {
				rows++
			}
			return rs.Err()
		})
		if err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
		if rows == 0 {
			t.Fatalf("%s for %s: no rows (the benchmark would measure nothing)", filter, p.name)
		}
		if i >= 3 { // warm-up
			out = append(out, time.Since(t0))
		}
	}
	return out
}
