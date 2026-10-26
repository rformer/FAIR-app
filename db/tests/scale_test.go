package tests

// F-001 T-08 verification: change -> scope visible <= 60 s p99 at target
// scale (10k users, 2k BUs, 50k assignments; requirements NFR "Scale").
// Slow: runs only with FAIR_TEST_SCALE=1.

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// scopeSLA is the NFR; the worker's poll interval (2 s by default) is added
// to every measured drain, so drains must finish well inside it.
const (
	scopeSLA   = 60 * time.Second
	pollBudget = 2 * time.Second
)

const scaleLoad = `
DO $$
DECLARE r uuid; a uuid; b uuid; i int; j int; k int;
BEGIN
  SELECT id INTO r FROM iam.bu WHERE parent_id IS NULL;
  FOR i IN 1..10 LOOP
    INSERT INTO iam.bu (name, code, parent_id, restricted) VALUES ('a', 'L1_' || i, r, false) RETURNING id INTO a;
    FOR j IN 1..10 LOOP
      INSERT INTO iam.bu (name, code, parent_id, restricted) VALUES ('b', 'L2_' || i || '_' || j, a, false) RETURNING id INTO b;
      FOR k IN 1..19 LOOP
        INSERT INTO iam.bu (name, code, parent_id, restricted) VALUES ('c', 'L3_' || i || '_' || j || '_' || k, b, false);
      END LOOP;
    END LOOP;
  END LOOP;
END $$;
-- 5% of leaf BUs restricted, with mixed roll-up modes.
UPDATE iam.bu SET restricted = true, rollup_mode = (ARRAY['excluded', 'aggregate', 'full']::iam.bu_rollup_mode[])[1 + (hashtext(code) & 1023) % 3]
WHERE depth = 3 AND (hashtext(code) & 1023) % 20 = 0;

INSERT INTO iam.app_user (email) SELECT 'u' || g || '@scale.test' FROM generate_series(1, 10000) g;
INSERT INTO iam.app_user (email) VALUES ('admin@scale.test');

WITH r AS (INSERT INTO iam.role (name) VALUES ('Bench Viewer') RETURNING id)
INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
SELECT id, 1, ARRAY['register.view', 'analysis.view', 'report.view'], 'scale test' FROM r;

-- Bulk load: grantor checks and outbox triggers are not what this measures.
ALTER TABLE iam.assignment DISABLE TRIGGER USER;
WITH bus AS (SELECT id, depth, row_number() OVER (PARTITION BY depth ORDER BY id) AS n, count(*) OVER (PARTITION BY depth) AS c FROM iam.bu),
     roles AS (SELECT id, row_number() OVER (ORDER BY name) AS n, count(*) OVER () AS c FROM iam.role
               WHERE name IN ('Executive Viewer', 'Risk Analyst', 'Risk Owner', 'Approver', 'Auditor', 'Bench Viewer')),
     users AS (SELECT id, row_number() OVER (ORDER BY id) AS n FROM iam.app_user WHERE email LIKE 'u%@scale.test'),
     picks AS (
       SELECT g,
         1 + (hashtext('u' || g) & 2147483647) % 10000 AS un,
         1 + (hashtext('r' || g) & 2147483647) % 6 AS rn,
         CASE WHEN g % 100 = 0 THEN 0 WHEN g % 25 = 0 THEN 1 WHEN g % 4 = 0 THEN 2 ELSE 3 END AS d,
         hashtext('b' || g) & 2147483647 AS bh
       FROM generate_series(1, 52000) g)
INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
SELECT 'user', u.id, ro.id, b.id, (SELECT id FROM iam.app_user WHERE email = 'admin@scale.test')
FROM picks p
JOIN users u ON u.n = p.un
JOIN roles ro ON ro.n = p.rn
JOIN bus b ON b.depth = p.d AND b.n = 1 + p.bh % b.c
ON CONFLICT (principal_kind, principal_id, role_id, bu_id) WHERE revoked_at IS NULL DO NOTHING;
ALTER TABLE iam.assignment ENABLE TRIGGER USER;
SELECT iam.bootstrap_platform_admin((SELECT id FROM iam.app_user WHERE email = 'admin@scale.test'));
`

func TestScopeLatencyAtScale(t *testing.T) {
	if os.Getenv("FAIR_TEST_SCALE") != "1" {
		t.Skip("set FAIR_TEST_SCALE=1 to run the T-08 scale test")
	}
	e := setup(t)
	start := time.Now()
	e.mustOwner(scaleLoad)
	counts := e.mustOwner("SELECT (SELECT count(*) FROM iam.app_user) || ' users, ' || (SELECT count(*) FROM iam.bu) || ' BUs, ' || (SELECT count(*) FROM iam.assignment) || ' assignments'")
	t.Logf("loaded %s in %v", counts, time.Since(start).Round(time.Second))

	timed := func(label string, sql string) time.Duration {
		t0 := time.Now()
		out, err := e.as("app_rw", sql)
		d := time.Since(t0)
		if err != nil {
			t.Fatalf("%s: %v %s", label, err, out)
		}
		t.Logf("%-55s %8v  (%s)", label, d.Round(time.Millisecond), out)
		return d
	}
	drainAll := "SELECT sum(changed) FROM (SELECT (authz.drain_outbox(100000)).changed) x"

	full := timed("initial full reconcile (nightly job)", "SELECT count(*) FROM authz.reconcile_scopes()")
	timed("drain leftovers", drainAll)
	if full > 30*time.Minute {
		t.Errorf("full reconcile took %v; the nightly job timeout is 30 min", full)
	}

	// 100 single grants: each change, then the drain that makes it visible.
	var singles []time.Duration
	for i := range 100 {
		e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
			SELECT 'user', (SELECT id FROM iam.app_user WHERE email = 'u%d@scale.test'), (SELECT id FROM iam.role WHERE name = 'Bench Viewer'),
			       (SELECT id FROM iam.bu WHERE code = 'L2_%d_%d'), (SELECT id FROM iam.app_user WHERE email = 'admin@scale.test')
			ON CONFLICT DO NOTHING`, 9000+i, 1+i%10, 1+(i/10)%10))
		t0 := time.Now()
		if _, err := e.as("app_rw", drainAll); err != nil {
			t.Fatal(err)
		}
		singles = append(singles, time.Since(t0))
	}
	slices.Sort(singles)
	p50, p99 := singles[49], singles[98]
	t.Logf("%-55s p50 %v  p99 %v  max %v", "single grant -> scope (100 samples)", p50.Round(time.Millisecond), p99.Round(time.Millisecond), singles[99].Round(time.Millisecond))

	// Worst cases: one change fanning out to many users.
	var worst []string
	check := func(label, change string) {
		e.mustOwner(change)
		d := timed(label, drainAll)
		if d+pollBudget > scopeSLA {
			worst = append(worst, fmt.Sprintf("%s: %v", label, d))
		}
	}
	check("restrict a level-1 BU (~200 BUs below)", "UPDATE iam.bu SET restricted = true WHERE code = 'L1_1'")
	check("unrestrict it", "UPDATE iam.bu SET restricted = false WHERE code = 'L1_1'")
	check("move a level-2 subtree to another level-1 BU", "UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code = 'L1_2') WHERE code = 'L2_1_1'")
	check("re-version a role held by ~1/6 of assignments", `INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, current_version + 1, ARRAY['register.view', 'analysis.view'], 'scale' FROM iam.role WHERE name = 'Bench Viewer'`)

	if p99+pollBudget > scopeSLA || len(worst) > 0 {
		t.Fatalf("scope SLA (%v incl. %v poll) missed: p99 %v; worst cases %s", scopeSLA, pollBudget, p99, strings.Join(worst, "; "))
	}
}
