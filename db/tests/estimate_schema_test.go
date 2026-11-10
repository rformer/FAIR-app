package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-004 T-04 (F-004-AC-07, AC-09; design §4.1, §4.4; ADR-007 amendment 3):
// schema estimate. Answers and calibration are the definer's alone,
// append-only where the design says so, and the limits and states hold
// whatever the caller.
func TestEstimateSchema(t *testing.T) {
	r := riskFixture(t) // analyst at A, mallory at B
	riskFixtureFunctions(r.env)
	estimateFixtureFunctions(r.env)
	ctx := context.Background()
	exec := func(user, sql string, args ...any) error {
		return r.tx(user, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql, args...); return err })
	}
	var req string
	if err := r.tx("analyst", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT rlsfx.request($1)::text", r.bu["A"]).Scan(&req)
	}); err != nil {
		t.Fatal(err)
	}
	estimator := r.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rlsfx-estimator@example.test'")

	// app_rw reaches none of the definer's tables.
	for _, tbl := range []string{"answer", "notice_outbox", "question_set", "question", "exercise", "exercise_answer", "score"} {
		r.mustFail("app_rw", "SELECT 1 FROM estimate."+tbl+" LIMIT 1", "permission denied")
	}
	// ...nor the columns the database sets, nor updates or deletes.
	for _, q := range []string{
		"INSERT INTO estimate.request (bu_id, scenario_id, scenario_version, title, context, due_at, created_by) SELECT bu_id, scenario_id, 1, 'x', '{}', now() + interval '1 day', created_by FROM estimate.request",
		"UPDATE estimate.request SET status = 'closed'",
		"UPDATE estimate.request_estimator SET finished_at = now()",
		"DELETE FROM estimate.request_factor",
	} {
		if err := exec("analyst", q); !strings.HasPrefix(pgCode(err), "42501") {
			t.Errorf("app_rw: %s: %s", q, pgCode(err))
		}
	}

	// Answers and pinned references are append-only for every role, the
	// superuser included (PF021).
	r.admin(r.db, fmt.Sprintf(`INSERT INTO estimate.answer (request_id, bu_id, estimator, pointer, revision, state, estimate, calibration)
		VALUES ('%s', '%s', '%s', '/lef/tef/contact_frequency', 1, 'submitted', '{"min": "1"}', '{"class": "not_measured"}')`, req, r.bu["A"], estimator))
	for _, q := range []string{"UPDATE estimate.answer SET state = 'draft'", "DELETE FROM estimate.answer", "TRUNCATE estimate.answer",
		"UPDATE estimate.request_reference SET version = 2", "DELETE FROM estimate.request_reference", "DELETE FROM estimate.request"} {
		if err := r.psqlAs(nil, r.db, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("superuser: %s: %v", q, err)
		}
	}
	// A revision beyond 100, an answer with neither an estimate nor a decline.
	for _, q := range []string{
		fmt.Sprintf(`INSERT INTO estimate.answer (request_id, bu_id, estimator, pointer, revision, state, estimate, calibration) VALUES ('%s', '%s', '%s', '/lef/tef/contact_frequency', 101, 'draft', '{}', '{}')`, req, r.bu["A"], estimator),
		fmt.Sprintf(`INSERT INTO estimate.answer (request_id, bu_id, estimator, pointer, revision, state, calibration) VALUES ('%s', '%s', '%s', '/lef/tef/contact_frequency', 2, 'draft', '{}')`, req, r.bu["A"], estimator),
		fmt.Sprintf(`INSERT INTO estimate.answer (request_id, bu_id, estimator, pointer, revision, state, estimate, calibration) VALUES ('%s', '%s', '%s', '/lef/vulnerability', 1, 'draft', '{}', '{}')`, req, r.bu["A"], estimator),
	} {
		if err := r.psqlAs(nil, r.db, q); err == nil || !strings.Contains(err.Error(), "violates") {
			t.Errorf("answer accepted: %s: %v", q, err)
		}
	}

	// Requests: attributed, in their scenario's BU, due ahead, at most 20
	// open per scenario; factors and references only at creation; estimators
	// must hold estimate.submit there.
	if got := r.adminQuery("SELECT (created_by = " + uid("analyst") + ") || '/' || status || '/' || bu_id FROM estimate.request WHERE id = '" + req + "'"); got != "true/open/"+r.bu["A"] {
		t.Fatalf("request: %s", got)
	}
	scenario := r.adminQuery("SELECT scenario_id FROM estimate.request WHERE id = '" + req + "'")
	insert := func(user, bu, due string) error {
		return exec(user, "INSERT INTO estimate.request (bu_id, scenario_id, scenario_version, title, context, due_at) VALUES ($1, $2, 1, 'Again', '{}', "+due+")", bu, scenario)
	}
	for name, c := range map[string]struct{ user, bu, due, want string }{
		"due in the past":              {"analyst", r.bu["A"], "now() - interval '1 hour'", "PF022"},
		"another BU than its scenario": {"analyst", r.bu["A1"], "now() + interval '1 day'", "PF022"},
		"a scenario not visible":       {"mallory", r.bu["B"], "now() + interval '1 day'", "PF022"},
		"no context":                   {"", r.bu["A"], "now() + interval '1 day'", "PF022"},
	} {
		if err := insert(c.user, c.bu, c.due); !strings.HasPrefix(pgCode(err), c.want) {
			t.Errorf("%s: %s", name, pgCode(err))
		}
	}
	for i := 0; i < 19; i++ {
		if err := insert("analyst", r.bu["A"], "now() + interval '1 day'"); err != nil {
			t.Fatalf("open request %d: %s", i+2, pgCode(err))
		}
	}
	if err := insert("analyst", r.bu["A"], "now() + interval '1 day'"); !strings.Contains(pgCode(err), "at most 20 open requests") {
		t.Fatalf("21st open request: %s", pgCode(err))
	}
	if err := exec("analyst", "INSERT INTO estimate.request_factor (request_id, pointer, factor, unit, definition) VALUES ($1, '/primary_loss/response', 'response', 'currency', 'd')", req); !strings.Contains(pgCode(err), "named when the request is created") {
		t.Errorf("a factor added later: %s", pgCode(err))
	}
	rc := r.create(t, "analyst", "reference_class", r.bu["A"], modeltest.ReferenceClass())
	if err := exec("analyst", "INSERT INTO estimate.request_reference (request_id, entry_id, version) VALUES ($1, $2, 1)", req, rc); !strings.Contains(pgCode(err), "attached when the request is created") {
		t.Errorf("a reference added later: %s", pgCode(err))
	}
	if err := exec("analyst", "INSERT INTO estimate.request_estimator (request_id, user_id) VALUES ($1, $2)", req, r.adminQuery("SELECT id FROM iam.app_user WHERE email = 'mallory@example.test'")); !strings.Contains(pgCode(err), "does not hold estimate.submit") {
		t.Errorf("an estimator without estimate.submit: %s", pgCode(err))
	}
	// A reference must be a reference class the analyst can see.
	tc := r.create(t, "analyst", "threat_community", r.bu["A"], modeltest.ThreatCommunity())
	bRC := r.create(t, "mallory", "reference_class", r.bu["B"], modeltest.ReferenceClass())
	for name, entry := range map[string]string{"another kind": tc, "an unseen entry": bRC} {
		err := r.tx("analyst", func(tx pgx.Tx) error {
			var id string
			if err := tx.QueryRow(ctx, "INSERT INTO estimate.request (bu_id, scenario_id, scenario_version, title, context, due_at) VALUES ($1, rlsfx.scenario($1), 1, 'R', '{}', now() + interval '1 day') RETURNING id::text", r.bu["A"]).Scan(&id); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO estimate.request_reference (request_id, entry_id, version) VALUES ($1, $2, 1)", id, entry)
			return err
		})
		if !strings.Contains(pgCode(err), "does not exist or is not visible") {
			t.Errorf("%s as a reference: %s", name, pgCode(err))
		}
	}

	// Questions: answers fit their kind; a version changes only to be retired.
	r.admin(r.db, `INSERT INTO estimate.question_set (id, origin, name, status, release) VALUES ('aaaaaaaa-0000-4000-8000-000000000001', 'shipped', 'S', 'active', '2026.11');
		INSERT INTO estimate.question (id, version, set_id, kind, text, answer, source) VALUES ('aaaaaaaa-0000-4000-8000-000000000002', 1, 'aaaaaaaa-0000-4000-8000-000000000001', 'binary', 'Q?', 'true', 'S')`)
	for _, q := range []string{
		"INSERT INTO estimate.question (id, version, set_id, kind, text, answer, source) VALUES (gen_random_uuid(), 1, 'aaaaaaaa-0000-4000-8000-000000000001', 'binary', 'Q?', 'maybe', 'S')",
		"INSERT INTO estimate.question (id, version, set_id, kind, text, answer, source) VALUES (gen_random_uuid(), 1, 'aaaaaaaa-0000-4000-8000-000000000001', 'range', 'Q?', '12', 'S')",
		"UPDATE estimate.question SET text = 'Changed'",
	} {
		if err := r.psqlAs(nil, r.db, q); err == nil {
			t.Errorf("question accepted: %s", q)
		}
	}
	r.admin(r.db, "UPDATE estimate.question SET retired_at = now()")
	if err := r.psqlAs(nil, r.db, "UPDATE estimate.question SET retired_at = now()"); err == nil || !strings.Contains(err.Error(), "once") {
		t.Errorf("retired twice: %v", err)
	}

	// allow_definer: a NOLOGIN *_definer role, not the roll-up or guard
	// role, on a registered table, one definer per table.
	for q, want := range map[string]string{
		"SELECT authz.allow_definer('estimate.request', 'app_rw')":          "must be a NOLOGIN",
		"SELECT authz.allow_definer('estimate.request', 'rollup_definer')":  "must be a NOLOGIN",
		"SELECT authz.allow_definer('estimate.answer', 'estimate_definer')": "not a BU-owned table",
		"SELECT authz.allow_definer('estimate.request', 'risk_definer')":    "already has a definer",
	} {
		r.ownerFails(q, want)
	}
	// Re-applying the BU policies keeps the definer's.
	r.mustOwner("SELECT authz.apply_bu_rls('estimate.request', 'scenario')")
	if got := r.mustOwner("SELECT string_agg(polname, ',' ORDER BY polname) FROM pg_policy WHERE polrelid = 'estimate.request'::regclass AND polname LIKE 'bu_definer%'"); got != "bu_definer_select,bu_definer_update" {
		t.Fatalf("definer policies after re-application: %s", got)
	}
}
