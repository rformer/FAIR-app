package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
)

// F-007 T-02 (F-007-AC-07, AC-11; F-007 design §5.2): F-005 aggregates for
// the register: a purpose, and members that are aggregates (nested), with
// visibility followed to every leaf.

// nestedAggregate requests an aggregate of members at bu as user, in SQL
// as the register will (the analysts' API takes runs only), and works it.
func nestedAggregate(t *testing.T, ae *analysisEnv, user, bu, name string, members ...analysis.MemberRef) (string, error) {
	t.Helper()
	var id string
	err := ae.tx(user, func(tx pgx.Tx) error {
		var err error
		id, err = analysis.RequestAggregate(context.Background(), tx, func(context.Context, pgx.Tx, analysis.AggregateArgs) error { return nil },
			analysis.AggregateRequest{BU: bu, Name: name, Members: members})
		return err
	})
	if err != nil {
		return "", err
	}
	if err := ae.aggregates.Attempt(t.Context(), id, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	return id, nil
}

func TestAnalysisNestedAggregates(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B, erin an Executive Viewer at A, platform2 at ENTERPRISE; R restricted under A
	ra.bu["R"] = ra.adminQuery("SELECT id FROM iam.bu WHERE code = 'R'")
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('carol@example.test', 'Carol')")
	ra.mustOwner(grant("platform", "user:carol", "Risk Analyst", "A"))
	ra.mustOwner(grant("platform", "user:carol", "Risk Analyst", "R"))
	ra.drain()
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	s0 := scenarioAt(t, ra, "analyst", ra.bu["A"], "Head office fraud")
	sr := scenarioAt(t, ra, "carol", ra.bu["R"], "Restricted payroll")
	r1, r0 := runWith(t, ae, "analyst", s1, 1, 2000, "7"), runWith(t, ae, "analyst", s0, 1, 2000, "7")
	rr := runWith(t, ae, "carol", sr, 1, 2000, "7")
	r3 := runWith(t, ae, "analyst", s0, 1, 3000, "7")
	run := func(id, set string) analysis.MemberRef { return analysis.MemberRef{RunID: id, ControlSet: set} }
	agg := func(id string) analysis.MemberRef { return analysis.MemberRef{AggregateID: id} }
	mustAggregate := func(user, bu, name string, members ...analysis.MemberRef) string {
		t.Helper()
		id, err := nestedAggregate(t, ae, user, bu, name, members...)
		if err != nil || ra.adminQuery("SELECT state FROM analysis.aggregate WHERE id = '"+id+"'") != "succeeded" {
			t.Fatalf("%s: %v", name, err)
		}
		return id
	}

	// Two aggregates of runs, then one of them: a nested aggregate.
	a1 := mustAggregate("analyst", ra.bu["A1"], "Claims", run(r1, "Current"), run(r1, "Proposed"))
	a0 := mustAggregate("analyst", ra.bu["A"], "Head office", run(r0, "Current"), run(r0, "Proposed"))
	n := mustAggregate("analyst", ra.bu["A"], "Division", agg(a1), agg(a0))
	// The ramp: each of a1 and a0 loses 3·(i mod 10) a year, so n 6·(i mod 10).
	h := ae.call(t, "GET", "analyst", "/api/v1/analyses/aggregates/"+n+"/histogram?scale=linear", nil)
	if h.code != 200 || edge(h.body, 60) != 54 || h.body["zero"] != 200.0 {
		t.Fatalf("the nested aggregate's histogram: %d %s", h.code, h.raw)
	}
	got := ae.call(t, "GET", "analyst", "/api/v1/analyses/aggregates/"+n, nil)
	members, _ := got.body["members"].([]any)
	if got.code != 200 || got.body["purpose"] != "analysis" || len(members) != 2 ||
		members[0].(map[string]any)["aggregate_id"] != a1 || members[1].(map[string]any)["aggregate_name"] != "Head office" {
		t.Fatalf("the nested aggregate: %d %s", got.code, got.raw)
	}
	if d := ra.adminQuery("SELECT count(*) FROM analysis.aggregate WHERE id = '" + n + "' AND result_digest ~ '^[0-9a-f]{64}$'"); d != "1" {
		t.Errorf("digest: %s", d)
	}
	// A run and an aggregate together.
	mustAggregate("analyst", ra.bu["A"], "Mixed", run(r0, "Current"), agg(a1))

	// Refusals: an unfinished member, other iterations, outside the subtree,
	// a member the caller cannot see.
	queued := ""
	if err := ae.tx("analyst", func(tx pgx.Tx) error {
		var err error
		queued, err = analysis.RequestAggregate(context.Background(), tx, func(context.Context, pgx.Tx, analysis.AggregateArgs) error { return nil },
			analysis.AggregateRequest{BU: ra.bu["A"], Name: "Queued", Members: []analysis.MemberRef{run(r0, "Current"), run(r1, "Current")}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		user, bu string
		members  []analysis.MemberRef
		code     string
	}{
		"a queued aggregate":  {"analyst", ra.bu["A"], []analysis.MemberRef{agg(queued), agg(a1)}, "PF024"},
		"other iterations":    {"analyst", ra.bu["A"], []analysis.MemberRef{agg(a0), run(r3, "Current")}, "PF024"},
		"outside the subtree": {"analyst", ra.bu["A1"], []analysis.MemberRef{agg(a1), agg(a0)}, "PF024"},
		"mallory, hidden":     {"mallory", ra.bu["B"], []analysis.MemberRef{agg(a1), agg(a0)}, "P0002"},
		"the same one twice":  {"analyst", ra.bu["A"], []analysis.MemberRef{agg(a1), agg(a1)}, "23505"},
		"no such aggregate":   {"analyst", ra.bu["A"], []analysis.MemberRef{agg("00000000-0000-4000-8000-000000000000"), agg(a1)}, "P0002"},
	} {
		if _, err := nestedAggregate(t, ae, c.user, c.bu, name, c.members...); !strings.HasPrefix(pgCode(err), c.code+" ") {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	// app_rw cannot choose a purpose: only the register's functions make
	// exposure and roll-up aggregates (F-007 T-05, T-07).
	if err := ae.tx("analyst", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "INSERT INTO analysis.aggregate (id, bu_id, name, seed, iterations, purpose) VALUES (gen_random_uuid(), $1, 'x', 1, 2000, 'rollup')", ra.bu["A"])
		return err
	}); !strings.HasPrefix(pgCode(err), "42501 ") {
		t.Errorf("app_rw set a purpose: %v", err)
	}

	// Visibility follows nested members to every leaf: carol (A and R)
	// combines a run at R with one at A1 at A, and nests it. The analyst
	// sees A, and so both aggregates' own rows' business unit, but not R:
	// neither is visible to them, nor listed.
	c := mustAggregate("carol", ra.bu["A"], "With payroll", run(rr, "Current"), run(r1, "Current"))
	nc := mustAggregate("carol", ra.bu["A"], "Division with payroll", agg(c), agg(a0))
	for _, id := range []string{c, nc} {
		if got := ae.call(t, "GET", "analyst", "/api/v1/analyses/aggregates/"+id, nil); got.code != 404 {
			t.Errorf("the analyst reads %s: %d", id, got.code)
		}
		if got := ae.call(t, "GET", "carol", "/api/v1/analyses/aggregates/"+id, nil); got.code != 200 {
			t.Errorf("carol reads %s: %d %s", id, got.code, got.raw)
		}
	}
	if _, err := nestedAggregate(t, ae, "analyst", ra.bu["A"], "Over a hidden one", agg(c), agg(a0)); !strings.HasPrefix(pgCode(err), "P0002 ") {
		t.Errorf("the analyst nests an aggregate over a hidden run: %v", err)
	}
	if got := ra.adminQuery("SELECT count(*) FROM analysis.aggregate_member WHERE aggregate_id = '" + nc + "'"); got != "2" {
		t.Errorf("members: %s", got)
	}

	// The analysts' list shows purpose 'analysis' only.
	// (Made a roll-up by the superuser: the register's functions come with
	// T-05 and T-07.)
	ra.admin(ra.db, "ALTER TABLE analysis.aggregate DISABLE TRIGGER aggregate_before_update; "+
		"UPDATE analysis.aggregate SET purpose = 'rollup' WHERE id = '"+n+"'; ALTER TABLE analysis.aggregate ENABLE TRIGGER aggregate_before_update")
	listed := map[string]bool{}
	for _, x := range ae.call(t, "GET", "analyst", "/api/v1/analyses/aggregates", nil).body["aggregates"].([]any) {
		listed[x.(map[string]any)["id"].(string)] = true
	}
	if listed[n] || !listed[a1] || !listed[a0] {
		t.Errorf("listed %v: the roll-up %s should not be", listed, n)
	}
	if got := ae.call(t, "GET", "analyst", "/api/v1/analyses/aggregates/"+n, nil); got.code != 200 || got.body["purpose"] != "rollup" {
		t.Errorf("a roll-up read by id: %d %s", got.code, got.raw)
	}
}
