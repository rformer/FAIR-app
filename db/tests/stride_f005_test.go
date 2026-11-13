package tests

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/rformer/fair-app/internal/analysis"
)

// F-005 T-16 (design §8): the STRIDE suite for the simulation engine. Each
// test attacks one mitigation of a §8 row through the API, the database or
// the worker, as an attacker in that row would; TestSTRIDECatalog ties the
// rows to them. The engine channel's and the engine's isolation attacks are
// unit tests in internal/enginegate.

// f005 is a succeeded run of a scenario at A1 by the analyst (a Risk
// Analyst at A), worked against the fake engine; erin is an Executive
// Viewer at A, mallory a Risk Analyst at B.
type f005 struct {
	ra  *riskAPIEnv
	ae  *analysisEnv
	sid string
	run string
}

func strideF005Fixture(t *testing.T) f005 {
	t.Helper()
	ra := strideF003Fixture(t)
	ae := analysisAPI(t, ra, defaultLimits, true)
	sid := analysisScenario(t, ra)
	return f005{ra: ra, ae: ae, sid: sid, run: runOf(t, ae, "analyst", sid, 2000, false)}
}

// as runs fn in a transaction as app_rw under user's signed context ("" for
// none), rolled back.
func (f f005) as(t *testing.T, user string, fn func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	pool := f.ae.worker.DB
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if user != "" {
		if _, err := tx.Exec(ctx, "SELECT set_config('authz.ctx', $1, true)", f.ra.mint(user, ctxKey1)); err != nil {
			t.Fatal(err)
		}
	}
	return fn(tx)
}

// T: stored results are altered. Finished runs, results, series and inputs
// are append-only for every role, the superuser included; the digest is in
// the audit event; a reproduction re-derives it.
func TestSTRIDEF005ResultTamper(t *testing.T) {
	f := strideF005Fixture(t)
	for _, sql := range []string{
		"UPDATE analysis.run SET result_digest = repeat('c', 64) WHERE id = '" + f.run + "'",
		"UPDATE analysis.run SET seed = 8 WHERE id = '" + f.run + "'",
		"UPDATE analysis.result SET summary = '{\"ale\": {\"mean\": 1}}' WHERE run_id = '" + f.run + "'",
		"UPDATE analysis.series SET ale = decode(repeat('00', 16000), 'hex') WHERE run_id = '" + f.run + "'",
		"UPDATE analysis.run_input SET bundle = '\\x7b7d' WHERE run_id = '" + f.run + "'",
		"DELETE FROM analysis.series WHERE run_id = '" + f.run + "'",
		"DELETE FROM analysis.run WHERE id = '" + f.run + "'",
		"TRUNCATE analysis.result CASCADE",
	} {
		if got := f.ra.adminState(sql); got != "PF023" {
			t.Errorf("the superuser: %s: %s", sql, got)
		}
	}
	digest := f.ra.adminQuery("SELECT result_digest FROM analysis.run WHERE id = '" + f.run + "'")
	if n := f.ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.run_succeeded' AND body -> 'attributes' ->> 'result_digest' = '" + digest + "'"); n != "1" {
		t.Errorf("the digest in the succeeded event: %s", n)
	}
	// A reproduction re-derives the results and compares the digests.
	got := f.ae.call(t, "POST", "analyst", "/api/v1/analyses/runs/"+f.run+"/reproduce", nil)
	if got.code != 202 {
		t.Fatalf("reproduce: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	if err := f.ae.work(t, id, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	if r := f.ra.adminQuery("SELECT reproduction FROM analysis.run WHERE id = '" + id + "'"); r != "match" {
		t.Errorf("reproduction: %s", r)
	}
}

// T: a client supplies results or forges a run's record. Results are
// written only by finish_run, once, for a running run holding its attempt
// token; the engine fields come from the worker, never from a request.
func TestSTRIDEF005ResultWrite(t *testing.T) {
	f := strideF005Fixture(t)
	queued := runOf(t, f.ae, "analyst", f.sid, 2000, true)
	for name, c := range map[string]struct{ sql, want string }{
		"set a run's digest":              {"UPDATE analysis.run SET result_digest = repeat('c', 64) WHERE id = '" + queued + "'", "42501"},
		"write a summary":                 {"UPDATE analysis.result SET summary = '{}' WHERE run_id = '" + queued + "'", "42501"},
		"insert a run with an engine":     {"INSERT INTO analysis.run (bu_id, scenario_id, scenario_version, bundle_digest, seed, iterations, control_sets, engine_version) SELECT bu_id, '" + f.sid + "', 1, repeat('a', 64), 1, 1000, '{Current}', '9.9.9' FROM risk.scenario WHERE id = '" + f.sid + "'", "42501"},
		"finish a queued run":             {"SELECT analysis.finish_run('" + queued + "', 'guess', '{\"version\": \"0.1.0\", \"architecture\": \"amd64\"}', '[]', '{\"Current\": {}, \"Proposed\": {}}', repeat('d', 64))", "PF024"},
		"read a bundle without its token": {"SELECT analysis.run_bundle('" + queued + "', 'guess')", "PF024"},
		"read a spec without its token":   {"SELECT analysis.run_spec('" + queued + "', 'guess')", "PF024"},
		"finish a finished run":           {"SELECT analysis.finish_run('" + f.run + "', 'guess', '{}', '[]', '{}', repeat('d', 64))", "PF024"},
	} {
		err := f.as(t, "analyst", func(tx pgx.Tx) error { _, err := tx.Exec(context.Background(), c.sql); return err })
		if !strings.Contains(pgCode(err), c.want) {
			t.Errorf("%s: %v, want %s", name, err, c.want)
		}
	}
	// A running run: a guessed token is refused; only the attempt's holds.
	var token string
	if err := f.as(t, "", func(tx pgx.Tx) error {
		if err := tx.QueryRow(context.Background(), "SELECT analysis.start_run($1)", queued).Scan(&token); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), "SELECT analysis.put_series($1, 'guess', 'Current', decode(repeat('00', 16000), 'hex'))", queued)
		return err
	}); !strings.Contains(pgCode(err), "PF024") {
		t.Errorf("put a series with a guessed token: %v", err)
	}
	// The API takes no results and no engine record.
	if got := f.ae.call(t, "POST", "analyst", "/api/v1/analyses/runs", map[string]any{"scenario_id": f.sid, "version": 1, "engine": map[string]any{"version": "9"}}); got.code != 400 {
		t.Errorf("a request with an engine record: %d", got.code)
	}
	if e := f.ra.adminQuery("SELECT engine_version || '/' || architecture FROM analysis.run WHERE id = '" + f.run + "'"); e != "0.1.0/amd64" {
		t.Errorf("the engine record is the engine's Info: %s", e)
	}
}

// T: a faulty or substituted engine. The worker refuses an engine whose
// validation did not pass, before it simulates anything; each run records
// the engine image's digest.
func TestSTRIDEF005EngineValidation(t *testing.T) {
	f := strideF005Fixture(t)
	if d := f.ra.adminQuery("SELECT image_digest FROM analysis.run WHERE id = '" + f.run + "'"); d != "sha256:"+strings.Repeat("ab", 32) {
		t.Errorf("the image digest recorded: %q", d)
	}
	f.ae.engine.set("ok", false)
	id := runOf(t, f.ae, "analyst", f.sid, 2000, true)
	var cancel *river.JobCancelError
	if err := f.ae.work(t, id, 1, analysis.Attempts); !errors.As(err, &cancel) {
		t.Errorf("an unvalidated engine: %v", err)
	}
	if s := f.ae.state(id); s != "failed/engine_not_validated" {
		t.Errorf("the run: %s", s)
	}
	if f.ae.engine.calls != 0 {
		t.Error("the unvalidated engine was asked to simulate")
	}
}

// I: results cross business units. Runs, results, series and inputs are
// read under RLS; another BU's analyst sees none of them, through the API
// or the database.
func TestSTRIDEF005Visibility(t *testing.T) {
	f := strideF005Fixture(t)
	for _, path := range []string{"/api/v1/analyses/runs/" + f.run, "/api/v1/analyses/runs/" + f.run + "/series/Current"} {
		if got := f.ae.call(t, "GET", "mallory", path, nil); got.code != 404 {
			t.Errorf("mallory GET %s: %d", path, got.code)
		}
	}
	if got := f.ae.call(t, "GET", "mallory", "/api/v1/analyses/runs?scenario="+f.sid, nil); len(got.body["runs"].([]any)) != 0 {
		t.Errorf("mallory lists: %s", got.raw)
	}
	for _, table := range []string{"analysis.run", "analysis.result", "analysis.series", "analysis.run_input"} {
		var n int
		if err := f.as(t, "mallory", func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n)
		}); err != nil || n != 0 {
			t.Errorf("mallory reads %s: %d %v", table, n, err)
		}
		if err := f.as(t, "", func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n)
		}); err == nil && n != 0 {
			t.Errorf("no context reads %s: %d", table, n)
		}
	}
	// erin (a viewer at A) reads the run; its input needs the scenario's
	// read scope too, which a viewer holds here.
	if got := f.ae.call(t, "GET", "erin", "/api/v1/analyses/runs/"+f.run, nil); got.code != 200 {
		t.Errorf("a viewer reads the run: %d", got.code)
	}
}

// E: a viewer runs, reproduces, cancels or aggregates. Each needs
// analysis.run; viewers hold analysis.view only, and the database refuses
// them too.
func TestSTRIDEF005Escalation(t *testing.T) {
	f := strideF005Fixture(t)
	queued := runOf(t, f.ae, "analyst", f.sid, 2000, true)
	for name, c := range map[string]struct {
		path string
		body any
		want int
	}{
		"run":       {"/api/v1/analyses/runs", map[string]any{"scenario_id": f.sid, "version": 1}, 403},
		"reproduce": {"/api/v1/analyses/runs/" + f.run + "/reproduce", nil, 403},
		"cancel":    {"/api/v1/analyses/runs/" + queued + "/cancel", map[string]any{"reason": "mine"}, 404},
		"aggregate": {"/api/v1/analyses/aggregates", map[string]any{"bu_id": f.ra.bu["A1"], "name": "x", "members": []any{
			map[string]any{"run_id": f.run, "control_set": "Current"}, map[string]any{"run_id": f.run, "control_set": "Proposed"}}}, 403},
	} {
		if got := f.ae.call(t, "POST", "erin", c.path, c.body); got.code != c.want {
			t.Errorf("a viewer: %s: %d %s, want %d", name, got.code, got.raw, c.want)
		}
	}
	if s := f.ae.state(queued); s != "queued" {
		t.Errorf("the viewer changed the run: %s", s)
	}
	// In the database: the viewer's context writes nothing.
	err := f.as(t, "erin", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "SELECT analysis.request_run($1, 1, convert_to('{}', 'UTF8'), 1, 1000, '{Current}', NULL, 1000, 2000000, 5)", f.sid)
		return err
	})
	if err == nil {
		t.Error("the viewer requested a run in the database")
	}
	if err := f.as(t, "erin", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "SELECT analysis.cancel_run($1, 'mine')", queued)
		return err
	}); !strings.HasPrefix(pgCode(err), "P0002") {
		t.Errorf("the viewer cancels in the database: %v", err)
	}
}

// R: every run and aggregate event is recorded in its transaction with the
// actor, the BU and (for runs) the bundle digest.
func TestAnalysisAuditEvents(t *testing.T) {
	f := strideF005Fixture(t)
	bu := f.ra.bu["A1"]
	analyst := f.ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'analyst@example.test'")
	digest := f.ra.adminQuery("SELECT bundle_digest FROM analysis.run WHERE id = '" + f.run + "'")
	// A failed run, a cancelled run, a reproduction, an aggregate that
	// succeeds and one that fails.
	f.ae.engine.set("model_error", true)
	failed := runOf(t, f.ae, "analyst", f.sid, 2000, true)
	_ = f.ae.work(t, failed, 1, analysis.Attempts)
	f.ae.engine.set("ok", true)
	cancelled := runOf(t, f.ae, "analyst", f.sid, 2000, true)
	if got := f.ae.call(t, "POST", "analyst", "/api/v1/analyses/runs/"+cancelled+"/cancel", map[string]any{"reason": "Wrong sets"}); got.code != 200 {
		t.Fatalf("cancel: %d", got.code)
	}
	rep := f.ae.call(t, "POST", "analyst", "/api/v1/analyses/runs/"+f.run+"/reproduce", nil)
	if err := f.ae.work(t, rep.body["id"].(string), 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	other := runOf(t, f.ae, "analyst", f.sid, 2000, false)
	agg := f.ae.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": bu, "name": "Audited", "members": []any{
		map[string]any{"run_id": f.run, "control_set": "Current"}, map[string]any{"run_id": other, "control_set": "Current"}}})
	if agg.code != 202 {
		t.Fatalf("aggregate: %d %s", agg.code, agg.raw)
	}
	if err := f.ae.aggregates.Attempt(context.Background(), agg.body["id"].(string), 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	f.ae.engine.set("ok", false)
	agg2 := f.ae.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": bu, "name": "Refused", "members": []any{
		map[string]any{"run_id": f.run, "control_set": "Current"}, map[string]any{"run_id": other, "control_set": "Current"}}})
	_ = f.ae.aggregates.Attempt(context.Background(), agg2.body["id"].(string), 1, analysis.Attempts)

	for _, c := range []struct{ typ, actor, attr, value string }{
		{"analysis.run_requested", analyst, "bundle_digest", digest},
		{"analysis.run_succeeded", "system:risk", "bundle_digest", digest},
		{"analysis.run_failed", "system:risk", "failure", "invalid_bundle"},
		{"analysis.run_cancelled", analyst, "bundle_digest", digest},
		{"analysis.run_reproduced", "system:risk", "outcome", "match"},
		{"analysis.aggregate_created", analyst, "members", "2"},
		{"analysis.aggregate_succeeded", "system:risk", "members", "2"},
		{"analysis.aggregate_failed", "system:risk", "failure", "engine_not_validated"},
	} {
		n := f.ra.adminQuery(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '` + c.typ + `' AND body ->> 'actor' = '` + c.actor +
			`' AND body ->> 'bu_id' = '` + bu + `' AND body -> 'attributes' ->> '` + c.attr + `' = '` + c.value + `'`)
		if n == "0" {
			t.Errorf("%s by %s with %s %s at A1: none", c.typ, c.actor, c.attr, c.value)
		}
	}
}

// D: run floods and huge runs. The active-run limit, iteration and size
// bounds, member limits and the body limit refuse them.
func TestAnalysisLimits(t *testing.T) {
	ra := strideF003Fixture(t)
	ae := analysisAPI(t, ra, analysis.Limits{IterationsDefault: 1000, IterationsMin: 1000, IterationsMax: 2_000_000, MaxActive: 2}, true)
	doc := ra.scenarioDoc(t)
	sets := []any{doc["control_sets"].([]any)[0]}
	for i := range 11 {
		sets = append(sets, map[string]any{"name": "Set " + string(rune('A'+i)), "current": false, "controls": []any{}})
	}
	doc["control_sets"] = sets
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	sid := got.body["id"].(string)
	post := func(body any) apiResp { return ae.call(t, "POST", "analyst", "/api/v1/analyses/runs", body) }
	// Iterations × control sets at most 20,000,000: 2,000,000 × 12 sets.
	if got := post(map[string]any{"scenario_id": sid, "version": 1, "iterations": 2_000_000}); got.code != 422 {
		t.Errorf("a run too large: %d %s", got.code, got.raw)
	}
	if got := post(map[string]any{"scenario_id": sid, "version": 1, "iterations": 999}); got.code != 422 {
		t.Errorf("too few iterations: %d", got.code)
	}
	for range 2 {
		if got := post(map[string]any{"scenario_id": sid, "version": 1, "control_sets": []string{"Current"}}); got.code != 202 {
			t.Fatalf("a run: %d %s", got.code, got.raw)
		}
	}
	if got := post(map[string]any{"scenario_id": sid, "version": 1, "control_sets": []string{"Current"}}); got.code != 409 || got.body["error"] != "too_many_runs" {
		t.Errorf("past the active-run limit: %d %s", got.code, got.raw)
	}
	// The body limit (64 KiB), and the member bounds.
	if got := post(map[string]any{"scenario_id": sid, "version": 1, "control_sets": []string{strings.Repeat("x", 70<<10)}}); got.code != 400 {
		t.Errorf("a body over 64 KiB: %d", got.code)
	}
	members := []any{}
	for range 201 {
		members = append(members, map[string]any{"run_id": "00000000-0000-4000-8000-000000000000", "control_set": "Current"})
	}
	for _, ms := range [][]any{members[:1], members} {
		if got := ae.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": ra.bu["A1"], "name": "x", "members": ms}); got.code != 400 {
			t.Errorf("an aggregate of %d members: %d", len(ms), got.code)
		}
	}
}
