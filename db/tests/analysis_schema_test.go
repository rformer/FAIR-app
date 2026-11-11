package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// F-005 T-02 (F-005-AC-01 to AC-06, AC-15, AC-16, AC-18, AC-19, AC-22,
// AC-23; design §4; ADR-007 amendment 4): schema analysis. Runs and
// aggregates are requested by app_rw under the caller's context, changed
// only by analysis_definer's functions with the worker's attempt token, and
// never changed once finished.
func TestAnalysisSchema(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B, platform2 at ENTERPRISE, buadmin at A1, buadmin3 at R
	ctx := context.Background()
	pool := ra.appPool() // one pool: riskEnv.tx opens one per call
	q := func(user, sql string, args ...any) (string, error) {
		var out string
		tx, err := pool.Begin(ctx)
		if err != nil {
			return "", err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if user != "" {
			if _, err := tx.Exec(ctx, "SELECT set_config('authz.ctx', $1, true)", ra.mint(user, ctxKey1)); err != nil {
				return "", err
			}
		}
		if err := tx.QueryRow(ctx, sql, args...).Scan(&out); err != nil {
			return "", err
		}
		return out, tx.Commit(ctx)
	}
	must := func(user, sql string, args ...any) string {
		t.Helper()
		out, err := q(user, sql, args...)
		if err != nil {
			t.Fatalf("%s: %s: %s", user, sql, pgCode(err))
		}
		return out
	}
	scenario := func(user, bu string) string {
		t.Helper()
		got := ra.call(t, "POST", user, "/api/v1/scenarios", map[string]any{"bu_id": bu, "document": ra.scenarioDoc(t), "change_note": "v1"})
		if got.code != 201 {
			t.Fatalf("scenario: %d %s", got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	// F-005 T-11 (migration 0104): request_run takes the bundle and records
	// its SHA-256.
	bundle := []byte(`{"format":"fair.scenario-input.v1","test":true}`)
	sum := sha256.Sum256(bundle)
	digest := hex.EncodeToString(sum[:])
	const request = "SELECT analysis.request_run($1, 1, $2, 7, $3, $4, $5, 1000, 2000000, $6)::text"
	run := func(user, sid string, iterations int, sets []string, reproduces any, maxActive int) (string, error) {
		return q(user, request, sid, bundle, iterations, sets, reproduces, maxActive)
	}
	sid := scenario("analyst", ra.bu["A1"])

	// Requests: attributed, queued, with an empty result and series per set.
	r1, err := run("analyst", sid, 1000, []string{"Current", "Proposed"}, nil, 5)
	if err != nil {
		t.Fatal(pgCode(err))
	}
	if got := ra.adminQuery(`SELECT (requested_by = ` + uid("analyst") + `) || '/' || state || '/' || bu_id || '/' ||
		(SELECT count(*) FROM analysis.result WHERE run_id = r.id AND summary IS NULL) || '/' || (SELECT count(*) FROM analysis.series WHERE run_id = r.id AND ale IS NULL)
		FROM analysis.run r WHERE id = '` + r1 + `'`); got != "true/queued/"+ra.bu["A1"]+"/2/2" {
		t.Fatalf("a requested run: %s", got)
	}
	for name, c := range map[string]struct {
		user  string
		iters int
		sets  []string
		max   int
		want  string
	}{
		"too few iterations":     {"analyst", 999, []string{"Current"}, 5, "PF024"},
		"too many iterations":    {"analyst", 2000001, []string{"Current"}, 5, "PF024"},
		"too many runs":          {"analyst", 1000, []string{"Current"}, 1, "PF024 analysis: at most 1 runs"},
		"a set named twice":      {"analyst", 1000, []string{"Current", "Current"}, 5, "PF024"},
		"too large":              {"analyst", 2000000, []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}, 50, "23514"},
		"a scenario not visible": {"mallory", 1000, []string{"Current"}, 5, "P0002"},
		"no context":             {"", 1000, []string{"Current"}, 5, "PF024"},
	} {
		if _, err := run(c.user, sid, c.iters, c.sets, nil, c.max); !strings.HasPrefix(pgCode(err), c.want) {
			t.Errorf("%s: %s", name, pgCode(err))
		}
	}
	// app_rw changes nothing directly, and inserts only in its scenario's BU.
	for _, sql := range []string{"UPDATE analysis.run SET state = 'succeeded'", "UPDATE analysis.result SET summary = '{}'", "DELETE FROM analysis.series",
		"UPDATE analysis.run SET seed = 1 WHERE id = '" + r1 + "'"} {
		if _, err := q("analyst", sql+" RETURNING 'x'"); err == nil {
			t.Errorf("app_rw: %s", sql)
		}
	}
	if _, err := q("analyst", "INSERT INTO analysis.run (bu_id, scenario_id, scenario_version, bundle_digest, seed, iterations, control_sets) VALUES ($1, $2, 1, $3, 1, 1000, '{Current}') RETURNING id::text",
		ra.bu["A"], sid, digest); !strings.Contains(pgCode(err), "its scenario's business unit") {
		t.Errorf("a run in another BU: %s", pgCode(err))
	}

	// The worker: the attempt token gates every change.
	tok := must("analyst", "SELECT analysis.start_run($1)", r1)
	zero := strings.Repeat("00", 8000)
	for name, sql := range map[string]string{
		"progress with another token": "SELECT analysis.progress($1, 'nope', 0.5)",
		"a short series":              "SELECT analysis.put_series($1, $2, 'Current', decode('00', 'hex'))::text",
		"a series of another set":     "SELECT analysis.put_series($1, $2, 'Other', decode('" + zero + "', 'hex'))::text",
		"finish without series":       "SELECT analysis.finish_run($1, $2, '{\"version\": \"1.0.0\", \"architecture\": \"amd64\"}', '[]', '{\"Current\": {}, \"Proposed\": {}}', $3)",
	} {
		args := []any{r1, tok, strings.Repeat("b", 64)}[:strings.Count(sql, "$")]
		if _, err := q("", sql, args...); err == nil || (name == "progress with another token" && !strings.Contains(pgCode(err), "not held")) {
			t.Errorf("%s: %s", name, pgCode(err))
		}
	}
	if got := must("", "SELECT analysis.progress($1, $2, 0.5)", r1, tok); got != "running" {
		t.Fatalf("progress: %s", got)
	}
	for _, set := range []string{"Current", "Proposed"} {
		must("", "SELECT analysis.put_series($1, $2, $3, decode('"+zero+"', 'hex'))::text", r1, tok, set)
	}
	if _, err := q("", "SELECT analysis.finish_run($1, $2, $3, '[]', '{\"Current\": {}}', $4)", r1, tok, `{"version": "1.0.0", "architecture": "amd64"}`, strings.Repeat("b", 64)); err == nil {
		t.Fatal("finish without every summary")
	}
	finish := func(id, tok, version, arch, digest string) string {
		t.Helper()
		return must("", "SELECT analysis.finish_run($1, $2, $3, '[{\"code\": \"bounds\"}]', '{\"Current\": {\"mean\": \"1\"}, \"Proposed\": {\"mean\": \"0.5\"}}', $4)",
			id, tok, fmt.Sprintf(`{"version": %q, "architecture": %q, "image_digest": "sha256:%s"}`, version, arch, strings.Repeat("c", 64)), digest)
	}
	if got := finish(r1, tok, "1.0.0", "amd64", strings.Repeat("b", 64)); got != "succeeded" {
		t.Fatalf("finish: %s", got)
	}
	if got := ra.adminQuery("SELECT state || '/' || progress || '/' || engine_version || '/' || architecture || '/' || (attempt IS NULL) || '/' || (SELECT summary ->> 'mean' FROM analysis.result WHERE run_id = r.id AND control_set = 'Proposed') FROM analysis.run r WHERE id = '" + r1 + "'"); got != "succeeded/1/1.0.0/amd64/true/0.5" {
		t.Fatalf("a finished run: %s", got)
	}
	// Finished: immutable for every role, the superuser included.
	for _, sql := range []string{"UPDATE analysis.run SET warnings = '[]' WHERE id = '" + r1 + "'", "UPDATE analysis.result SET summary = '{}' WHERE run_id = '" + r1 + "'",
		"UPDATE analysis.series SET ale = NULL WHERE run_id = '" + r1 + "'", "DELETE FROM analysis.run WHERE id = '" + r1 + "'", "TRUNCATE analysis.series CASCADE"} {
		if err := ra.psqlAs(nil, ra.db, sql); err == nil || !strings.Contains(err.Error(), "PF023") && !strings.Contains(err.Error(), "never change") && !strings.Contains(err.Error(), "only by the analysis functions") && !strings.Contains(err.Error(), "kept") && !strings.Contains(err.Error(), "written once") {
			t.Errorf("superuser: %s: %v", sql, err)
		}
	}

	// Cancel: the requester, or analysis.run at the BU; not when finished.
	r2, _ := run("analyst", sid, 1000, []string{"Current"}, nil, 5)
	if _, err := q("mallory", "SELECT analysis.cancel_run($1, 'mine')::text", r2); !strings.HasPrefix(pgCode(err), "P0002") {
		t.Errorf("an outsider cancels: %s", pgCode(err))
	}
	tok2 := must("", "SELECT analysis.start_run($1)", r2)
	must("buadmin", "SELECT analysis.cancel_run($1, 'Wrong control sets')::text", r2)
	if got := must("", "SELECT analysis.progress($1, $2, 0.6)", r2, tok2); got != "cancelled" {
		t.Fatalf("a cancelled run's progress: %s", got)
	}
	if _, err := q("analyst", "SELECT analysis.cancel_run($1, 'again')::text", r1); !strings.Contains(pgCode(err), "is succeeded") {
		t.Errorf("cancelling a finished run: %s", pgCode(err))
	}
	// Failing: a queued run without a token, a running one with it.
	r3, _ := run("analyst", sid, 1000, []string{"Current"}, nil, 5)
	must("", "SELECT analysis.fail_run($1, NULL, 'engine_not_validated', 'validation failed')::text", r3)

	// Reproduction: the original's inputs; compared on finishing.
	reproduce := func(bundleNow []byte) (string, error) {
		return q("analyst", "SELECT analysis.request_run($1, 1, $2, 7, 1000, '{Current,Proposed}', $3, 1000, 2000000, 5)::text", sid, bundleNow, r1)
	}
	if _, err := q("analyst", "SELECT analysis.request_run($1, 1, $2, 8, 1000, '{Current,Proposed}', $3, 1000, 2000000, 5)::text", sid, bundle, r1); !strings.Contains(pgCode(err), "original's inputs") {
		t.Errorf("a reproduction with another seed: %s", pgCode(err))
	}
	if _, err := reproduce([]byte(`{"changed":true}`)); !strings.Contains(pgCode(err), "no longer has the original's digest") {
		t.Errorf("a changed bundle: %s", pgCode(err))
	}
	for _, c := range []struct{ version, arch, digest, want string }{
		{"1.0.0", "amd64", strings.Repeat("b", 64), "match"}, {"1.0.0", "amd64", strings.Repeat("e", 64), "mismatch"},
		{"1.1.0", "amd64", strings.Repeat("e", 64), "other_version"}, {"1.0.0", "arm64", strings.Repeat("e", 64), "other_architecture"},
	} {
		id, err := reproduce(bundle)
		if err != nil {
			t.Fatal(pgCode(err))
		}
		tk := must("", "SELECT analysis.start_run($1)", id)
		for _, set := range []string{"Current", "Proposed"} {
			must("", "SELECT analysis.put_series($1, $2, $3, decode('"+zero+"', 'hex'))::text", id, tk, set)
		}
		if got := finish(id, tk, c.version, c.arch, c.digest); got != c.want {
			t.Errorf("reproduction on %s %s: %s, want %s", c.version, c.arch, got, c.want)
		}
	}

	// Moving the scenario moves its runs, results and series.
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+sid+"/move", map[string]any{"to_bu_id": ra.bu["A"], "reason": "Reorganised"}); got.code != 200 {
		t.Fatalf("move: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery(`SELECT (SELECT count(DISTINCT bu_id) FROM analysis.run WHERE scenario_id = '` + sid + `') || '/' ||
		(SELECT bool_and(bu_id = '` + ra.bu["A"] + `') FROM analysis.result WHERE run_id = '` + r1 + `') || '/' || (SELECT bool_and(bu_id = '` + ra.bu["A"] + `') FROM analysis.series WHERE run_id = '` + r1 + `')`); got != "1/true/true" {
		t.Fatalf("moved runs: %s", got)
	}

	// Aggregates: succeeded members the caller sees, in the aggregate's
	// subtree, of equal iterations.
	finished := func(user, sid string, iterations int) string {
		t.Helper()
		id, err := run(user, sid, iterations, []string{"Current"}, nil, 50)
		if err != nil {
			t.Fatal(pgCode(err))
		}
		tk := must("", "SELECT analysis.start_run($1)", id)
		must("", "SELECT analysis.put_series($1, $2, 'Current', decode(repeat('00', $3 * 8), 'hex'))::text", id, tk, iterations)
		must("", "SELECT analysis.finish_run($1, $2, '{\"version\": \"1.0.0\", \"architecture\": \"amd64\"}', '[]', '{\"Current\": {}}', $3)", id, tk, strings.Repeat("f", 64))
		return id
	}
	ra.mustOwner(grant("platform", "user:platform2", "Risk Analyst", "R"))
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('exec@example.test', 'Exec')")
	ra.mustOwner(grant("platform", "user:exec", "Executive Viewer", "ENTERPRISE"))
	ra.drain()
	sA, sR := scenario("platform2", ra.bu["A"]), ""
	{
		asset := ra.named(t, "buadmin3", "asset", ra.bu["R"], "R asset")
		tc := ra.named(t, "buadmin3", "threat_community", ra.bu["R"], "R threat")
		ctl := ra.named(t, "buadmin3", "control", ra.bu["R"], "R control")
		got := ra.call(t, "POST", "buadmin3", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["R"], "document": ra.scenarioPinning("R scenario", asset, tc, ctl), "change_note": "v1"})
		if got.code != 201 {
			t.Fatalf("R scenario: %d %s", got.code, got.raw)
		}
		sR = got.body["id"].(string)
	}
	mA, mR, mBig := finished("platform2", sA, 1000), finished("buadmin3", sR, 1000), finished("platform2", sA, 2000)
	members := func(ids ...string) string {
		var parts []string
		for _, id := range ids {
			parts = append(parts, fmt.Sprintf(`{"run_id": %q, "control_set": "Current"}`, id))
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	agg := func(user, bu, m string) (string, error) {
		return q(user, "SELECT analysis.request_aggregate($1, 'Enterprise view', 3, $2)::text", bu, m)
	}
	for name, c := range map[string]struct{ user, bu, members, want string }{
		"one member":           {"platform2", ra.bu["ENTERPRISE"], members(mA), "PF024"},
		"unequal iterations":   {"platform2", ra.bu["ENTERPRISE"], members(mA, mBig), "PF024"},
		"outside its subtree":  {"platform2", ra.bu["A1"], members(mA, mA2(t, finished, sA)), "PF024"},
		"a member not visible": {"analyst", ra.bu["A"], members(mA, mR), "P0002"},
		"a run not succeeded":  {"analyst", ra.bu["A"], members(mA, r3), "PF024"},
	} {
		if _, err := agg(c.user, c.bu, c.members); !strings.HasPrefix(pgCode(err), c.want) {
			t.Errorf("%s: %s", name, pgCode(err))
		}
	}
	a1, err := agg("platform2", ra.bu["ENTERPRISE"], members(mA, mR))
	if err != nil {
		t.Fatal(pgCode(err))
	}
	// Visible only to a reader who sees every member (ADR-007 amendment 4).
	for user, want := range map[string]string{"platform2": "1/2", "exec": "0/0"} {
		if got := must(user, "SELECT (SELECT count(*) FROM analysis.aggregate WHERE id = $1) || '/' || (SELECT count(*) FROM analysis.aggregate_member WHERE aggregate_id = $1)", a1); got != want {
			t.Errorf("%s sees %s of the aggregate, want %s", user, got, want)
		}
	}
	atk := must("", "SELECT analysis.start_aggregate($1)", a1)
	if _, err := q("", "SELECT analysis.finish_aggregate($1, $2, '{\"version\": \"1.0.0\", \"architecture\": \"amd64\"}', '{}', decode('00', 'hex'), $3)::text", a1, atk, strings.Repeat("9", 64)); err == nil {
		t.Error("an aggregate's series of the wrong length")
	}
	must("", "SELECT analysis.finish_aggregate($1, $2, '{\"version\": \"1.0.0\", \"architecture\": \"amd64\"}', '{}', decode('"+zero+"', 'hex'), $3)::text", a1, atk, strings.Repeat("9", 64))
	if err := ra.psqlAs(nil, ra.db, "UPDATE analysis.aggregate SET name = 'Renamed' WHERE id = '"+a1+"'"); err == nil {
		t.Error("a finished aggregate changed")
	}

	// Every step recorded, in its transaction.
	if got := ra.adminQuery(`SELECT string_agg(body ->> 'type', ',' ORDER BY id) FROM (SELECT DISTINCT ON (body ->> 'type') id, body FROM audit.intake
		WHERE body ->> 'type' LIKE 'analysis.%' ORDER BY body ->> 'type', id) x`); got !=
		"analysis.run_requested,analysis.run_succeeded,analysis.run_cancelled,analysis.run_failed,analysis.run_reproduced,analysis.aggregate_created,analysis.aggregate_succeeded" {
		t.Errorf("events: %s", got)
	}
	if got := ra.adminQuery(`SELECT string_agg(body -> 'attributes' ->> 'outcome', ',' ORDER BY id) FROM audit.intake WHERE body ->> 'type' = 'analysis.run_reproduced'`); got != "match,mismatch,other_version,other_architecture" {
		t.Errorf("reproduction outcomes: %s", got)
	}
	if got := ra.adminQuery(`SELECT body ->> 'reason' || '/' || (body ->> 'bu_id') FROM audit.intake WHERE body ->> 'type' = 'analysis.run_cancelled'`); got != "Wrong control sets/"+ra.bu["A1"] {
		t.Errorf("cancel event: %s", got)
	}
}

// mA2 is a succeeded run of a scenario at A, for a member outside A1.
func mA2(t *testing.T, finished func(string, string, int) string, sA string) string {
	t.Helper()
	return finished("platform2", sA, 1000)
}
