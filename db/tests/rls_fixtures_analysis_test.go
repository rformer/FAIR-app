package tests

import (
	"fmt"

	"github.com/rformer/fair-app/internal/rlstest"
)

// F-005 T-02: RLS fixtures for the analysis tables (design §4.1). One helper
// makes, at a BU and as the caller (so RLS and the triggers apply), a
// scenario, a run of it that the worker's functions finish, and an
// aggregate of that run with one member; the run table's fixture row is a
// queued run. Its setup builds on the rlsfx helpers of risk_schema_test.go,
// so this file must sort after that one (Go runs init functions in
// file-name order).
func init() {
	for _, fx := range []rlstest.Fixture{
		{Table: "analysis.run", PK: "id", Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.run('%s', false)::text", bu) }},
		{Table: "analysis.result", PK: "run_id", Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.run('%s', false)::text", bu) }},
		{Table: "analysis.series", PK: "run_id", Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.run('%s', false)::text", bu) }},
		// F-005 T-11 (migration 0104): the run's input bundle (analysis data, read with scenario scope too).
		{Table: "analysis.run_input", PK: "run_id", Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.run('%s', false)::text", bu) }},
		{Table: "analysis.aggregate", PK: "id", Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.aggregate('%s')::text", bu) }},
		{Table: "analysis.aggregate_member", PK: "aggregate_id", Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.aggregate('%s')::text", bu) }},
	} {
		// app_rw inserts these and never updates or deletes them; the
		// definer's functions change them (ADR-007 amendment 3).
		fx.Missing, fx.Touch = "00000000-0000-0000-0000-000000000000", "bu_id = bu_id"
		fx.Refused = []string{"update", "delete", "move"}
		rlsFixtures[fx.Table] = fx
	}
	rlsFixtureSetups = append(rlsFixtureSetups, analysisFixtureFunctions)
}

func analysisFixtureFunctions(e *env) {
	e.admin(e.db, `CREATE FUNCTION rlsfx.run(bu uuid, finished boolean) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE s uuid := rlsfx.scenario(bu); id uuid; tok text;
BEGIN
  id := analysis.request_run(s, 1, convert_to('{"fixture":true}', 'UTF8'), 1, 1000, ARRAY['Current'], NULL, 1000, 2000000, 1000000);
  IF finished THEN
    tok := analysis.start_run(id);
    PERFORM analysis.put_series(id, tok, 'Current', decode(repeat('00', 8000), 'hex'));
    PERFORM analysis.finish_run(id, tok, '{"version": "0.0.0-fixture", "architecture": "amd64"}', '[]', '{"Current": {}}', repeat('b', 64));
  END IF;
  RETURN id;
END $$;
CREATE FUNCTION rlsfx.aggregate(bu uuid) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE r uuid := rlsfx.run(bu, true); id uuid := gen_random_uuid();
BEGIN
  INSERT INTO analysis.aggregate (id, bu_id, name, seed, iterations) VALUES (id, bu, 'Fixture aggregate', 1, 1000);
  INSERT INTO analysis.aggregate_member (aggregate_id, bu_id, position, run_id, control_set) VALUES (id, bu, 0, r, 'Current');
  RETURN id;
END $$;
GRANT EXECUTE ON FUNCTION rlsfx.run(uuid, boolean), rlsfx.aggregate(uuid) TO app_rw;`)
}
