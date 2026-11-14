package tests

import (
	"fmt"

	"github.com/rformer/fair-app/internal/rlstest"
)

// F-007 T-03: RLS fixtures for the register tables (design §5.1). The
// helpers make, at a BU and as the caller (so RLS and the triggers apply),
// a risk with a valid version 1 owned by the caller, linked to a scenario
// of the same BU when asked, and a risk with its treatment. They build on
// the rlsfx helpers of risk_schema_test.go, so this file must sort after
// that one (Go runs init functions in file-name order).
func init() {
	head := func(table, pk, fn string) rlstest.Fixture {
		// Heads change only through the register's functions and triggers.
		return rlstest.Fixture{Table: table, PK: pk, Missing: "00000000-0000-0000-0000-000000000000", Touch: "current_version = current_version",
			Refused: []string{"update", "delete", "move"}, Insert: func(bu string) string { return fmt.Sprintf("SELECT (%s)::text", fmt.Sprintf(fn, bu)) }}
	}
	child := func(table, pk, fn, suffix string) rlstest.Fixture {
		return rlstest.Fixture{Table: table, PK: pk, Missing: "none", Touch: "bu_id = bu_id",
			Refused: []string{"update", "delete", "move"}, Insert: func(bu string) string { return fmt.Sprintf("SELECT (%s)::text || '%s'", fmt.Sprintf(fn, bu), suffix) }}
	}
	for _, fx := range []rlstest.Fixture{
		head("register.risk", "id", "rlsfx.risk('%s', false)"),
		child("register.risk_version", "(risk_id::text || '/' || version)", "rlsfx.risk('%s', false)", "/1"),
		head("register.risk_scenario", "risk_id", "rlsfx.risk('%s', true)"),
		head("register.treatment", "risk_id", "rlsfx.treatment('%s')"),
		child("register.treatment_version", "(risk_id::text || '/' || version)", "rlsfx.treatment('%s')", "/1"),
	} {
		rlsFixtures[fx.Table] = fx
	}
	rlsFixtureSetups = append(rlsFixtureSetups, registerFixtureFunctions)
}

func registerFixtureFunctions(e *env) {
	e.admin(e.db, `CREATE FUNCTION rlsfx.me() RETURNS uuid LANGUAGE sql SECURITY DEFINER AS $$ SELECT (authz.ctx_scope()).user_id $$;
CREATE FUNCTION rlsfx.doc(d jsonb) RETURNS bytea LANGUAGE sql AS $$ SELECT convert_to(risk.canonical(d), 'UTF8') $$;
CREATE FUNCTION rlsfx.risk(bu uuid, link boolean) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE id uuid := gen_random_uuid(); b bytea;
BEGIN
  INSERT INTO register.risk (id, bu_id) VALUES (id, bu);
  b := rlsfx.doc(jsonb_build_object('schema_version', 1, 'title', 'Fixture risk', 'owner', rlsfx.me(), 'state', 'open',
    'scenarios', CASE WHEN link THEN jsonb_build_array(jsonb_build_object('scenario_id', rlsfx.scenario(bu))) ELSE '[]'::jsonb END));
  INSERT INTO register.risk_version (risk_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'fixture');
  RETURN id;
EXCEPTION WHEN sqlstate 'PF026' THEN
  -- The harness prints the message only: carry the problems in it.
  DECLARE dt text;
  BEGIN
    GET STACKED DIAGNOSTICS dt = PG_EXCEPTION_DETAIL;
    RAISE EXCEPTION '% (%)', SQLERRM, dt USING ERRCODE = 'PF026';
  END;
END $$;
CREATE FUNCTION rlsfx.treatment(bu uuid) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE r uuid := rlsfx.risk(bu, false); b bytea := rlsfx.doc('{"schema_version": 1, "decision": "avoid", "rationale": "Fixture."}');
BEGIN
  INSERT INTO register.treatment (risk_id, bu_id) VALUES (r, bu);
  INSERT INTO register.treatment_version (risk_id, version, document, digest, change_note) VALUES (r, 1, b, encode(sha256(b), 'hex'), 'fixture');
  RETURN r;
END $$;
GRANT EXECUTE ON FUNCTION rlsfx.me(), rlsfx.doc(jsonb), rlsfx.risk(uuid, boolean), rlsfx.treatment(uuid) TO app_rw;`)
}
