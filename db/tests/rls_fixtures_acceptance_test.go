package tests

import (
	"fmt"

	"github.com/rformer/fair-app/internal/rlstest"
)

// F-008 T-02: RLS fixtures for the acceptance tables (design §5). Only
// acceptance_definer writes them (its functions check the caller); the
// fixture stands in for those functions: written past RLS by its owner, it
// refuses, as the harness requires of inserts, a BU outside the caller's
// acceptance write scope, and makes a pending acceptance of a fresh risk
// (rlsfx.risk, rls_fixtures_register_test.go; plpgsql, so it may be
// created first) with its requested step.
func init() {
	for _, fx := range []rlstest.Fixture{
		{Table: "acceptance.acceptance", PK: "id", Missing: "00000000-0000-0000-0000-000000000000", Touch: "steps = steps",
			Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.acceptance('%s')::text", bu) }},
		{Table: "acceptance.step", PK: "(acceptance_id::text || '/' || n)", Missing: "none", Touch: "bu_id = bu_id",
			Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.acceptance('%s')::text || '/1'", bu) }},
	} {
		fx.Refused = []string{"update", "delete", "move"}
		rlsFixtures[fx.Table] = fx
	}
	rlsFixtureSetups = append(rlsFixtureSetups, acceptanceFixtureFunctions)
}

func acceptanceFixtureFunctions(e *env) {
	e.admin(e.db, `CREATE FUNCTION rlsfx.acceptance(bu uuid) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE id uuid := gen_random_uuid(); r uuid;
BEGIN
  IF NOT bu = ANY (authz.visible_bus('acceptance', 'write')) THEN
    RAISE EXCEPTION 'new row violates row-level security policy for table "acceptance" (fixture)' USING ERRCODE = '42501';
  END IF;
  r := rlsfx.risk(bu, false);
  INSERT INTO acceptance.acceptance (id, bu_id, risk_id, state, tier, tier_bu_id, approvals_needed, mean, expires_on, requested_by, steps)
  VALUES (id, bu, r, 'pending', 1, bu, 1, 0, current_date + 30, (authz.ctx_scope()).user_id, 1);
  INSERT INTO acceptance.step (acceptance_id, n, bu_id, kind, actor, reason, data)
  VALUES (id, 1, bu, 'requested', (authz.ctx_scope()).user_id, 'fixture', '{}');
  RETURN id;
END $$;
GRANT EXECUTE ON FUNCTION rlsfx.acceptance(uuid) TO app_rw;`)
}
