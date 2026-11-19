package tests

import (
	"fmt"

	"github.com/rformer/fair-app/internal/rlstest"
)

// F-013 T-02: the RLS fixture for framework.control_mapping (design §5).
// Only framework_definer writes it (the projection trigger, T-06); the
// fixture stands in for that trigger: written past RLS by its owner, it
// refuses, as the harness requires of inserts, a BU outside the caller's
// control write scope, and maps a control of that BU to a fixture
// requirement.
func init() {
	fx := rlstest.Fixture{Table: "framework.control_mapping", PK: "control_id", Missing: "00000000-0000-0000-0000-000000000000", Touch: "current = current",
		Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.control_mapping('%s')::text", bu) }}
	fx.Refused = []string{"update", "delete", "move"}
	rlsFixtures[fx.Table] = fx
	rlsFixtureSetups = append(rlsFixtureSetups, frameworkFixtureFunctions)
}

func frameworkFixtureFunctions(e *env) {
	e.admin(e.db, `CREATE FUNCTION rlsfx.control_mapping(bu uuid) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE c uuid := gen_random_uuid(); v uuid; r uuid;
BEGIN
  IF NOT bu = ANY (authz.visible_bus('control', 'write')) THEN
    RAISE EXCEPTION 'new row violates row-level security policy for table "control_mapping" (fixture)' USING ERRCODE = '42501';
  END IF;
  INSERT INTO framework.family (key, title) VALUES ('rls-fixture', 'RLS fixture') ON CONFLICT DO NOTHING;
  SELECT x.id INTO v FROM framework.version x WHERE x.family = 'rls-fixture';
  IF v IS NULL THEN
    INSERT INTO framework.version (family, label, title, source, format, sha256)
    VALUES ('rls-fixture', '1', 'RLS fixture', 'shipped', 'simple', repeat('0', 64)) RETURNING version.id INTO v;
    INSERT INTO framework.requirement (version_id, identifier, title, ord) VALUES (v, 'fx-1', 'Fixture requirement', 0);
  END IF;
  SELECT x.id INTO r FROM framework.requirement x WHERE x.version_id = v AND x.identifier = 'fx-1';
  INSERT INTO risk.control (id, bu_id, created_by) VALUES (c, bu, (authz.ctx_scope()).user_id);
  INSERT INTO framework.control_mapping (control_id, control_version, bu_id, requirement_id, strength, implementation)
  VALUES (c, 1, bu, r, 'full', 'in_place');
  RETURN c;
END $$;
GRANT EXECUTE ON FUNCTION rlsfx.control_mapping(uuid) TO app_rw;`)
}
