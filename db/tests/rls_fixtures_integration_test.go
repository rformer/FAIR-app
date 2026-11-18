package tests

import (
	"fmt"

	"github.com/rformer/fair-app/internal/rlstest"
)

// F-011 T-03: the RLS fixture for integration.loss_event (design §5). Only
// integration_definer writes it (its functions check the caller); the
// fixture stands in for those functions: written past RLS by its owner, it
// refuses, as the harness requires of inserts, a BU outside the caller's
// library write scope, and makes a loss event of a per-BU fixture
// integration.
func init() {
	fx := rlstest.Fixture{Table: "integration.loss_event", PK: "id", Missing: "00000000-0000-0000-0000-000000000000", Touch: "event_type = event_type",
		Insert: func(bu string) string { return fmt.Sprintf("SELECT rlsfx.loss_event('%s')::text", bu) }}
	fx.Refused = []string{"update", "delete", "move"}
	rlsFixtures[fx.Table] = fx
	rlsFixtureSetups = append(rlsFixtureSetups, integrationFixtureFunctions)
}

func integrationFixtureFunctions(e *env) {
	e.admin(e.db, `CREATE FUNCTION rlsfx.loss_event(bu uuid) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE id uuid := gen_random_uuid(); i uuid;
BEGIN
  IF NOT bu = ANY (authz.visible_bus('library', 'write')) THEN
    RAISE EXCEPTION 'new row violates row-level security policy for table "loss_event" (fixture)' USING ERRCODE = '42501';
  END IF;
  SELECT x.id INTO i FROM integration.integration x WHERE x.bu_id = bu AND x.name = 'rls fixture';
  IF i IS NULL THEN
    INSERT INTO integration.integration (bu_id, name, kind, delivery, created_by)
    VALUES (bu, 'rls fixture', 'loss_events', 'push', (authz.ctx_scope()).user_id) RETURNING integration.id INTO i;
  END IF;
  INSERT INTO integration.loss_event (id, bu_id, integration_id, external_id, occurred_on, event_type)
  VALUES (id, bu, i, id::text, current_date, 'fixture');
  RETURN id;
END $$;
GRANT EXECUTE ON FUNCTION rlsfx.loss_event(uuid) TO app_rw;`)
}
