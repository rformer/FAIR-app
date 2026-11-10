package tests

import (
	"fmt"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/rlstest"
)

// F-004 T-04: RLS fixtures for the estimate request tables (design §4.1).
// One helper makes a whole request at a BU, as the caller (so RLS and the
// triggers apply): a scenario, a reference class, the request, one factor,
// one estimator and one reference. Its setup builds on the rlsfx helpers of
// risk_schema_test.go, so this file must sort after that one (Go runs init
// functions in file-name order).
func init() {
	for _, fx := range []rlstest.Fixture{
		{Table: "estimate.request", PK: "id", Missing: "00000000-0000-0000-0000-000000000000", Touch: "title = title"},
		{Table: "estimate.request_factor", PK: "request_id"},
		{Table: "estimate.request_estimator", PK: "request_id"},
		{Table: "estimate.request_reference", PK: "request_id"},
	} {
		// app_rw inserts these and never updates or deletes them; the
		// definer's functions change them (ADR-007 amendment 3).
		if fx.Missing == "" {
			fx.Missing, fx.Touch = "00000000-0000-0000-0000-000000000000", "bu_id = bu_id"
		}
		fx.Refused = []string{"update", "delete", "move"}
		fx.Insert = func(bu string) string { return fmt.Sprintf("SELECT rlsfx.request('%s')::text", bu) }
		rlsFixtures[fx.Table] = fx
	}
	rlsFixtureSetups = append(rlsFixtureSetups, estimateFixtureFunctions)
}

func estimateFixtureFunctions(e *env) {
	t := e.t
	e.admin(e.db, `INSERT INTO rlsfx.tmpl VALUES ('reference_class', '`+templateJSON(t, "reference_class", modeltest.ReferenceClass())+`');
INSERT INTO iam.app_user (email, display_name) VALUES ('rlsfx-estimator@example.test', 'Fixture estimator');
-- Test-only: the fixture estimator holds the Estimator role at every BU a
-- fixture row is made in (restricted ones need an explicit assignment).
CREATE FUNCTION rlsfx.estimator(bu uuid) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE u uuid := (SELECT id FROM iam.app_user WHERE email = 'rlsfx-estimator@example.test');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id
                 WHERE a.principal_id = u AND a.bu_id = bu AND r.name = 'Estimator' AND a.revoked_at IS NULL) THEN
    ALTER TABLE iam.assignment DISABLE TRIGGER USER;
    INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
    SELECT 'user', u, r.id, bu, u FROM iam.role r WHERE r.name = 'Estimator';
    ALTER TABLE iam.assignment ENABLE TRIGGER USER;
  END IF;
  RETURN u;
END $$;
CREATE FUNCTION rlsfx.request(bu uuid) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE s uuid := rlsfx.scenario(bu); rc uuid := rlsfx.entry('reference_class', bu); est uuid := rlsfx.estimator(bu); id uuid;
BEGIN
  INSERT INTO estimate.request (bu_id, scenario_id, scenario_version, title, context, due_at)
  VALUES (bu, s, 1, 'Fixture request', '{}', now() + interval '1 day') RETURNING request.id INTO id;
  INSERT INTO estimate.request_factor (request_id, pointer, factor, unit, definition)
  VALUES (id, '/lef/tef/contact_frequency', 'contact_frequency', 'events_per_year', 'How often the threat community comes into contact with the asset.');
  INSERT INTO estimate.request_estimator (request_id, user_id) VALUES (id, est);
  INSERT INTO estimate.request_reference (request_id, entry_id, version) VALUES (id, rc, 1);
  RETURN id;
END $$;
GRANT EXECUTE ON FUNCTION rlsfx.estimator(uuid), rlsfx.request(uuid) TO app_rw;`)
}
