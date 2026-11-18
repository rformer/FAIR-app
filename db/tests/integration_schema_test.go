package tests

import (
	"fmt"
	"testing"
)

// F-011 T-03 (F-011-AC-02, AC-03, AC-08, AC-19; design §5): the integration
// schema is integration_definer's; loss events are BU-owned (library); the
// state rules (PF031) and the integration limit (PF032) hold for every role.
func TestIntegrationSchema(t *testing.T) {
	e := setup(t)
	definerOnly := []string{"integration", "secret", "run", "record", "link", "proposal", "applied", "derivation", "notice_outbox"}
	for _, role := range []string{"app_rw", "app_integrate", "app_notify", "app_posture", "app_audit", "app_gateway"} {
		for _, tbl := range definerOnly {
			if got := e.adminState("SET ROLE " + role + "; PERFORM count(*) FROM integration." + tbl); got != "42501" {
				t.Errorf("%s reads integration.%s: %s", role, tbl, got)
			}
		}
	}
	if got := e.adminState("SET ROLE integration_definer; PERFORM count(*) FROM integration.secret"); got != "ok" {
		t.Errorf("integration_definer reads secrets: %s", got)
	}
	// Loss events: BU-owned, type library, shared down; app_rw reads under
	// RLS and never writes; app_integrate never reads them.
	if got := e.adminQuery(`SELECT resource_type || ':' || shared_down || ':' || coalesce(definer::text, '-') || ':' || coalesce(inserter::text, '-')
		FROM iam.bu_owned_tables WHERE table_name = 'integration.loss_event'::regclass`); got != "library:true:integration_definer:integration_definer" {
		t.Errorf("loss_event registration: %s", got)
	}
	for _, sql := range []string{
		"INSERT INTO integration.loss_event (bu_id, integration_id, external_id, occurred_on, event_type) SELECT id, id, 'x', current_date, 'x' FROM iam.bu LIMIT 1",
		"UPDATE integration.loss_event SET event_type = 'y'",
		"DELETE FROM integration.loss_event",
	} {
		if got := e.adminState("SET ROLE app_rw; " + sql); got != "42501" {
			t.Errorf("app_rw: %s: %s", sql, got)
		}
	}
	if got := e.adminState("SET ROLE app_integrate; PERFORM count(*) FROM integration.loss_event"); got != "42501" {
		t.Errorf("app_integrate reads loss events: %s", got)
	}
	// Roles: NOBYPASSRLS; the service logs in, the definer does not.
	if got := e.adminQuery(`SELECT string_agg(rolname || ':' || rolcanlogin || ':' || rolbypassrls, ',' ORDER BY rolname) FROM pg_roles
		WHERE rolname IN ('app_integrate', 'integration_definer')`); got != "app_integrate:true:false,integration_definer:false:false" {
		t.Errorf("roles: %s", got)
	}

	// The state rules (as the owner here, so only the triggers refuse).
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('ian@example.test', 'Ian')")
	user := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'ian@example.test'")
	root := e.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	newIntegration := func(name, delivery string) string {
		return fmt.Sprintf(`INSERT INTO integration.integration (bu_id, name, kind, delivery, created_by) VALUES ('%s', '%s', 'assets', '%s', '%s')`, root, name, delivery, user)
	}
	integ := e.adminQuery(newIntegration("CMDB", "push") + " RETURNING id")
	run := e.adminQuery("INSERT INTO integration.run (integration_id, trigger, actor) VALUES ('" + integ + "', 'push', '" + user + "') RETURNING id")
	proposal := func(digest string) string {
		return fmt.Sprintf(`INSERT INTO integration.proposal (integration_id, run_id, bu_id, target_type, external_id, action, document, digest)
			VALUES ('%s', '%s', '%s', 'asset', 'a-1', 'create', '{}', repeat('%s', 64))`, integ, run, root, digest)
	}
	prop := e.adminQuery(proposal("a") + " RETURNING id")
	event := func(ext, amounts string) string {
		return fmt.Sprintf(`INSERT INTO integration.loss_event (bu_id, integration_id, external_id, occurred_on, event_type, amounts)
			VALUES ('%s', '%s', '%s', current_date, 'fraud', '%s')`, root, integ, ext, amounts)
	}
	decided := "decided_by = '" + user + "', decided_at = now()"
	for _, c := range []struct{ name, sql, want string }{
		{"a kind changed", "UPDATE integration.integration SET kind = 'risks' WHERE id = '" + integ + "'", "PF031"},
		{"a connector without settings", newIntegration("x", "connector"), "23514"},
		{"a duplicate name", newIntegration("cmdb", "file"), "23505"},
		{"paused", "UPDATE integration.integration SET state = 'paused', version = 2 WHERE id = '" + integ + "'", "ok"},
		{"a second pending proposal for one record", proposal("b"), "23505"},
		{"a proposal's document", `UPDATE integration.proposal SET document = '{"x": 1}' WHERE id = '` + prop + "'", "PF031"},
		{"rejected without a reason", "UPDATE integration.proposal SET state = 'rejected', " + decided + " WHERE id = '" + prop + "'", "23514"},
		{"rejected", "UPDATE integration.proposal SET state = 'rejected', " + decided + ", reason = 'wrong value' WHERE id = '" + prop + "'", "ok"},
		{"a decided proposal", "UPDATE integration.proposal SET state = 'pending', decided_by = NULL, decided_at = NULL, reason = NULL WHERE id = '" + prop + "'", "PF031"},
		{"a proposal deleted", "DELETE FROM integration.proposal WHERE id = '" + prop + "'", "PF031"},
		{"a run's input", "UPDATE integration.run SET complete = true WHERE id = '" + run + "'", "PF031"},
		{"failed without a cause", "UPDATE integration.run SET state = 'failed', finished_at = now() WHERE id = '" + run + "'", "23514"},
		{"succeeded", `UPDATE integration.run SET state = 'succeeded', finished_at = now(), counts = '{"received": 1}' WHERE id = '` + run + "'", "ok"},
		{"a finished run", "UPDATE integration.run SET counts = '{}' WHERE id = '" + run + "'", "PF031"},
		{"a link", fmt.Sprintf(`INSERT INTO integration.link (integration_id, external_id, target_type, target_id) VALUES ('%s', 'a-1', 'asset', '%s')`, integ, user), "ok"},
		{"a link's target", "UPDATE integration.link SET target_id = gen_random_uuid() WHERE integration_id = '" + integ + "'", "PF031"},
		{"a link's digests", "UPDATE integration.link SET last_digest = repeat('c', 64) WHERE integration_id = '" + integ + "'", "ok"},
		{"amounts by an unknown form", event("e-1", `{"other": "1"}`), "23514"},
		{"an amount as a number", event("e-1", `{"response": 1}`), "23514"},
		{"a loss event", event("e-1", `{"response": "12500.5"}`), "ok"},
		{"a loss event's source", "UPDATE integration.loss_event SET external_id = 'e-2'", "PF031"},
		{"a loss event archived", "UPDATE integration.loss_event SET archived_at = now()", "ok"},
		{"a loss event deleted", "DELETE FROM integration.loss_event", "PF031"},
		{"deleted", "UPDATE integration.integration SET state = 'deleted', deleted_at = now() WHERE id = '" + integ + "'", "ok"},
		{"a deleted integration", "UPDATE integration.integration SET name = 'again' WHERE id = '" + integ + "'", "PF031"},
		{"an integration deleted from the table", "DELETE FROM integration.integration WHERE id = '" + integ + "'", "PF031"},
	} {
		if got := e.adminState(c.sql); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// At most 50 integrations that are not deleted (PF032).
	e.adminQuery(fmt.Sprintf(`INSERT INTO integration.integration (bu_id, name, kind, delivery, created_by)
		SELECT '%s', 'i' || n, 'assets', 'push', '%s' FROM generate_series(1, 50) n RETURNING 1`, root, user))
	if got := e.adminState(newIntegration("i51", "push")); got != "PF032" {
		t.Errorf("a 51st integration: %s", got)
	}
}
