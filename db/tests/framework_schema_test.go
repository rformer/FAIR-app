package tests

import "testing"

// F-013 T-02 (design §2, §5): the framework schema is framework_definer's;
// the control-mapping projection is BU-owned (control) and written only by
// the definer; the state rules (PF033) and limits (PF034) hold for every
// role.
func TestFrameworkSchema(t *testing.T) {
	e := setup(t)
	definerOnly := []string{"family", "version", "requirement", "baseline", "crosswalk", "relationship", "import"}
	for _, role := range []string{"app_rw", "app_integrate", "app_notify", "app_posture", "app_audit", "app_gateway"} {
		for _, tbl := range definerOnly {
			if got := e.adminState("SET ROLE " + role + "; PERFORM count(*) FROM framework." + tbl); got != "42501" {
				t.Errorf("%s reads framework.%s: %s", role, tbl, got)
			}
		}
	}
	if got := e.adminQuery(`SELECT resource_type || ':' || shared_down || ':' || coalesce(definer::text, '-') || ':' || coalesce(inserter::text, '-')
		FROM iam.bu_owned_tables WHERE table_name = 'framework.control_mapping'::regclass`); got != "control:true:framework_definer:framework_definer" {
		t.Errorf("control_mapping registration: %s", got)
	}
	for _, sql := range []string{
		"INSERT INTO framework.control_mapping (control_id, control_version, bu_id, requirement_id, strength) SELECT gen_random_uuid(), 1, id, gen_random_uuid(), 'full' FROM iam.bu LIMIT 1",
		"UPDATE framework.control_mapping SET current = false",
		"DELETE FROM framework.control_mapping",
	} {
		if got := e.adminState("SET ROLE app_rw; " + sql); got != "42501" {
			t.Errorf("app_rw: %s: %s", sql, got)
		}
	}

	// State rules, for every role (the owner here).
	e.mustOwner("INSERT INTO framework.family (key, title) VALUES ('test-fw', 'Test framework')")
	v := e.mustOwner("INSERT INTO framework.version (family, label, title, source, format, sha256) VALUES ('test-fw', '1', 'Test 1', 'shipped', 'simple', repeat('a', 64)) RETURNING id")
	r := e.mustOwner("INSERT INTO framework.requirement (version_id, identifier, title, ord) VALUES ('" + v + "', 'tf-1', 'One', 0) RETURNING id")
	for name, c := range map[string]struct{ sql, want string }{
		"a requirement changed":       {"UPDATE framework.requirement SET title = 'x' WHERE id = '" + r + "'", "PF033"},
		"a requirement deleted":       {"DELETE FROM framework.requirement WHERE id = '" + r + "'", "PF033"},
		"a version's content changed": {"UPDATE framework.version SET title = 'x' WHERE id = '" + v + "'", "PF033"},
		"a version deleted":           {"DELETE FROM framework.version WHERE id = '" + v + "'", "PF033"},
		"a family changed":            {"UPDATE framework.family SET title = 'x'", "PF033"},
		"requirements truncated":      {"TRUNCATE framework.requirement CASCADE", "PF033"},
		"retired without a time":      {"UPDATE framework.version SET state = 'retired' WHERE id = '" + v + "'", "23514"},
		"a duplicate identifier":      {"INSERT INTO framework.requirement (version_id, identifier, title, ord) VALUES ('" + v + "', 'tf-1', 'Again', 1)", "23505"},
		"a bad identifier":            {"INSERT INTO framework.requirement (version_id, identifier, title, ord) VALUES ('" + v + "', ' x', 'Bad', 1)", "23514"},
	} {
		if got := e.adminState(c.sql); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	if got := e.adminState("UPDATE framework.version SET state = 'retired', retired_at = now() WHERE id = '" + v + "'"); got != "ok" {
		t.Fatalf("retire: %s", got)
	}
	if got := e.adminState("UPDATE framework.version SET state = 'active', retired_at = NULL WHERE id = '" + v + "'"); got != "PF033" {
		t.Errorf("a retired version reactivated: %s", got)
	}
	// Limits: 20,000 requirements a version, in one statement.
	v2 := e.mustOwner("INSERT INTO framework.version (family, label, title, source, format, sha256) VALUES ('test-fw', '2', 'Test 2', 'shipped', 'simple', repeat('b', 64)) RETURNING id")
	if got := e.adminState("INSERT INTO framework.requirement (version_id, identifier, title, ord) SELECT '" + v2 + "', 'r-' || i, 'R', i FROM generate_series(1, 20001) i"); got != "PF034" {
		t.Errorf("20,001 requirements: %s", got)
	}
	if got := e.adminState("INSERT INTO framework.requirement (version_id, identifier, title, ord) SELECT '" + v2 + "', 'r-' || i, 'R', i FROM generate_series(1, 20000) i"); got != "ok" {
		t.Errorf("20,000 requirements: %s", got)
	}
}
