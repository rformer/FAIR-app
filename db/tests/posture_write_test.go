package tests

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// F-015 T-09 (AC-02): the posture write path.

// adminQuery runs SQL as the admin (superuser) and returns its output.
func (e *env) adminQuery(sql string) string {
	e.t.Helper()
	cmd := exec.CommandContext(context.Background(), "psql", "--no-psqlrc", "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1", "-d", e.db, "-c", sql)
	cmd.Env = e.adminEnv
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("admin query failed: %v\n%s\n%s", err, sql, out)
	}
	return strings.TrimSpace(string(out))
}

// trap wraps a PL/pgSQL statement so a failure reports its SQLSTATE.
func trap(stmt string) string {
	return "DO $do$ BEGIN " + stmt + "; EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'sqlstate=% %', SQLSTATE, SQLERRM; END $do$"
}

// sqlstate runs a PL/pgSQL statement as role and returns "ok" or the
// SQLSTATE it raised.
func (e *env) sqlstate(role, stmt string) string {
	e.t.Helper()
	out, err := e.as(role, trap(stmt))
	return stateOf(out, err)
}

// adminState is sqlstate for the admin (superuser).
func (e *env) adminState(stmt string) string {
	e.t.Helper()
	cmd := exec.CommandContext(context.Background(), "psql", "--no-psqlrc", "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1", "-d", e.db, "-c", trap(stmt))
	cmd.Env = e.adminEnv
	out, err := cmd.CombinedOutput()
	return stateOf(string(out), err)
}

func stateOf(out string, err error) string {
	if err == nil {
		return "ok"
	}
	if _, rest, ok := strings.Cut(out, "sqlstate="); ok && len(rest) >= 5 {
		return rest[:5]
	}
	return out
}

func (e *env) wantState(role, stmt, want string) {
	e.t.Helper()
	if got := e.sqlstate(role, stmt); got != want {
		e.t.Errorf("%s: %s\n got %s, want %s", role, stmt, got, want)
	}
}

// postureFixture seeds definitions, an active FedRAMP-family profile and a
// user, as the installer and package import (T-10) will. It returns the user
// id.
func postureFixture(e *env) string {
	e.t.Helper()
	e.admin(e.db, `
INSERT INTO posture.setting_def (key, type, direction, enum_order, bu_scopable, hard_floor, hard_floor_families, owner_feature, registered_version) VALUES
  ('session.idle_timeout',     'duration', 'lower_is_stricter', NULL, false, NULL, '{}', 'F-001', '1'),
  ('auth.lockout_threshold',   'int',      'lower_is_stricter', NULL, false, NULL, '{}', 'F-001', '1'),
  ('tls.min_version',          'enum',     'ordered', ARRAY['1.0','1.1','1.2','1.3'], false, '"1.2"', '{}', 'F-001', '1'),
  ('session.network_binding',  'enum',     'ordered', ARRAY['off','flag','reauthenticate'], true, NULL, '{}', 'F-001', '1'),
  ('fips.enabled',             'bool',     'true_is_stricter', NULL, false, 'true', '{fedramp,cmmc}', 'F-001', '1');
INSERT INTO posture.profile (id, version, name, family, kind, package_digest, status)
  VALUES ('test-fedramp', '1.0.0', 'FedRAMP Moderate', 'fedramp', 'builtin', repeat('a', 64), 'active');
INSERT INTO posture.profile_value (profile_id, version, key, default_value, bound) VALUES
  ('test-fedramp', '1.0.0', 'session.idle_timeout',    '"15m0s"', '"15m0s"'),
  ('test-fedramp', '1.0.0', 'auth.lockout_threshold',  '3', '5'),
  ('test-fedramp', '1.0.0', 'tls.min_version',         '"1.2"', '"1.2"'),
  ('test-fedramp', '1.0.0', 'session.network_binding', '"reauthenticate"', '"flag"'),
  ('test-fedramp', '1.0.0', 'fips.enabled',            'true', 'true');
INSERT INTO posture.active_profile (profile_id, version) VALUES ('test-fedramp', '1.0.0');`)
	return postureAdmins(e)
}

// postureAdmins creates two Platform Admins, admin and admin2 (both hold
// settings.change and settings.approve), materializes their scope and adds
// context key k1, so posture calls can run with a signed context. It returns
// admin's id.
func postureAdmins(e *env) string {
	e.t.Helper()
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('admin@example.test', 'Admin'), ('admin2@example.test', 'Admin 2')")
	e.mustOwner("SELECT iam.bootstrap_platform_admin(" + uid("admin") + ")")
	e.mustOwner(grant("admin", "user:admin2", "Platform Admin", "ENTERPRISE"))
	e.drain()
	e.addCtxKey(ctxKey1)
	return e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin@example.test'")
}

// asUser runs sql as role with user's signed database context.
func (e *env) asUser(role, user, sql string) (string, error) {
	e.t.Helper()
	return e.as(role, "SET authz.ctx = '"+e.mint(user, ctxKey1)+"'; "+sql)
}

func (e *env) mustAsUser(role, user, sql string) string {
	e.t.Helper()
	out, err := e.asUser(role, user, sql)
	if err != nil {
		e.t.Fatalf("%s as %s: %v\n%s\n%s", role, user, err, sql, out)
	}
	return strings.TrimSpace(out)
}

// wantStateAs is wantState with user's signed context.
func (e *env) wantStateAs(role, user, stmt, want string) {
	e.t.Helper()
	out, err := e.asUser(role, user, trap(stmt))
	if got := stateOf(out, err); got != want {
		e.t.Errorf("%s as %s: %s\n got %s, want %s", role, user, stmt, got, want)
	}
}

func addMACKey(e *env, id string) {
	e.t.Helper()
	e.mustOwner("SELECT posture.add_mac_key('" + id + "', authz.gen_random_bytes(32))")
}

// request returns SQL for the id of a change recorded by posture.request_change
// (run it with a signed context: mustAsUser, wantStateAs).
func request(key, bu, value, explanation string) string {
	return "(posture.request_change('" + key + "', " + bu + ", '" + value + "', " + explanation + ")).change_id"
}

// Verification for T-09: application roles cannot write; only the definer
// functions can, and only for app_posture.
func TestPostureNoDirectWrites(t *testing.T) {
	e := setup(t)
	postureFixture(e)
	addMACKey(e, "k1")
	for _, role := range []string{"app_rw", "app_engine", "app_posture"} {
		for _, stmt := range []string{
			`INSERT INTO posture.setting_value (key, value, source, row_mac, mac_key_id) VALUES ('tls.min_version', '"1.0"', 'profile', '\x00', 'k1')`,
			`UPDATE posture.setting_value SET value = '"1.0"'`,
			`DELETE FROM posture.setting_value`,
			`UPDATE posture.exception SET expires_at = now() + interval '10 years'`,
			`UPDATE posture.active_profile SET profile_id = 'x'`,
			`INSERT INTO posture.mac_key VALUES ('evil', decode(repeat('00', 32), 'hex'))`,
		} {
			e.wantState(role, stmt, "42501") // insufficient_privilege
		}
	}
	e.wantStateAs("app_engine", "admin", "PERFORM "+request("session.idle_timeout", "NULL", `"10m0s"`, "NULL"), "42501")
	e.wantState("app_engine", "PERFORM posture.apply_change(gen_random_uuid())", "42501")
	for _, role := range []string{"app_rw", "app_engine"} {
		e.wantState(role, "PERFORM posture.apply_revert(gen_random_uuid())", "42501")
		e.wantState(role, "PERFORM posture.mac_mismatches()", "42501")
	}
	// Since T-16 every service embeds settings.Set as app_rw: the change
	// functions are callable, and the database still decides who may change
	// what (signed context, settings.change).
	e.wantState("app_rw", "PERFORM "+request("session.idle_timeout", "NULL", `"10m0s"`, "NULL"), "PF007")
	e.mustOwner("INSERT INTO iam.app_user (email) VALUES ('nobody@example.test')")
	e.mustOwner(grant("admin", "user:nobody", "Executive Viewer", "ENTERPRISE"))
	e.drain()
	e.wantStateAs("app_rw", "nobody", "PERFORM "+request("session.idle_timeout", "NULL", `"10m0s"`, "NULL"), "PF008")
	e.wantStateAs("app_rw", "admin", "PERFORM "+request("session.idle_timeout", "NULL", `"10m0s"`, "NULL"), "ok")
	// Internal helpers are not callable, not even by the posture service.
	e.wantState("app_posture", "PERFORM posture.write_value('tls.min_version', NULL, '\"1.0\"', 'profile', NULL, NULL)", "42501")
	e.wantState("app_posture", "PERFORM posture.add_mac_key('evil', decode(repeat('00', 32), 'hex'))", "42501")
	e.wantState("app_posture", "PERFORM posture.row_mac('k1', 'a', NULL, '1', 'profile', NULL, NULL)", "42501")
}

func TestPostureChangeFlow(t *testing.T) {
	e := setup(t)
	postureFixture(e)

	// No MAC key yet: nothing can be written (fail closed).
	id := strings.TrimSpace(e.mustAsUser("app_posture", "admin", "SELECT "+request("session.idle_timeout", "NULL", `"10m0s"`, "NULL")))
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "PF006")
	addMACKey(e, "k1")

	// Tighten: recorded as requested, applied, MAC'd.
	if got := e.adminQuery("SELECT direction || ':' || state || ':' || old_value::text FROM posture.change WHERE id = '" + id + "'"); got != `tighten:requested:"15m0s"` {
		t.Fatalf("tighten recorded as %s", got)
	}
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "ok")
	if got := e.adminQuery("SELECT value::text || ':' || source || ':' || (change_id = '" + id + "') FROM posture.setting_value WHERE key = 'session.idle_timeout'"); got != `"10m0s":change:true` {
		t.Fatalf("value after tighten: %s", got)
	}
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "PF003") // applied once only

	// Loosen within bounds (lockout 3 -> 5, bound 5) applies; it is recorded as a loosening.
	id = e.mustAsUser("app_posture", "admin", "SELECT "+request("auth.lockout_threshold", "NULL", "5", "NULL"))
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "ok")
	if got := e.adminQuery("SELECT direction FROM posture.change WHERE id = '" + id + "'"); got != "loosen" {
		t.Fatalf("lockout 3 -> 5 recorded as %s", got)
	}

	// Out of bounds: needs an explanation and an approval request, then
	// cannot be applied until approvals can be verified (F-001 T-26).
	// (Since T-14 the explanation opens the approval request itself.)
	e.wantStateAs("app_posture", "admin", "PERFORM "+request("auth.lockout_threshold", "NULL", "8", "NULL"), "PF002")
	id = e.mustAsUser("app_posture", "admin", "SELECT "+request("auth.lockout_threshold", "NULL", "8", "'needed for a pilot'"))
	if got := e.adminQuery("SELECT c.state || ':' || a.status FROM posture.change c JOIN iam.approval_request a ON a.id = c.approval_request_id WHERE c.id = '" + id + "'"); got != "pending_approval:pending" {
		t.Fatalf("out-of-bounds change is %s", got)
	}
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "AP004") // not approved yet

	// Requesters need a signed context and settings.change.
	e.wantState("app_posture", "PERFORM "+request("auth.lockout_threshold", "NULL", "4", "NULL"), "PF007")
	e.mustOwner("INSERT INTO iam.app_user (email) VALUES ('viewer@example.test')")
	e.mustOwner(grant("admin", "user:viewer", "Auditor", "ENTERPRISE"))
	e.drain()
	e.wantStateAs("app_posture", "viewer", "PERFORM "+request("auth.lockout_threshold", "NULL", "4", "NULL"), "PF008")

	// Hard floors, everywhere and per family.
	e.wantStateAs("app_posture", "admin", "PERFORM "+request("tls.min_version", "NULL", `"1.1"`, "'x'"), "PF001")
	e.wantStateAs("app_posture", "admin", "PERFORM "+request("fips.enabled", "NULL", "false", "'x'"), "PF001")

	// Invalid values.
	for _, c := range [][2]string{
		{"session.idle_timeout", "15"}, {"session.idle_timeout", `"15 minutes"`}, {"session.idle_timeout", `"-5m"`},
		{"auth.lockout_threshold", `"3"`}, {"auth.lockout_threshold", "3.5"}, {"tls.min_version", `"2.0"`},
		{"tls.min_version", "1.3"}, {"fips.enabled", `"true"`}, {"no.such_setting", "1"},
	} {
		e.wantStateAs("app_posture", "admin", "PERFORM "+request(c[0], "NULL", c[1], "NULL"), "PF004")
	}

	// BU overrides only where the setting allows them.
	root := e.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	e.wantStateAs("app_posture", "admin", "PERFORM "+request("session.idle_timeout", "'"+root+"'", `"5m0s"`, "NULL"), "PF004")
	id = e.mustAsUser("app_posture", "admin", "SELECT "+request("session.network_binding", "'"+root+"'", `"reauthenticate"`, "NULL"))
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "ok")

	// Re-evaluated at apply time: a change recorded in bounds is refused if
	// the bound has since tightened.
	id = e.mustAsUser("app_posture", "admin", "SELECT "+request("session.network_binding", "NULL", `"flag"`, "NULL"))
	e.admin(e.db, `UPDATE posture.profile_value SET bound = '"reauthenticate"' WHERE key = 'session.network_binding'`)
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "PF002")

	if got := mustAs(e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s MAC mismatches after legitimate writes", got)
	}
}

// Verification for T-09: a direct database edit (here by a superuser, who
// bypasses every grant and policy) is detected by the drift check.
func TestPostureDirectEditDetected(t *testing.T) {
	e := setup(t)
	postureFixture(e)
	addMACKey(e, "k1")
	for _, c := range [][2]string{{"session.idle_timeout", `"10m0s"`}, {"auth.lockout_threshold", "4"}} {
		id := e.mustAsUser("app_posture", "admin", "SELECT "+request(c[0], "NULL", c[1], "NULL"))
		e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "ok")
	}
	edits := map[string]string{
		"value":        `UPDATE posture.setting_value SET value = '"1h0m0s"' WHERE key = 'session.idle_timeout'`,
		"source":       `UPDATE posture.setting_value SET source = 'profile', change_id = NULL WHERE key = 'session.idle_timeout'`,
		"MAC swapped":  `UPDATE posture.setting_value s SET row_mac = o.row_mac FROM posture.setting_value o WHERE s.key = 'session.idle_timeout' AND o.key = 'auth.lockout_threshold'`,
		"inserted row": `INSERT INTO posture.setting_value (key, value, source, row_mac, mac_key_id) VALUES ('tls.min_version', '"1.0"', 'profile', decode(repeat('00', 32), 'hex'), 'k1')`,
		"re-keyed":     `INSERT INTO posture.mac_key VALUES ('k0', authz.gen_random_bytes(32)); UPDATE posture.setting_value SET mac_key_id = 'k0' WHERE key = 'session.idle_timeout'`,
	}
	// Each edit is reported (applied one at a time, then undone).
	for name, sql := range edits {
		before := e.adminQuery("SELECT count(*) FROM posture.mac_mismatches()")
		e.admin(e.db, "CREATE TABLE IF NOT EXISTS public.snap AS SELECT * FROM posture.setting_value; "+sql)
		got := e.adminQuery("SELECT coalesce(string_agg(key, ','), '') FROM posture.mac_mismatches()")
		if before != "0" || got == "" {
			t.Errorf("%s: mismatches before %s, after %q", name, before, got)
		}
		e.admin(e.db, "DELETE FROM posture.setting_value; INSERT INTO posture.setting_value SELECT * FROM public.snap; DROP TABLE public.snap; DELETE FROM posture.mac_key WHERE key_id = 'k0'")
	}

	// Rotation: rows signed by a retired key still verify; new writes use the new key.
	addMACKey(e, "k2")
	e.mustOwner("SELECT posture.retire_mac_key('k1')")
	id := e.mustAsUser("app_posture", "admin", "SELECT "+request("auth.lockout_threshold", "NULL", "3", "NULL"))
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "ok")
	if got := e.adminQuery("SELECT string_agg(key || '=' || mac_key_id, ',' ORDER BY key) FROM posture.setting_value"); got != "auth.lockout_threshold=k2,session.idle_timeout=k1" {
		t.Fatalf("keys after rotation: %s", got)
	}
	if got := mustAs(e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s mismatches after rotation", got)
	}
}

func TestPostureRevert(t *testing.T) {
	e := setup(t)
	user := postureFixture(e)
	addMACKey(e, "k1")
	root := e.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	// Exceptions are created by approved out-of-bounds changes (T-14, after
	// F-001 T-26); seed them here as that path will.
	seed := func(key, bu, value, bound string, expired bool) string {
		at := "now() + interval '1 day'"
		created := "now()"
		if expired {
			at, created = "now() - interval '1 second'", "now() - interval '90 days'"
		}
		id := e.adminQuery(`INSERT INTO posture.exception (key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, created_at, expires_at, state)
			VALUES ('` + key + `', ` + bu + `, '` + value + `', '` + bound + `', 'pilot', '` + user + `', '` + user + `', ` + created + `, ` + at + `, 'active') RETURNING id`)
		e.adminQuery(`SELECT posture.write_value('` + key + `', ` + bu + `, '` + value + `', 'exception', NULL, '` + id + `')`)
		return id
	}

	live := seed("auth.lockout_threshold", "NULL", "8", "5", false)
	e.wantState("app_posture", "PERFORM posture.apply_revert('"+live+"')", "PF003") // not expired yet

	inst := seed("session.idle_timeout", "NULL", `"30m0s"`, `"15m0s"`, true)
	e.wantState("app_posture", "PERFORM posture.apply_revert('"+inst+"')", "ok")
	if got := e.adminQuery("SELECT value::text || ':' || source || ':' || (exception_id = '" + inst + "') FROM posture.setting_value WHERE key = 'session.idle_timeout'"); got != `"15m0s":revert:true` {
		t.Fatalf("instance revert gave %s", got)
	}
	e.wantState("app_posture", "PERFORM posture.apply_revert('"+inst+"')", "PF003") // already reverted

	bu := seed("session.network_binding", "'"+root+"'", `"off"`, `"flag"`, true)
	e.wantState("app_posture", "PERFORM posture.apply_revert('"+bu+"')", "ok")
	if got := e.adminQuery("SELECT count(*) FROM posture.setting_value WHERE key = 'session.network_binding'"); got != "0" {
		t.Fatalf("BU revert left %s rows; the BU must inherit again", got)
	}

	// A later change already replaced the exception's value: only the exception closes.
	sup := seed("tls.min_version", "NULL", `"1.2"`, `"1.2"`, true)
	id := e.mustAsUser("app_posture", "admin", "SELECT "+request("tls.min_version", "NULL", `"1.3"`, "NULL"))
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "ok")
	e.wantState("app_posture", "PERFORM posture.apply_revert('"+sup+"')", "ok")
	if got := e.adminQuery("SELECT value::text || ':' || source FROM posture.setting_value WHERE key = 'tls.min_version'"); got != `"1.3":change` {
		t.Fatalf("revert of a superseded exception changed the value: %s", got)
	}
	if got := e.adminQuery("SELECT string_agg(state, ',' ORDER BY state) FROM posture.exception"); got != "active,reverted,reverted,reverted" {
		t.Fatalf("exception states %s", got)
	}
	if got := mustAs(e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s mismatches after reverts", got)
	}
}

func TestPostureDurations(t *testing.T) {
	e := setup(t)
	for in, want := range map[string]string{
		"0": "0", "15m0s": "900000000000", "2160h0m0s": "7776000000000000", "1.5s": "1500000000",
		"500ms": "500000000", "1h2m3s4ms5us6ns": "3723004005006", "1µs": "1000", ".5m": "30000000000",
	} {
		if got := e.adminQuery("SELECT posture.duration_ns('" + in + "')::bigint"); got != want {
			t.Errorf("duration_ns(%q) = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"15", "1x", "", "m", "1h 2m", "1.2.3s", "-5m"} {
		if got := e.adminState("PERFORM posture.duration_ns('" + bad + "')"); got != "PF004" {
			t.Errorf("duration_ns(%q): %s, want PF004", bad, got)
		}
	}
}

func mustAs(e *env, role, sql string) string {
	e.t.Helper()
	out, err := e.as(role, sql)
	if err != nil {
		e.t.Fatalf("%s: %v\n%s\n%s", role, err, sql, out)
	}
	return strings.TrimSpace(out)
}
