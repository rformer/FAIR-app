package tests

import (
	"strings"
	"testing"
)

// F-015 T-08 (design §5 access model): posture tables.
var postureTables = []string{"active_profile", "change", "exception", "mac_key", "profile", "profile_value", "setting_def", "setting_value"}

// Verification for T-08: application roles have no access to posture tables,
// reads included; RLS is forced with a posture_definer-only policy.
func TestPostureTablesLocked(t *testing.T) {
	e := setup(t)
	got := e.mustOwner(`SELECT string_agg(c.relname || ':' || pg_get_userbyid(c.relowner) || ':' || c.relrowsecurity || ':' || c.relforcerowsecurity, ',' ORDER BY c.relname)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'posture' AND c.relkind = 'r'`)
	var want []string
	for _, tbl := range postureTables {
		want = append(want, tbl+":fair_owner:true:true")
	}
	if got != strings.Join(want, ",") {
		t.Fatalf("posture tables\n got: %s\nwant: %s", got, strings.Join(want, ","))
	}
	policies := e.mustOwner(`SELECT string_agg(DISTINCT polname || ':' || cmd || ':' || roles::text, ',')
		FROM (SELECT p.polname, p.polcmd::text AS cmd, ARRAY(SELECT pg_get_userbyid(r) FROM unnest(p.polroles) r) AS roles
		      FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		      WHERE n.nspname = 'posture') x`)
	if policies != "definer_only:*:{posture_definer}" {
		t.Fatalf("posture policies: %s", policies)
	}
	if n := e.mustOwner(`SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'posture'`); n != "8" {
		t.Fatalf("%s policies, want one per table", n)
	}

	for _, role := range []string{"app_rw", "app_engine", "app_posture", "app_migrator"} {
		for _, tbl := range postureTables {
			out := e.mustOwner(`SELECT has_table_privilege('` + role + `', 'posture.` + tbl + `', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')`)
			if out != "f" {
				t.Errorf("%s has privileges on posture.%s", role, tbl)
			}
			if role != "app_migrator" {
				e.mustFail(role, "SELECT * FROM posture."+tbl, "permission denied")
			}
		}
	}
	e.mustFail("app_posture", "CREATE TABLE posture.evil (id int)", "permission denied")
	e.mustFail("app_rw", "SELECT 1 FROM posture.setting_value", "permission denied")

	// What the posture service's readiness check expects of its connection.
	out, err := e.as("app_posture", `SELECT current_user || ':' || has_schema_privilege('posture', 'USAGE') || ':' ||
		has_table_privilege('posture.setting_value', 'SELECT')`)
	if err != nil || out != "app_posture:true:false" {
		t.Fatalf("app_posture readiness view %q (err %v)", out, err)
	}
	if out, err := e.as("app_rw", "SELECT has_schema_privilege('posture', 'USAGE')"); err != nil || out != "f" {
		t.Fatalf("app_rw schema usage %q (err %v), want none until T-11", out, err)
	}
}

// A mistaken grant still exposes no rows: only posture_definer has a policy.
func TestPostureRLSDefenceInDepth(t *testing.T) {
	e := setup(t)
	e.admin(e.db, `INSERT INTO posture.setting_def (key, type, direction, owner_feature, registered_version)
		VALUES ('session.idle_timeout', 'duration', 'lower_is_stricter', 'F-001', '1')`)
	e.admin(e.db, "GRANT USAGE ON SCHEMA posture TO app_rw; GRANT SELECT, UPDATE, DELETE ON posture.setting_def TO app_rw")
	if out, err := e.as("app_rw", "SELECT count(*) FROM posture.setting_def"); err != nil || out != "0" {
		t.Fatalf("app_rw with a mistaken grant sees %q rows (err %v), want 0", out, err)
	}
	if out, err := e.as("app_rw", "UPDATE posture.setting_def SET bu_scopable = true RETURNING key"); err != nil || out != "" {
		t.Fatalf("app_rw with a mistaken grant updated %q (err %v)", out, err)
	}
}

func TestPostureConstraints(t *testing.T) {
	e := setup(t)
	mac := `decode(repeat('00', 32), 'hex')`
	seed := []string{
		`INSERT INTO posture.mac_key (key_id, secret) VALUES ('k1', decode(repeat('00', 32), 'hex'))`,
		`INSERT INTO posture.setting_def (key, type, direction, enum_order, owner_feature, registered_version)
		 VALUES ('tls.min_version', 'enum', 'ordered', ARRAY['1.0','1.1','1.2','1.3'], 'F-001', '1')`,
		`INSERT INTO posture.profile (id, version, name, family, kind, package_digest, status)
		 VALUES ('test-fedramp', '1.0.0', 'FedRAMP Moderate', 'fedramp', 'builtin', repeat('a', 64), 'active')`,
		`INSERT INTO posture.setting_value (key, value, source, row_mac, mac_key_id) VALUES ('tls.min_version', '"1.2"', 'profile', ` + mac + `, 'k1')`,
		`INSERT INTO posture.active_profile (profile_id, version) VALUES ('test-fedramp', '1.0.0')`,
	}
	for _, s := range seed {
		e.admin(e.db, s)
	}
	type refusal struct{ sql, want string }
	check := "violates check constraint"
	refused := map[string]refusal{
		"type and direction disagree": {`INSERT INTO posture.setting_def (key, type, direction, owner_feature, registered_version)
			VALUES ('a.b', 'bool', 'lower_is_stricter', 'F-001', '1')`, check},
		"enum without order": {`INSERT INTO posture.setting_def (key, type, direction, owner_feature, registered_version)
			VALUES ('a.b', 'enum', 'ordered', 'F-001', '1')`, check},
		"bad key": {`INSERT INTO posture.setting_def (key, type, direction, owner_feature, registered_version)
			VALUES ('NoDots', 'bool', 'true_is_stricter', 'F-001', '1')`, "setting_def_key_check"},
		"built-in without digest": {`INSERT INTO posture.profile (id, version, name, family, kind, status)
			VALUES ('x', '1', 'X', 'fedramp', 'builtin', 'active')`, check},
		"custom without base": {`INSERT INTO posture.profile (id, version, name, family, kind, status)
			VALUES ('x', '1', 'X', 'fedramp', 'custom', 'draft')`, check},
		"loosened without justification": {`INSERT INTO posture.profile_value (profile_id, version, key, default_value, bound, loosened)
			VALUES ('test-fedramp', '1.0.0', 'tls.min_version', '"1.2"', '"1.2"', true)`, check},
		"second instance-wide value": {`INSERT INTO posture.setting_value (key, value, source, row_mac, mac_key_id)
			VALUES ('tls.min_version', '"1.3"', 'profile', ` + mac + `, 'k1')`, "setting_value_key_bu_id_key"},
		"change source without change": {`INSERT INTO posture.setting_value (key, bu_id, value, source, row_mac, mac_key_id)
			VALUES ('tls.min_version', (SELECT id FROM iam.bu LIMIT 1), '"1.3"', 'change', ` + mac + `, 'k1')`, check},
		"short row_mac": {`INSERT INTO posture.setting_value (key, bu_id, value, source, row_mac, mac_key_id)
			VALUES ('tls.min_version', (SELECT id FROM iam.bu LIMIT 1), '"1.3"', 'profile', '\x00', 'k1')`, "setting_value_row_mac_check"},
		"second active profile": {`INSERT INTO posture.active_profile (singleton, profile_id, version)
			VALUES (true, 'test-fedramp', '1.0.0')`, "active_profile_pkey"},
		"change for unregistered key": {`INSERT INTO posture.change (key, new_value, direction, requested_by, state)
			VALUES ('no.such', '1', 'neutral', (SELECT id FROM iam.app_user LIMIT 1), 'rejected')`, "change_key_fkey"},
	}
	e.admin(e.db, `INSERT INTO iam.app_user (email, display_name) VALUES ('posture@example.test', 'Posture Test')`)
	for name, r := range refused {
		err := e.psqlAs(nil, e.db, r.sql)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), r.want) {
			t.Errorf("%s: refused for the wrong reason: %v", name, err)
		}
	}
}
