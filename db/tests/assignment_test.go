package tests

// F-001 T-07 (AC-20, AC-21, AC-22, AC-28, AC-30): assignment grantor checks
// and the escalation test suite.

import (
	"fmt"
	"strings"
	"testing"
)

func uid(name string) string {
	return fmt.Sprintf("(SELECT id FROM iam.app_user WHERE email = '%s@example.test')", name)
}

func roleID(name string) string {
	return fmt.Sprintf("(SELECT id FROM iam.role WHERE name = '%s')", name)
}

func buID(code string) string {
	return fmt.Sprintf("(SELECT id FROM iam.bu WHERE code = '%s')", code)
}

func grpID(name string) string {
	return fmt.Sprintf("(SELECT id FROM iam.grp WHERE display_name = '%s')", name)
}

// grant returns SQL for grantor assigning role at bu to a user or group
// principal ("user:name" or "group:name").
func grant(grantor, principal, role, bu string) string {
	kind, name, _ := strings.Cut(principal, ":")
	pid := uid(name)
	if kind == "group" {
		pid = grpID(name)
	}
	return fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		VALUES ('%s', %s, %s, %s, %s)`, kind, pid, roleID(role), buID(bu), uid(grantor))
}

func revoke(revoker, principal, role, bu string) string {
	return fmt.Sprintf(`UPDATE iam.assignment SET revoked_at = now(), revoked_by = %s
		WHERE principal_id = %s AND role_id = %s AND bu_id = %s AND revoked_at IS NULL`, uid(revoker), uid(principal), roleID(role), buID(bu))
}

// assignmentFixture builds ENTERPRISE -> {A -> {A1, R (restricted) -> R1}, B}
// and users; "platform" is bootstrapped as the first Platform Admin.
func assignmentFixture(t *testing.T) *env {
	e := setup(t)
	e.addBU("A", "ENTERPRISE")
	e.addBU("A1", "A")
	e.addBU("B", "ENTERPRISE")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'R', 'R', id, true FROM iam.bu WHERE code = 'A'")
	e.addBU("R1", "R")
	for _, u := range []string{"platform", "platform2", "buadmin", "buadmin2", "buadmin3", "analyst", "mallory", "erin"} {
		e.mustOwner(fmt.Sprintf("INSERT INTO iam.app_user (email, display_name) VALUES ('%s@example.test', '%s')", u, u))
	}
	e.mustOwner("SELECT iam.bootstrap_platform_admin(" + uid("platform") + ")")
	// Neither admin nor risk data, so only AC-28 can stop a self-grant of it.
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Directory Reader') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, 1, ARRAY['bu.view', 'user.view'], 'test' FROM r`)
	return e
}

func TestAssignmentBootstrap(t *testing.T) {
	e := setup(t)
	e.mustOwner("INSERT INTO iam.app_user (email, status) VALUES ('off@example.test', 'disabled'), ('on@example.test', 'active'), ('two@example.test', 'active')")
	e.ownerFails("SELECT iam.bootstrap_platform_admin((SELECT id FROM iam.app_user WHERE email = 'off@example.test'))", "not an active user")
	e.mustFail("app_rw", "SELECT iam.bootstrap_platform_admin(gen_random_uuid())", "permission denied")
	e.mustOwner("SELECT iam.bootstrap_platform_admin((SELECT id FROM iam.app_user WHERE email = 'on@example.test'))")
	e.ownerFails("SELECT iam.bootstrap_platform_admin((SELECT id FROM iam.app_user WHERE email = 'two@example.test'))", "already exists")
	// Outside the bootstrap function a grantor is mandatory.
	e.ownerFails(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id)
		SELECT 'user', id, `+roleID("Auditor")+`, `+buID("ENTERPRISE")+` FROM iam.app_user WHERE email = 'two@example.test'`, "granted_by is required")
}

// TestAssignmentEscalationSuite is the T-07 verification: BU Admin to admin
// role, crossing a restricted BU, self-grant (direct and via a group), and
// admin + risk-data combinations.
func TestAssignmentEscalationSuite(t *testing.T) {
	e := assignmentFixture(t)
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Admins+Mallory'), ('Mallory only')")
	e.mustOwner("INSERT INTO iam.grp_member SELECT " + grpID("Admins+Mallory") + ", id FROM iam.app_user WHERE email IN ('buadmin@example.test', 'mallory@example.test')")
	e.mustOwner("INSERT INTO iam.grp_member SELECT " + grpID("Mallory only") + ", " + uid("mallory"))

	steps := []struct {
		name, sql, wantErr string // wantErr "" means the step must succeed
	}{
		{"platform makes buadmin BU Admin of A", grant("platform", "user:buadmin", "BU Admin", "A"), ""},
		{"platform makes analyst Risk Analyst at A1", grant("platform", "user:analyst", "Risk Analyst", "A1"), ""},
		{"BU Admin assigns inside subtree (AC-21, AC-22)", grant("buadmin", "user:mallory", "Risk Analyst", "A1"), ""},
		{"AC-20: a second assignment at another BU", grant("platform", "user:mallory", "Executive Viewer", "B"), ""},

		{"BU Admin assigns outside subtree", grant("buadmin", "user:erin", "Risk Analyst", "B"), "lacks access.assign"},
		{"BU Admin assigns into restricted BU below it", grant("buadmin", "user:erin", "Executive Viewer", "R"), "lacks access.assign"},
		{"BU Admin assigns below a restricted BU", grant("buadmin", "user:erin", "Executive Viewer", "R1"), "lacks access.assign"},
		{"BU Admin grants BU Admin", grant("buadmin", "user:erin", "BU Admin", "A1"), "contains admin permissions"},
		{"BU Admin grants Platform Admin", grant("buadmin", "user:erin", "Platform Admin", "A"), "contains admin permissions"},

		{"self-grant by BU Admin", grant("buadmin", "user:buadmin", "Directory Reader", "A1"), "AC-28"},
		{"self-grant by Platform Admin", grant("platform", "user:platform", "Directory Reader", "A"), "AC-28"},
		{"self-grant via own group", grant("buadmin", "group:Admins+Mallory", "Directory Reader", "A1"), "AC-28"},
		{"others may grant the same role", grant("platform", "user:buadmin", "Directory Reader", "A1"), ""},

		{"AC-30: admin user gets risk data via a group", grant("platform", "group:Admins+Mallory", "Executive Viewer", "A1"), "AC-30"},
		{"AC-30: risk-data user gets an admin role", grant("platform", "user:analyst", "BU Admin", "A1"), "AC-30"},
		{"group without admins is fine", grant("platform", "group:Mallory only", "Executive Viewer", "A1"), ""},

		{"root grantor assigns into restricted BU", grant("platform", "user:buadmin2", "BU Admin", "R"), ""},
		{"explicit BU Admin at R assigns below it", grant("buadmin2", "user:erin", "Executive Viewer", "R1"), ""},
		{"BU Admin at R still cannot reach A1", grant("buadmin2", "user:erin", "Executive Viewer", "A1"), "lacks access.assign"},

		{"duplicate live assignment", grant("platform", "user:mallory", "Executive Viewer", "B"), "assignment_live"},
		{"unknown principal", strings.Replace(grant("platform", "user:nobody", "Auditor", "B"), uid("nobody"), "gen_random_uuid()", 1), "unknown user"},
		{"mapped assignments wait for T-24", `INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by, source, mapping_id)
			VALUES ('user', ` + uid("erin") + `, ` + roleID("Auditor") + `, ` + buID("B") + `, ` + uid("platform") + `, 'mapped', gen_random_uuid())`, "T-24"},

		{"revoke by someone without authority", revoke("mallory", "analyst", "Risk Analyst", "A1"), "lacks access.assign"},
		{"self-revoke", revoke("buadmin", "buadmin", "BU Admin", "A"), "AC-28"},
		{"BU Admin revokes inside subtree", revoke("buadmin", "mallory", "Risk Analyst", "A1"), ""},
		{"changing an assignment", "UPDATE iam.assignment SET expires_at = now() + interval '1 year' WHERE principal_id = " + uid("analyst"), "immutable"},
		{"deleting an assignment", "DELETE FROM iam.assignment WHERE principal_id = " + uid("analyst"), "never changed or deleted"},

		{"platform revokes buadmin", revoke("platform", "buadmin", "BU Admin", "A"), ""},
		{"revoked grantor has no authority", grant("buadmin", "user:erin", "Risk Analyst", "A1"), "lacks access.assign"},
		{"platform makes platform2 Platform Admin", grant("platform", "user:platform2", "Platform Admin", "ENTERPRISE"), ""},
		{"disable platform2", "UPDATE iam.app_user SET status = 'disabled' WHERE id = " + uid("platform2"), ""},
		{"disabled grantor has no authority", grant("platform2", "user:erin", "Auditor", "B"), "not an active user"},
		{"archive B", "UPDATE iam.bu SET archived_at = now() WHERE code = 'B'", ""},
		{"archived BU", grant("platform", "user:erin", "Auditor", "B"), "archived"},
	}
	for _, s := range steps {
		out, err := e.owner(s.sql)
		switch {
		case s.wantErr == "" && err != nil:
			t.Fatalf("%s: unexpected failure: %s", s.name, out)
		case s.wantErr != "" && err == nil:
			t.Fatalf("%s: expected failure containing %q, but it succeeded", s.name, s.wantErr)
		case s.wantErr != "" && !strings.Contains(out, s.wantErr):
			t.Fatalf("%s: expected %q, got: %s", s.name, s.wantErr, out)
		}
	}
}

// AC-21 / AC-60: an assignment applies to its node and descendants, but not
// above it and not across a restricted BU.
func TestAssignmentScope(t *testing.T) {
	e := assignmentFixture(t)
	e.mustOwner(grant("platform", "user:erin", "Executive Viewer", "A"))
	for bu, want := range map[string]string{"A": "t", "A1": "t", "R": "f", "R1": "f", "ENTERPRISE": "f", "B": "f"} {
		if got := e.mustOwner(fmt.Sprintf("SELECT iam.user_has_permission(%s, 'register.view', %s)", uid("erin"), buID(bu))); got != want {
			t.Errorf("erin register.view at %s = %s, want %s", bu, got, want)
		}
	}
}

// Authority lapses when the grantor's assignment expires.
func TestAssignmentExpiredGrantor(t *testing.T) {
	e := assignmentFixture(t)
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by, expires_at)
		VALUES ('user', %s, %s, %s, %s, now() + interval '1 second')`, uid("buadmin3"), roleID("BU Admin"), buID("A"), uid("platform")))
	e.mustOwner(grant("buadmin3", "user:erin", "Executive Viewer", "A1"))
	e.mustOwner("SELECT pg_sleep(1.2)")
	e.ownerFails(grant("buadmin3", "user:mallory", "Executive Viewer", "A1"), "lacks access.assign")
}

func TestAssignmentRetiredRole(t *testing.T) {
	e := assignmentFixture(t)
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Old') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['bu.view'], 'x' FROM r`)
	e.mustOwner("UPDATE iam.role SET status = 'retired' WHERE name = 'Old'")
	e.ownerFails(grant("platform", "user:erin", "Old", "A"), "not assignable")
	e.mustOwner("INSERT INTO iam.role (name) VALUES ('Empty')")
	e.ownerFails(grant("platform", "user:erin", "Empty", "A"), "not assignable")
}
