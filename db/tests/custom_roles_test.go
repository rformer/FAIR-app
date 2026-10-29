package tests

import (
	"net/http"
	"strings"
	"testing"
)

// F-001 T-28 (AC-51, AC-52, AC-54, AC-55, AC-56): custom roles through the
// gateway and the iam API.

func TestCustomRoleLifecycle(t *testing.T) {
	se := sodFixture(t) // the gateway, the iam API, admin and admin2
	e := se.e
	admin := se.admin
	roleID := func(name string) string { return e.adminQuery("SELECT id FROM iam.role WHERE name = '" + name + "'") }
	events := func(typ string) string {
		return e.adminQuery("SELECT coalesce(string_agg(payload->>'severity' || ':' || (payload->'attributes'->>'name'), ',' ORDER BY id), '') FROM iam.event_outbox WHERE payload->>'type' = '" + typ + "'")
	}

	// The catalog, privileged permissions flagged (AC-54).
	perms := se.do(t, "GET", "/api/v1/permissions", admin, nil, nil)
	if perms.code != 200 || !strings.Contains(perms.raw, `{"key":"audit.view","resource_type":"audit","action":"read","privileged":true,"risk_data":false,"retired":false}`) {
		t.Fatalf("permissions: %d %.300s", perms.code, perms.raw)
	}

	// AC-51: create.
	r := se.call(t, admin, "POST", "/api/v1/roles", map[string]any{"name": "Reviewer", "permissions": []string{"report.view", "analysis.view"}, "reason": "quarterly reviews"})
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	reviewer := r.body["id"].(string)
	if events("role.created") != "info:Reviewer" || events("role.privileged_added") != "" {
		t.Fatalf("create audit: %s / %s", events("role.created"), events("role.privileged_added"))
	}
	for name, body := range map[string]map[string]any{
		"duplicate name":     {"name": "Reviewer", "permissions": []string{"report.view"}, "reason": "x"},
		"unknown permission": {"name": "X1", "permissions": []string{"nope.nope"}, "reason": "x"},
		"no permissions":     {"name": "X2", "permissions": []string{}, "reason": "x"},
		"no reason":          {"name": "X3", "permissions": []string{"report.view"}, "reason": " "},
	} {
		if r := se.call(t, admin, "POST", "/api/v1/roles", body); r.code != 409 && r.code != 400 {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}

	// AC-52: built-in roles are clonable, never editable or retirable.
	c := se.call(t, admin, "POST", "/api/v1/roles/"+roleID("Auditor")+"/clone", map[string]any{"name": "Auditor (EU)", "reason": "EU entity"})
	if c.code != 201 {
		t.Fatalf("clone: %d %s", c.code, c.raw)
	}
	if e.adminQuery("SELECT (SELECT permissions FROM iam.role_version v JOIN iam.role r ON r.id = v.role_id AND v.version = r.current_version WHERE r.name = 'Auditor (EU)') = (SELECT permissions FROM iam.role_version v JOIN iam.role r ON r.id = v.role_id AND v.version = r.current_version WHERE r.name = 'Auditor')") != "t" {
		t.Fatal("the clone differs from its source")
	}
	if !strings.Contains(events("role.privileged_added"), "high:Auditor (EU)") {
		t.Fatalf("cloning privileged permissions was not flagged: %s", events("role.privileged_added"))
	}
	if r := se.call(t, admin, "PUT", "/api/v1/roles/"+roleID("Auditor"), map[string]any{"permissions": []string{"report.view"}, "expected_version": 1, "reason": "x"}); r.code != 409 {
		t.Fatalf("edit a built-in role: %d %s", r.code, r.raw)
	}
	if r := se.call(t, admin, "POST", "/api/v1/roles/"+roleID("Auditor")+"/retire", map[string]any{"reason": "x"}); r.code != 409 {
		t.Fatalf("retire a built-in role: %d %s", r.code, r.raw)
	}

	// AC-55: the diff before saving: added, removed, privileged, who is affected.
	e.mustOwner(grant("admin", "user:other", "Reviewer", "ENTERPRISE"))
	d := se.do(t, "GET", "/api/v1/roles/"+reviewer+"/diff?permissions=analysis.view,audit.view", admin, nil, nil)
	if d.code != 200 || strings.Join(strs(d.body["added"]), ",") != "audit.view" || strings.Join(strs(d.body["removed"]), ",") != "report.view" ||
		strings.Join(strs(d.body["privileged_added"]), ",") != "audit.view" || d.body["affected_users"] != float64(1) || d.body["current_version"] != float64(1) {
		t.Fatalf("diff: %d %s", d.code, d.raw)
	}
	u := se.call(t, admin, "PUT", "/api/v1/roles/"+reviewer, map[string]any{"permissions": []string{"analysis.view", "audit.view"}, "expected_version": 1, "reason": "auditors join reviews"})
	if u.code != 200 || u.body["version"] != float64(2) {
		t.Fatalf("update: %d %s", u.code, u.raw)
	}
	if !strings.Contains(events("role.privileged_added"), "high:Reviewer") || events("role.updated") != "info:Reviewer" {
		t.Fatalf("update audit: %s / %s", events("role.privileged_added"), events("role.updated"))
	}
	if v := se.do(t, "GET", "/api/v1/roles/"+reviewer+"/versions", admin, nil, nil); len(v.body["versions"].([]any)) != 2 {
		t.Fatalf("versions: %s", v.raw)
	}
	if g := se.do(t, "GET", "/api/v1/roles/"+reviewer, admin, nil, nil); strings.Join(strs(g.body["privileged"]), ",") != "audit.view" || g.body["users"] != float64(1) {
		t.Fatalf("role: %s", g.raw)
	}
	e.drain()
	if e.adminQuery("SELECT iam.user_has_permission("+uid("other")+", 'audit.view', "+buID("ENTERPRISE")+")") != "t" {
		t.Fatal("the new version did not reach the holder")
	}
	for name, c := range map[string]struct {
		body map[string]any
		code int
	}{
		"a stale version":     {map[string]any{"permissions": []string{"analysis.view"}, "expected_version": 1, "reason": "x"}, 409},
		"no change":           {map[string]any{"permissions": []string{"audit.view", "analysis.view"}, "expected_version": 2, "reason": "x"}, 409},
		"no expected version": {map[string]any{"permissions": []string{"analysis.view"}, "reason": "x"}, 400},
		"an SoD pair (AC-53)": {map[string]any{"permissions": []string{"analysis.edit", "acceptance.approve"}, "expected_version": 2, "reason": "x"}, 409},
	} {
		if r := se.call(t, admin, "PUT", "/api/v1/roles/"+reviewer, c.body); r.code != c.code {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if d := se.do(t, "GET", "/api/v1/roles/"+reviewer+"/diff?permissions=analysis.edit,acceptance.approve", admin, nil, nil); len(d.body["sod_conflicts"].([]any)) != 1 {
		t.Fatalf("diff SoD: %s", d.raw)
	}

	// AC-30 when a role changes: a holder with admin permissions may not
	// gain risk-data ones through the edit.
	r = se.call(t, admin, "POST", "/api/v1/roles", map[string]any{"name": "Directory", "permissions": []string{"bu.view", "user.view"}, "reason": "x"})
	directory := r.body["id"].(string)
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('dir@example.test', 'Dir')")
	e.mustOwner(grant("admin", "user:dir", "Directory", "ENTERPRISE"))
	e.mustOwner(grant("admin", "user:dir", "BU Admin", "ENTERPRISE"))
	if d := se.do(t, "GET", "/api/v1/roles/"+directory+"/diff?permissions=bu.view,user.view,report.view", admin, nil, nil); d.body["admin_risk_users"] != float64(1) {
		t.Fatalf("diff AC-30: %s", d.raw)
	}
	if r := se.call(t, admin, "PUT", "/api/v1/roles/"+directory, map[string]any{"permissions": []string{"bu.view", "user.view", "report.view"}, "expected_version": 1, "reason": "x"}); r.code != 409 || !strings.Contains(r.raw, "AC-30") {
		t.Fatalf("an edit combining admin and risk data: %d %s", r.code, r.raw)
	}

	// AC-56: not while held or mapped; retired roles take no versions or assignments.
	if r := se.call(t, admin, "POST", "/api/v1/roles/"+reviewer+"/retire", map[string]any{"reason": "replaced"}); r.code != 409 || !strings.Contains(r.raw, "1 live assignment") {
		t.Fatalf("retire a held role: %d %s", r.code, r.raw)
	}
	e.mustOwner("UPDATE iam.assignment SET revoked_at = now(), revoked_by = " + uid("admin") + " WHERE role_id = '" + reviewer + "'")
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Reviewers')")
	e.mustOwner("INSERT INTO iam.group_role_mapping (grp_id, role_id, bu_id, reason, created_by) VALUES (" + grpID("Reviewers") + ", '" + reviewer + "', " + buID("ENTERPRISE") + ", 'x', " + uid("admin") + ")")
	if r := se.call(t, admin, "POST", "/api/v1/roles/"+reviewer+"/retire", map[string]any{"reason": "replaced"}); r.code != 409 || !strings.Contains(r.raw, "1 group mapping") {
		t.Fatalf("retire a mapped role: %d %s", r.code, r.raw)
	}
	e.mustOwner("UPDATE iam.group_role_mapping SET removed_at = now() WHERE role_id = '" + reviewer + "'")
	if r := se.call(t, admin, "POST", "/api/v1/roles/"+reviewer+"/retire", map[string]any{"reason": "replaced"}); r.code != 200 {
		t.Fatalf("retire: %d %s", r.code, r.raw)
	}
	if events("role.retired") != "high:Reviewer" {
		t.Fatalf("retire audit %q", events("role.retired"))
	}
	if r := se.call(t, admin, "PUT", "/api/v1/roles/"+reviewer, map[string]any{"permissions": []string{"analysis.view"}, "expected_version": 2, "reason": "x"}); r.code != 409 {
		t.Fatalf("edit a retired role: %d", r.code)
	}
	e.ownerFails(grant("admin", "user:other", "Reviewer", "ENTERPRISE"), "not assignable")
}

func TestCustomRoleAccess(t *testing.T) {
	se := sodFixture(t)
	e := se.e
	user := se.login(t, "user") // no role.view
	if r := se.do(t, "GET", "/api/v1/roles", user, nil, nil); r.code != http.StatusNotFound {
		t.Fatalf("without role.view: %d", r.code)
	}
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('roles@example.test', 'Roles')")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Role Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['role.view'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:roles", "Role Viewer", "ENTERPRISE"))
	e.drain()
	viewer := se.login(t, "roles")
	l := se.do(t, "GET", "/api/v1/roles", viewer, nil, nil)
	if l.code != 200 || len(l.body["roles"].([]any)) < 8 {
		t.Fatalf("viewer list: %d %.300s", l.code, l.raw)
	}
	if r := se.call(t, viewer, "POST", "/api/v1/roles", map[string]any{"name": "Mine", "permissions": []string{"report.view"}, "reason": "x"}); r.code != http.StatusForbidden {
		t.Fatalf("create without role.manage: %d %s", r.code, r.raw)
	}
	if r := se.call(t, viewer, "POST", "/api/v1/roles/"+e.adminQuery("SELECT id FROM iam.role WHERE name = 'Auditor'")+"/clone", map[string]any{"name": "Mine", "reason": "x"}); r.code != http.StatusForbidden {
		t.Fatalf("clone without role.manage: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "GET", "/api/v1/roles/00000000-0000-0000-0000-000000000000", viewer, nil, nil); r.code != 404 {
		t.Fatalf("unknown role: %d", r.code)
	}
}
