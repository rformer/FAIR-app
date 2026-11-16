package tests

import (
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/access/catalog"
)

// F-004 T-01 (F-004 design §12): permission catalog version 3 on an
// installation at version 2. The new keys arrive with notices, the
// Estimator role is created, built-in roles gain their keys, and custom
// roles are untouched (F-001 AC-57).
func TestCatalogVersion3Upgrade(t *testing.T) {
	// Version 3 is the shipped catalog without version 4's additions.
	c3, br3 := catalogVersion3(t)
	added := []string{"calibration.audit", "calibration.manage", "calibration.take", "estimate.request", "estimate.submit"}
	c2, br2 := cloneRelease(c3, br3)
	c2.Version, br2.CatalogVersion = 2, 2
	for _, k := range added {
		dropPermission(c2, br2, k)
	}
	br2.Roles = slices.DeleteFunc(br2.Roles, func(r catalog.BuiltinRole) bool { return r.Name == "Estimator" })
	e := setupWith(t, func() (*catalog.Catalog, *catalog.BuiltinRoles, error) { return c2, br2, nil })

	for _, u := range []string{"platform", "dana", "rita"} {
		e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
	}
	e.mustOwner("SELECT iam.bootstrap_platform_admin(" + uid("platform") + ")")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Scenario Reader') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['scenario.view'], 'test' FROM r`)
	e.mustOwner(grant("platform", "user:rita", "Scenario Reader", "ENTERPRISE"))
	if n := e.mustOwner("SELECT count(*) FROM iam.role WHERE name = 'Estimator'"); n != "0" {
		t.Fatal("setup: version 2 already has the Estimator role")
	}

	r := e.sync(t, c3, br3)
	if r.PreviousVersion != 2 || r.Version != 3 || strings.Join(r.AddedPermissions, ",") != strings.Join(added, ",") ||
		strings.Join(r.CreatedRoles, ",") != "Estimator" || len(r.CustomRolesChanged) != 0 {
		t.Fatalf("sync result %+v", r)
	}
	slices.Sort(r.VersionedRoles)
	if got := strings.Join(r.VersionedRoles, ","); got != "Approver,Auditor,BU Admin,Executive Viewer,Platform Admin,Risk Analyst,Risk Owner" {
		t.Fatalf("versioned roles %s", got)
	}
	if got := e.mustOwner("SELECT string_agg(subject, ',' ORDER BY subject COLLATE \"C\") FROM iam.catalog_notice WHERE catalog_version = 3 AND kind = 'added'"); got != strings.Join(added, ",") {
		t.Fatalf("added notices %s", got)
	}
	if got := e.mustOwner(`SELECT string_agg(key || ':' || action || ':' || privileged || ':' || risk_data, ',' ORDER BY key COLLATE "C") FROM iam.permission WHERE key = ANY (ARRAY['` + strings.Join(added, "','") + `'])`); got !=
		"calibration.audit:read:true:false,calibration.manage:admin:true:false,calibration.take:read:false:false,estimate.request:write:false:true,estimate.submit:write:false:true" {
		t.Fatalf("permissions %s", got)
	}
	// The custom role keeps its version and permissions.
	if v, perms := e.rolePerms("Scenario Reader"); v != 1 || strings.Join(perms, ",") != "scenario.view" {
		t.Fatalf("custom role v%d %v", v, perms)
	}
	if _, perms := e.rolePerms("Estimator"); strings.Join(perms, ",") != "calibration.take,estimate.submit" {
		t.Fatalf("Estimator %v", perms)
	}

	e.mustOwner(grant("platform", "user:dana", "Estimator", "ENTERPRISE"))
	e.drain()
	holds := func(user, perm string) string {
		return e.adminQuery("SELECT iam.user_has_permission(" + uid(user) + ", '" + perm + "', " + buID("ENTERPRISE") + ")")
	}
	for _, c := range []struct{ user, perm, want string }{
		{"dana", "estimate.submit", "t"}, {"dana", "calibration.take", "t"}, {"dana", "scenario.view", "f"}, {"dana", "estimate.request", "f"},
		{"rita", "scenario.view", "t"}, {"rita", "calibration.take", "f"},
		{"platform", "calibration.manage", "t"}, {"platform", "calibration.take", "t"}, {"platform", "estimate.request", "f"},
	} {
		if got := holds(c.user, c.perm); got != c.want {
			t.Errorf("%s holds %s: %s", c.user, c.perm, got)
		}
	}

	// The same release again changes nothing.
	if again := e.sync(t, c3, br3); len(again.AddedPermissions)+len(again.CreatedRoles)+len(again.VersionedRoles) != 0 {
		t.Fatalf("second sync %+v", again)
	}
}

// catalogVersion4 is the shipped catalog as it was at version 4: without
// version 5's Report Publisher role and Auditor's report.export (F-010 T-01).
func catalogVersion4(t *testing.T) (*catalog.Catalog, *catalog.BuiltinRoles) {
	t.Helper()
	c, br := release(t)
	if c.Version != 5 {
		t.Fatalf("the shipped catalog is version %d", c.Version)
	}
	c4, br4 := cloneRelease(c, br)
	c4.Version, br4.CatalogVersion = 4, 4
	br4.Roles = slices.DeleteFunc(br4.Roles, func(r catalog.BuiltinRole) bool { return r.Name == "Report Publisher" })
	for i := range br4.Roles {
		if br4.Roles[i].Name == "Auditor" {
			br4.Roles[i].Permissions = slices.DeleteFunc(br4.Roles[i].Permissions, func(k string) bool { return k == "report.export" })
		}
	}
	return c4, br4
}

// catalogVersion3 is the shipped catalog as it was at version 3: without
// version 4's notification.view (F-009 T-01).
func catalogVersion3(t *testing.T) (*catalog.Catalog, *catalog.BuiltinRoles) {
	t.Helper()
	c, br := catalogVersion4(t)
	c3, br3 := cloneRelease(c, br)
	c3.Version, br3.CatalogVersion = 3, 3
	dropPermission(c3, br3, "notification.view")
	return c3, br3
}

// F-009 T-01 (F-009 design §10): permission catalog version 4 on an
// installation at version 3: notification.view arrives with a notice,
// Platform Admin and Auditor gain it, custom roles are untouched.
func TestCatalogVersion4Upgrade(t *testing.T) {
	c4, br4 := catalogVersion4(t)
	c3, br3 := catalogVersion3(t)
	e := setupWith(t, func() (*catalog.Catalog, *catalog.BuiltinRoles, error) { return c3, br3, nil })
	for _, u := range []string{"platform", "aud", "rita"} {
		e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
	}
	e.mustOwner("SELECT iam.bootstrap_platform_admin(" + uid("platform") + ")")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Notice Reader') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['posture.view'], 'test' FROM r`)
	e.mustOwner(grant("platform", "user:rita", "Notice Reader", "ENTERPRISE"))
	e.mustOwner(grant("platform", "user:aud", "Auditor", "ENTERPRISE"))

	r := e.sync(t, c4, br4)
	slices.Sort(r.VersionedRoles)
	if r.PreviousVersion != 3 || r.Version != 4 || strings.Join(r.AddedPermissions, ",") != "notification.view" || len(r.CreatedRoles) != 0 ||
		strings.Join(r.VersionedRoles, ",") != "Auditor,Platform Admin" || len(r.CustomRolesChanged) != 0 {
		t.Fatalf("sync result %+v", r)
	}
	if got := e.mustOwner("SELECT string_agg(subject, ',') FROM iam.catalog_notice WHERE catalog_version = 4 AND kind = 'added'"); got != "notification.view" {
		t.Fatalf("added notices %s", got)
	}
	if got := e.mustOwner("SELECT action || ':' || privileged || ':' || risk_data FROM iam.permission WHERE key = 'notification.view'"); got != "read:false:false" {
		t.Fatalf("notification.view %s", got)
	}
	if v, perms := e.rolePerms("Notice Reader"); v != 1 || strings.Join(perms, ",") != "posture.view" {
		t.Fatalf("custom role v%d %v", v, perms)
	}
	e.drain()
	for _, c := range []struct{ user, want string }{{"platform", "t"}, {"aud", "t"}, {"rita", "f"}} {
		if got := e.adminQuery("SELECT iam.user_has_permission(" + uid(c.user) + ", 'notification.view', " + buID("ENTERPRISE") + ")"); got != c.want {
			t.Errorf("%s holds notification.view: %s", c.user, got)
		}
	}
	if again := e.sync(t, c4, br4); len(again.AddedPermissions)+len(again.CreatedRoles)+len(again.VersionedRoles) != 0 {
		t.Fatalf("second sync %+v", again)
	}
}

// F-010 T-01 (F-010 design §10; OQ4 as amended 2026-11-16): permission
// catalog version 5 on an installation at version 4: the built-in Report
// Publisher role (report.view, report.export) is created and Auditor gains
// report.export; Executive Viewer and Risk Analyst stay unprivileged, and
// custom roles are untouched.
func TestCatalogVersion5Upgrade(t *testing.T) {
	c5, br5 := release(t)
	c4, br4 := catalogVersion4(t)
	e := setupWith(t, func() (*catalog.Catalog, *catalog.BuiltinRoles, error) { return c4, br4, nil })
	for _, u := range []string{"platform", "aud", "exec", "rita"} {
		e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
	}
	e.mustOwner("SELECT iam.bootstrap_platform_admin(" + uid("platform") + ")")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Report Reader') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['report.view'], 'test' FROM r`)
	e.mustOwner(grant("platform", "user:rita", "Report Reader", "ENTERPRISE"))
	e.mustOwner(grant("platform", "user:aud", "Auditor", "ENTERPRISE"))
	e.mustOwner(grant("platform", "user:exec", "Executive Viewer", "ENTERPRISE"))

	r := e.sync(t, c5, br5)
	if r.PreviousVersion != 4 || r.Version != 5 || len(r.AddedPermissions) != 0 || strings.Join(r.CreatedRoles, ",") != "Report Publisher" ||
		strings.Join(r.VersionedRoles, ",") != "Auditor" || len(r.CustomRolesChanged) != 0 {
		t.Fatalf("sync result %+v", r)
	}
	if v, perms := e.rolePerms("Report Publisher"); v != 1 || strings.Join(perms, ",") != "report.export,report.view" {
		t.Fatalf("Report Publisher v%d %v", v, perms)
	}
	if v, perms := e.rolePerms("Report Reader"); v != 1 || strings.Join(perms, ",") != "report.view" {
		t.Fatalf("custom role v%d %v", v, perms)
	}
	e.drain()
	for _, c := range []struct{ user, want string }{{"aud", "t"}, {"exec", "f"}, {"rita", "f"}} {
		if got := e.adminQuery("SELECT iam.user_has_permission(" + uid(c.user) + ", 'report.export', " + buID("ENTERPRISE") + ")"); got != c.want {
			t.Errorf("%s holds report.export: %s", c.user, got)
		}
	}
	// Executive Viewer and Risk Analyst hold no privileged permission.
	for _, role := range []string{"Executive Viewer", "Risk Analyst"} {
		_, perms := e.rolePerms(role)
		for _, k := range perms {
			if e.mustOwner("SELECT privileged::text FROM iam.permission WHERE key = '"+k+"'") == "true" {
				t.Errorf("%s holds privileged %s", role, k)
			}
		}
	}
	if again := e.sync(t, c5, br5); len(again.AddedPermissions)+len(again.CreatedRoles)+len(again.VersionedRoles) != 0 {
		t.Fatalf("second sync %+v", again)
	}
}
