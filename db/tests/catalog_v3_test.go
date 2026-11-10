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
	c3, br3 := release(t)
	if c3.Version != 3 {
		t.Fatalf("the shipped catalog is version %d", c3.Version)
	}
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
