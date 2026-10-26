package tests

// F-001 T-06 (AC-52, AC-55, AC-57): permission catalog sync, built-in role
// immutability and role versioning.

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/access/catalog"
)

// release returns the build's catalog and built-in roles.
func release(t *testing.T) (*catalog.Catalog, *catalog.BuiltinRoles) {
	t.Helper()
	c, br, err := catalog.Release()
	if err != nil {
		t.Fatal(err)
	}
	return c, br
}

func syncSQL(t *testing.T, c *catalog.Catalog, br *catalog.BuiltinRoles) string {
	t.Helper()
	b, err := catalog.SyncPayload(c, br)
	if err != nil {
		t.Fatal(err)
	}
	return "SELECT iam.sync_release($payload$" + string(b) + "$payload$::jsonb)"
}

type syncResult struct {
	Version          int      `json:"version"`
	PreviousVersion  int      `json:"previous_version"`
	AddedPermissions []string `json:"added_permissions"`
	CreatedRoles     []string `json:"created_roles"`
	VersionedRoles   []string `json:"versioned_roles"`
}

func (e *env) sync(t *testing.T, c *catalog.Catalog, br *catalog.BuiltinRoles) syncResult {
	t.Helper()
	var r syncResult
	if err := json.Unmarshal([]byte(e.mustOwner(syncSQL(t, c, br))), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// rolePerms returns the current version and permissions of a role.
func (e *env) rolePerms(name string) (int, []string) {
	e.t.Helper()
	out := e.mustOwner(fmt.Sprintf(`SELECT r.current_version || '|' || array_to_string(v.permissions, ',')
		FROM iam.role r JOIN iam.role_version v ON v.role_id = r.id AND v.version = r.current_version
		WHERE r.name = '%s'`, name))
	ver, perms, _ := strings.Cut(out, "|")
	n, err := strconv.Atoi(ver)
	if err != nil {
		e.t.Fatalf("role %s: %v (%q)", name, err, out)
	}
	if perms == "" {
		return n, nil
	}
	return n, strings.Split(perms, ",")
}

// cloneRelease deep-copies the release so tests can derive other versions.
func cloneRelease(c *catalog.Catalog, br *catalog.BuiltinRoles) (*catalog.Catalog, *catalog.BuiltinRoles) {
	c2 := &catalog.Catalog{Version: c.Version, Permissions: slices.Clone(c.Permissions)}
	br2 := &catalog.BuiltinRoles{CatalogVersion: br.CatalogVersion}
	for _, r := range br.Roles {
		br2.Roles = append(br2.Roles, catalog.BuiltinRole{Name: r.Name, Permissions: slices.Clone(r.Permissions)})
	}
	return c2, br2
}

func TestReleaseSyncSeedsCatalogAndBuiltinRoles(t *testing.T) {
	e := setup(t)
	c, br := release(t)
	r := e.sync(t, c, br)
	if r.Version != 1 || r.PreviousVersion != 0 || len(r.AddedPermissions) != len(c.Permissions) || len(r.CreatedRoles) != len(br.Roles) {
		t.Fatalf("first sync = %+v", r)
	}
	if out := e.mustOwner("SELECT count(*) FILTER (WHERE risk_data) || '/' || count(*) FILTER (WHERE privileged) || '/' || count(*) FROM iam.permission"); out != "19/30/56" {
		t.Fatalf("risk/privileged/total = %s, want 19/30/56", out)
	}
	for _, role := range br.Roles {
		ver, perms := e.rolePerms(role.Name)
		if ver != 1 || !slices.Equal(perms, role.Permissions) {
			t.Errorf("%s: version %d perms %v, want 1 %v", role.Name, ver, perms, role.Permissions)
		}
	}

	// Idempotent: a second sync of the same release changes nothing.
	if r := e.sync(t, c, br); len(r.AddedPermissions)+len(r.CreatedRoles)+len(r.VersionedRoles) != 0 {
		t.Fatalf("second sync changed something: %+v", r)
	}
	if out := e.mustOwner("SELECT max(current_version) FROM iam.role"); out != "1" {
		t.Fatalf("versions after re-sync = %s, want 1", out)
	}
}

// AC-52: built-in roles cannot be edited, versioned, retired or deleted by
// anyone, including the owner outside iam.sync_release; they can be cloned.
func TestBuiltinRolesImmutable(t *testing.T) {
	e := setup(t)
	c, br := release(t)
	e.sync(t, c, br)

	e.ownerFails("UPDATE iam.role SET name = 'Admin2' WHERE name = 'Platform Admin'", "cannot be edited")
	e.ownerFails("UPDATE iam.role SET status = 'retired' WHERE name = 'Auditor'", "cannot be edited")
	e.ownerFails("UPDATE iam.role SET builtin = false WHERE name = 'Auditor'", "immutable")
	e.ownerFails(`INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, 2, ARRAY['bu.view'], 'x' FROM iam.role WHERE name = 'Auditor'`, "cannot be edited")
	e.ownerFails("DELETE FROM iam.role WHERE name = 'Auditor'", "never changed or deleted")
	e.ownerFails("DELETE FROM iam.role_version", "never changed or deleted")
	e.ownerFails("INSERT INTO iam.role (name, builtin) VALUES ('Fake Admin', true)", "release catalog")
	e.ownerFails("INSERT INTO iam.permission VALUES ('evil.grant', 'evil', 'read', false, false, 1)", "sync_release")
	e.ownerFails("UPDATE iam.permission SET privileged = false WHERE key = 'audit.view'", "never changed")
	e.ownerFails("UPDATE iam.permission_catalog SET version = 99", "sync_release")
	// Setting the sync flag by hand does not help a non-owner session.
	e.mustFail("app_rw", "SELECT set_config('iam.release_sync', 'on', false); SELECT * FROM iam.role", "permission denied")

	// Clone (AC-52): a custom role with the built-in's permissions.
	_, auditor := e.rolePerms("Auditor")
	e.mustOwner(fmt.Sprintf(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Auditor (EU)') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, 1, ARRAY['%s'], 'clone of Auditor' FROM r`, strings.Join(auditor, "','")))
	if ver, perms := e.rolePerms("Auditor (EU)"); ver != 1 || !slices.Equal(perms, auditor) {
		t.Fatalf("clone = v%d %v", ver, perms)
	}
}

// AC-55: role versions are append-only and increment by one.
func TestRoleVersionsIncrement(t *testing.T) {
	e := setup(t)
	c, br := release(t)
	e.sync(t, c, br)
	e.mustOwner("INSERT INTO iam.role (name) VALUES ('Custom')")
	ins := func(version int, perms string) string {
		return fmt.Sprintf(`INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
			SELECT id, %d, %s, 'test' FROM iam.role WHERE name = 'Custom'`, version, perms)
	}
	e.ownerFails(ins(2, "ARRAY['bu.view']"), "next version of \"Custom\" is 1")
	e.mustOwner(ins(1, "ARRAY['register.view', 'bu.view']"))
	e.mustOwner(ins(2, "ARRAY['register.view']"))
	e.ownerFails(ins(2, "ARRAY['bu.view']"), "next version of \"Custom\" is 3")
	e.ownerFails(ins(4, "ARRAY['bu.view']"), "next version of \"Custom\" is 3")
	e.ownerFails(ins(3, "ARRAY['nope.nope']"), "unknown permission nope.nope")
	e.ownerFails(ins(3, "ARRAY['bu.view', 'bu.view']"), "distinct")
	e.ownerFails(ins(3, "ARRAY['bu.view', NULL]"), "distinct")
	e.ownerFails("UPDATE iam.role SET current_version = 7 WHERE name = 'Custom'", "advances only")
	e.ownerFails("UPDATE iam.role_version SET permissions = '{}' WHERE version = 1", "never changed")

	if out := e.mustOwner(`SELECT string_agg(v.version || ':' || array_to_string(v.permissions, ','), ' ' ORDER BY v.version)
		FROM iam.role_version v JOIN iam.role r ON r.id = v.role_id WHERE r.name = 'Custom'`); out != "1:bu.view,register.view 2:register.view" {
		t.Fatalf("history = %q", out) // permissions are stored sorted
	}
	if ver, _ := e.rolePerms("Custom"); ver != 2 {
		t.Fatalf("current_version = %d, want 2", ver)
	}
	// Custom roles can be renamed and retired.
	e.mustOwner("UPDATE iam.role SET name = 'Custom 2', status = 'retired' WHERE name = 'Custom'")
}

// AC-57: an upgrade adds new permissions to the built-in roles that define
// them and to no custom role. Unsupported changes are refused (D-OQ5).
func TestReleaseUpgrade(t *testing.T) {
	e := setup(t)
	c1, br1 := release(t)
	e.sync(t, c1, br1)
	_, viewer := e.rolePerms("Executive Viewer")
	e.mustOwner(fmt.Sprintf(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Board Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, 1, ARRAY['%s'], 'clone' FROM r`, strings.Join(viewer, "','")))

	c2, br2 := cloneRelease(c1, br1)
	c2.Version, br2.CatalogVersion = 2, 2
	c2.Permissions = append(c2.Permissions, catalog.Permission{Key: "dashboard.view", ResourceType: "dashboard", Action: catalog.ActionRead, RiskData: true, IntroducedIn: 2})
	for i := range br2.Roles {
		if br2.Roles[i].Name == "Executive Viewer" {
			br2.Roles[i].Permissions = append(br2.Roles[i].Permissions, "dashboard.view")
			slices.Sort(br2.Roles[i].Permissions)
		}
	}
	r := e.sync(t, c2, br2)
	if r.PreviousVersion != 1 || !slices.Equal(r.AddedPermissions, []string{"dashboard.view"}) ||
		!slices.Equal(r.VersionedRoles, []string{"Executive Viewer"}) || len(r.CreatedRoles) != 0 {
		t.Fatalf("upgrade result = %+v", r)
	}
	if ver, perms := e.rolePerms("Executive Viewer"); ver != 2 || !slices.Contains(perms, "dashboard.view") {
		t.Fatalf("Executive Viewer = v%d %v", ver, perms)
	}
	if ver, perms := e.rolePerms("Board Viewer"); ver != 1 || slices.Contains(perms, "dashboard.view") {
		t.Fatalf("custom role changed by upgrade (AC-57): v%d %v", ver, perms)
	}

	e.ownerFails(syncSQL(t, c1, br1), "older than installed")

	removed, brR := cloneRelease(c2, br2)
	removed.Version, brR.CatalogVersion = 3, 3
	removed.Permissions = slices.DeleteFunc(removed.Permissions, func(p catalog.Permission) bool { return p.Key == "drift.acknowledge" })
	for i := range brR.Roles {
		brR.Roles[i].Permissions = slices.DeleteFunc(brR.Roles[i].Permissions, func(k string) bool { return k == "drift.acknowledge" })
	}
	e.ownerFails(syncSQL(t, removed, brR), "removal is not supported")

	reclass, brC := cloneRelease(c2, br2)
	reclass.Version, brC.CatalogVersion = 3, 3
	for i := range reclass.Permissions {
		if reclass.Permissions[i].Key == "entitlement.view" {
			reclass.Permissions[i].Privileged = false
		}
	}
	e.ownerFails(syncSQL(t, reclass, brC), "reclassification is not supported")

	// A new key at the installed version (catalog changed, version not bumped),
	// stamped with an old version, or stamped ahead of the release is refused.
	for _, tc := range []struct{ version, introduced int }{{2, 2}, {3, 2}, {3, 4}} {
		bad, brB := cloneRelease(c2, br2)
		bad.Version, brB.CatalogVersion = tc.version, tc.version
		bad.Permissions = append(bad.Permissions, catalog.Permission{Key: "widget.view", ResourceType: "widget", Action: catalog.ActionRead, IntroducedIn: tc.introduced})
		e.ownerFails(syncSQL(t, bad, brB), "must be introduced in (2, ")
	}

	// A failed sync leaves no trace.
	if out := e.mustOwner("SELECT version FROM iam.permission_catalog"); out != "2" {
		t.Fatalf("catalog version after refused syncs = %s", out)
	}
}

func TestRBACTablesClosedToAppRoles(t *testing.T) {
	e := setup(t)
	c, br := release(t)
	for _, role := range []string{"app_rw", "app_engine"} {
		for _, tbl := range []string{"iam.permission", "iam.permission_catalog", "iam.role", "iam.role_version"} {
			e.mustFail(role, "SELECT * FROM "+tbl, "permission denied")
		}
		e.mustFail(role, syncSQL(t, c, br), "permission denied")
	}
	// The migrator must SET ROLE explicitly; it inherits nothing.
	e.mustFail("app_migrator", syncSQL(t, c, br), "permission denied")
}
