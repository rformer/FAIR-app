package tests

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/access/catalog"
)

// F-001 T-29 (AC-57, AC-58; D-OQ5): catalog upgrades leave admin notices;
// releases retire and reclassify permissions; custom roles move between
// instances as JSON.

// nextRelease is the installed release with version v and edit applied.
func nextRelease(t *testing.T, v int, edit func(*catalog.Catalog, *catalog.BuiltinRoles)) (*catalog.Catalog, *catalog.BuiltinRoles) {
	t.Helper()
	c, br := release(t)
	c2, br2 := cloneRelease(c, br)
	c2.Version, br2.CatalogVersion = v, v
	edit(c2, br2)
	return c2, br2
}

func dropPermission(c *catalog.Catalog, br *catalog.BuiltinRoles, key string) {
	c.Permissions = slices.DeleteFunc(c.Permissions, func(p catalog.Permission) bool { return p.Key == key })
	for i := range br.Roles {
		br.Roles[i].Permissions = slices.DeleteFunc(br.Roles[i].Permissions, func(k string) bool { return k == key })
	}
}

func TestCatalogRetirementAndReclassification(t *testing.T) {
	se := sodFixture(t)
	e := se.e
	if err := se.customRole("Drift Ack", "drift.acknowledge", "posture.view"); err != nil {
		t.Fatal(err)
	}
	e.mustOwner(grant("admin", "user:other", "Drift Ack", "ENTERPRISE"))
	e.drain()
	holds := func(perm string) string {
		return e.adminQuery("SELECT iam.user_has_permission(" + uid("other") + ", '" + perm + "', " + buID("ENTERPRISE") + ")")
	}
	if holds("drift.acknowledge") != "t" {
		t.Fatal("setup: the custom role grants nothing")
	}

	// Release 2: drift.acknowledge removed, entitlement.view no longer
	// privileged, bu.view now risk data, dashboard.view new.
	c2, br2 := nextRelease(t, 2, func(c *catalog.Catalog, br *catalog.BuiltinRoles) {
		dropPermission(c, br, "drift.acknowledge")
		for i := range c.Permissions {
			switch c.Permissions[i].Key {
			case "entitlement.view":
				c.Permissions[i].Privileged = false
			case "bu.view":
				c.Permissions[i].RiskData = true
			}
		}
		c.Permissions = append(c.Permissions, catalog.Permission{Key: "dashboard.view", ResourceType: "dashboard", Action: catalog.ActionRead, RiskData: true, IntroducedIn: 2})
	})
	r := e.sync(t, c2, br2)
	if strings.Join(r.RetiredPermissions, ",") != "drift.acknowledge" || strings.Join(r.ReclassifiedPermissions, ",") != "bu.view,entitlement.view" ||
		strings.Join(r.CustomRolesChanged, ",") != "Drift Ack" || strings.Join(r.AddedPermissions, ",") != "dashboard.view" {
		t.Fatalf("sync result %+v", r)
	}
	// Retired, not deleted; the custom role lost it (and so did its holder),
	// built-in roles follow the release.
	if got := e.adminQuery("SELECT retired_in_version FROM iam.permission WHERE key = 'drift.acknowledge'"); got != "2" {
		t.Fatalf("retired_in_version %q", got)
	}
	if ver, perms := e.rolePerms("Drift Ack"); ver != 2 || strings.Join(perms, ",") != "posture.view" {
		t.Fatalf("Drift Ack after retirement: v%d %v", ver, perms)
	}
	e.drain()
	if holds("drift.acknowledge") != "f" || holds("posture.view") != "t" {
		t.Fatal("the holder kept a retired permission or lost the rest")
	}
	if got := e.adminQuery("SELECT privileged::text || risk_data::text FROM iam.permission WHERE key = 'entitlement.view'"); got != "falsefalse" {
		t.Fatalf("entitlement.view after reclassification: %s", got)
	}
	// Admin notices, through the API; high-severity audit.
	n := se.do(t, "GET", "/api/v1/permissions/notices?pending=true", se.admin, nil, nil)
	kinds := map[string]bool{}
	var ids []string
	adminRisk := 0.0
	for _, x := range n.body["notices"].([]any) {
		m := x.(map[string]any)
		kinds[m["kind"].(string)+":"+m["subject"].(string)] = true
		ids = append(ids, m["id"].(string))
		if m["subject"] == "bu.view" {
			adminRisk = m["detail"].(map[string]any)["admin_risk_users"].(float64)
		}
	}
	for _, want := range []string{"added:dashboard.view", "retired:drift.acknowledge", "reclassified:entitlement.view", "reclassified:bu.view", "role_changed:Drift Ack"} {
		if !kinds[want] {
			t.Errorf("notices lack %s: %v", want, kinds)
		}
	}
	if adminRisk < 1 {
		t.Errorf("bu.view becoming risk data puts admins in AC-30 conflict; the notice says %v", adminRisk)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' IN ('catalog.permission_retired', 'catalog.permission_reclassified') AND payload->>'severity' = 'high'"); got != "3" {
		t.Fatalf("%s catalog audit events", got)
	}
	if a := se.call(t, se.admin, "POST", "/api/v1/permissions/notices/acknowledge", map[string]any{"ids": ids}); a.code != 200 || a.body["acknowledged"] != float64(len(ids)) {
		t.Fatalf("acknowledge: %d %s", a.code, a.raw)
	}
	if n := se.do(t, "GET", "/api/v1/permissions/notices?pending=true", se.admin, nil, nil); len(n.body["notices"].([]any)) != 0 {
		t.Fatalf("pending after acknowledgment: %s", n.raw)
	}
	// A retired permission cannot be added to a role; the catalog shows it.
	if r := se.call(t, se.admin, "POST", "/api/v1/roles", map[string]any{"name": "Late", "permissions": []string{"drift.acknowledge"}, "reason": "x"}); r.code != 400 {
		t.Fatalf("a role with a retired permission: %d %s", r.code, r.raw)
	}
	retiredFlag := map[string]any{}
	for _, x := range se.do(t, "GET", "/api/v1/permissions", se.admin, nil, nil).body["permissions"].([]any) {
		m := x.(map[string]any)
		retiredFlag[m["key"].(string)] = m["retired"]
	}
	if retiredFlag["drift.acknowledge"] != true || retiredFlag["posture.view"] != false {
		t.Fatalf("catalog retired flags: %v / %v", retiredFlag["drift.acknowledge"], retiredFlag["posture.view"])
	}

	// Release 3 brings it back: restored, but custom roles are not given it (AC-57).
	c3, br3 := nextRelease(t, 3, func(c *catalog.Catalog, _ *catalog.BuiltinRoles) {
		c.Permissions = append(c.Permissions, catalog.Permission{Key: "dashboard.view", ResourceType: "dashboard", Action: catalog.ActionRead, RiskData: true, IntroducedIn: 2})
	})
	r3 := e.sync(t, c3, br3)
	if strings.Join(r3.RestoredPermissions, ",") != "drift.acknowledge" {
		t.Fatalf("restore: %+v", r3)
	}
	if _, perms := e.rolePerms("Drift Ack"); slices.Contains(perms, "drift.acknowledge") {
		t.Fatal("a restored permission was given back to a custom role")
	}
	if got := e.adminQuery("SELECT retired_at IS NULL FROM iam.permission WHERE key = 'drift.acknowledge'"); got != "t" {
		t.Fatal("not restored")
	}
	// Identity stays fixed: a changed resource type is refused.
	bad, brB := nextRelease(t, 4, func(c *catalog.Catalog, _ *catalog.BuiltinRoles) {
		c.Permissions = append(c.Permissions, catalog.Permission{Key: "dashboard.view", ResourceType: "dashboard", Action: catalog.ActionRead, RiskData: true, IntroducedIn: 3})
	})
	e.ownerFails(syncSQL(t, bad, brB), "changed its resource type or introduction version")
	// Permission rows still never go away, even for the owner.
	e.ownerFails("DELETE FROM iam.permission WHERE key = 'dashboard.view'", "never changed or deleted")
}

func TestRoleExportImport(t *testing.T) {
	se := sodFixture(t)
	e := se.e
	admin := se.admin
	for _, c := range []map[string]any{
		{"name": "Reviewer", "permissions": []string{"analysis.view", "report.view"}, "reason": "x"},
		{"name": "Board", "permissions": []string{"report.view"}, "reason": "x"},
	} {
		if r := se.call(t, admin, "POST", "/api/v1/roles", c); r.code != 201 {
			t.Fatalf("create: %d %s", r.code, r.raw)
		}
	}
	// AC-58: the document.
	ex := se.do(t, "GET", "/api/v1/roles/export", admin, nil, nil)
	if ex.code != 200 || ex.body["format"] != "fair.roles.v1" || len(ex.body["roles"].([]any)) != 2 || ex.body["catalog_version"] != float64(1) ||
		!strings.Contains(ex.hdr.Get("Content-Disposition"), "roles.json") {
		t.Fatalf("export: %d %s", ex.code, ex.raw)
	}
	one := se.do(t, "GET", "/api/v1/roles/export?ids="+e.adminQuery("SELECT id FROM iam.role WHERE name = 'Board'"), admin, nil, nil)
	if len(one.body["roles"].([]any)) != 1 {
		t.Fatalf("export one: %s", one.raw)
	}

	// The document as another instance would receive it: Reviewer changed,
	// Board unchanged, Promoted new.
	doc := map[string]any{"format": "fair.roles.v1", "catalog_version": 1, "roles": []any{
		map[string]any{"name": "Reviewer", "permissions": []string{"analysis.view", "report.view", "audit.view"}},
		map[string]any{"name": "Board", "permissions": []string{"report.view"}},
		map[string]any{"name": "Promoted", "permissions": []string{"report.view", "bu.view"}},
	}}
	outcomes := func(r gwResp) string {
		var parts []string
		for _, x := range r.body["roles"].([]any) {
			m := x.(map[string]any)
			parts = append(parts, m["name"].(string)+":"+m["outcome"].(string))
		}
		return strings.Join(parts, ",")
	}
	dry := se.call(t, admin, "POST", "/api/v1/roles/import?dry_run=true", map[string]any{"document": doc, "reason": "promote from test"})
	if dry.code != 200 || dry.body["applied"] != false || outcomes(dry) != "Reviewer:updated,Board:unchanged,Promoted:created" {
		t.Fatalf("dry run: %d %s", dry.code, dry.raw)
	}
	if d := dry.body["roles"].([]any)[0].(map[string]any)["diff"].(map[string]any); strings.Join(strs(d["privileged_added"]), ",") != "audit.view" {
		t.Fatalf("dry-run diff: %v", d)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.role WHERE name = 'Promoted'"); n != "0" {
		t.Fatal("a dry run saved")
	}
	ap := se.call(t, admin, "POST", "/api/v1/roles/import", map[string]any{"document": doc, "reason": "promote from test"})
	if ap.code != 200 || ap.body["applied"] != true || outcomes(ap) != "Reviewer:updated,Board:unchanged,Promoted:created" {
		t.Fatalf("import: %d %s", ap.code, ap.raw)
	}
	if ver, perms := e.rolePerms("Reviewer"); ver != 2 || !slices.Contains(perms, "audit.view") {
		t.Fatalf("Reviewer after import: v%d %v", ver, perms)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'role.imported'"); got != "2" {
		t.Fatalf("%s import audit events", got)
	}
	// All or nothing: one bad role keeps the good one out too.
	bad := map[string]any{"format": "fair.roles.v1", "roles": []any{
		map[string]any{"name": "Second", "permissions": []string{"report.view"}},
		map[string]any{"name": "Auditor", "permissions": []string{"report.view"}},
		map[string]any{"name": "Unknown", "permissions": []string{"nope.nope"}},
		map[string]any{"name": "Conflict", "permissions": []string{"analysis.edit", "acceptance.approve"}},
	}}
	b := se.call(t, admin, "POST", "/api/v1/roles/import", map[string]any{"document": bad, "reason": "x"})
	if b.code != http.StatusConflict || b.body["errors"] != float64(3) || b.body["applied"] != false {
		t.Fatalf("a failing import: %d %s", b.code, b.raw)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.role WHERE name = 'Second'"); n != "0" {
		t.Fatal("a failing import applied part of itself")
	}
	raw, _ := json.Marshal(b.body["roles"])
	for _, want := range []string{"built-in role", "unknown permission", "separation of duties"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("report lacks %q: %s", want, raw)
		}
	}
	for name, body := range map[string]map[string]any{
		"not a document": {"document": map[string]any{"format": "other"}, "reason": "x"},
		"no reason":      {"document": doc, "reason": " "},
	} {
		if r := se.call(t, admin, "POST", "/api/v1/roles/import", body); r.code != 400 {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	// Export needs role.view, import role.manage.
	user := se.login(t, "user")
	if r := se.do(t, "GET", "/api/v1/roles/export", user, nil, nil); r.code != 404 {
		t.Fatalf("export without role.view: %d", r.code)
	}
}
