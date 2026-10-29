package tests

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/scim"
)

// F-001 T-24 (AC-12, AC-13, AC-14): group-to-role mappings, with SCIM
// driving membership as an IdP does, through the gateway.

type mappingEnv struct {
	*idpEnv
	tok string
}

func mappingFixture(t *testing.T) mappingEnv {
	t.Helper()
	ie := idpFixture(t)
	e := ie.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("A1", "A")
	e.addBU("B", "ENTERPRISE")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'R', 'R', id, true FROM iam.bu WHERE code = 'A'")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Mapper') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['access.view', 'access.map_groups'], 'test' FROM r`)
	return mappingEnv{idpEnv: ie, tok: ie.scimToken(t, ie.create(t, "oidc", "Corp", "corp.example"))}
}

func (me mappingEnv) scimUser(t *testing.T, name string) string {
	t.Helper()
	r := me.scimDo(t, me.tok, "POST", "/Users", user(name+"@corp.example", nil), nil)
	if r.code != 201 {
		t.Fatalf("provision %s: %d %s", name, r.code, r.raw)
	}
	return r.body["id"].(string)
}

func (me mappingEnv) scimGroup(t *testing.T, name string, members ...string) string {
	t.Helper()
	var ms []any
	for _, m := range members {
		ms = append(ms, map[string]any{"value": m})
	}
	r := me.scimDo(t, me.tok, "POST", "/Groups", map[string]any{"schemas": []string{scim.SchemaGroup}, "displayName": name, "members": ms}, nil)
	if r.code != 201 {
		t.Fatalf("group %s: %d %s", name, r.code, r.raw)
	}
	return r.body["id"].(string)
}

func (me mappingEnv) members(t *testing.T, gid, op, uid string) {
	t.Helper()
	o := map[string]any{"op": op, "path": "members", "value": []any{map[string]any{"value": uid}}}
	if op == "remove" {
		o = map[string]any{"op": "remove", "path": `members[value eq "` + uid + `"]`}
	}
	if r := me.scimDo(t, me.tok, "PATCH", "/Groups/"+gid, map[string]any{"schemas": []string{scim.SchemaPatch}, "Operations": []any{o}}, nil); r.code != 200 {
		t.Fatalf("membership %s: %d %s", op, r.code, r.raw)
	}
}

func (me mappingEnv) mapGroup(t *testing.T, cookie, gid, role, bu string) gwResp {
	t.Helper()
	h := me.csrf(t, cookie)
	h["Idempotency-Key"] = "map-" + gid[:8] + "-" + strings.ReplaceAll(role, " ", "") + "-" + bu + "-" + cookie[:6]
	return me.do(t, "POST", "/api/v1/group-mappings", cookie, map[string]any{"group_id": gid,
		"role_id": me.e.adminQuery("SELECT id FROM iam.role WHERE name = '" + role + "'"),
		"bu_id":   me.e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + bu + "'"), "reason": "ticket 7"}, h)
}

// mapped is "<source>:<mapping>|..." of the user's live assignments.
func (me mappingEnv) mapped(uid string) string {
	return me.e.adminQuery("SELECT coalesce(string_agg(source || ':' || coalesce(mapping_id::text, '-'), '|' ORDER BY granted_at), '') FROM iam.assignment WHERE principal_id = '" + uid + "' AND revoked_at IS NULL")
}

func TestGroupMappingLifecycle(t *testing.T) {
	me := mappingFixture(t)
	e := me.e
	ann, ben := me.scimUser(t, "ann"), me.scimUser(t, "ben")
	gid := me.scimGroup(t, "Analysts", ann)

	// AC-12: the mapping; the current member gets a mapped assignment (AC-14).
	r := me.mapGroup(t, me.admin, gid, "Executive Viewer", "A")
	mid, _ := r.body["id"].(string)
	if r.code != 201 || r.body["assigned"] != float64(1) || r.body["skipped"] != float64(0) {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	if got := me.mapped(ann); got != "mapped:"+mid {
		t.Fatalf("ann's assignments %q", got)
	}
	e.drain()
	if e.adminQuery("SELECT count(*) FROM authz.user_scope WHERE user_id = '"+ann+"'") != "1" {
		t.Fatal("the mapped assignment gave no access")
	}

	// AC-13: joining and leaving, as the IdP sends them, change assignments
	// in the same transaction (well within the 60 s budget), then access.
	start := time.Now()
	me.members(t, gid, "add", ben)
	if got := me.mapped(ben); got != "mapped:"+mid {
		t.Fatalf("after joining: %q", got)
	}
	me.members(t, gid, "remove", ann)
	if got := me.mapped(ann); got != "" {
		t.Fatalf("after leaving: %q", got)
	}
	t.Logf("membership change -> assignment change in %v (AC-13: <= 60 s)", time.Since(start).Round(time.Millisecond))
	if got := e.adminQuery("SELECT (revoked_by IS NULL)::text FROM iam.assignment WHERE principal_id = '" + ann + "' AND mapping_id = '" + mid + "'"); got != "true" {
		t.Fatalf("the system revocation names a revoker: %s", got)
	}
	e.drain()
	// No access for ann (her row, if kept, is empty); ben reads in A.
	if e.adminQuery("SELECT count(*) FROM authz.user_scope WHERE user_id = '"+ann+"' AND read_bus <> '{}'::jsonb") != "0" ||
		e.adminQuery("SELECT count(*) FROM authz.user_scope WHERE user_id = '"+ben+"' AND read_bus <> '{}'::jsonb") != "1" {
		t.Fatal("scope does not follow the mapped assignments")
	}

	// Deactivation ends the mapped assignment; reactivation restores it.
	patch := func(active any) {
		me.scimDo(t, me.tok, "PATCH", "/Users/"+ben, map[string]any{"schemas": []string{scim.SchemaPatch},
			"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": active}}}, nil)
	}
	patch(false)
	if got := me.mapped(ben); got != "" {
		t.Fatalf("a deactivated member keeps %q", got)
	}
	g := me.do(t, "GET", "/api/v1/group-mappings/"+mid, me.admin, nil, nil)
	if sk := g.body["skipped"].([]any); len(sk) != 1 || !strings.Contains(sk[0].(map[string]any)["reason"].(string), "not active") {
		t.Fatalf("skipped while inactive: %s", g.raw)
	}
	patch(true)
	if got := me.mapped(ben); got != "mapped:"+mid {
		t.Fatalf("after reactivation: %q", got)
	}
	if g := me.do(t, "GET", "/api/v1/group-mappings/"+mid, me.admin, nil, nil); len(g.body["skipped"].([]any)) != 0 || g.body["assigned"] != float64(1) {
		t.Fatalf("after reactivation: %s", g.raw)
	}

	// Mapped assignments are the mappings' alone.
	e.ownerFails("UPDATE iam.assignment SET revoked_at = now(), revoked_by = "+uid("admin")+" WHERE mapping_id = '"+mid+"' AND revoked_at IS NULL", "end with their group membership")
	e.ownerFails(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, source, mapping_id, granted_by)
		VALUES ('user', '`+ann+`', `+roleID("Executive Viewer")+`, `+buID("A")+`, 'mapped', '`+mid+`', `+uid("admin")+`)`, "written by group mappings only")

	// Removing the mapping ends its assignments.
	h := me.csrf(t, me.admin)
	h["Idempotency-Key"] = "unmap-" + mid[:8]
	if r := me.do(t, "DELETE", "/api/v1/group-mappings/"+mid+"?reason=reorg", me.admin, nil, h); r.code != 200 || r.body["revoked"] != float64(1) {
		t.Fatalf("remove: %d %s", r.code, r.raw)
	}
	if got := me.mapped(ben); got != "" {
		t.Fatalf("after the mapping's removal: %q", got)
	}
	if r := me.do(t, "GET", "/api/v1/group-mappings/"+mid, me.admin, nil, nil); r.code != 404 {
		t.Fatalf("a removed mapping: %d", r.code)
	}

	// A group deleted through SCIM takes its mappings with it.
	gid2 := me.scimGroup(t, "Owners", ann)
	r2 := me.mapGroup(t, me.admin, gid2, "Risk Owner", "A1")
	if r2.code != 201 || me.mapped(ann) == "" {
		t.Fatalf("second mapping: %d %s", r2.code, r2.raw)
	}
	me.scimDo(t, me.tok, "DELETE", "/Groups/"+gid2, nil, nil)
	if got := me.mapped(ann); got != "" {
		t.Fatalf("after the group's deletion: %q", got)
	}
	if got := e.adminQuery("SELECT (removed_at IS NOT NULL)::text FROM iam.group_role_mapping WHERE id = '" + r2.body["id"].(string) + "'"); got != "true" {
		t.Fatal("the deleted group's mapping is live")
	}

	audit := e.adminQuery(`SELECT string_agg(payload->>'type' || ':' || (payload->>'severity'), ',' ORDER BY id) FROM iam.event_outbox
		WHERE payload->>'type' LIKE 'group_mapping.%' OR payload->>'type' LIKE 'assignment.mapped_%'`)
	for _, want := range []string{"group_mapping.created:high", "assignment.mapped_granted:info", "assignment.mapped_revoked:info",
		"assignment.mapped_skipped:info", "group_mapping.removed:high"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit %q lacks %s", audit, want)
		}
	}
}

// A member the grant would put in breach of a rule is skipped and audited;
// the membership change itself succeeds. Mapping needs authority (AC-22).
func TestGroupMappingConflictsAndAuthority(t *testing.T) {
	me := mappingFixture(t)
	e := me.e
	mia, ann, boss := me.scimUser(t, "mia"), me.scimUser(t, "ann"), me.scimUser(t, "boss")
	// mia maps groups at A; boss is a BU Admin at B (admin permissions).
	e.mustOwner(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by) VALUES
		('user', '` + mia + `', ` + roleID("Mapper") + `, ` + buID("A") + `, ` + uid("admin") + `),
		('user', '` + boss + `', ` + roleID("BU Admin") + `, ` + buID("B") + `, ` + uid("admin") + `)`)
	e.drain()
	cookie := func(id string) string {
		e.mustOwner("UPDATE iam.app_user SET email = split_part(email, '@', 1) || '@example.test' WHERE id = '" + id + "'")
		c := me.login(t, strings.Split(e.adminQuery("SELECT email FROM iam.app_user WHERE id = '"+id+"'"), "@")[0])
		return c
	}
	miaC := cookie(mia)
	gid := me.scimGroup(t, "Team", mia, ann)

	// AC-28: mia's own mapping skips mia; ann is assigned.
	r := me.mapGroup(t, miaC, gid, "Executive Viewer", "A1")
	if r.code != 201 || r.body["assigned"] != float64(1) || r.body["skipped"] != float64(1) {
		t.Fatalf("mapping by a member: %d %s", r.code, r.raw)
	}
	mid := r.body["id"].(string)
	if got := me.mapped(mia); strings.Contains(got, "mapped") {
		t.Fatalf("the mapping's creator got its assignment (AC-28): %q", got)
	}
	// AC-30: boss (admin permissions) joining a group mapped to a risk-data
	// role is skipped, audited high; the SCIM request succeeds.
	me.members(t, gid, "add", boss)
	if got := me.mapped(boss); strings.Contains(got, "mapped") {
		t.Fatalf("admin + risk data combined without approval (AC-30): %q", got)
	}
	g := me.do(t, "GET", "/api/v1/group-mappings/"+mid, me.admin, nil, nil)
	reasons := ""
	for _, s := range g.body["skipped"].([]any) {
		reasons += s.(map[string]any)["reason"].(string) + "|"
	}
	if !strings.Contains(reasons, "AC-28") || !strings.Contains(reasons, "AC-30") {
		t.Fatalf("skipped reasons %q", reasons)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'assignment.mapped_skipped' AND payload->>'severity' = 'high'"); n != "2" {
		t.Fatalf("%s high-severity skips", n)
	}
	// Leaving the group clears the skip.
	me.members(t, gid, "remove", boss)
	if g := me.do(t, "GET", "/api/v1/group-mappings/"+mid, me.admin, nil, nil); len(g.body["skipped"].([]any)) != 1 {
		t.Fatalf("skips after boss left: %s", g.raw)
	}

	// AC-22: mia maps at A only, never inside the restricted R, never a role
	// with admin permissions; without access.view the API is 404.
	gid2 := me.scimGroup(t, "Other", ann)
	for name, c := range map[string]struct {
		role, bu string
		code     int
	}{
		"another BU":               {"Executive Viewer", "B", 403},
		"a restricted BU":          {"Executive Viewer", "R", 403},
		"a role with admin":        {"BU Admin", "A", 403},
		"a custom role with admin": {"Mapper", "A", 403},
	} {
		if r := me.mapGroup(t, miaC, gid2, c.role, c.bu); r.code != c.code {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if r := me.mapGroup(t, me.admin, gid2, "BU Admin", "A"); r.code != 201 {
		t.Fatalf("a root mapper maps an admin role: %d %s", r.code, r.raw)
	}
	viewer := me.login(t, "user")
	if r := me.do(t, "GET", "/api/v1/group-mappings", viewer, nil, nil); r.code != 404 {
		t.Fatalf("without access.view: %d", r.code)
	}
	// mia sees the mappings in A's subtree only (Team at A1, Other at A).
	if l := me.do(t, "GET", "/api/v1/group-mappings", miaC, nil, nil); l.code != 200 || len(l.body["mappings"].([]any)) != 2 {
		t.Fatalf("mia's view: %d %s", l.code, l.raw)
	}
	// Bad input.
	h := me.csrf(t, me.admin)
	h["Idempotency-Key"] = "map-bad-1"
	if r := me.do(t, "POST", "/api/v1/group-mappings", me.admin, map[string]any{"group_id": "x", "role_id": "y", "bu_id": "z", "reason": "r"}, h); r.code != 400 {
		t.Errorf("malformed ids: %d", r.code)
	}
	if r := me.mapGroup(t, me.admin, "00000000-0000-0000-0000-000000000000", "Executive Viewer", "A"); r.code != 404 {
		t.Errorf("unknown group: %d %s", r.code, r.raw)
	}
	if r := me.mapGroup(t, me.admin, gid, "Executive Viewer", "A1"); r.code != http.StatusConflict {
		t.Errorf("a duplicate mapping: %d %s", r.code, r.raw)
	}
}
