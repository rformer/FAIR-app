package tests

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/scope"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-001 T-23b (AC-11, AC-25, AC-47, AC-54; design §6): user administration
// through the gateway and the iam API.

type userAdminEnv struct {
	*idpEnv
}

// userAdminFixture: ENTERPRISE -> {A -> {A1, R (restricted) -> R1}, B};
// buadmin is BU Admin at A; alice at A1, bob at B, rhea at R; gina through
// the group Team A (assigned at A); nobody has no assignment; um holds a
// custom User Manager role (user.view, user.manage) at the root.
func userAdminFixture(t *testing.T) userAdminEnv {
	t.Helper()
	ie := idpFixture(t)
	e := ie.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("A1", "A")
	e.addBU("B", "ENTERPRISE")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT 'R', 'R', id, true FROM iam.bu WHERE code = 'A'")
	e.addBU("R1", "R")
	for _, u := range []string{"buadmin", "alice", "bob", "rhea", "gina", "nobody", "um"} {
		e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + strings.ToUpper(u[:1]) + u[1:] + "')")
	}
	e.mustOwner(grant("admin", "user:buadmin", "BU Admin", "A"))
	e.mustOwner(grant("admin", "user:alice", "Executive Viewer", "A1"))
	e.mustOwner(grant("admin", "user:bob", "Executive Viewer", "B"))
	e.mustOwner(grant("admin", "user:rhea", "Executive Viewer", "R"))
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Team A'), ('Team B')")
	e.mustOwner("INSERT INTO iam.grp_member (grp_id, user_id) VALUES (" + grpID("Team A") + ", " + uid("gina") + ")")
	e.mustOwner(grant("admin", "group:Team A", "Executive Viewer", "A"))
	e.mustOwner(grant("admin", "group:Team B", "Executive Viewer", "B"))
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('User Manager') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['user.view', 'user.manage'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:um", "User Manager", "ENTERPRISE"))
	e.drain()
	return userAdminEnv{ie}
}

func (ue userAdminEnv) emails(t *testing.T, cookie, query string) []string {
	t.Helper()
	r := ue.do(t, "GET", "/api/v1/users"+query, cookie, nil, nil)
	if r.code != 200 {
		t.Fatalf("list %s: %d %s", query, r.code, r.raw)
	}
	var out []string
	for _, u := range r.body["users"].([]any) {
		out = append(out, strings.TrimSuffix(u.(map[string]any)["email"].(string), "@example.test"))
	}
	sort.Strings(out)
	return out
}

func (ue userAdminEnv) act(t *testing.T, cookie, user, action, reason string) gwResp {
	t.Helper()
	h := ue.csrf(t, cookie)
	h[server.IdempotencyHeader] = "ua-" + action + "-" + user + "-" + strings.ReplaceAll(reason, " ", "_")
	return ue.do(t, "POST", "/api/v1/users/"+ue.e.adminQuery("SELECT id FROM iam.app_user WHERE email = '"+user+"@example.test'")+"/"+action,
		cookie, map[string]any{"reason": reason}, h)
}

// Who sees whom: everyone with user.view at the root; at a BU, the users
// and groups assigned in its subtree (restricted BUs excepted); nothing
// without user.view (404).
func TestUserAdminVisibility(t *testing.T) {
	ue := userAdminFixture(t)
	e := ue.e
	admin := ue.admin
	buadmin := ue.login(t, "buadmin")

	all := ue.emails(t, admin, "?limit=1000")
	for _, want := range []string{"admin", "alice", "bob", "buadmin", "gina", "nobody", "rhea", "um"} {
		if !contains(all, want) {
			t.Errorf("root view lacks %s: %v", want, all)
		}
	}
	// BU Admin at A: alice (A1), gina (Team A at A) and itself; not bob (B),
	// rhea (restricted R) or nobody.
	if got := strings.Join(ue.emails(t, buadmin, ""), ","); got != "alice,buadmin,gina" {
		t.Fatalf("BU-scoped view: %s", got)
	}
	bob := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'bob@example.test'")
	alice := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'alice@example.test'")
	if r := ue.do(t, "GET", "/api/v1/users/"+bob, buadmin, nil, nil); r.code != 404 {
		t.Fatalf("a user outside the BU: %d", r.code)
	}
	r := ue.do(t, "GET", "/api/v1/users/"+alice, buadmin, nil, nil)
	if r.code != 200 || r.body["status"] != "active" || len(r.body["assignments"].([]any)) != 1 {
		t.Fatalf("a user inside the BU: %d %s", r.code, r.raw)
	}
	// gina's assignment comes through the group and says so.
	gina := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'gina@example.test'")
	g := ue.do(t, "GET", "/api/v1/users/"+gina, buadmin, nil, nil)
	if a := g.body["assignments"].([]any); len(a) != 1 || a[0].(map[string]any)["via_group"] == nil || len(g.body["groups"].([]any)) != 1 {
		t.Fatalf("group assignment: %s", g.raw)
	}
	// Groups: Team A only for the BU Admin, both at the root.
	groups := func(cookie string) int {
		r := ue.do(t, "GET", "/api/v1/groups", cookie, nil, nil)
		return len(r.body["groups"].([]any))
	}
	if groups(buadmin) != 1 || groups(admin) != 2 {
		t.Fatalf("groups: BU %d, root %d", groups(buadmin), groups(admin))
	}
	if r := ue.do(t, "GET", "/api/v1/groups/"+e.adminQuery("SELECT id FROM iam.grp WHERE display_name = 'Team B'"), buadmin, nil, nil); r.code != 404 {
		t.Fatalf("a group outside the BU: %d", r.code)
	}
	// Without user.view anywhere the API does not exist (AC-25).
	viewer := ue.login(t, "user") // Executive Viewer at the root
	for _, p := range []string{"/api/v1/users", "/api/v1/users/" + alice, "/api/v1/groups"} {
		if r := ue.do(t, "GET", p, viewer, nil, nil); r.code != 404 {
			t.Errorf("%s without user.view: %d", p, r.code)
		}
	}
	// Filters and pages.
	if got := ue.emails(t, admin, "?q=AL"); strings.Join(got, ",") != "alice" {
		t.Errorf("q prefix: %v", got)
	}
	e.mustOwner("UPDATE iam.app_user SET status = 'locked' WHERE email = 'nobody@example.test'")
	if got := ue.emails(t, admin, "?status=locked"); strings.Join(got, ",") != "nobody" {
		t.Errorf("status filter: %v", got)
	}
	page := ue.do(t, "GET", "/api/v1/users?limit=2&offset=1", admin, nil, nil)
	if len(page.body["users"].([]any)) != 2 || page.body["total"].(float64) < 8 {
		t.Errorf("page: %s", page.raw)
	}
	for _, q := range []string{"?status=gone", "?source=ldap", "?limit=0", "?offset=-1", "?idp=x"} {
		if r := ue.do(t, "GET", "/api/v1/users"+q, admin, nil, nil); r.code != 400 {
			t.Errorf("%s: %d", q, r.code)
		}
	}
}

func TestUserAdminActions(t *testing.T) {
	ue := userAdminFixture(t)
	e := ue.e
	seedPosture(t, e)
	admin, buadmin, um := ue.admin, ue.login(t, "buadmin"), ue.login(t, "um")
	aliceSession := ue.login(t, "alice")
	auditOf := func(typ string) string {
		return e.adminQuery("SELECT coalesce(string_agg((payload->>'severity') || ':' || (payload->>'reason') || ':' || (payload->'attributes'->'before'->>'status') || '>' || (payload->'attributes'->'after'->>'status'), ',' ORDER BY id), '') FROM iam.event_outbox WHERE payload->>'type' = '" + typ + "'")
	}

	// disable: immediate, sessions end (T-22), audited high with before/after.
	if r := ue.act(t, admin, "alice", "disable", "left the company"); r.code != 200 || r.body["status"] != "disabled" {
		t.Fatalf("disable: %d %s", r.code, r.raw)
	}
	if r := ue.do(t, "GET", "/api/v1/me", aliceSession, nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("a disabled user's session: %d", r.code)
	}
	if got := auditOf("user.disabled"); got != "high:left the company:active>disabled" {
		t.Fatalf("disable audit %q", got)
	}
	for name, c := range map[string]struct {
		cookie, user, action, reason string
		code                         int
	}{
		"disable again":                    {admin, "alice", "disable", "again", 409},
		"no reason":                        {admin, "bob", "disable", " ", 400},
		"no user.manage":                   {buadmin, "alice", "enable", "please", 403},
		"one's own account":                {admin, "admin", "disable", "oops", 409},
		"enable an active user":            {admin, "bob", "enable", "noop", 409},
		"unlock a user that is not locked": {admin, "bob", "unlock", "noop", 409},
	} {
		if r := ue.act(t, c.cookie, c.user, c.action, c.reason); r.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, r.code, r.raw, c.code)
		}
	}
	if r := ue.do(t, "POST", "/api/v1/users/00000000-0000-0000-0000-000000000000/disable", admin, map[string]any{"reason": "x"},
		map[string]string{server.IdempotencyHeader: "ua-unknown-user-1", "X-CSRF-Token": ue.csrf(t, admin)["X-CSRF-Token"], "Origin": ue.url}); r.code != 404 {
		t.Errorf("unknown user: %d", r.code)
	}
	if r := ue.do(t, "POST", "/api/v1/users/"+e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'bob@example.test'")+"/promote", admin,
		map[string]any{"reason": "x"}, map[string]string{server.IdempotencyHeader: "ua-bad-action-1", "X-CSRF-Token": ue.csrf(t, admin)["X-CSRF-Token"], "Origin": ue.url}); r.code != 404 {
		t.Errorf("unknown action: %d", r.code)
	}

	// enable: re-enables what inactivity or an administrator disabled, and
	// counts as activity, so the next sweep leaves the user alone.
	e.mustOwner("UPDATE iam.app_user SET last_login_at = now() - interval '200 days', created_at = now() - interval '300 days' WHERE email = 'alice@example.test'")
	// Her (revoked) session must not count as recent activity either: only the re-enabling does.
	e.mustOwner("UPDATE iam.session SET last_seen_at = now() - interval '200 days', created_at = now() - interval '200 days' WHERE user_id = " + uid("alice"))
	if r := ue.act(t, admin, "alice", "enable", "returned"); r.code != 200 || r.body["status"] != "active" {
		t.Fatalf("enable: %d %s", r.code, r.raw)
	}
	w := scope.New(scope.Options{Pool: e.appPool(), Audit: audit.NewMemory()})
	if _, err := w.SweepInactive(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.adminQuery("SELECT status FROM iam.app_user WHERE email = 'alice@example.test'"); got != "active" {
		t.Fatalf("the sweep disabled a just re-enabled user: %s", got)
	}
	// An inactivity-disabled user can be re-enabled too.
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled', disabled_reason = 'inactive' WHERE email = 'bob@example.test'")
	if r := ue.act(t, admin, "bob", "enable", "back from leave"); r.code != 200 {
		t.Fatalf("enable after inactivity: %d %s", r.code, r.raw)
	}
	// What SCIM disabled, only the IdP re-enables; a locked user is unlocked.
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled', disabled_reason = 'scim' WHERE email = 'rhea@example.test'")
	if r := ue.act(t, admin, "rhea", "enable", "please"); r.code != 409 || !strings.Contains(r.raw, "identity provider") {
		t.Fatalf("enable a SCIM-disabled user: %d %s", r.code, r.raw)
	}
	e.mustOwner("UPDATE iam.app_user SET status = 'locked' WHERE email = 'gina@example.test'")
	if r := ue.act(t, admin, "gina", "enable", "please"); r.code != 409 || !strings.Contains(r.raw, "unlock") {
		t.Fatalf("enable a locked user: %d %s", r.code, r.raw)
	}
	if r := ue.act(t, admin, "gina", "unlock", "verified by phone"); r.code != 200 || r.body["status"] != "active" {
		t.Fatalf("unlock: %d %s", r.code, r.raw)
	}
	if got := auditOf("user.unlocked"); got != "high:verified by phone:locked>active" {
		t.Fatalf("unlock audit %q", got)
	}

	// Never the last active root administrator: admin and admin2 are root
	// grantors; once admin2 is disabled, admin cannot be (by um, who manages
	// users but is not a grantor).
	if r := ue.act(t, admin, "admin2", "disable", "rotation"); r.code != 200 {
		t.Fatalf("disable one of two root administrators: %d %s", r.code, r.raw)
	}
	if r := ue.act(t, um, "admin", "disable", "takeover"); r.code != 409 || !strings.Contains(r.raw, "last active root administrator") {
		t.Fatalf("disable the last root administrator: %d %s", r.code, r.raw)
	}
	// Mutations need an Idempotency-Key; replays answer the stored result.
	h := ue.csrf(t, admin)
	if r := ue.do(t, "POST", "/api/v1/users/"+e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'nobody@example.test'")+"/disable", admin,
		map[string]any{"reason": "x"}, h); r.code != 400 {
		t.Fatalf("no Idempotency-Key: %d", r.code)
	}
	first := ue.act(t, admin, "nobody", "disable", "cleanup")
	again := ue.act(t, admin, "nobody", "disable", "cleanup")
	if first.code != 200 || again.code != 200 || again.hdr.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %d / %d %v", first.code, again.code, again.hdr)
	}
	e.mustFail("app_rw", "SELECT iam.user_admin_action(gen_random_uuid(), 'disable', 'x')", "signed database context")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
