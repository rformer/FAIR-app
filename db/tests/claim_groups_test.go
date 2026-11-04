package tests

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/authn/saml/samltest"
	"github.com/rformer/fair-app/internal/scim"
)

// F-001 T-24b (AC-12, AC-13): group membership from login claims. An IdP's
// group_claim names the SAML attribute or OIDC claim; at each sign-in its
// values set the user's membership in the IdP's declared claim groups, and
// the T-24 mappings grant or revoke the mapped roles in that transaction.
// SCIM groups are never changed by claims, nor claim groups by SCIM.

// claimGroup declares a claim group (as the API does) and maps it to role
// at bu; returns the group and mapping ids.
func claimGroup(e *env, idp, value, name, role, bu string) (string, string) {
	gid := e.adminQuery(fmt.Sprintf("INSERT INTO iam.grp (display_name, idp_id, source, claim_value) VALUES ('%s', '%s', 'claim', '%s') RETURNING id",
		name, idp, value))
	mid := e.adminQuery(fmt.Sprintf(`INSERT INTO iam.group_role_mapping (grp_id, role_id, bu_id, reason, created_by)
		SELECT '%s', r.id, b.id, 'test', %s FROM iam.role r, iam.bu b WHERE r.name = '%s' AND b.code = '%s' RETURNING id`, gid, uid("admin"), role, bu))
	return gid, mid
}

// claimState is "<group>,..." the user is in (claim and SCIM groups), and
// "<mapping>,..." of their live mapped assignments.
func claimState(e *env, user string) (groups, mapped string) {
	groups = e.adminQuery(`SELECT coalesce(string_agg(g.display_name, ',' ORDER BY g.display_name), '') FROM iam.grp_member m
		JOIN iam.grp g ON g.id = m.grp_id WHERE m.user_id = ` + uid(user))
	mapped = e.adminQuery(`SELECT coalesce(string_agg(g.display_name, ',' ORDER BY g.display_name), '') FROM iam.assignment a
		JOIN iam.group_role_mapping m ON m.id = a.mapping_id JOIN iam.grp g ON g.id = m.grp_id
		WHERE a.principal_id = ` + uid(user) + ` AND a.revoked_at IS NULL AND a.source = 'mapped'`)
	return groups, mapped
}

func claimEvents(e *env, typ string) string {
	return e.adminQuery(`SELECT coalesce(string_agg((payload->>'severity') || ':' || coalesce(payload->'attributes'->>'claim', ''), '|' ORDER BY id), '')
		FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE topic = 'audit' AND payload->>'type' = '` + typ + `'`)
}

func TestClaimGroupsSAML(t *testing.T) {
	se := samlFixture(t, false)
	e := se.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("B", "ENTERPRISE")
	e.addBU("P", "ENTERPRISE")
	e.mustOwner(`UPDATE iam.idp SET metadata = metadata || '{"group_claim": "groups"}' WHERE id = '` + se.idpID + `'`)
	claimGroup(e, se.idpID, "analysts", "Analysts", "Executive Viewer", "A")
	claimGroup(e, se.idpID, "CN=Auditors,OU=Groups", "Auditors", "Executive Viewer", "B")
	// A SCIM group of the same IdP, with the user in it and mapped: claims
	// never touch it.
	sg := e.adminQuery("INSERT INTO iam.grp (display_name, idp_id) VALUES ('Provisioned', '" + se.idpID + "') RETURNING id")
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.group_role_mapping (grp_id, role_id, bu_id, reason, created_by)
		SELECT '%s', r.id, b.id, 'test', %s FROM iam.role r, iam.bu b WHERE r.name = 'Executive Viewer' AND b.code = 'P'`, sg, uid("admin")))
	e.mustOwner("INSERT INTO iam.grp_member (grp_id, user_id) SELECT '" + sg + "', " + uid("user"))
	// Another IdP's claim group with the same value: never joined.
	other := e.adminQuery("INSERT INTO iam.idp (kind, name) VALUES ('saml', 'Other') RETURNING id")
	claimGroup(e, other, "analysts", "Other analysts", "Executive Viewer", "A")

	login := func(attrs map[string][]string) int {
		t.Helper()
		code, _ := se.samlLogin(t, "user@example.test", samltest.MultiFactor, attrs)
		return code
	}
	expect := func(step, groups, mapped string) {
		t.Helper()
		if g, m := claimState(e, "user"); g != groups || m != mapped {
			t.Fatalf("%s: groups %q mapped %q, want %q and %q", step, g, m, groups, mapped)
		}
	}
	expect("before", "Provisioned", "Provisioned")

	// A declared value joins (and grants the mapped role); undeclared ones
	// are ignored; the value matches exactly.
	if c := login(map[string][]string{"groups": {"analysts", "engineering", "ANALYSTS"}}); c != http.StatusOK {
		t.Fatalf("sign-in: %d", c)
	}
	expect("joined", "Analysts,Provisioned", "Analysts,Provisioned")
	if got := claimEvents(e, "authn.group_claims_applied"); got != "info:present" {
		t.Fatalf("applied events %q", got)
	}
	// The next sign-in: one left, one joined (a DN value).
	login(map[string][]string{"groups": {"CN=Auditors,OU=Groups"}})
	expect("moved", "Auditors,Provisioned", "Auditors,Provisioned")
	// Unchanged membership: no further event.
	login(map[string][]string{"groups": {"CN=Auditors,OU=Groups"}})
	if got := claimEvents(e, "authn.group_claims_applied"); got != "info:present|info:present" {
		t.Fatalf("applied events %q", got)
	}
	// No claim, or an empty one: no claim groups; the SCIM group stays.
	login(nil)
	expect("absent", "Provisioned", "Provisioned")
	login(map[string][]string{"groups": {"analysts"}})
	login(map[string][]string{"groups": {}})
	expect("empty", "Provisioned", "Provisioned")

	// An overage pointer or a claim over the caps: memberships kept,
	// audited high, the sign-in succeeds.
	login(map[string][]string{"groups": {"analysts"}})
	if c := login(map[string][]string{samlOverage: {"https://graph.microsoft.com/v1.0/users/x/getMemberObjects"}}); c != http.StatusOK {
		t.Fatalf("overage sign-in: %d", c)
	}
	expect("overage", "Analysts,Provisioned", "Analysts,Provisioned")
	// A value over 256 characters makes the claim unreadable. (A SAML
	// response is also bounded by the XML guard of 1000 traversed elements,
	// which refuses the whole sign-in first; Entra sends at most 150 groups
	// in SAML. The 500-value cap is tested with OIDC.)
	if c := login(map[string][]string{"groups": {"analysts", strings.Repeat("x", 257)}}); c != http.StatusOK {
		t.Fatalf("oversized sign-in: %d", c)
	}
	expect("unreadable", "Analysts,Provisioned", "Analysts,Provisioned")
	if got := claimEvents(e, "authn.group_claims_unreadable"); got != "high:overage|high:unreadable" {
		t.Fatalf("unreadable events %q", got)
	}
	// 200 values, one of 256 characters, are read.
	many := make([]string, 200)
	for i := range many {
		many[i] = fmt.Sprintf("g%d", i)
	}
	many[199] = strings.Repeat("y", 256)
	login(map[string][]string{"groups": many})
	expect("many", "Provisioned", "Provisioned")

	// A denied sign-in changes nothing.
	if code, _ := se.samlLogin(t, "user@example.test", singleFactorClass, map[string][]string{"groups": {"analysts"}}); code != http.StatusUnauthorized {
		t.Fatalf("single factor: %d", code)
	}
	expect("denied", "Provisioned", "Provisioned")

	// Without a group_claim setting, claims are not read.
	login(map[string][]string{"groups": {"analysts"}})
	e.mustOwner("UPDATE iam.idp SET metadata = metadata - 'group_claim' WHERE id = '" + se.idpID + "'")
	login(nil)
	expect("no setting", "Analysts,Provisioned", "Analysts,Provisioned")

	// A removed claim group is no longer joined.
	e.mustOwner("UPDATE iam.idp SET metadata = metadata || '{\"group_claim\": \"groups\"}' WHERE id = '" + se.idpID + "'")
	e.mustOwner("UPDATE iam.group_role_mapping SET removed_at = now(), removed_by = " + uid("admin") + " WHERE grp_id IN (SELECT id FROM iam.grp WHERE display_name = 'Auditors')")
	e.mustOwner("UPDATE iam.grp SET scim_deleted_at = now() WHERE display_name = 'Auditors'")
	login(map[string][]string{"groups": {"CN=Auditors,OU=Groups", "analysts"}})
	expect("removed group", "Analysts,Provisioned", "Analysts,Provisioned")
}

const samlOverage = "http://schemas.microsoft.com/claims/groups.link"

func TestClaimGroupsOIDC(t *testing.T) {
	oe := oidcFixture(t)
	e := oe.e
	e.addBU("A", "ENTERPRISE")
	e.mustOwner(`UPDATE iam.idp SET metadata = metadata || '{"group_claim": "roles"}' WHERE id = '` + oe.idpID + `'`)
	claimGroup(e, oe.idpID, "/fair/analysts", "Analysts", "Executive Viewer", "A")
	signIn := func(extra map[string]any) {
		t.Helper()
		x := map[string]any{"amr": []string{"mfa"}}
		for k, v := range extra {
			x[k] = v
		}
		resp, _ := oe.signIn(t, "user@example.test", "/", x)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("sign-in %v: %d", extra, resp.StatusCode)
		}
	}
	expect := func(step, groups string) {
		t.Helper()
		if g, m := claimState(e, "user"); g != groups || m != groups {
			t.Fatalf("%s: groups %q mapped %q, want %q", step, g, m, groups)
		}
	}
	signIn(map[string]any{"roles": []string{"/fair/analysts", "/other"}})
	expect("list", "Analysts")
	signIn(map[string]any{"groups": []string{"/fair/analysts"}}) // another claim: roles absent
	expect("absent", "")
	signIn(map[string]any{"roles": "/fair/analysts"}) // a single string
	expect("string", "Analysts")
	// Entra's overage signals keep memberships.
	signIn(map[string]any{"_claim_names": map[string]any{"roles": "src1"}, "_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.example/x"}}})
	signIn(map[string]any{"hasgroups": true})
	// Not a list of strings: unreadable.
	signIn(map[string]any{"roles": []any{"/fair/analysts", 7}})
	signIn(map[string]any{"roles": map[string]any{"a": 1}})
	// The caps: 501 values, or a value of 257 characters.
	many := make([]string, 501)
	for i := range many {
		many[i] = fmt.Sprintf("g%d", i)
	}
	signIn(map[string]any{"roles": many})
	signIn(map[string]any{"roles": []string{"/fair/analysts", strings.Repeat("z", 257)}})
	expect("kept", "Analysts")
	if got := claimEvents(e, "authn.group_claims_unreadable"); got != "high:overage|high:overage|high:unreadable|high:unreadable|high:unreadable|high:unreadable" {
		t.Fatalf("unreadable events %q", got)
	}
	// 500 values, one of 256 characters (multi-byte: characters, not bytes).
	many = many[:500]
	many[0], many[499] = "/fair/analysts", strings.Repeat("é", 256)
	signIn(map[string]any{"roles": many})
	expect("at the caps", "Analysts")
	signIn(map[string]any{"roles": []string{}})
	expect("empty", "")
}

// The claim-group API (idp.view, idp.manage), the group_claim setting, and
// SCIM's view: claim groups are not SCIM's.
func TestClaimGroupsAPI(t *testing.T) {
	ie := idpFixture(t)
	e := ie.e
	e.addBU("A", "ENTERPRISE")
	idp := ie.create(t, "oidc", "Corp", "corp.example")
	base := "/api/v1/idps/" + idp + "/claim-groups"

	r := ie.do(t, "POST", base, ie.admin, map[string]any{"claim_value": "analysts", "display_name": "Analysts", "reason": "ticket 9"}, ie.hdr())
	gid, _ := r.body["id"].(string)
	if r.code != http.StatusCreated || gid == "" {
		t.Fatalf("declare: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery(`SELECT payload->>'severity' || ':' || (payload->>'reason') || ':' || (payload->'attributes'->>'claim_value')
		FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'idp.claim_group_added'`); got != "high:ticket 9:analysts" {
		t.Fatalf("added event %q", got)
	}
	for name, c := range map[string]struct {
		body map[string]any
		code int
	}{
		"duplicate":   {map[string]any{"claim_value": "analysts", "display_name": "Again", "reason": "x"}, http.StatusConflict},
		"no reason":   {map[string]any{"claim_value": "b", "display_name": "B"}, http.StatusBadRequest},
		"too long":    {map[string]any{"claim_value": strings.Repeat("v", 257), "display_name": "B", "reason": "x"}, http.StatusBadRequest},
		"control":     {map[string]any{"claim_value": "a\nb", "display_name": "B", "reason": "x"}, http.StatusBadRequest},
		"no name":     {map[string]any{"claim_value": "b", "display_name": " ", "reason": "x"}, http.StatusBadRequest},
		"empty value": {map[string]any{"claim_value": "", "display_name": "B", "reason": "x"}, http.StatusBadRequest},
	} {
		if r := ie.do(t, "POST", base, ie.admin, c.body, ie.hdr()); r.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, r.code, r.raw, c.code)
		}
	}
	missing := "/api/v1/idps/00000000-0000-4000-8000-000000000000/claim-groups"
	if r := ie.do(t, "POST", missing, ie.admin, map[string]any{"claim_value": "a", "display_name": "A", "reason": "x"}, ie.hdr()); r.code != http.StatusNotFound {
		t.Errorf("unknown IdP: %d", r.code)
	}
	if r := ie.do(t, "GET", missing, ie.admin, nil, nil); r.code != http.StatusNotFound {
		t.Errorf("list for an unknown IdP: %d", r.code)
	}

	// The group_claim setting.
	if r := ie.patch(t, idp, map[string]any{"settings": map[string]any{"group_claim": "groups"}, "reason": "x"}); r.code != http.StatusNoContent {
		t.Fatalf("group_claim: %d %s", r.code, r.raw)
	}
	for _, bad := range []any{"", 7, strings.Repeat("c", 257), "a\tb"} {
		if r := ie.patch(t, idp, map[string]any{"settings": map[string]any{"group_claim": bad}, "reason": "x"}); r.code != http.StatusBadRequest {
			t.Errorf("group_claim %v: %d", bad, r.code)
		}
	}

	// Mapped: removal refused; mapping removed: allowed, members leave.
	me := mappingEnv{idpEnv: ie}
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Mapper') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['access.view', 'access.map_groups'], 'test' FROM r`)
	m := me.mapGroup(t, ie.admin, gid, "Executive Viewer", "A")
	mid, _ := m.body["id"].(string)
	if m.code != http.StatusCreated {
		t.Fatalf("mapping a claim group: %d %s", m.code, m.raw)
	}
	e.mustOwner("UPDATE iam.app_user SET idp_id = '" + idp + "' WHERE email = 'user@example.test'")
	e.mustOwner("INSERT INTO iam.grp_member (grp_id, user_id) SELECT '" + gid + "', " + uid("user"))
	l := ie.do(t, "GET", base, ie.admin, nil, nil)
	if l.code != 200 || !strings.Contains(l.raw, `"claim_value":"analysts"`) || !strings.Contains(l.raw, `"members":1`) || !strings.Contains(l.raw, `"mappings":1`) {
		t.Fatalf("list: %d %s", l.code, l.raw)
	}
	if r := ie.do(t, "DELETE", base+"/"+gid+"?reason=gone", ie.admin, nil, ie.hdr()); r.code != http.StatusConflict {
		t.Fatalf("removing a mapped group: %d %s", r.code, r.raw)
	}

	// SCIM neither lists nor changes claim groups, nor shows them on users.
	tok := ie.scimToken(t, idp)
	if s := ie.scimDo(t, tok, "GET", "/Groups", nil, nil); s.code != 200 || strings.Contains(s.raw, gid) {
		t.Fatalf("SCIM lists a claim group: %d %s", s.code, s.raw)
	}
	if s := ie.scimDo(t, tok, "PATCH", "/Groups/"+gid, map[string]any{"schemas": []string{scim.SchemaPatch},
		"Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": "Hijacked"}}}, nil); s.code != http.StatusNotFound {
		t.Fatalf("SCIM changed a claim group: %d %s", s.code, s.raw)
	}
	if s := ie.scimDo(t, tok, "DELETE", "/Groups/"+gid, nil, nil); s.code != http.StatusNotFound {
		t.Fatalf("SCIM deleted a claim group: %d %s", s.code, s.raw)
	}

	// Nor through the functions directly (the token's IdP owns the group).
	th := fmt.Sprintf(`'\x%x'`, sha256.Sum256([]byte(tok)))
	e.mustFail("app_rw", "SELECT * FROM iam.scim_group_write("+th+", '"+gid+"', NULL, '{}', 'Hijacked', NULL, '{}')", "no group")
	e.mustFail("app_rw", "SELECT iam.scim_group_delete("+th+", '"+gid+"', NULL)", "no group")
	if got := e.adminQuery("SELECT display_name || ':' || (scim_deleted_at IS NULL)::text FROM iam.grp WHERE id = '" + gid + "'"); got != "Analysts:true" {
		t.Fatalf("claim group after SCIM attempts: %s", got)
	}

	if r := ie.do(t, "DELETE", "/api/v1/group-mappings/"+mid+"?reason=done", ie.admin, nil, ie.hdr()); r.code != http.StatusOK {
		t.Fatalf("removing the mapping: %d %s", r.code, r.raw)
	}
	if r := ie.do(t, "DELETE", base+"/"+gid, ie.admin, nil, ie.hdr()); r.code != http.StatusBadRequest {
		t.Fatalf("removal without a reason: %d %s", r.code, r.raw)
	}
	if r := ie.do(t, "DELETE", base+"/"+gid+"?reason=gone", ie.admin, nil, ie.hdr()); r.code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", r.code, r.raw)
	}
	if g, _ := claimState(e, "user"); g != "" {
		t.Fatalf("members of a removed group: %q", g)
	}
	if r := ie.do(t, "DELETE", base+"/"+gid+"?reason=again", ie.admin, nil, ie.hdr()); r.code != http.StatusNotFound {
		t.Fatalf("removing twice: %d", r.code)
	}
	if got := e.adminQuery("SELECT count(*) FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'idp.claim_group_removed'"); got != "1" {
		t.Fatalf("removed events %s", got)
	}
	// The value can be declared again.
	if r := ie.do(t, "POST", base, ie.admin, map[string]any{"claim_value": "analysts", "display_name": "Analysts", "reason": "back"}, ie.hdr()); r.code != http.StatusCreated {
		t.Fatalf("declaring again: %d %s", r.code, r.raw)
	}

	// Without idp.view the routes do not exist; with idp.view only, changes are forbidden.
	viewer := ie.login(t, "user")
	if r := ie.do(t, "GET", base, viewer, nil, nil); r.code != http.StatusNotFound {
		t.Fatalf("without idp.view: %d", r.code)
	}
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('IdP viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['idp.view'], 'test' FROM r`)
	e.mustOwner(grant("admin", "user:user", "IdP viewer", "ENTERPRISE"))
	e.drain()
	if r := ie.do(t, "GET", base, viewer, nil, nil); r.code != http.StatusOK {
		t.Fatalf("with idp.view: %d %s", r.code, r.raw)
	}
	h := ie.csrf(t, viewer)
	h["Idempotency-Key"] = "claim-viewer-1"
	if r := ie.do(t, "POST", base, viewer, map[string]any{"claim_value": "x", "display_name": "X", "reason": "x"}, h); r.code != http.StatusForbidden {
		t.Fatalf("declaring without idp.manage: %d %s", r.code, r.raw)
	}
}

// The login function itself: only the user's own IdP, statuses checked,
// the caps enforced again in the database.
func TestLoginGroupClaimsFunction(t *testing.T) {
	se := samlFixture(t, false)
	e := se.e
	e.addBU("A", "ENTERPRISE")
	claimGroup(e, se.idpID, "analysts", "Analysts", "Executive Viewer", "A")
	user := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'user@example.test'")
	other := e.adminQuery("INSERT INTO iam.idp (kind, name) VALUES ('saml', 'Other') RETURNING id")
	call := func(idp, status, vals string) string {
		return "SELECT iam.login_group_claims('" + user + "', '" + idp + "', '" + status + "', " + vals + ")"
	}
	e.mustFail("app_rw", call(other, "present", "'{analysts}'"), "does not sign in with IdP")
	e.mustFail("app_rw", call(se.idpID, "whatever", "'{}'"), "unknown claim status")
	e.mustFail("app_rw", call(se.idpID, "present", "array_fill('a'::text, ARRAY[501])"), "at most 500 values")
	e.mustFail("app_rw", call(se.idpID, "present", "ARRAY[repeat('a', 257)]"), "at most 500 values")
	e.mustFail("app_rw", call(se.idpID, "present", "ARRAY[NULL::text]"), "at most 500 values")
	if out, err := e.as("app_rw", "SELECT iam.login_group_claims('"+user+"', '"+se.idpID+"', 'present', '{analysts}')"); err != nil || !strings.Contains(out, "joined") {
		t.Fatalf("app_rw: %q %v", out, err)
	}
	// Claim groups are written only by their functions as far as app roles
	// go: no direct table access.
	e.mustFail("app_rw", "INSERT INTO iam.grp (display_name, idp_id, source, claim_value) VALUES ('X', '"+se.idpID+"', 'claim', 'x')", "permission denied")
}
