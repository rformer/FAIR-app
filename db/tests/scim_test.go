package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/scim"
)

// F-001 T-21 (AC-07, AC-08): the SCIM 2.0 service provider through the
// gateway, as an IdP's SCIM client uses it. Each test cites the RFC 7643 /
// 7644 section it checks.

type scimResp struct {
	code int
	body map[string]any
	raw  string
	hdr  http.Header
}

// scimDo calls the SCIM endpoint with a bearer token (no session).
func (ie *idpEnv) scimDo(t *testing.T, token, method, path string, body any, hdr map[string]string) scimResp {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, ie.url+"/scim/v2"+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return scimResp{resp.StatusCode, m, string(raw), resp.Header}
}

// scimToken issues a SCIM token for idp through the iam API.
func (ie *idpEnv) scimToken(t *testing.T, idp string) string {
	t.Helper()
	r := ie.do(t, "POST", "/api/v1/idps/"+idp+"/scim-tokens", ie.admin, map[string]any{"name": "Entra provisioning", "reason": "onboarding"}, ie.hdr())
	tok, _ := r.body["token"].(string)
	if r.code != http.StatusCreated || !strings.HasPrefix(tok, "fscim_") {
		t.Fatalf("issuing a SCIM token: %d %s", r.code, r.raw)
	}
	return tok
}

func scimErr(t *testing.T, r scimResp, status int, scimType string) {
	t.Helper()
	if r.code != status || r.body["status"] != fmt.Sprint(status) || (scimType != "" && r.body["scimType"] != scimType) ||
		!strings.Contains(fmt.Sprint(r.body["schemas"]), scim.SchemaError) {
		t.Fatalf("want %d %s (RFC 7644 §3.12), got %d %s", status, scimType, r.code, r.raw)
	}
}

func user(name string, extra map[string]any) map[string]any {
	u := map[string]any{"schemas": []string{scim.SchemaUser}, "userName": name, "active": true,
		"name":   map[string]any{"givenName": "Test", "familyName": name},
		"emails": []any{map[string]any{"value": name, "type": "work", "primary": true}}}
	for k, v := range extra {
		u[k] = v
	}
	return u
}

// AC-08: SCIM-only bearer tokens per IdP, which expire and rotate.
func TestSCIMTokens(t *testing.T) {
	ie := idpFixture(t)
	e := ie.e
	idp := ie.create(t, "oidc", "Corp", "corp.example")
	other := ie.create(t, "saml", "Partner", "partner.example")

	// Issued once: a replay does not reveal it again, and it is not kept.
	h := ie.hdr()
	first := ie.do(t, "POST", "/api/v1/idps/"+idp+"/scim-tokens", ie.admin, map[string]any{"name": "Entra", "reason": "onboarding"}, h)
	tok, _ := first.body["token"].(string)
	if first.code != 201 || len(tok) < 40 {
		t.Fatalf("issue: %d %s", first.code, first.raw)
	}
	replay := ie.do(t, "POST", "/api/v1/idps/"+idp+"/scim-tokens", ie.admin, map[string]any{"name": "Entra", "reason": "onboarding"}, h)
	if replay.code != http.StatusConflict || replay.body["error"] != "secret_not_replayed" || strings.Contains(replay.raw, tok) {
		t.Fatalf("replayed issue: %d %s", replay.code, replay.raw)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.idempotency WHERE position('" + tok + "' IN convert_from(body, 'UTF8')) > 0"); n != "0" {
		t.Fatal("the token was stored with the idempotent response")
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.api_token WHERE position('" + tok + "'::bytea IN token_hash) > 0 OR prefix = '" + tok + "'"); n != "0" {
		t.Fatal("the token is stored in clear")
	}
	list := ie.do(t, "GET", "/api/v1/idps/"+idp+"/scim-tokens", ie.admin, nil, nil)
	if list.code != 200 || strings.Contains(list.raw, tok) || !strings.Contains(list.raw, tok[:12]) {
		t.Fatalf("list: %d %s", list.code, list.raw)
	}
	if r := ie.scimDo(t, tok, "GET", "/Users", nil, nil); r.code != 200 {
		t.Fatalf("a fresh token: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery("SELECT last_used_at IS NOT NULL FROM iam.api_token WHERE id = '" + first.body["id"].(string) + "'"); got != "t" {
		t.Fatal("last use not recorded")
	}

	// Refused: no token, a wrong one, a session cookie instead, another scheme.
	for name, r := range map[string]scimResp{
		"none":    ie.scimDo(t, "", "GET", "/Users", nil, nil),
		"unknown": ie.scimDo(t, "fscim_"+strings.Repeat("A", 43), "GET", "/Users", nil, nil),
		"cookie":  ie.scimDo(t, "", "GET", "/Users", nil, map[string]string{"Cookie": "__Host-sid=" + ie.admin}),
		"basic":   ie.scimDo(t, "", "GET", "/Users", nil, map[string]string{"Authorization": "Basic " + tok}),
	} {
		if r.code != 401 || !strings.HasPrefix(r.hdr.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: %d %v", name, r.code, r.hdr)
		}
	}
	// A SCIM token is not a session: the platform's API refuses it.
	if r := ie.do(t, "GET", "/api/v1/idps", "", nil, map[string]string{"Authorization": "Bearer " + tok}); r.code != 401 {
		t.Fatalf("SCIM token on the platform API: %d", r.code)
	}

	// One IdP's token never sees another's users.
	otherTok := ie.scimToken(t, other)
	if r := ie.scimDo(t, tok, "POST", "/Users", user("alice@corp.example", nil), nil); r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	if r := ie.scimDo(t, otherTok, "GET", "/Users", nil, nil); r.body["totalResults"] != float64(0) {
		t.Fatalf("another IdP's token sees users: %s", r.raw)
	}
	aliceID := e.adminQuery("SELECT id FROM iam.app_user WHERE user_name = 'alice@corp.example'")
	if r := ie.scimDo(t, otherTok, "GET", "/Users/"+aliceID, nil, nil); r.code != 404 {
		t.Fatalf("another IdP's user by id: %d", r.code)
	}
	if r := ie.scimDo(t, otherTok, "DELETE", "/Users/"+aliceID, nil, nil); r.code != 404 {
		t.Fatalf("deleting another IdP's user: %d", r.code)
	}

	// Rotation: a second token works alongside; revoking the first ends it.
	second := ie.scimToken(t, idp)
	if r := ie.do(t, "DELETE", "/api/v1/idps/"+idp+"/scim-tokens/"+first.body["id"].(string)+"?reason=rotation", ie.admin, nil, ie.hdr()); r.code != 204 {
		t.Fatalf("revoke: %d %s", r.code, r.raw)
	}
	if r := ie.scimDo(t, tok, "GET", "/Users", nil, nil); r.code != 401 {
		t.Fatalf("revoked token: %d", r.code)
	}
	if r := ie.scimDo(t, second, "GET", "/Users", nil, nil); r.code != 200 {
		t.Fatalf("the rotated-in token: %d", r.code)
	}
	// Expiry: at most a year; an expired token is refused.
	for _, days := range []int{0, 366} {
		r := ie.do(t, "POST", "/api/v1/idps/"+idp+"/scim-tokens", ie.admin, map[string]any{"name": "x", "expires_in_days": days, "reason": "r"}, ie.hdr())
		if r.code != 400 {
			t.Errorf("expires_in_days %d: %d", days, r.code)
		}
	}
	e.mustOwner("UPDATE iam.api_token SET created_at = now() - interval '2 days', expires_at = now() - interval '1 second' WHERE prefix = '" + second[:12] + "'")
	if r := ie.scimDo(t, second, "GET", "/Users", nil, nil); r.code != 401 {
		t.Fatalf("expired token: %d", r.code)
	}

	// scim.manage: a viewer of IdPs cannot issue tokens; app_rw cannot read them.
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('IdP Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['idp.view'], 'test' FROM r`)
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('viewer@example.test', 'Viewer')")
	e.mustOwner(grant("admin", "user:viewer", "IdP Viewer", "ENTERPRISE"))
	e.drain()
	viewer := ie.login(t, "viewer")
	vh := ie.csrf(t, viewer)
	vh["Idempotency-Key"] = "viewer-scim-token-1"
	if r := ie.do(t, "POST", "/api/v1/idps/"+idp+"/scim-tokens", viewer, map[string]any{"name": "x", "reason": "r"}, vh); r.code != 403 {
		t.Fatalf("issue without scim.manage: %d", r.code)
	}
	e.mustFail("app_rw", "SELECT * FROM iam.api_token", "permission denied")
	audit := e.adminQuery(`SELECT string_agg(payload->>'type', ',' ORDER BY id) FROM iam.event_outbox WHERE payload->>'type' LIKE 'token.%' AND payload->>'severity' = 'high'`)
	if !strings.Contains(audit, "token.created") || !strings.Contains(audit, "token.revoked") {
		t.Fatalf("token audit %q", audit)
	}
}

// RFC 7644 §3.3, §3.4.1, §3.5.1, §3.5.2, §3.6, §3.14: the User lifecycle.
func TestSCIMUsers(t *testing.T) {
	ie := idpFixture(t)
	e := ie.e
	idp := ie.create(t, "oidc", "Corp", "corp.example")
	tok := ie.scimToken(t, idp)

	// §3.3 create: 201, Location, ETag, meta; read-only and password ignored.
	in := user("bjensen@corp.example", map[string]any{"externalId": "E-701984", "password": "t1meMa$heen", "id": "client-chosen",
		"title": "Tour Guide", scim.SchemaEnterprise: map[string]any{"employeeNumber": "701984", "department": "Tours"}})
	in["schemas"] = []string{scim.SchemaUser, scim.SchemaEnterprise}
	c := ie.scimDo(t, tok, "POST", "/Users", in, nil)
	if c.code != 201 || c.hdr.Get("Content-Type") != "application/scim+json" {
		t.Fatalf("create: %d %s", c.code, c.raw)
	}
	id, _ := c.body["id"].(string)
	meta, _ := c.body["meta"].(map[string]any)
	if id == "client-chosen" || meta["resourceType"] != "User" || meta["location"] != ie.url+"/scim/v2/Users/"+id ||
		c.hdr.Get("Location") != meta["location"] || c.hdr.Get("ETag") != `W/"1"` || meta["version"] != `W/"1"` {
		t.Fatalf("create response: %s %v", c.raw, c.hdr)
	}
	if _, ok := c.body["password"]; ok || strings.Contains(c.raw, "t1meMa") {
		t.Fatal("the password was returned")
	}
	if got := e.adminQuery("SELECT position('t1meMa' IN scim_resource::text) FROM iam.app_user WHERE id = '" + id + "'"); got != "0" {
		t.Fatal("the password was stored")
	}
	ext, _ := c.body[scim.SchemaEnterprise].(map[string]any)
	if ext["department"] != "Tours" || c.body["title"] != "Tour Guide" {
		t.Fatalf("round trip: %s", c.raw)
	}
	// The platform's user: login subject = userName (the default), source scim.
	if got := e.adminQuery("SELECT external_id || '|' || email || '|' || status || '|' || source || '|' || scim_external_id FROM iam.app_user WHERE id = '" + id + "'"); got != "bjensen@corp.example|bjensen@corp.example|active|scim|E-701984" {
		t.Fatalf("app_user %q", got)
	}

	// §3.3 uniqueness; §3.12 errors.
	scimErr(t, ie.scimDo(t, tok, "POST", "/Users", user("BJensen@corp.example", nil), nil), 409, "uniqueness")
	scimErr(t, ie.scimDo(t, tok, "POST", "/Users", map[string]any{"schemas": []string{scim.SchemaUser}}, nil), 400, "invalidValue")
	scimErr(t, ie.scimDo(t, tok, "POST", "/Users", `{"userName": `, nil), 400, "invalidSyntax")
	scimErr(t, ie.scimDo(t, tok, "POST", "/Users", map[string]any{"schemas": []string{scim.SchemaGroup}, "userName": "x"}, nil), 400, "invalidSyntax")
	if r := ie.scimDo(t, tok, "POST", "/Users", "userName=x", map[string]string{"Content-Type": "text/plain"}); r.code != 415 {
		t.Fatalf("text/plain: %d", r.code)
	}

	// §3.4.1 read; §3.14 conditional GET.
	g := ie.scimDo(t, tok, "GET", "/Users/"+id, nil, nil)
	if g.code != 200 || g.body["userName"] != "bjensen@corp.example" || g.hdr.Get("ETag") != `W/"1"` {
		t.Fatalf("get: %d %s", g.code, g.raw)
	}
	if r := ie.scimDo(t, tok, "GET", "/Users/"+id, nil, map[string]string{"If-None-Match": `W/"1"`}); r.code != 304 {
		t.Fatalf("If-None-Match: %d", r.code)
	}
	scimErr(t, ie.scimDo(t, tok, "GET", "/Users/00000000-0000-0000-0000-000000000000", nil, nil), 404, "")
	scimErr(t, ie.scimDo(t, tok, "GET", "/Users/not-an-id", nil, nil), 404, "")
	// §3.9 attributes and excludedAttributes.
	p := ie.scimDo(t, tok, "GET", "/Users/"+id+"?attributes=userName", nil, nil)
	if p.body["userName"] == nil || p.body["id"] == nil || p.body["title"] != nil || p.body["emails"] != nil {
		t.Fatalf("attributes=userName: %s", p.raw)
	}
	x := ie.scimDo(t, tok, "GET", "/Users/"+id+"?excludedAttributes=emails,title", nil, nil)
	if x.body["emails"] != nil || x.body["title"] != nil || x.body["userName"] == nil {
		t.Fatalf("excludedAttributes: %s", x.raw)
	}

	// §3.5.2 PATCH as Entra ID sends it; §3.14 If-Match.
	patch := map[string]any{"schemas": []string{scim.SchemaPatch}, "Operations": []any{
		map[string]any{"op": "Replace", "path": "title", "value": "Senior Guide"},
		map[string]any{"op": "Add", "path": `emails[type eq "home"].value`, "value": "babs@home.example"},
		map[string]any{"op": "Replace", "path": scim.SchemaEnterprise + ":department", "value": "Sales"},
	}}
	pr := ie.scimDo(t, tok, "PATCH", "/Users/"+id, patch, map[string]string{"If-Match": `W/"1"`})
	if pr.code != 200 || pr.body["title"] != "Senior Guide" || pr.hdr.Get("ETag") != `W/"2"` || !strings.Contains(pr.raw, "babs@home.example") ||
		pr.body[scim.SchemaEnterprise].(map[string]any)["department"] != "Sales" {
		t.Fatalf("patch: %d %s", pr.code, pr.raw)
	}
	scimErr(t, ie.scimDo(t, tok, "PATCH", "/Users/"+id, patch, map[string]string{"If-Match": `W/"1"`}), 412, "")
	scimErr(t, ie.scimDo(t, tok, "PATCH", "/Users/"+id, map[string]any{"Operations": patch["Operations"]}, nil), 400, "invalidSyntax")
	scimErr(t, ie.scimDo(t, tok, "PATCH", "/Users/"+id, map[string]any{"schemas": []string{scim.SchemaPatch},
		"Operations": []any{map[string]any{"op": "replace", "path": "groups", "value": []any{}}}}, nil), 400, "mutability")
	scimErr(t, ie.scimDo(t, tok, "PATCH", "/Users/"+id, map[string]any{"schemas": []string{scim.SchemaPatch},
		"Operations": []any{map[string]any{"op": "replace", "path": `emails[type eq "fax"]`, "value": map[string]any{"value": "x"}}}}, nil), 400, "noTarget")
	scimErr(t, ie.scimDo(t, tok, "PATCH", "/Users/"+id, map[string]any{"schemas": []string{scim.SchemaPatch},
		"Operations": []any{map[string]any{"op": "replace", "path": "userName", "value": "x"}}}, map[string]string{"If-Match": `"nonsense"`}), 400, "invalidVers")

	// Deactivation (AC-07) as Entra sends it: the platform user is disabled,
	// audited high; reactivation restores it.
	deact := map[string]any{"schemas": []string{scim.SchemaPatch}, "Operations": []any{map[string]any{"op": "Replace", "path": "active", "value": "False"}}}
	if r := ie.scimDo(t, tok, "PATCH", "/Users/"+id, deact, nil); r.code != 200 || r.body["active"] != false {
		t.Fatalf("deactivate: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery("SELECT status || '|' || disabled_reason FROM iam.app_user WHERE id = '" + id + "'"); got != "disabled|scim" {
		t.Fatalf("after deactivation %q", got)
	}
	react := map[string]any{"schemas": []string{scim.SchemaPatch}, "Operations": []any{map[string]any{"op": "replace", "value": map[string]any{"active": true}}}}
	if r := ie.scimDo(t, tok, "PATCH", "/Users/"+id, react, nil); r.code != 200 {
		t.Fatalf("reactivate: %d %s", r.code, r.raw)
	}
	if got := e.adminQuery("SELECT status FROM iam.app_user WHERE id = '" + id + "'"); got != "active" {
		t.Fatalf("after reactivation %q", got)
	}
	// A locally locked user is not unlocked by SCIM.
	e.mustOwner("UPDATE iam.app_user SET status = 'locked' WHERE id = '" + id + "'")
	ie.scimDo(t, tok, "PATCH", "/Users/"+id, react, nil)
	if got := e.adminQuery("SELECT status FROM iam.app_user WHERE id = '" + id + "'"); got != "locked" {
		t.Fatalf("SCIM unlocked a locked user: %q", got)
	}
	e.mustOwner("UPDATE iam.app_user SET status = 'active' WHERE id = '" + id + "'")
	audit := e.adminQuery(`SELECT string_agg(payload->>'type' || ':' || (payload->>'severity'), ',' ORDER BY id) FROM iam.event_outbox WHERE payload->>'type' LIKE 'scim.user.%'`)
	for _, want := range []string{"scim.user.created:info", "scim.user.updated:info", "scim.user.deactivated:high", "scim.user.reactivated:high"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit %q lacks %s", audit, want)
		}
	}

	// §3.5.1 PUT replaces: what is not sent is cleared.
	put := user("bjensen@corp.example", nil)
	r := ie.scimDo(t, tok, "PUT", "/Users/"+id, put, nil)
	if r.code != 200 || r.body["title"] != nil || r.body[scim.SchemaEnterprise] != nil || r.body["externalId"] != nil {
		t.Fatalf("put: %d %s", r.code, r.raw)
	}

	// The login subject can be externalId instead (an IdP setting).
	if pr := ie.patch(t, idp, map[string]any{"settings": map[string]any{"scim_subject_attribute": "externalId"}}); pr.code != 204 {
		t.Fatalf("setting: %d %s", pr.code, pr.raw)
	}
	if pr := ie.patch(t, idp, map[string]any{"settings": map[string]any{"scim_subject_attribute": "email"}}); pr.code != 400 {
		t.Fatalf("an unknown subject attribute: %d", pr.code)
	}
	ie.scimDo(t, tok, "PUT", "/Users/"+id, user("bjensen@corp.example", map[string]any{"externalId": "oid-123"}), nil)
	if got := e.adminQuery("SELECT external_id FROM iam.app_user WHERE id = '" + id + "'"); got != "oid-123" {
		t.Fatalf("subject from externalId: %q", got)
	}

	// §3.6 DELETE: gone from SCIM, the platform user disabled with its
	// history; the same userName can be provisioned again.
	if r := ie.scimDo(t, tok, "DELETE", "/Users/"+id, nil, nil); r.code != 204 {
		t.Fatalf("delete: %d %s", r.code, r.raw)
	}
	scimErr(t, ie.scimDo(t, tok, "GET", "/Users/"+id, nil, nil), 404, "")
	scimErr(t, ie.scimDo(t, tok, "DELETE", "/Users/"+id, nil, nil), 404, "")
	if got := e.adminQuery("SELECT status || '|' || disabled_reason || '|' || (external_id IS NULL) FROM iam.app_user WHERE id = '" + id + "'"); got != "disabled|scim_deleted|true" {
		t.Fatalf("deleted user %q", got)
	}
	if r := ie.scimDo(t, tok, "POST", "/Users", user("bjensen@corp.example", nil), nil); r.code != 201 || r.body["id"] == id {
		t.Fatalf("re-provisioning: %d %s", r.code, r.raw)
	}
}

// RFC 7644 §3.4.2: filtering, pagination, .search.
func TestSCIMListing(t *testing.T) {
	ie := idpFixture(t)
	idp := ie.create(t, "oidc", "Corp", "corp.example")
	tok := ie.scimToken(t, idp)
	for i := range 12 {
		u := user(fmt.Sprintf("user%02d@corp.example", i), map[string]any{"externalId": fmt.Sprintf("E%02d", i)})
		if i%3 == 0 {
			u["active"] = false
			u["title"] = "Contractor"
		}
		if r := ie.scimDo(t, tok, "POST", "/Users", u, nil); r.code != 201 {
			t.Fatalf("seed %d: %d %s", i, r.code, r.raw)
		}
	}
	list := func(q string) scimResp {
		t.Helper()
		r := ie.scimDo(t, tok, "GET", "/Users"+q, nil, nil)
		if r.code != 200 || !strings.Contains(fmt.Sprint(r.body["schemas"]), scim.SchemaList) {
			t.Fatalf("list %s: %d %s", q, r.code, r.raw)
		}
		return r
	}
	all := list("")
	if all.body["totalResults"] != float64(12) || all.body["startIndex"] != float64(1) || len(all.body["Resources"].([]any)) != 12 {
		t.Fatalf("all: %s", all.raw)
	}
	for q, want := range map[string]float64{
		`?filter=userName%20eq%20%22USER03@corp.example%22`:                                     1, // as Entra and Okta look users up
		`?filter=externalId%20eq%20%22E05%22`:                                                   1,
		`?filter=externalId%20eq%20%22e05%22`:                                                   0, // caseExact
		`?filter=active%20eq%20false`:                                                           4,
		`?filter=title%20pr%20and%20userName%20sw%20%22user0%22`:                                4,
		`?filter=emails%5Btype%20eq%20%22work%22%20and%20value%20ew%20%2211@corp.example%22%5D`: 1,
		`?filter=meta.created%20gt%20%222000-01-01T00:00:00Z%22`:                                12,
	} {
		if got := list(q).body["totalResults"]; got != want {
			t.Errorf("%s: %v, want %v", q, got, want)
		}
	}
	// Pagination (§3.4.2.4): 1-based, count caps the page, totalResults is all.
	pg := list("?startIndex=11&count=5")
	if pg.body["totalResults"] != float64(12) || pg.body["itemsPerPage"] != float64(2) || pg.body["startIndex"] != float64(11) {
		t.Fatalf("page: %s", pg.raw)
	}
	if z := list("?count=0"); z.body["totalResults"] != float64(12) || len(z.body["Resources"].([]any)) != 0 {
		t.Fatalf("count=0: %s", z.raw)
	}
	if z := list("?startIndex=0&count=-3"); z.body["startIndex"] != float64(1) || len(z.body["Resources"].([]any)) != 0 {
		t.Fatalf("out-of-range values: %s", z.raw)
	}
	scimErr(t, ie.scimDo(t, tok, "GET", "/Users?filter=userName%20eq", nil, nil), 400, "invalidFilter")
	scimErr(t, ie.scimDo(t, tok, "GET", "/Users?filter=active%20gt%20true", nil, nil), 400, "invalidFilter")
	// §3.4.3 POST .search.
	s := ie.scimDo(t, tok, "POST", "/Users/.search", map[string]any{"schemas": []string{scim.SchemaSearch}, "filter": `active eq false`,
		"attributes": []string{"userName"}, "startIndex": 1, "count": 2}, nil)
	res, _ := s.body["Resources"].([]any)
	if s.code != 200 || s.body["totalResults"] != float64(4) || len(res) != 2 || res[0].(map[string]any)["emails"] != nil {
		t.Fatalf(".search: %d %s", s.code, s.raw)
	}
}

// RFC 7643 §4.2, RFC 7644 §3.5.2: Groups and memberships.
func TestSCIMGroups(t *testing.T) {
	ie := idpFixture(t)
	e := ie.e
	idp := ie.create(t, "oidc", "Corp", "corp.example")
	tok := ie.scimToken(t, idp)
	var ids []string
	for _, n := range []string{"a@corp.example", "b@corp.example", "c@corp.example"} {
		r := ie.scimDo(t, tok, "POST", "/Users", user(n, nil), nil)
		ids = append(ids, r.body["id"].(string))
	}
	other := ie.scimToken(t, ie.create(t, "saml", "Partner", "partner.example"))
	stranger := ie.scimDo(t, other, "POST", "/Users", user("z@partner.example", nil), nil).body["id"].(string)

	c := ie.scimDo(t, tok, "POST", "/Groups", map[string]any{"schemas": []string{scim.SchemaGroup}, "displayName": "Risk Analysts",
		"externalId": "G-1", "members": []any{map[string]any{"value": ids[0]}, map[string]any{"value": ids[1]}}}, nil)
	gid, _ := c.body["id"].(string)
	if c.code != 201 || len(c.body["members"].([]any)) != 2 || c.hdr.Get("ETag") != `W/"1"` {
		t.Fatalf("create group: %d %s", c.code, c.raw)
	}
	m0 := c.body["members"].([]any)[0].(map[string]any)
	if m0["$ref"] != ie.url+"/scim/v2/Users/"+m0["value"].(string) || m0["display"] == nil {
		t.Fatalf("member representation: %v", m0)
	}
	// A member from another IdP, or not a user, is refused.
	scimErr(t, ie.scimDo(t, tok, "POST", "/Groups", map[string]any{"schemas": []string{scim.SchemaGroup}, "displayName": "X",
		"members": []any{map[string]any{"value": stranger}}}, nil), 400, "invalidValue")
	scimErr(t, ie.scimDo(t, tok, "POST", "/Groups", map[string]any{"schemas": []string{scim.SchemaGroup}, "displayName": "X",
		"members": []any{map[string]any{"value": gid, "type": "Group"}}}, nil), 400, "invalidValue")

	// Membership PATCH as Entra (add, remove by filter) and Okta (remove with value) send it.
	for _, op := range []map[string]any{
		{"op": "Add", "path": "members", "value": []any{map[string]any{"value": ids[2]}}},
		{"op": "Remove", "path": `members[value eq "` + ids[0] + `"]`},
		{"op": "remove", "path": "members", "value": []any{map[string]any{"value": ids[1]}}},
	} {
		if r := ie.scimDo(t, tok, "PATCH", "/Groups/"+gid, map[string]any{"schemas": []string{scim.SchemaPatch}, "Operations": []any{op}}, nil); r.code != 200 {
			t.Fatalf("patch %v: %d %s", op, r.code, r.raw)
		}
	}
	if got := e.adminQuery("SELECT string_agg(user_id::text, ',') FROM iam.grp_member WHERE grp_id = '" + gid + "'"); got != ids[2] {
		t.Fatalf("members %q, want %s", got, ids[2])
	}
	// The user shows its groups (read-only); groups filter by member.
	u := ie.scimDo(t, tok, "GET", "/Users/"+ids[2], nil, nil)
	if gs, _ := u.body["groups"].([]any); len(gs) != 1 || gs[0].(map[string]any)["value"] != gid {
		t.Fatalf("user groups: %s", u.raw)
	}
	if r := ie.scimDo(t, tok, "GET", `/Groups?filter=members%5Bvalue%20eq%20%22`+ids[2]+`%22%5D`, nil, nil); r.body["totalResults"] != float64(1) {
		t.Fatalf("filter by member: %s", r.raw)
	}
	if r := ie.scimDo(t, tok, "GET", `/Groups?filter=displayName%20eq%20%22risk%20analysts%22&excludedAttributes=members`, nil, nil); r.body["totalResults"] != float64(1) ||
		r.body["Resources"].([]any)[0].(map[string]any)["members"] != nil {
		t.Fatalf("filter by name without members: %s", r.raw)
	}
	// Membership changes reach the access model (the scope outbox).
	if got := e.adminQuery("SELECT count(*) FROM iam.outbox"); got == "0" {
		t.Fatal("membership changes did not queue a scope recompute")
	}
	// A user deleted from SCIM leaves its groups.
	ie.scimDo(t, tok, "DELETE", "/Users/"+ids[2], nil, nil)
	if got := e.adminQuery("SELECT count(*) FROM iam.grp_member WHERE grp_id = '" + gid + "'"); got != "0" {
		t.Fatalf("%s memberships after the user's deletion", got)
	}
	// PUT replaces the group; DELETE removes it.
	if r := ie.scimDo(t, tok, "PUT", "/Groups/"+gid, map[string]any{"schemas": []string{scim.SchemaGroup}, "displayName": "Analysts",
		"members": []any{map[string]any{"value": ids[0]}}}, nil); r.code != 200 || r.body["displayName"] != "Analysts" || r.body["externalId"] != nil {
		t.Fatalf("put group: %d %s", r.code, r.raw)
	}
	if r := ie.scimDo(t, tok, "DELETE", "/Groups/"+gid, nil, map[string]string{"If-Match": `W/"1"`}); r.code != 412 {
		t.Fatalf("delete with a stale version: %d", r.code)
	}
	if r := ie.scimDo(t, tok, "DELETE", "/Groups/"+gid, nil, nil); r.code != 204 {
		t.Fatalf("delete group: %d", r.code)
	}
	scimErr(t, ie.scimDo(t, tok, "GET", "/Groups/"+gid, nil, nil), 404, "")
	if got := e.adminQuery("SELECT count(*) FROM iam.grp_member WHERE grp_id = '" + gid + "'"); got != "0" {
		t.Fatal("a deleted group kept members")
	}
}

// RFC 7644 §3.7 Bulk, with the size caps (design §7: bulk abuse).
func TestSCIMBulk(t *testing.T) {
	ie := idpFixture(t)
	e := ie.e
	idp := ie.create(t, "oidc", "Corp", "corp.example")
	tok := ie.scimToken(t, idp)
	req := map[string]any{"schemas": []string{scim.SchemaBulkReq}, "Operations": []any{
		map[string]any{"method": "POST", "path": "/Users", "bulkId": "u1", "data": user("bulk1@corp.example", nil)},
		map[string]any{"method": "POST", "path": "/Groups", "bulkId": "g1", "data": map[string]any{"schemas": []string{scim.SchemaGroup},
			"displayName": "Bulk Group", "members": []any{map[string]any{"value": "bulkId:u1"}}}},
		map[string]any{"method": "PATCH", "path": "/Users/bulkId:u1", "data": map[string]any{"schemas": []string{scim.SchemaPatch},
			"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}}}},
		map[string]any{"method": "POST", "path": "/Users", "bulkId": "dup", "data": user("bulk1@corp.example", nil)},
		map[string]any{"method": "POST", "path": "/Users", "data": user("nobulkid@corp.example", nil)},
		map[string]any{"method": "DELETE", "path": "/Groups/bulkId:nope"},
	}}
	r := ie.scimDo(t, tok, "POST", "/Bulk", req, nil)
	if r.code != 200 || !strings.Contains(fmt.Sprint(r.body["schemas"]), scim.SchemaBulkResp) {
		t.Fatalf("bulk: %d %s", r.code, r.raw)
	}
	var statuses []string
	for _, op := range r.body["Operations"].([]any) {
		statuses = append(statuses, op.(map[string]any)["status"].(string))
	}
	if strings.Join(statuses, ",") != "201,201,200,409,400,409" {
		t.Fatalf("statuses %v: %s", statuses, r.raw)
	}
	first := r.body["Operations"].([]any)[0].(map[string]any)
	if !strings.HasPrefix(first["location"].(string), ie.url+"/scim/v2/Users/") || first["version"] != `W/"1"` || first["bulkId"] != "u1" {
		t.Fatalf("operation response: %v", first)
	}
	if got := e.adminQuery("SELECT status FROM iam.app_user WHERE user_name = 'bulk1@corp.example'"); got != "disabled" {
		t.Fatalf("bulk deactivation: %q", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.grp_member m JOIN iam.grp g ON g.id = m.grp_id WHERE g.display_name = 'Bulk Group'"); got != "1" {
		t.Fatalf("bulkId member reference: %s", got)
	}
	// failOnErrors stops after that many errors.
	req["failOnErrors"] = 1
	req["Operations"] = []any{
		map[string]any{"method": "POST", "path": "/Users", "bulkId": "a", "data": user("bulk1@corp.example", nil)},
		map[string]any{"method": "POST", "path": "/Users", "bulkId": "b", "data": user("never@corp.example", nil)},
	}
	if r := ie.scimDo(t, tok, "POST", "/Bulk", req, nil); len(r.body["Operations"].([]any)) != 1 {
		t.Fatalf("failOnErrors: %s", r.raw)
	}
	// Caps: operations and payload size (413).
	var many []any
	for i := range scim.MaxOperations + 1 {
		many = append(many, map[string]any{"method": "DELETE", "path": fmt.Sprintf("/Users/%08d-0000-0000-0000-000000000000", i)})
	}
	scimErr(t, ie.scimDo(t, tok, "POST", "/Bulk", map[string]any{"schemas": []string{scim.SchemaBulkReq}, "Operations": many}, nil), 413, "")
	big := `{"schemas": ["` + scim.SchemaBulkReq + `"], "Operations": [], "pad": "` + strings.Repeat("x", scim.MaxPayloadSize) + `"}`
	scimErr(t, ie.scimDo(t, tok, "POST", "/Bulk", big, nil), 413, "")
	scimErr(t, ie.scimDo(t, tok, "POST", "/Bulk", map[string]any{"Operations": []any{}}, nil), 400, "invalidSyntax")
}

// RFC 7644 §4: discovery.
func TestSCIMDiscovery(t *testing.T) {
	ie := idpFixture(t)
	tok := ie.scimToken(t, ie.create(t, "oidc", "Corp", "corp.example"))
	sp := ie.scimDo(t, tok, "GET", "/ServiceProviderConfig", nil, nil)
	bulk, _ := sp.body["bulk"].(map[string]any)
	filter, _ := sp.body["filter"].(map[string]any)
	if sp.code != 200 || sp.body["patch"].(map[string]any)["supported"] != true || bulk["maxOperations"] != float64(scim.MaxOperations) ||
		bulk["maxPayloadSize"] != float64(scim.MaxPayloadSize) || filter["maxResults"] != float64(scim.MaxResults) ||
		sp.body["etag"].(map[string]any)["supported"] != true || sp.body["changePassword"].(map[string]any)["supported"] != false {
		t.Fatalf("ServiceProviderConfig: %s", sp.raw)
	}
	if schemes := sp.body["authenticationSchemes"].([]any); schemes[0].(map[string]any)["type"] != "oauthbearertoken" {
		t.Fatalf("authenticationSchemes: %v", schemes)
	}
	rt := ie.scimDo(t, tok, "GET", "/ResourceTypes", nil, nil)
	if rt.body["totalResults"] != float64(2) {
		t.Fatalf("ResourceTypes: %s", rt.raw)
	}
	if u := ie.scimDo(t, tok, "GET", "/ResourceTypes/User", nil, nil); u.body["endpoint"] != "/Users" || !strings.Contains(u.raw, scim.SchemaEnterprise) {
		t.Fatalf("ResourceTypes/User: %s", u.raw)
	}
	sc := ie.scimDo(t, tok, "GET", "/Schemas", nil, nil)
	if sc.body["totalResults"] != float64(3) {
		t.Fatalf("Schemas: %s", sc.raw)
	}
	us := ie.scimDo(t, tok, "GET", "/Schemas/"+scim.SchemaUser, nil, nil)
	if us.code != 200 || !strings.Contains(us.raw, `"name":"userName"`) || !strings.Contains(us.raw, `"uniqueness":"server"`) {
		t.Fatalf("Schemas/User: %s", us.raw)
	}
	scimErr(t, ie.scimDo(t, tok, "GET", "/Schemas/urn:example:nope", nil, nil), 404, "")
	scimErr(t, ie.scimDo(t, tok, "GET", "/Me", nil, nil), 501, "")
	scimErr(t, ie.scimDo(t, tok, "GET", "/Nope", nil, nil), 404, "")
	if r := ie.scimDo(t, "", "GET", "/ServiceProviderConfig", nil, nil); r.code != 401 {
		t.Fatalf("discovery without a token: %d", r.code)
	}
}
