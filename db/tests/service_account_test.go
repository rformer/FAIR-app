package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-001 T-33 (AC-36, AC-37, AC-38): service accounts scoped to a BU and to
// explicit API scopes, client secrets shown once and stored as HMACs,
// expiring within token.max_lifetime, exchanged for access tokens at the
// gateway (client credentials) or with a pinned certificate (mTLS).

var saPepper = []byte("token-pepper-0123456789abcdef-0123456789")

type saEnv struct {
	*idpEnv
	admin2 string
}

func saFixture(t *testing.T) *saEnv {
	t.Helper()
	ie := idpFixture(t)
	e := ie.e
	seedPosture(t, e) // token.max_lifetime: 90 days (Enterprise Baseline)
	e.addBU("A", "ENTERPRISE")
	e.addBU("A1", "A")
	e.addBU("B", "ENTERPRISE")
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('bob@example.test', 'Bob')")
	e.mustOwner(grant("admin", "user:bob", "BU Admin", "A"))
	e.drain()
	ie.api.TokenPepper = saPepper
	ie.g.ServiceAccounts = &gateway.ServiceAccounts{DB: e.gatewayPool(), Pepper: saPepper, CertHeader: "X-Client-Cert", PerMinute: 1000}
	ie.resetHandler(t)
	return &saEnv{idpEnv: ie, admin2: ie.login(t, "admin2")}
}

// hdrFor: a mutation's headers for another session.
func (se *saEnv) hdrFor(t *testing.T, cookie string) map[string]string {
	t.Helper()
	h := se.csrf(t, cookie)
	h[server.IdempotencyHeader] = fmt.Sprintf("sa-test-%d", time.Now().UnixNano())
	return h
}

func (se *saEnv) createSA(t *testing.T, name, bu, method string, scopes ...string) string {
	t.Helper()
	r := se.do(t, "POST", "/api/v1/service-accounts", se.admin, map[string]any{"name": name, "bu_id": se.e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + bu + "'"),
		"scopes": scopes, "auth_method": method, "reason": "integration"}, se.hdr())
	id, _ := r.body["id"].(string)
	if r.code != http.StatusCreated || id == "" {
		t.Fatalf("create %s: %d %s", name, r.code, r.raw)
	}
	se.e.drain() // the scope worker gives the account its scope
	return id
}

func (se *saEnv) secret(t *testing.T, sa string) string {
	t.Helper()
	r := se.do(t, "POST", "/api/v1/service-accounts/"+sa+"/tokens", se.admin, map[string]any{"name": "ci", "reason": "pipeline"}, se.hdr())
	s, _ := r.body["client_secret"].(string)
	if r.code != http.StatusCreated || !strings.HasPrefix(s, authn.SecretPrefix) {
		t.Fatalf("issue secret: %d %s", r.code, r.raw)
	}
	return s
}

type tokReq struct {
	form        url.Values
	basicID     string
	basicSecret string
	certPEM     string // X-Client-Cert, as an ingress passes it
	contentType string
	query       string
}

func (se *saEnv) token(t *testing.T, q tokReq) gwResp {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", se.url+gateway.TokenPath+q.query, strings.NewReader(q.form.Encode()))
	ct := q.contentType
	if ct == "" {
		ct = "application/x-www-form-urlencoded"
	}
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Forwarded-For", loginIP)
	if q.basicID != "" {
		req.SetBasicAuth(url.QueryEscape(q.basicID), url.QueryEscape(q.basicSecret))
	}
	if q.certPEM != "" {
		req.Header.Set("X-Client-Cert", url.QueryEscape(q.certPEM))
	}
	return send(t, http.DefaultClient, req)
}

func send(t *testing.T, c *http.Client, req *http.Request) gwResp {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return gwResp{resp.StatusCode, m, string(raw), resp.Header}
}

func (se *saEnv) accessToken(t *testing.T, sa, secret string) string {
	t.Helper()
	r := se.token(t, tokReq{form: url.Values{"grant_type": {"client_credentials"}}, basicID: sa, basicSecret: secret})
	tok, _ := r.body["access_token"].(string)
	if r.code != http.StatusOK || !strings.HasPrefix(tok, authn.AccessPrefix) {
		t.Fatalf("token: %d %s", r.code, r.raw)
	}
	return tok
}

// bearer calls the API with an access token (and optionally a client
// certificate passed by the ingress).
func (se *saEnv) bearer(t *testing.T, method, path, tok, certPEM string) gwResp {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, se.url+path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Forwarded-For", loginIP)
	if certPEM != "" {
		req.Header.Set("X-Client-Cert", url.QueryEscape(certPEM))
	}
	return send(t, http.DefaultClient, req)
}

func busOf(r gwResp) []string {
	var out []string
	list, _ := r.body["bus"].([]any)
	for _, b := range list {
		out = append(out, b.(map[string]any)["code"].(string))
	}
	return out
}

func TestServiceAccounts(t *testing.T) {
	se := saFixture(t)
	e := se.e
	buA := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")

	// AC-36: a BU and explicit scopes; held scopes apply at once, audited.
	sa := se.createSA(t, "Reporter", "A", "client_credentials", "bu.view")
	got := se.do(t, "GET", "/api/v1/service-accounts/"+sa, se.admin, nil, nil)
	if got.code != 200 || got.body["bu_code"] != "A" || fmt.Sprint(got.body["scopes"]) != "[bu.view]" || got.body["status"] != "active" {
		t.Fatalf("read: %d %s", got.code, got.raw)
	}
	if a := e.adminQuery(`SELECT payload->>'severity' FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'service_account.created'
		AND payload->>'target' = 'service_account:` + sa + `'`); a != "high" {
		t.Fatalf("creation audit: %q", a)
	}
	// Refused: privileged and unknown scopes, no scopes, no reason, a duplicate
	// name, another method, an archived BU.
	for name, body := range map[string]map[string]any{
		"privileged scope": {"name": "X1", "bu_id": buA, "scopes": []string{"bu.view", "bu.manage"}, "auth_method": "client_credentials", "reason": "r"},
		"admin scope":      {"name": "X2", "bu_id": buA, "scopes": []string{"service_account.manage"}, "auth_method": "client_credentials", "reason": "r"},
		"unknown scope":    {"name": "X3", "bu_id": buA, "scopes": []string{"bu.fly"}, "auth_method": "client_credentials", "reason": "r"},
		"no scopes":        {"name": "X4", "bu_id": buA, "scopes": []string{}, "auth_method": "client_credentials", "reason": "r"},
		"no reason":        {"name": "X5", "bu_id": buA, "scopes": []string{"bu.view"}, "auth_method": "client_credentials", "reason": ""},
		"other method":     {"name": "X6", "bu_id": buA, "scopes": []string{"bu.view"}, "auth_method": "password", "reason": "r"},
	} {
		if r := se.do(t, "POST", "/api/v1/service-accounts", se.admin, body, se.hdr()); r.code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if r := se.do(t, "POST", "/api/v1/service-accounts", se.admin, map[string]any{"name": " reporter ", "bu_id": buA, "scopes": []string{"bu.view"},
		"auth_method": "mtls", "reason": "r"}, se.hdr()); r.code != http.StatusConflict {
		t.Errorf("duplicate name: %d %s", r.code, r.raw)
	}
	// Only holders of service_account.manage see the API, and only at their BUs.
	bob := se.login(t, "bob")
	if r := se.do(t, "GET", "/api/v1/service-accounts", bob, nil, nil); r.code != http.StatusNotFound {
		t.Fatalf("without service_account.manage: %d %s", r.code, r.raw)
	}

	// A service account is not a user: not listed, not administrable there.
	if r := se.do(t, "GET", "/api/v1/users", se.admin, nil, nil); r.code != 200 || strings.Contains(r.raw, sa) {
		t.Fatalf("users list shows the service account: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "POST", "/api/v1/users/"+sa+"/disable", se.admin, map[string]any{"reason": "x"}, se.hdr()); r.code != http.StatusNotFound {
		t.Fatalf("user action on a service account: %d %s", r.code, r.raw)
	}
	// Its private role is no one else's and changes only with it.
	role := e.adminQuery("SELECT role_id FROM iam.service_account WHERE id = '" + sa + "'")
	if r := se.do(t, "GET", "/api/v1/roles", se.admin, nil, nil); r.code != 200 || strings.Contains(r.raw, role) {
		t.Fatalf("roles list shows the private role: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "PUT", "/api/v1/roles/"+role, se.admin, map[string]any{"permissions": []string{"bu.view", "role.view"},
		"expected_version": 1, "reason": "widen"}, se.hdr()); r.code != http.StatusConflict {
		t.Fatalf("editing the private role: %d %s", r.code, r.raw)
	}
	e.ownerFails(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		VALUES ('user', `+uid("bob")+`, '`+role+`', '`+buA+`', `+uid("admin")+`)`, "belongs to a service account")
	e.ownerFails(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by, source)
		VALUES ('user', '`+sa+`', '`+role+`', '`+buA+`', `+uid("admin")+`, 'service')`, "holds its own role at its BU, once")
	e.ownerFails("UPDATE iam.role SET service_account_id = NULL WHERE id = '"+role+"'", "immutable")
	grp := e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Ops') RETURNING id")
	if r := se.do(t, "POST", "/api/v1/group-mappings", se.admin, map[string]any{"group_id": grp, "role_id": role, "bu_id": buA, "reason": "x"},
		se.hdr()); r.code != http.StatusBadRequest {
		t.Fatalf("mapping the private role: %d %s", r.code, r.raw)
	}

	// AC-37: a client secret, shown once, stored only as an HMAC under the
	// token pepper; a replay is refused; the expiry is bounded.
	h := se.hdr()
	first := se.do(t, "POST", "/api/v1/service-accounts/"+sa+"/tokens", se.admin, map[string]any{"name": "ci", "reason": "pipeline"}, h)
	secret, _ := first.body["client_secret"].(string)
	if first.code != http.StatusCreated || !strings.HasPrefix(secret, authn.SecretPrefix) || first.body["client_id"] != sa {
		t.Fatalf("issue: %d %s", first.code, first.raw)
	}
	exp, _ := time.Parse(time.RFC3339Nano, first.body["expires_at"].(string))
	if d := time.Until(exp); d < 89*24*time.Hour || d > 90*24*time.Hour {
		t.Fatalf("default expiry %v, want token.max_lifetime (90 days)", d)
	}
	if again := se.do(t, "POST", "/api/v1/service-accounts/"+sa+"/tokens", se.admin, map[string]any{"name": "ci", "reason": "pipeline"}, h); again.code != http.StatusConflict ||
		again.body["error"] != "secret_not_replayed" || strings.Contains(again.raw, secret) {
		t.Fatalf("replay: %d %s", again.code, again.raw)
	}
	want, _ := authn.TokenHMAC(saPepper, secret)
	plain := sha256.Sum256([]byte(secret))
	if stored := e.adminQuery("SELECT encode(token_hash, 'hex') FROM iam.api_token WHERE owner_id = '" + sa + "'"); stored != hex.EncodeToString(want) ||
		stored == hex.EncodeToString(plain[:]) {
		t.Fatalf("stored %s, want the HMAC", stored)
	}
	if n := e.adminQuery(`SELECT count(*) FROM iam.idempotency WHERE position('` + secret + `' IN convert_from(coalesce(body, ''), 'UTF8')) > 0`); n != "0" {
		t.Fatal("the secret is in the idempotency store")
	}
	if l := se.do(t, "GET", "/api/v1/service-accounts/"+sa+"/tokens", se.admin, nil, nil); l.code != 200 || strings.Contains(l.raw, secret) ||
		!strings.Contains(l.raw, secret[:12]) {
		t.Fatalf("list: %d %s", l.code, l.raw)
	}
	if r := se.do(t, "POST", "/api/v1/service-accounts/"+sa+"/tokens", se.admin, map[string]any{"name": "long", "expires_in_days": 91, "reason": "x"}, se.hdr()); r.code != http.StatusBadRequest ||
		!strings.Contains(r.raw, "token.max_lifetime") {
		t.Fatalf("beyond token.max_lifetime: %d %s", r.code, r.raw)
	}

	// AC-38: client credentials at the gateway.
	cc := url.Values{"grant_type": {"client_credentials"}}
	ok := se.token(t, tokReq{form: cc, basicID: sa, basicSecret: secret})
	access, _ := ok.body["access_token"].(string)
	if ok.code != 200 || ok.body["token_type"] != "Bearer" || ok.body["expires_in"] != float64(600) || ok.body["scope"] != "bu.view" ||
		ok.hdr.Get("Cache-Control") != "no-store" || !strings.HasPrefix(access, authn.AccessPrefix) {
		t.Fatalf("token: %d %s %v", ok.code, ok.raw, ok.hdr)
	}
	if r := se.token(t, tokReq{form: url.Values{"grant_type": {"client_credentials"}, "client_id": {sa}, "client_secret": {secret}, "scope": {"bu.view"}}}); r.code != 200 {
		t.Fatalf("secret in the body, scope requested: %d %s", r.code, r.raw)
	}
	for name, q := range map[string]tokReq{
		"wrong secret":    {form: cc, basicID: sa, basicSecret: secret + "x"},
		"unknown client":  {form: cc, basicID: "00000000-0000-0000-0000-000000000000", basicSecret: secret},
		"another client":  {form: cc, basicID: buA, basicSecret: secret},
		"no credential":   {form: url.Values{"grant_type": {"client_credentials"}, "client_id": {sa}}},
		"a SCIM token":    {form: cc, basicID: sa, basicSecret: "fscim_" + secret[4:]},
		"malformed id":    {form: cc, basicID: "reporter", basicSecret: secret},
		"no secret value": {form: cc, basicID: sa},
	} {
		r := se.token(t, q)
		if r.code != http.StatusUnauthorized || r.body["error"] != "invalid_client" {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if r := se.token(t, tokReq{form: cc, basicID: sa, basicSecret: "bad"}); r.hdr.Get("WWW-Authenticate") != `Basic realm="fair"` {
		t.Errorf("Basic failure without a challenge: %v", r.hdr)
	}
	if a := e.adminQuery(`SELECT string_agg(DISTINCT payload->>'reason' || '/' || (payload->>'severity'), ',' ORDER BY payload->>'reason' || '/' || (payload->>'severity'))
		FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'authn.client_credentials_failed'`); a != "invalid_secret/high,unknown_client/low" {
		t.Errorf("failure audit: %q", a)
	}
	for name, c := range map[string]struct {
		q    tokReq
		code string
	}{
		"other grant":     {tokReq{form: url.Values{"grant_type": {"password"}}, basicID: sa, basicSecret: secret}, "unsupported_grant_type"},
		"JSON body":       {tokReq{form: cc, basicID: sa, basicSecret: secret, contentType: "application/json"}, "invalid_request"},
		"two methods":     {tokReq{form: url.Values{"grant_type": {"client_credentials"}, "client_secret": {secret}}, basicID: sa, basicSecret: secret}, "invalid_request"},
		"repeated":        {tokReq{form: url.Values{"grant_type": {"client_credentials", "client_credentials"}}, basicID: sa, basicSecret: secret}, "invalid_request"},
		"secret in URL":   {tokReq{form: cc, basicID: sa, basicSecret: secret, query: "?client_secret=" + secret}, "invalid_request"},
		"wider scope":     {tokReq{form: url.Values{"grant_type": {"client_credentials"}, "scope": {"bu.view role.view"}}, basicID: sa, basicSecret: secret}, "invalid_scope"},
		"privilege scope": {tokReq{form: url.Values{"grant_type": {"client_credentials"}, "scope": {"bu.manage"}}, basicID: sa, basicSecret: secret}, "invalid_scope"},
	} {
		if r := se.token(t, c.q); r.code != http.StatusBadRequest || r.body["error"] != c.code {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if a := e.adminQuery(`SELECT count(*) FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'authn.client_credentials' AND payload->>'actor' = '` + sa + `'`); a != "2" {
		t.Errorf("issuance audit: %s", a)
	}
	if e.adminQuery("SELECT last_login_at IS NOT NULL FROM iam.app_user WHERE id = '"+sa+"'") != "t" {
		t.Error("token issuance is not recorded as activity (inactivity sweep)")
	}
	ah, _ := authn.TokenHMAC(saPepper, access)
	if e.adminQuery("SELECT count(*) FROM iam.sa_access_token WHERE token_hmac = '\\x"+hex.EncodeToString(ah)+"'") != "1" {
		t.Fatal("the access token is not stored as its HMAC")
	}

	// The access token reaches the services, scoped to the BU and the scopes.
	if r := se.bearer(t, "GET", "/api/v1/bus", access, ""); r.code != 200 || fmt.Sprint(busOf(r)) != "[A A1]" {
		t.Fatalf("BUs seen by the service account: %d %s", r.code, r.raw)
	}
	if r := se.bearer(t, "GET", "/api/v1/roles", access, ""); r.code != http.StatusNotFound {
		t.Fatalf("outside its scopes: %d %s", r.code, r.raw)
	}
	if r := se.bearer(t, "GET", "/api/v1/service-accounts", access, ""); r.code != http.StatusNotFound {
		t.Fatalf("service-account administration: %d %s", r.code, r.raw)
	}
	r := se.bearer(t, "POST", "/api/v1/posture/anything", access, "")
	up := <-se.upstream
	if r.code != http.StatusTeapot || up.Header.Get("Cookie") != "" || strings.Contains(up.Header.Get("Authorization"), access) {
		t.Fatalf("proxied: %d %v", r.code, up.Header)
	}
	c, err := authz.VerifyJWT(se.keys, strings.TrimPrefix(up.Header.Get("Authorization"), "Bearer "), "posture", time.Now())
	if err != nil || c.Subject != sa || !c.ServiceAccount || c.ScopeVersion == 0 {
		t.Fatalf("internal JWT: %+v %v", c, err)
	}
	for name, tok := range map[string]string{"forged": authn.AccessPrefix + strings.Repeat("A", 43), "the secret": secret, "empty": ""} {
		if r := se.bearer(t, "GET", "/api/v1/bus", tok, ""); r.code != http.StatusUnauthorized {
			t.Errorf("%s token: %d %s", name, r.code, r.raw)
		}
	}
	if r := se.do(t, "GET", "/api/v1/bus", se.admin, nil, map[string]string{"Authorization": "Bearer " + access}); r.code != http.StatusBadRequest {
		t.Fatalf("cookie and bearer: %d %s", r.code, r.raw)
	}
	if r := se.bearer(t, "GET", "/api/v1/me", access, ""); r.code != http.StatusUnauthorized {
		t.Fatalf("the gateway's session API with a bearer token: %d %s", r.code, r.raw)
	}

	// Scope changes: held scopes at once, removals at once; the account's
	// scope follows after the scope worker.
	if r := se.do(t, "PATCH", "/api/v1/service-accounts/"+sa, se.admin, map[string]any{"scopes": []string{"bu.view", "role.view"}, "reason": "reporting"}, se.hdr()); r.code != 200 {
		t.Fatalf("add a held scope: %d %s", r.code, r.raw)
	}
	e.drain()
	if r := se.bearer(t, "GET", "/api/v1/roles", access, ""); r.code != 200 {
		t.Fatalf("after adding role.view: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "PATCH", "/api/v1/service-accounts/"+sa, se.admin, map[string]any{"scopes": []string{"bu.view"}, "name": "Reporter 2", "reason": "narrow"}, se.hdr()); r.code != 200 ||
		r.body["name"] != "Reporter 2" {
		t.Fatalf("remove a scope, rename: %d %s", r.code, r.raw)
	}
	e.drain()
	if r := se.bearer(t, "GET", "/api/v1/roles", access, ""); r.code != http.StatusNotFound {
		t.Fatalf("after removing role.view: %d %s", r.code, r.raw)
	}

	// Scopes the actor does not hold (risk data, which no admin may hold,
	// AC-30) need a second holder of service_account.manage.
	pend := se.do(t, "PATCH", "/api/v1/service-accounts/"+sa, se.admin, map[string]any{"scopes": []string{"bu.view", "register.view"}, "reason": "risk feed"}, se.hdr())
	approval, _ := pend.body["approval_id"].(string)
	if pend.code != http.StatusAccepted || fmt.Sprint(pend.body["unheld_scopes"]) != "[register.view]" {
		t.Fatalf("unheld scope: %d %s", pend.code, pend.raw)
	}
	if r := se.do(t, "GET", "/api/v1/service-accounts/"+sa, se.admin, nil, nil); fmt.Sprint(r.body["scopes"]) != "[bu.view]" {
		t.Fatalf("scopes changed before approval: %s", r.raw)
	}
	apply := func(id string) gwResp {
		return se.do(t, "POST", "/api/v1/service-accounts/apply", se.admin, map[string]any{"approval_id": id}, se.hdr())
	}
	if r := apply(approval); r.code != http.StatusConflict {
		t.Fatalf("apply before approval: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "POST", "/api/v1/approvals/"+approval+"/decision", se.admin, map[string]any{"approve": true, "reason": "self"}, se.hdr()); r.code != http.StatusForbidden {
		t.Fatalf("self-approval: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "POST", "/api/v1/approvals/"+approval+"/decision", se.admin2, map[string]any{"approve": true, "reason": "ok for the feed"}, se.hdrFor(t, se.admin2)); r.code != 200 {
		t.Fatalf("approve: %d %s", r.code, r.raw)
	}
	if r := apply(approval); r.code != 200 || fmt.Sprint(r.body["scopes"]) != "[bu.view register.view]" {
		t.Fatalf("apply: %d %s", r.code, r.raw)
	}
	if r := apply(approval); r.code != http.StatusConflict {
		t.Fatalf("applied twice: %d %s", r.code, r.raw)
	}
	if a := e.adminQuery(`SELECT payload->'attributes'->>'approved_by' = ` + uid("admin2") + `::text FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev
		WHERE payload->>'type' = 'service_account.scopes_changed' ORDER BY id DESC LIMIT 1`); a != "t" {
		t.Fatalf("approval not in the audit: %s", a)
	}
	// A creation with an unheld scope, and a stale scope request.
	pend = se.do(t, "POST", "/api/v1/service-accounts", se.admin, map[string]any{"name": "Feed", "bu_id": buA, "scopes": []string{"register.view"},
		"auth_method": "client_credentials", "reason": "feed"}, se.hdr())
	created, _ := pend.body["approval_id"].(string)
	if pend.code != http.StatusAccepted || e.adminQuery("SELECT count(*) FROM iam.service_account WHERE name = 'Feed'") != "0" {
		t.Fatalf("create with an unheld scope: %d %s", pend.code, pend.raw)
	}
	stale := se.do(t, "PATCH", "/api/v1/service-accounts/"+sa, se.admin, map[string]any{"scopes": []string{"register.view", "report.view"}, "reason": "more"}, se.hdr())
	staleID, _ := stale.body["approval_id"].(string)
	if r := se.do(t, "PATCH", "/api/v1/service-accounts/"+sa, se.admin, map[string]any{"scopes": []string{"register.view"}, "reason": "drop bu.view"}, se.hdr()); r.code != 200 {
		t.Fatalf("narrowing: %d %s", r.code, r.raw)
	}
	for _, id := range []string{created, staleID} {
		if r := se.do(t, "POST", "/api/v1/approvals/"+id+"/decision", se.admin2, map[string]any{"approve": true, "reason": "ok"}, se.hdrFor(t, se.admin2)); r.code != 200 {
			t.Fatalf("approve %s: %d %s", id, r.code, r.raw)
		}
	}
	if r := apply(created); r.code != 200 || r.body["name"] != "Feed" || fmt.Sprint(r.body["scopes"]) != "[register.view]" {
		t.Fatalf("apply creation: %d %s", r.code, r.raw)
	}
	if r := apply(staleID); r.code != http.StatusConflict || !strings.Contains(r.raw, "changed since the request") {
		t.Fatalf("stale request: %d %s", r.code, r.raw)
	}

	// Expiry and revocation end access tokens at once.
	e.drain()
	if r := se.bearer(t, "GET", "/api/v1/posture/x", access, ""); r.code != http.StatusTeapot {
		t.Fatalf("before expiry: %d %s", r.code, r.raw)
	}
	<-se.upstream
	e.mustOwner("UPDATE iam.sa_access_token SET issued_at = now() - interval '11 minutes', expires_at = now() - interval '1 minute' WHERE token_hmac = '\\x" + hex.EncodeToString(ah) + "'")
	if r := se.bearer(t, "GET", "/api/v1/posture/x", access, ""); r.code != http.StatusUnauthorized || r.hdr.Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("expired access token: %d %s %v", r.code, r.raw, r.hdr)
	}
	access = se.accessToken(t, sa, secret)
	e.mustOwner("UPDATE iam.api_token SET created_at = now() - interval '91 days', expires_at = now() - interval '1 second' WHERE owner_id = '" + sa + "'")
	if r := se.bearer(t, "GET", "/api/v1/posture/x", access, ""); r.code != http.StatusUnauthorized {
		t.Fatalf("access token of an expired secret: %d %s", r.code, r.raw)
	}
	if r := se.token(t, tokReq{form: cc, basicID: sa, basicSecret: secret}); r.code != http.StatusUnauthorized {
		t.Fatalf("expired secret: %d %s", r.code, r.raw)
	}
	secret = se.secret(t, sa)
	access = se.accessToken(t, sa, secret)
	tid := e.adminQuery("SELECT id FROM iam.api_token WHERE owner_id = '" + sa + "' AND revoked_at IS NULL AND expires_at > now()")
	if r := se.do(t, "DELETE", "/api/v1/service-accounts/"+sa+"/tokens/"+tid+"?reason=rotated", se.admin, nil, se.hdr()); r.code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", r.code, r.raw)
	}
	if r := se.bearer(t, "GET", "/api/v1/posture/x", access, ""); r.code != http.StatusUnauthorized {
		t.Fatalf("access token after revocation: %d %s", r.code, r.raw)
	}
	if r := se.token(t, tokReq{form: cc, basicID: sa, basicSecret: secret}); r.code != http.StatusUnauthorized {
		t.Fatalf("revoked secret: %d %s", r.code, r.raw)
	}

	// Disabling ends everything at once; enabling needs no new secret.
	secret = se.secret(t, sa)
	access = se.accessToken(t, sa, secret)
	if r := se.do(t, "POST", "/api/v1/service-accounts/"+sa+"/disable", se.admin, map[string]any{"reason": "incident"}, se.hdr()); r.code != 200 || r.body["status"] != "disabled" {
		t.Fatalf("disable: %d %s", r.code, r.raw)
	}
	if r := se.bearer(t, "GET", "/api/v1/posture/x", access, ""); r.code != http.StatusUnauthorized {
		t.Fatalf("access token of a disabled account: %d %s", r.code, r.raw)
	}
	if r := se.token(t, tokReq{form: cc, basicID: sa, basicSecret: secret}); r.code != http.StatusUnauthorized {
		t.Fatalf("token for a disabled account: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "POST", "/api/v1/service-accounts/"+sa+"/tokens", se.admin, map[string]any{"reason": "x"}, se.hdr()); r.code != http.StatusConflict {
		t.Fatalf("secret for a disabled account: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "POST", "/api/v1/service-accounts/"+sa+"/enable", se.admin, map[string]any{"reason": "resolved"}, se.hdr()); r.code != 200 || r.body["status"] != "active" {
		t.Fatalf("enable: %d %s", r.code, r.raw)
	}
	e.drain()
	access = se.accessToken(t, sa, secret)
	if r := se.bearer(t, "GET", "/api/v1/posture/x", access, ""); r.code != http.StatusTeapot {
		t.Fatalf("after enabling: %d %s", r.code, r.raw)
	}
	<-se.upstream
	// Disabled another way (the inactivity sweep), its live tokens stop too.
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled', disabled_reason = 'inactive' WHERE id = '" + sa + "'")
	if r := se.bearer(t, "GET", "/api/v1/posture/x", access, ""); r.code != http.StatusUnauthorized {
		t.Fatalf("access token of an account the sweep disabled: %d %s", r.code, r.raw)
	}

	// The roles: app_rw cannot issue or look up access tokens, app_gateway
	// cannot administer accounts, and nobody reads the tables.
	e.mustFail("app_rw", "SELECT * FROM iam.sa_access_lookup('\\x00')", "permission denied")
	e.mustFail("app_rw", "SELECT * FROM iam.sa_token_issue(NULL, NULL, NULL, NULL, NULL, NULL, NULL)", "permission denied")
	e.mustFail("app_gateway", "SELECT * FROM iam.service_account_list(NULL)", "permission denied")
	e.mustFail("app_rw", "SELECT * FROM iam.sa_access_token", "permission denied")
	e.mustFail("app_gateway", "SELECT * FROM iam.service_account", "permission denied")
}

// testCert is a client certificate and its PEM.
type testCert struct {
	tls tls.Certificate
	pem string
	der []byte
}

func newCert(t *testing.T, mut func(*x509.Certificate)) testCert {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "scanner"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if mut != nil {
		mut(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{tls: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, der: der,
		pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func TestServiceAccountMTLS(t *testing.T) {
	se := saFixture(t)
	e := se.e
	sa := se.createSA(t, "Scanner", "A", "mtls", "bu.view")
	cs := se.createSA(t, "Secretive", "B", "client_credentials", "bu.view")
	cert, other := newCert(t, nil), newCert(t, nil)
	add := func(id, pemText string) gwResp {
		return se.do(t, "POST", "/api/v1/service-accounts/"+id+"/certificates", se.admin, map[string]any{"name": "scanner", "certificate": pemText, "reason": "deploy"}, se.hdr())
	}
	r := add(sa, cert.pem)
	sum := sha256.Sum256(cert.der)
	if r.code != http.StatusCreated || r.body["thumbprint_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("register: %d %s", r.code, r.raw)
	}
	exp, _ := time.Parse(time.RFC3339Nano, r.body["expires_at"].(string))
	if d := time.Until(exp); d > 90*24*time.Hour || d < 89*24*time.Hour {
		t.Fatalf("a certificate valid a year is accepted for %v, want token.max_lifetime", d)
	}
	// Refused: a CA, a server-only certificate, an expired one, a chain, a
	// key FIPS TLS does not take, garbage, the same certificate twice, the
	// wrong account kind; and secrets for an mTLS account.
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edTmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "ed"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	edDER, _ := x509.CreateCertificate(rand.Reader, edTmpl, edTmpl, edPriv.Public(), edPriv)
	for name, p := range map[string]string{
		"CA":          newCert(t, func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }).pem,
		"server only": newCert(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }).pem,
		"expired": newCert(t, func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
		}).pem,
		"chain":   cert.pem + other.pem,
		"Ed25519": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edDER})),
		"garbage": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		if r := add(sa, p); r.code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if r := add(sa, cert.pem); r.code != http.StatusConflict {
		t.Errorf("the same certificate twice: %d %s", r.code, r.raw)
	}
	if r := add(cs, other.pem); r.code != http.StatusConflict {
		t.Errorf("a certificate for a client_credentials account: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "POST", "/api/v1/service-accounts/"+sa+"/tokens", se.admin, map[string]any{"reason": "x"}, se.hdr()); r.code != http.StatusConflict {
		t.Errorf("a secret for an mTLS account: %d %s", r.code, r.raw)
	}
	cc := url.Values{"grant_type": {"client_credentials"}, "client_id": {sa}}

	// Through the ingress: the certificate in the trusted header.
	r = se.token(t, tokReq{form: cc, certPEM: cert.pem})
	access, _ := r.body["access_token"].(string)
	if r.code != 200 || access == "" {
		t.Fatalf("token over mTLS (ingress): %d %s", r.code, r.raw)
	}
	for name, q := range map[string]tokReq{
		"no certificate":      {form: cc},
		"another certificate": {form: cc, certPEM: other.pem},
		"another account":     {form: url.Values{"grant_type": {"client_credentials"}, "client_id": {cs}}, certPEM: cert.pem},
	} {
		if r := se.token(t, q); r.code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	// RFC 8705 §3: the token works only with its certificate.
	if r := se.bearer(t, "GET", "/api/v1/bus", access, cert.pem); r.code != 200 || fmt.Sprint(busOf(r)) != "[A A1]" {
		t.Fatalf("bound token with its certificate: %d %s", r.code, r.raw)
	}
	for name, p := range map[string]string{"without the certificate": "", "with another certificate": other.pem} {
		if r := se.bearer(t, "GET", "/api/v1/bus", access, p); r.code != http.StatusUnauthorized {
			t.Errorf("bound token %s: %d %s", name, r.code, r.raw)
		}
	}
	// The header is believed only from the ingress.
	se.g.Sessions.Network.Trusted = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if r := se.token(t, tokReq{form: cc, certPEM: cert.pem}); r.code != http.StatusUnauthorized {
		t.Fatalf("certificate header from an untrusted hop: %d %s", r.code, r.raw)
	}
	if r := se.bearer(t, "GET", "/api/v1/bus", access, cert.pem); r.code != http.StatusUnauthorized {
		t.Fatalf("bound token, certificate header from an untrusted hop: %d %s", r.code, r.raw)
	}

	// The gateway's own mTLS listener: the certificate from the handshake.
	ln := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		se.handler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	ln.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	ln.StartTLS()
	t.Cleanup(ln.Close)
	base := ln.Client().Transport.(*http.Transport)
	client := func(c *testCert) *http.Client {
		tr := base.Clone() // a new connection each time, with only this certificate
		if c != nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{c.tls}
		}
		return &http.Client{Transport: tr}
	}
	post := func(c *testCert) gwResp {
		req, _ := http.NewRequestWithContext(context.Background(), "POST", ln.URL+gateway.TokenPath, strings.NewReader(cc.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return send(t, client(c), req)
	}
	r = post(&cert)
	direct, _ := r.body["access_token"].(string)
	if r.code != 200 || direct == "" {
		t.Fatalf("token over the gateway's mTLS listener: %d %s", r.code, r.raw)
	}
	if r := post(nil); r.code != http.StatusUnauthorized {
		t.Fatalf("no client certificate: %d %s", r.code, r.raw)
	}
	if r := post(&other); r.code != http.StatusUnauthorized {
		t.Fatalf("an unregistered certificate: %d %s", r.code, r.raw)
	}
	get := func(c *testCert, tok string) gwResp {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", ln.URL+"/api/v1/bus", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		return send(t, client(c), req)
	}
	if r := get(&cert, direct); r.code != 200 {
		t.Fatalf("bound token over mTLS: %d %s", r.code, r.raw)
	}
	if r := get(&other, direct); r.code != http.StatusUnauthorized {
		t.Fatalf("bound token with another certificate: %d %s", r.code, r.raw)
	}

	// Revoking the certificate ends its tokens.
	cid := e.adminQuery("SELECT id FROM iam.sa_certificate WHERE service_account_id = '" + sa + "'")
	if r := se.do(t, "DELETE", "/api/v1/service-accounts/"+sa+"/certificates/"+cid+"?reason=key+rotation", se.admin, nil, se.hdr()); r.code != http.StatusNoContent {
		t.Fatalf("revoke certificate: %d %s", r.code, r.raw)
	}
	if r := get(&cert, direct); r.code != http.StatusUnauthorized {
		t.Fatalf("token of a revoked certificate: %d %s", r.code, r.raw)
	}
	if r := post(&cert); r.code != http.StatusUnauthorized {
		t.Fatalf("revoked certificate: %d %s", r.code, r.raw)
	}
	if a := e.adminQuery(`SELECT string_agg(payload->>'type', ',' ORDER BY id) FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' LIKE 'service_account.certificate%'`); a != "service_account.certificate_added,service_account.certificate_revoked" {
		t.Fatalf("certificate audit: %s", a)
	}
}
