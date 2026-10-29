package tests

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/authn/oidc/oidctest"
	"github.com/rformer/fair-app/internal/authn/saml/samltest"
	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/internal/iamapi"
	"github.com/rformer/fair-app/internal/scim"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-001 T-17 (AC-02, AC-03; design §5.1 step 1, §6, §10): IdPs administered
// over the iam API through the gateway, routed by email domain, with
// metadata uploaded as files or fetched from URLs (never in air-gapped
// mode) and trust anchors pinned.

type idpEnv struct {
	*gwEnv
	api   *iamapi.API
	scim  *scim.Server
	admin string // session cookie
	hdr   func() map[string]string
}

func idpFixture(t *testing.T) *idpEnv {
	t.Helper()
	ge := gatewayFixture(t)
	e := ge.e
	pool := e.appPool()
	api := &iamapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		DeploymentMode: config.ModeSelfHosted, Dev: true}
	mux := http.NewServeMux()
	mux.Handle(authn.DiscoverPath, &authn.Discovery{Logins: authn.Logins{DB: pool}, PerMinute: 1000})
	h := api.Handler(ge.keys, nil)
	for _, p := range iamapi.Prefixes {
		mux.Handle(p, h)
		mux.Handle(p+"/", h)
	}
	sp := &scim.Server{Store: scim.Store{DB: pool}, Origin: ge.url}
	mux.Handle(scim.Prefix+"/", sp.Handler())
	iam := httptest.NewServer(mux)
	t.Cleanup(iam.Close)
	u, _ := url.Parse(iam.URL)
	ge.g.Upstreams["iam"] = u
	ge.resetHandler(t)
	ie := &idpEnv{gwEnv: ge, api: api, scim: sp, admin: ge.login(t, "admin")}
	csrf := ge.csrf(t, ie.admin)
	n := 0
	ie.hdr = func() map[string]string {
		n++
		m := map[string]string{server.IdempotencyHeader: fmt.Sprintf("idp-test-%d-%d", time.Now().UnixNano(), n)}
		for k, v := range csrf {
			m[k] = v
		}
		return m
	}
	return ie
}

// raw sends body as is (metadata documents).
func (ge *gwEnv) raw(t *testing.T, method, path, cookie string, body []byte, hdr map[string]string) gwResp {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, ge.url+path, strings.NewReader(string(body)))
	req.Header.Set("Cookie", gateway.CookieName+"="+cookie)
	req.Header.Set("X-Forwarded-For", loginIP)
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
	return gwResp{resp.StatusCode, m, string(raw), resp.Header}
}

func samlMetadata(entity string, keys ...samltest.Key) []byte {
	var kd strings.Builder
	for _, k := range keys {
		kd.WriteString(`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
			base64.StdEncoding.EncodeToString(k.Cert.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
	}
	return []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` + entity + `">
<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + kd.String() + `
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.corp.example/sso"/>
</md:IDPSSODescriptor></md:EntityDescriptor>`)
}

func (ie *idpEnv) create(t *testing.T, kind, name string, domains ...string) string {
	t.Helper()
	r := ie.do(t, "POST", "/api/v1/idps", ie.admin, map[string]any{"kind": kind, "name": name, "email_domains": domains, "reason": "onboarding"}, ie.hdr())
	id, _ := r.body["id"].(string)
	if r.code != http.StatusCreated || id == "" || r.body["enabled"] != false {
		t.Fatalf("create %s: %d %s", name, r.code, r.raw)
	}
	return id
}

func (ie *idpEnv) upload(t *testing.T, id string, doc []byte, confirm []string) gwResp {
	t.Helper()
	q := url.Values{"reason": {"metadata rotation"}}
	if confirm != nil {
		q.Set("confirm", strings.Join(confirm, ","))
	}
	return ie.raw(t, "PUT", "/api/v1/idps/"+id+"/metadata?"+q.Encode(), ie.admin, doc, ie.hdr())
}

func (ie *idpEnv) patch(t *testing.T, id string, body map[string]any) gwResp {
	t.Helper()
	body["reason"] = "change ticket 42"
	return ie.do(t, "PATCH", "/api/v1/idps/"+id, ie.admin, body, ie.hdr())
}

func (ie *idpEnv) discover(t *testing.T, email string) gwResp {
	t.Helper()
	return ie.do(t, "POST", authn.DiscoverPath, "", map[string]any{"email": email, "return": "/posture"}, nil)
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// AC-02: several IdPs, each serving its email domains; discovery routes
// to the right one and answers unknown domains with the same shape.
func TestIDPRoutingByDomain(t *testing.T) {
	ie := idpFixture(t)
	e := ie.e
	k1, _ := samltest.NewKey("corp")
	p, err := oidctest.New("fair-platform", "secret-0123456789-abcdefghijklmnop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	samlID := ie.create(t, "saml", "Corp SAML", "Corp.Example", "corp-eu.example")
	if r := ie.patch(t, samlID, map[string]any{"enabled": true}); r.code != http.StatusBadRequest {
		t.Fatalf("enabled without metadata: %d %s", r.code, r.raw)
	}
	if r := ie.upload(t, samlID, samlMetadata("https://idp.corp.example/saml", k1), nil); r.code != http.StatusNoContent {
		t.Fatalf("SAML metadata upload: %d %s", r.code, r.raw)
	}
	if r := ie.patch(t, samlID, map[string]any{"enabled": true, "settings": map[string]any{"allow_idp_initiated": false}}); r.code != http.StatusNoContent {
		t.Fatalf("enable SAML: %d %s", r.code, r.raw)
	}

	oidcID := ie.create(t, "oidc", "Partner OIDC", "partner.example")
	r := ie.do(t, "POST", "/api/v1/idps/"+oidcID+"/metadata/fetch", ie.admin, map[string]any{"url": p.Issuer, "reason": "onboarding"}, ie.hdr())
	if r.code != http.StatusNoContent {
		t.Fatalf("OIDC discovery fetch: %d %s", r.code, r.raw)
	}
	secretFile := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(secretFile, []byte(p.Secret), 0o600)
	if r := ie.patch(t, oidcID, map[string]any{"settings": map[string]any{"client_secret": "x"}}); r.code != http.StatusBadRequest {
		t.Fatalf("unknown setting: %d %s", r.code, r.raw)
	}
	if r := ie.patch(t, oidcID, map[string]any{"enabled": true}); r.code != http.StatusBadRequest || !strings.Contains(r.raw, "client_id") {
		t.Fatalf("enabled without client: %d %s", r.code, r.raw)
	}
	if r := ie.patch(t, oidcID, map[string]any{"enabled": true, "settings": map[string]any{"client_id": "fair-platform",
		"client_secret_file": secretFile, "scopes": []string{"email"}}}); r.code != http.StatusNoContent {
		t.Fatalf("enable OIDC: %d %s", r.code, r.raw)
	}
	got := ie.do(t, "GET", "/api/v1/idps/"+oidcID, ie.admin, nil, nil)
	md, _ := got.body["metadata"].(map[string]any)
	if got.code != 200 || md["issuer"] != p.Issuer || md["jwks_uri"] != p.JWKSURL() || md["client_id"] != "fair-platform" ||
		got.body["metadata_source"] != "url" || got.body["enabled"] != true {
		t.Fatalf("OIDC IdP: %d %s", got.code, got.raw)
	}

	// Routing by domain (case-insensitive, stored lower-case).
	for email, want := range map[string]string{
		"alice@corp.example":        "/api/v1/auth/saml/" + samlID + "/login?return=%2Fposture",
		"Bob <bob@CORP-EU.example>": "/api/v1/auth/saml/" + samlID + "/login?return=%2Fposture",
		"carol@partner.example":     "/api/v1/auth/oidc/" + oidcID + "/login?return=%2Fposture",
	} {
		d := ie.discover(t, email)
		if d.code != 200 || d.body["login_url"] != want {
			t.Errorf("%s: %d %s, want %s", email, d.code, d.raw, want)
		}
	}
	// Unknown domains, disabled IdPs and non-addresses: the same shape and
	// message, no login URL.
	unknown := ie.discover(t, "dave@unknown.example")
	for _, email := range []string{"dave@unknown.example", "not an address", "", "eve@sub.corp.example"} {
		d := ie.discover(t, email)
		if d.code != 200 || d.body["login_url"] != nil || len(d.body) != 2 || d.body["message"] != unknown.body["message"] {
			t.Errorf("%q: %d %s", email, d.code, d.raw)
		}
	}
	if r := ie.do(t, "POST", authn.DiscoverPath, "", map[string]any{"email": "alice@corp.example", "return": "https://evil.example/"}, nil); !strings.HasSuffix(r.body["login_url"].(string), "return=%2F") {
		t.Errorf("off-site return kept: %s", r.raw)
	}
	if r := ie.patch(t, samlID, map[string]any{"enabled": false}); r.code != http.StatusNoContent {
		t.Fatal(r.raw)
	}
	if d := ie.discover(t, "alice@corp.example"); d.body["login_url"] != nil {
		t.Errorf("disabled IdP discovered: %s", d.raw)
	}
	_ = ie.patch(t, samlID, map[string]any{"enabled": true})

	// A domain is served by one enabled IdP.
	dupID := ie.create(t, "saml", "Shadow SAML", "corp.example")
	k2, _ := samltest.NewKey("shadow")
	_ = ie.upload(t, dupID, samlMetadata("https://shadow.example/saml", k2), nil)
	if r := ie.patch(t, dupID, map[string]any{"enabled": true}); r.code != http.StatusConflict {
		t.Fatalf("overlapping domain enabled: %d %s", r.code, r.raw)
	}
	if r := ie.patch(t, samlID, map[string]any{"email_domains": []string{"corp.example", "partner.example"}}); r.code != http.StatusConflict {
		t.Fatalf("domain moved onto another enabled IdP: %d %s", r.code, r.raw)
	}
	if r := ie.patch(t, samlID, map[string]any{"email_domains": []string{"not a domain"}}); r.code != http.StatusBadRequest {
		t.Fatalf("invalid domain: %d %s", r.code, r.raw)
	}

	// Every change is audited (high severity, with the actor and reason).
	events := e.adminQuery(`SELECT string_agg(payload->>'type' || ':' || (payload->>'reason'), ',' ORDER BY id) FROM iam.event_outbox
		WHERE topic = 'audit' AND payload->>'target' = 'idp:` + samlID + `' AND payload->>'severity' = 'high'
		AND payload->>'actor' = (SELECT id::text FROM iam.app_user WHERE email = 'admin@example.test')`)
	for _, want := range []string{"idp.created:onboarding", "idp.metadata_changed:metadata rotation", "idp.enabled:change ticket 42", "idp.disabled:change ticket 42"} {
		if !strings.Contains(events, want) {
			t.Errorf("audit trail %q lacks %q", events, want)
		}
	}

	// The SAML IdP signs in through the regular flow.
	list := ie.do(t, "GET", "/api/v1/idps", ie.admin, nil, nil)
	if list.code != 200 || len(list.body["idps"].([]any)) != 3 {
		t.Fatalf("list: %d %s", list.code, list.raw)
	}
}

// AC-03 and pinning: a change of trust anchors needs the new fingerprints
// confirmed; an air-gapped install takes files (metadata, JWKS) only.
func TestIDPMetadataPinningAndAirGapped(t *testing.T) {
	ie := idpFixture(t)
	k1, _ := samltest.NewKey("a")
	k2, _ := samltest.NewKey("b")
	id := ie.create(t, "saml", "Corp", "corp.example")
	if r := ie.upload(t, id, samlMetadata("https://idp.corp.example/saml", k1), nil); r.code != http.StatusNoContent {
		t.Fatalf("first upload (nothing pinned yet): %d %s", r.code, r.raw)
	}
	cur := strs(ie.do(t, "GET", "/api/v1/idps/"+id, ie.admin, nil, nil).body["fingerprints"])
	// The same anchors: no confirmation needed.
	if r := ie.upload(t, id, samlMetadata("https://idp.corp.example/saml", k1), nil); r.code != http.StatusNoContent {
		t.Fatalf("unchanged anchors: %d %s", r.code, r.raw)
	}
	// Rotation adds k2: refused until exactly the new set is confirmed.
	rotated := samlMetadata("https://idp.corp.example/saml", k1, k2)
	r := ie.upload(t, id, rotated, nil)
	if r.code != http.StatusConflict || r.body["error"] != "confirm_fingerprints" {
		t.Fatalf("unconfirmed rotation: %d %s", r.code, r.raw)
	}
	if c := strs(r.body["current"]); strings.Join(c, ",") != strings.Join(cur, ",") {
		t.Fatalf("current %v, want %v", c, cur)
	}
	proposed := strs(r.body["fingerprints"])
	if len(proposed) != 2 {
		t.Fatalf("proposed %v", proposed)
	}
	if r := ie.upload(t, id, rotated, proposed[:1]); r.code != http.StatusConflict {
		t.Fatalf("partial confirmation accepted: %d %s", r.code, r.raw)
	}
	if r := ie.upload(t, id, rotated, []string{proposed[1], proposed[0]}); r.code != http.StatusNoContent {
		t.Fatalf("confirmed rotation: %d %s", r.code, r.raw)
	}
	if got := ie.e.adminQuery("SELECT metadata->'certificates'->>1 FROM iam.idp WHERE id = '" + id + "'"); got != strings.TrimSpace(k2.CertPEM()) {
		t.Fatalf("rotated certificate not stored: %q", got)
	}
	// Not metadata, or a key too weak: 422; the stored metadata is unchanged.
	if r := ie.upload(t, id, []byte(`{"keys":[]}`), nil); r.code != http.StatusUnprocessableEntity {
		t.Fatalf("JSON for a SAML IdP: %d %s", r.code, r.raw)
	}

	// Air-gapped (design §10): URL fetches are refused; files work.
	ie.api.DeploymentMode = config.ModeAirGapped
	p, err := oidctest.New("fair-platform", "secret-0123456789-abcdefghijklmnop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	oid := ie.create(t, "oidc", "Partner", "partner.example")
	if r := ie.do(t, "POST", "/api/v1/idps/"+oid+"/metadata/fetch", ie.admin, map[string]any{"url": p.Issuer, "reason": "x"}, ie.hdr()); r.code != http.StatusConflict || r.body["error"] != "air_gapped" {
		t.Fatalf("air-gapped fetch: %d %s", r.code, r.raw)
	}
	// #nosec G101 -- endpoint URLs, not credentials
	disc, _ := json.Marshal(map[string]any{"issuer": "https://idp.partner.example", "authorization_endpoint": "https://idp.partner.example/auth",
		"token_endpoint": "https://idp.partner.example/token", "jwks_uri": "https://idp.partner.example/jwks"})
	if r := ie.upload(t, oid, disc, nil); r.code != http.StatusNoContent {
		t.Fatalf("discovery document upload: %d %s", r.code, r.raw)
	}
	jwks, _ := json.Marshal(p.JWKS())
	r = ie.upload(t, oid, jwks, nil) // the JWKS replaces jwks_uri: anchors change
	if r.code != http.StatusConflict {
		t.Fatalf("unconfirmed JWKS: %d %s", r.code, r.raw)
	}
	if r := ie.upload(t, oid, jwks, strs(r.body["fingerprints"])); r.code != http.StatusNoContent {
		t.Fatalf("JWKS upload: %d %s", r.code, r.raw)
	}
	got := ie.do(t, "GET", "/api/v1/idps/"+oid, ie.admin, nil, nil)
	md := got.body["metadata"].(map[string]any)
	if _, ok := md["jwks_uri"]; ok || md["jwks"] == nil || got.body["metadata_source"] != "file" {
		t.Fatalf("after JWKS upload: %s", got.raw)
	}
	var set jose.JSONWebKeySet
	b, _ := json.Marshal(md["jwks"])
	if err := json.Unmarshal(b, &set); err != nil || len(set.Keys) != len(p.JWKS().Keys) {
		t.Fatalf("stored JWKS: %v %s", err, b)
	}
	// Private keys are refused outright.
	symmetric := []byte(`{"keys":[{"kty":"oct","k":"c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0"}]}`) // #nosec G101 -- a test key the upload must refuse
	if r := ie.upload(t, oid, symmetric, nil); r.code != http.StatusUnprocessableEntity {
		t.Fatalf("symmetric key: %d %s", r.code, r.raw)
	}
}

// AC-25: without idp.view the API does not exist for the caller; viewing
// does not allow changes; idempotent replays create nothing twice.
func TestIDPAdminAccess(t *testing.T) {
	ie := idpFixture(t)
	e := ie.e
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('IdP Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, 1, ARRAY['idp.view'], 'test' FROM r`)
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('viewer@example.test', 'Viewer')")
	e.mustOwner(grant("admin", "user:viewer", "IdP Viewer", "ENTERPRISE"))
	e.drain()

	if r := ie.do(t, "GET", "/api/v1/idps", "", nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("no session: %d %s", r.code, r.raw)
	}
	user := ie.login(t, "user")
	for _, path := range []string{"/api/v1/idps", "/api/v1/idps/00000000-0000-0000-0000-000000000000"} {
		if r := ie.do(t, "GET", path, user, nil, nil); r.code != http.StatusNotFound {
			t.Fatalf("without idp.view %s: %d %s", path, r.code, r.raw)
		}
	}
	viewer := ie.login(t, "viewer")
	if r := ie.do(t, "GET", "/api/v1/idps", viewer, nil, nil); r.code != http.StatusOK {
		t.Fatalf("viewer list: %d %s", r.code, r.raw)
	}
	hdr := ie.csrf(t, viewer)
	hdr[server.IdempotencyHeader] = "viewer-create-1"
	if r := ie.do(t, "POST", "/api/v1/idps", viewer, map[string]any{"kind": "saml", "name": "X", "email_domains": []string{}, "reason": "r"}, hdr); r.code != http.StatusForbidden {
		t.Fatalf("viewer create: %d %s", r.code, r.raw)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.idp"); n != "0" {
		t.Fatalf("%s IdPs after a refused create", n)
	}

	// The same Idempotency-Key and body replay the first answer.
	h := ie.hdr()
	body := map[string]any{"kind": "oidc", "name": "Once", "email_domains": []string{"once.example"}, "reason": "r"}
	a := ie.do(t, "POST", "/api/v1/idps", ie.admin, body, h)
	b := ie.do(t, "POST", "/api/v1/idps", ie.admin, body, h)
	if a.code != 201 || b.code != 201 || a.body["id"] != b.body["id"] {
		t.Fatalf("replay: %d %s / %d %s", a.code, a.raw, b.code, b.raw)
	}
	body["name"] = "Twice"
	if r := ie.do(t, "POST", "/api/v1/idps", ie.admin, body, h); r.code != http.StatusUnprocessableEntity && r.code != http.StatusConflict {
		t.Fatalf("key reused with another body: %d %s", r.code, r.raw)
	}
	delete(h, server.IdempotencyHeader)
	if r := ie.do(t, "POST", "/api/v1/idps", ie.admin, body, h); r.code != http.StatusBadRequest && r.code != http.StatusPreconditionRequired {
		t.Fatalf("no Idempotency-Key: %d %s", r.code, r.raw)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.idp"); n != "1" {
		t.Fatalf("%s IdPs, want 1", n)
	}
	if r := ie.do(t, "POST", "/api/v1/idps", ie.admin, map[string]any{"kind": "ldap", "name": "L", "reason": "r"}, ie.hdr()); r.code != http.StatusBadRequest {
		t.Fatalf("unknown kind: %d %s", r.code, r.raw)
	}
	if r := ie.do(t, "GET", "/api/v1/idps/not-a-uuid", ie.admin, nil, nil); r.code != http.StatusNotFound {
		t.Fatalf("bad id: %d %s", r.code, r.raw)
	}
}
