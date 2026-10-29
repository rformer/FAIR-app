package tests

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/authn/saml/samltest"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-001 T-15 (AC-01, AC-04): SAML login end to end: the browser, the
// gateway, the iam service's SP, the test IdP, and the session.

// mfaSettings stands in for the settings client: auth.mfa_required_all
// and auth.mfa_required_privileged (T-18).
type mfaSettings struct{ all, privileged, jit bool }

func (m *mfaSettings) Bool(key, _ string) (bool, error) {
	switch key {
	case settings.KeyAuthMFAAll:
		return m.all, nil
	case settings.KeyAuthMFAPrivileged:
		return m.privileged, nil
	case settings.KeyAuthJIT:
		return m.jit, nil
	}
	return false, fmt.Errorf("unexpected setting %s", key)
}

type samlEnv struct {
	*gwEnv
	mfa    *mfaSettings
	iam    *authn.SAML
	idpKey samltest.Key
	idpID  string
	idpIss string
	client *http.Client
}

func samlFixture(t *testing.T, allowIDPInitiated bool) *samlEnv {
	t.Helper()
	ge := gatewayFixture(t)
	e := ge.e
	key, err := samltest.NewKey("test-idp")
	if err != nil {
		t.Fatal(err)
	}
	se := &samlEnv{gwEnv: ge, idpKey: key, idpIss: "https://idp.example.test/realms/fair"}
	md, _ := json.Marshal(map[string]any{"entity_id": se.idpIss, "sso_url": "https://idp.example.test/sso",
		"certificates": []string{key.CertPEM()}, "allow_idp_initiated": allowIDPInitiated})
	se.idpID = e.adminQuery("INSERT INTO iam.idp (kind, name, email_domains, metadata) VALUES ('saml', 'Test IdP', '{example.test}', '" +
		strings.ReplaceAll(string(md), "'", "''") + "') RETURNING id")
	e.mustOwner("UPDATE iam.app_user SET idp_id = '" + se.idpID + "', external_id = email WHERE email IN ('user@example.test', 'other@example.test')")

	// iam's ticket key; the gateway verifies with the same key set.
	ticketKeys := newJWTKeys(t)
	se.mfa = &mfaSettings{all: true, privileged: true}
	se.iam = &authn.SAML{Logins: authn.Logins{DB: e.appPool(), Origin: ge.url, Tickets: ticketKeys, Settings: se.mfa}}
	iam := httptest.NewServer(se.iam.Handler())
	t.Cleanup(iam.Close)
	u, _ := url.Parse(iam.URL)
	ge.g.Upstreams["iam"] = u
	ge.g.Tickets = ticketKeys
	ge.resetHandler(t)
	se.client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return se
}

// startLogin follows the SP-initiated redirect and returns the request ID.
func (se *samlEnv) startLogin(t *testing.T, returnTo string) string {
	t.Helper()
	resp, err := httpGet(se.client, se.url+"/api/v1/auth/saml/"+se.idpID+"/login?return="+url.QueryEscape(returnTo))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc == nil || loc.Host != "idp.example.test" {
		t.Fatalf("login redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	raw, err := base64.StdEncoding.DecodeString(loc.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	xmlReq, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(` ID="([^"]+)"`).FindSubmatch(xmlReq)
	if m == nil || !bytes.Contains(xmlReq, []byte(se.url+"/api/v1/auth/saml/"+se.idpID+"/acs")) {
		t.Fatalf("AuthnRequest %s", xmlReq)
	}
	return string(m[1])
}

func (se *samlEnv) response(req, nameID string) samltest.Response {
	return samltest.Good(time.Now().UTC(), se.url+"/api/v1/auth/saml/"+se.idpID+"/acs", se.url+"/api/v1/auth/saml", se.idpIss, req, nameID)
}

// post sends the IdP's auto-submitted form to the ACS, cross-site.
func (se *samlEnv) post(t *testing.T, encoded string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", se.url+"/api/v1/auth/saml/"+se.idpID+"/acs",
		strings.NewReader(url.Values{"SAMLResponse": {encoded}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.example.test")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := se.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func sessionCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == gateway.CookieName && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

func (se *samlEnv) build(t *testing.T, r samltest.Response) string {
	t.Helper()
	s, err := se.idpKey.Build(r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSAMLLoginEndToEnd(t *testing.T) {
	se := samlFixture(t, false)
	e := se.e
	audit := func(typ string) string {
		return e.adminQuery("SELECT coalesce(string_agg(coalesce(payload->>'reason', '') , '|' ORDER BY id), '') FROM iam.event_outbox WHERE topic = 'audit' AND payload->>'type' = '" + typ + "'")
	}

	// SP-initiated: the browser comes back signed in, at the page it asked for.
	req := se.startLogin(t, "/posture?tab=drift")
	encoded := se.build(t, se.response(req, "user@example.test"))
	resp := se.post(t, encoded, nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	cookie := sessionCookie(resp)
	if resp.StatusCode != 200 || cookie == "" || !strings.Contains(string(body), `url=/posture?tab=drift`) {
		t.Fatalf("ACS: %d cookie=%t %s", resp.StatusCode, cookie != "", body)
	}
	if h := resp.Header.Get(authn.TicketHeader); h != "" {
		t.Fatal("the login ticket reached the browser")
	}
	set := resp.Header.Get("Set-Cookie")
	for _, attr := range []string{"Path=/", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(set, attr) {
			t.Errorf("cookie lacks %s: %s", attr, set)
		}
	}
	me := se.do(t, "GET", "/api/v1/me", cookie, nil, nil)
	userID := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'user@example.test'")
	if me.code != 200 || me.body["user_id"] != userID || me.body["auth_method"] != "saml" {
		t.Fatalf("/me after SAML login: %d %s", me.code, me.raw)
	}
	if got := se.sessionRow(t, cookie, "mfa_evidence->>'saml_authn_context'"); got != samltest.MultiFactor {
		t.Fatalf("MFA evidence %q", got)
	}
	if audit("authn.login.success") != "" || e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'authn.login.success'") != "1" {
		t.Fatalf("success audit %q", audit("authn.login.success"))
	}

	// The same response again: refused (replay), no session.
	again := se.post(t, encoded, nil)
	_ = again.Body.Close()
	if again.StatusCode != 401 || sessionCookie(again) != "" {
		t.Fatalf("replayed response: %d", again.StatusCode)
	}
	// Unknown and disabled users, an XSW attack, IdP-initiated where not allowed.
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE email = 'other@example.test'")
	wrapped := se.response(se.startLogin(t, "/"), "user@example.test")
	wrapped.AfterSign = func(doc *etree.Document) {
		evil := samltest.Assertion(samltest.Response{Now: time.Now().UTC(), NameID: "admin@example.test", AssertionID: "_evil", Issuer: se.idpIss})
		doc.Root().AddChild(evil)
	}
	for name, enc := range map[string]string{
		"unknown user":  se.build(t, se.response(se.startLogin(t, "/"), "nobody@example.test")),
		"disabled user": se.build(t, se.response(se.startLogin(t, "/"), "other@example.test")),
		"XSW":           se.build(t, wrapped),
		"IdP-initiated": se.build(t, se.response("", "user@example.test")),
	} {
		r := se.post(t, enc, nil)
		_ = r.Body.Close()
		if r.StatusCode != 401 || sessionCookie(r) != "" {
			t.Errorf("%s: %d", name, r.StatusCode)
		}
	}
	denied := audit("authn.login.denied")
	for _, want := range []string{"not a pending request", "unknown user", "user disabled", "Assertion elements", "IdP-initiated"} {
		if !strings.Contains(denied, want) {
			t.Errorf("denied audit lacks %q: %s", want, denied)
		}
	}

	// Roles: iam cannot redeem tickets; the gateway cannot look users up.
	e.mustFail("app_rw", "SELECT iam.login_ticket_use(gen_random_uuid(), now())", "permission denied")
	e.mustFail("app_gateway", "SELECT * FROM iam.login_user(gen_random_uuid(), 'x')", "permission denied")
	e.mustFail("app_rw", "SELECT * FROM iam.idp", "permission denied")
}

// The gateway accepts a ticket only from iam's response, signed by iam,
// fresh, and once.
func TestLoginTicketRedemption(t *testing.T) {
	ge := gatewayFixture(t)
	userID := ge.e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'user@example.test'")
	iamKeys, foreign := newJWTKeys(t), newJWTKeys(t)
	var next string // the ticket the stand-in iam answers with
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(authn.TicketHeader) != "" {
			w.WriteHeader(http.StatusTeapot) // a ticket from the browser reached iam
			return
		}
		w.Header().Set(authn.TicketHeader, next)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(stub.Close)
	u, _ := url.Parse(stub.URL)
	ge.g.Upstreams["iam"] = u
	ge.g.Tickets = iamKeys
	ge.resetHandler(t)
	login := func(hdr map[string]string) gwResp {
		return ge.do(t, "POST", "/api/v1/auth/saml/"+"00000000-0000-4000-8000-000000000000/acs", "", nil, hdr)
	}
	good, err := authn.IssueTicket(iamKeys, authn.Ticket{UserID: userID, AuthMethod: "saml", ReturnTo: "//evil.example.test"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next = good
	r := login(nil)
	if r.code != 200 || !strings.Contains(r.hdr.Get("Set-Cookie"), "__Host-sid=") || !strings.Contains(r.raw, "url=/\"") {
		t.Fatalf("a good ticket: %d %s %q", r.code, r.raw, r.hdr.Get("Set-Cookie"))
	}
	// Once only.
	if r := login(nil); r.code != 401 || r.hdr.Get("Set-Cookie") != "" {
		t.Fatalf("a ticket redeemed twice: %d", r.code)
	}
	// Signed by another key, or expired.
	other, _ := authn.IssueTicket(foreign, authn.Ticket{UserID: userID, AuthMethod: "saml"}, time.Now())
	old, _ := authn.IssueTicket(iamKeys, authn.Ticket{UserID: userID, AuthMethod: "saml"}, time.Now().Add(-2*time.Minute))
	for name, tok := range map[string]string{"foreign signer": other, "expired": old, "garbage": "a.b.c"} {
		next = tok
		if r := login(nil); r.code != 401 || r.hdr.Get("Set-Cookie") != "" {
			t.Errorf("%s: %d", name, r.code)
		}
	}
	// A ticket the browser sends is stripped before iam sees it.
	next = ""
	if r := login(map[string]string{authn.TicketHeader: good}); r.code == http.StatusTeapot {
		t.Fatal("a ticket from the browser was forwarded")
	}
}

// newJWTKeys is a fresh ES256 key set (login tickets).
func newJWTKeys(t *testing.T) *authz.LocalKeys {
	t.Helper()
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(filepath.Join(dir, "iam-1.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := authz.LoadLocalKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// httpGet and httpPostForm are GET and form POST with a context.
func httpGet(c *http.Client, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", u, nil) // #nosec G704 -- test servers
	if err != nil {
		return nil, err
	}
	return c.Do(req) // #nosec G704 -- test servers
}

func httpPostForm(c *http.Client, u string, v url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), "POST", u, strings.NewReader(v.Encode())) // #nosec G704 -- test servers
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.Do(req) // #nosec G704 -- test servers
}
