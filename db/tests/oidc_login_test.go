package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/authn/oidc/oidctest"
)

// F-001 T-16 (AC-01, AC-04): OIDC login end to end: the browser, the
// gateway, the iam service's relying party, the test provider and the
// session.

type oidcEnv struct {
	*gwEnv
	mfa    *mfaSettings
	p      *oidctest.Provider
	idpID  string
	client *http.Client
}

func oidcFixture(t *testing.T) *oidcEnv {
	t.Helper()
	ge := gatewayFixture(t)
	e := ge.e
	secret := "client-secret-0123456789-abcdefghijklmnop"
	p, err := oidctest.New("fair-platform", secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	secretFile := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	md, _ := json.Marshal(map[string]any{"issuer": p.Issuer, "authorization_endpoint": p.AuthURL(), "token_endpoint": p.TokenURL(),
		"jwks_uri": p.JWKSURL(), "client_id": "fair-platform", "client_secret_file": secretFile, "scopes": []string{"email"}})
	oe := &oidcEnv{gwEnv: ge, p: p, mfa: &mfaSettings{all: true, privileged: true}}
	oe.idpID = e.adminQuery("INSERT INTO iam.idp (kind, name, metadata) VALUES ('oidc', 'Test OIDC', '" +
		strings.ReplaceAll(string(md), "'", "''") + "') RETURNING id")
	e.mustOwner("UPDATE iam.app_user SET idp_id = '" + oe.idpID + "', external_id = email WHERE email IN ('user@example.test', 'other@example.test')")

	keys := newJWTKeys(t)
	rp := &authn.OIDC{Logins: authn.Logins{DB: e.appPool(), Origin: ge.url, Tickets: keys, Settings: oe.mfa}, HTTP: p.Server.Client()}
	iam := httptest.NewServer(rp.Handler())
	t.Cleanup(iam.Close)
	u, _ := url.Parse(iam.URL)
	ge.g.Upstreams["iam"] = u
	ge.g.Tickets = keys
	ge.resetHandler(t)
	oe.client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return oe
}

// signIn starts at the platform, signs in at the provider as subject and
// returns the callback's response.
func (oe *oidcEnv) signIn(t *testing.T, subject, returnTo string, extra map[string]any) (*http.Response, string) {
	t.Helper()
	start, err := httpGet(oe.client, oe.url+"/api/v1/auth/oidc/"+oe.idpID+"/login?return="+url.QueryEscape(returnTo))
	if err != nil {
		t.Fatal(err)
	}
	_ = start.Body.Close()
	loc := start.Header.Get("Location")
	if start.StatusCode != http.StatusFound || !strings.HasPrefix(loc, oe.p.AuthURL()) {
		t.Fatalf("login redirect: %d %q", start.StatusCode, loc)
	}
	if !strings.Contains(loc, "redirect_uri="+url.QueryEscape(oe.url+"/api/v1/auth/oidc/"+oe.idpID+"/callback")) {
		t.Fatalf("redirect_uri in %s", loc)
	}
	code, state, err := oe.p.Authorize(loc, subject, extra)
	if err != nil {
		t.Fatal(err)
	}
	cb := oe.url + "/api/v1/auth/oidc/" + oe.idpID + "/callback?" + url.Values{"code": {code}, "state": {state}}.Encode()
	resp, err := httpGet(oe.client, cb)
	if err != nil {
		t.Fatal(err)
	}
	return resp, cb
}

func TestOIDCLoginEndToEnd(t *testing.T) {
	oe := oidcFixture(t)
	e := oe.e
	resp, cb := oe.signIn(t, "user@example.test", "/posture", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	cookie := sessionCookie(resp)
	if resp.StatusCode != 200 || cookie == "" || !strings.Contains(string(body), "url=/posture") || resp.Header.Get(authn.TicketHeader) != "" {
		t.Fatalf("callback: %d cookie=%t %s", resp.StatusCode, cookie != "", body)
	}
	me := oe.do(t, "GET", "/api/v1/me", cookie, nil, nil)
	if me.code != 200 || me.body["auth_method"] != "oidc" {
		t.Fatalf("/me: %d %s", me.code, me.raw)
	}
	if got := oe.sessionRow(t, cookie, "mfa_evidence->'oidc_amr'"); got != `["pwd", "mfa"]` {
		t.Fatalf("MFA evidence %q", got)
	}

	// The same callback again (state spent), unknown and disabled users, the
	// IdP's error, and a token with another nonce: no session.
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE email = 'other@example.test'")
	again, err := httpGet(oe.client, cb)
	if err != nil {
		t.Fatal(err)
	}
	_ = again.Body.Close()
	if again.StatusCode != 401 || sessionCookie(again) != "" {
		t.Fatalf("callback replayed: %d", again.StatusCode)
	}
	for name, run := range map[string]func() *http.Response{
		"unknown user":  func() *http.Response { r, _ := oe.signIn(t, "nobody@example.test", "/", nil); return r },
		"disabled user": func() *http.Response { r, _ := oe.signIn(t, "other@example.test", "/", nil); return r },
		"nonce changed": func() *http.Response {
			oe.p.Claims = func(c map[string]any) { c["nonce"] = "attacker" }
			defer func() { oe.p.Claims = nil }()
			r, _ := oe.signIn(t, "user@example.test", "/", nil)
			return r
		},
		"IdP error": func() *http.Response {
			start, _ := httpGet(oe.client, oe.url+"/api/v1/auth/oidc/"+oe.idpID+"/login")
			_ = start.Body.Close()
			_, state, _ := oe.p.Authorize(start.Header.Get("Location"), "user@example.test", nil)
			r, _ := httpGet(oe.client, oe.url+"/api/v1/auth/oidc/"+oe.idpID+"/callback?"+url.Values{"error": {"access_denied"}, "state": {state}}.Encode())
			return r
		},
	} {
		r := run()
		_ = r.Body.Close()
		if r.StatusCode != 401 || sessionCookie(r) != "" {
			t.Errorf("%s: %d", name, r.StatusCode)
		}
	}
	denied := e.adminQuery("SELECT string_agg(payload->>'reason', '|' ORDER BY id) FROM iam.event_outbox WHERE payload->>'type' = 'authn.login.denied'")
	for _, want := range []string{"unknown, used or expired state", "unknown user", "user disabled", "nonce mismatch", `"access_denied"`} {
		if !strings.Contains(denied, want) {
			t.Errorf("denied audit lacks %q: %s", want, denied)
		}
	}
	// The client secret never reaches the database.
	if got := e.adminQuery("SELECT count(*) FROM iam.idp WHERE metadata::text LIKE '%client-secret-0123456789%'"); got != "0" {
		t.Fatal("the client secret is stored")
	}
	e.mustFail("app_gateway", "SELECT * FROM iam.oidc_state_consume(gen_random_uuid(), 'x')", "permission denied")
}
