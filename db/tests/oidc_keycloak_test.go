package tests

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// F-001 T-16 (AC-01): live OIDC interop with Keycloak (started by
// scripts/sso-e2e-keycloak.sh): a confidential client requiring PKCE S256,
// configured from the realm's discovery document; a user signs in through
// Keycloak's form, the gateway and the iam service.
func TestOIDCKeycloakInterop(t *testing.T) {
	kc := os.Getenv("FAIR_TEST_KEYCLOAK")
	if kc == "" {
		t.Skip("FAIR_TEST_KEYCLOAK not set (scripts/sso-e2e-keycloak.sh)")
	}
	oe := oidcFixture(t)
	e := oe.e
	realm := "oidc" + strings.ToLower(e.db[len(e.db)-6:])
	redirect := oe.url + "/api/v1/auth/oidc/" + oe.idpID + "/callback"
	secret := "kc-client-secret-0123456789-abcdefghij"
	admin := keycloakAdmin(t, kc)
	admin.do(t, "POST", "/admin/realms", map[string]any{"realm": realm, "enabled": true})
	t.Cleanup(func() { admin.do(t, "DELETE", "/admin/realms/"+realm, nil) })
	admin.do(t, "POST", "/admin/realms/"+realm+"/clients", map[string]any{
		"clientId": "fair-platform", "protocol": "openid-connect", "enabled": true, "publicClient": false, "secret": secret,
		"standardFlowEnabled": true, "directAccessGrantsEnabled": false, "redirectUris": []string{redirect},
		"attributes": map[string]string{"pkce.code.challenge.method": "S256"},
	})
	admin.do(t, "POST", "/admin/realms/"+realm+"/users", map[string]any{
		"username": "user", "email": "user@example.test", "firstName": "Test", "lastName": "User", "enabled": true, "emailVerified": true,
		"credentials": []map[string]any{{"type": "password", "value": "interop-Pa55word", "temporary": false}},
	})

	// Configure the platform's IdP from discovery; users are matched by email.
	var disc map[string]any
	if err := json.Unmarshal([]byte(admin.get(t, "/realms/"+realm+"/.well-known/openid-configuration")), &disc); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(t.TempDir(), "kc-secret")
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	md, _ := json.Marshal(map[string]any{"issuer": disc["issuer"], "authorization_endpoint": disc["authorization_endpoint"],
		"token_endpoint": disc["token_endpoint"], "jwks_uri": disc["jwks_uri"], "client_id": "fair-platform",
		"client_secret_file": secretFile, "scopes": []string{"email"}, "subject_claim": "email"})
	e.mustOwner("UPDATE iam.idp SET kind = 'keycloak', metadata = '" + strings.ReplaceAll(string(md), "'", "''") + "' WHERE id = '" + oe.idpID + "'")

	// T-18 (AC-05): a password-only login is not MFA, so while MFA is
	// required (the default) it is denied and audited; with MFA required of
	// privileged users only, this user signs in.
	if code, cookie, _ := oe.keycloakLogin(t, redirect); code != http.StatusUnauthorized || cookie != "" {
		t.Fatalf("a login without MFA: %d", code)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'authn.mfa_missing'"); got != "1" {
		t.Fatalf("%s logins without MFA audited", got)
	}
	oe.mfa.all = false
	code, cookie, body := oe.keycloakLogin(t, redirect)
	if code != 200 || cookie == "" || !strings.Contains(body, "url=/posture") {
		t.Fatalf("callback: %d cookie=%t %s", code, cookie != "", body)
	}
	me := oe.do(t, "GET", "/api/v1/me", cookie, nil, nil)
	if me.code != 200 || me.body["auth_method"] != "oidc" {
		t.Fatalf("/me: %d %s", me.code, me.raw)
	}
}

// keycloakLogin signs in through Keycloak's form in a fresh browser and
// returns the platform's answer to the callback: status, session cookie
// and body.
func (oe *oidcEnv) keycloakLogin(t *testing.T, redirect string) (int, string, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), oe.url) {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	start, err := httpGet(oe.client, oe.url+"/api/v1/auth/oidc/"+oe.idpID+"/login?return=%2Fposture")
	if err != nil {
		t.Fatal(err)
	}
	_ = start.Body.Close()
	page := getPage(t, browser, start.Header.Get("Location"))
	action := regexp.MustCompile(`<form id="kc-form-login"[^>]*action="([^"]+)"`).FindStringSubmatch(page)
	if action == nil {
		t.Fatalf("no Keycloak login form:\n%.600s", page)
	}
	back, err := httpPostForm(browser, html.UnescapeString(action[1]), url.Values{"username": {"user"}, "password": {"interop-Pa55word"}, "credentialId": {""}})
	if err != nil {
		t.Fatal(err)
	}
	_ = back.Body.Close()
	cb := back.Header.Get("Location")
	if back.StatusCode != http.StatusFound || !strings.HasPrefix(cb, redirect+"?") {
		t.Fatalf("Keycloak redirect: %d %q", back.StatusCode, cb)
	}
	resp, err := httpGet(oe.client, cb)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, sessionCookie(resp), string(body)
}
