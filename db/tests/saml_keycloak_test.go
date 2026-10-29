package tests

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// F-001 T-15 (AC-01): live interop with Keycloak, the IdP the platform
// bundles for self-hosted installs. scripts/sso-e2e-keycloak.sh starts
// Keycloak and sets FAIR_TEST_KEYCLOAK; the test configures a realm, a SAML
// client and a user through Keycloak's admin API, then signs in as a browser
// would, SP- and IdP-initiated, through the gateway and the iam service.
func TestSAMLKeycloakInterop(t *testing.T) {
	kc := os.Getenv("FAIR_TEST_KEYCLOAK") // e.g. http://keycloak:8080
	if kc == "" {
		t.Skip("FAIR_TEST_KEYCLOAK not set (scripts/sso-e2e-keycloak.sh)")
	}
	se := samlFixture(t, true)
	e := se.e
	realm := "fair" + strings.ToLower(e.db[len(e.db)-6:]) // a realm per run
	spEntity, acs := se.url+"/api/v1/auth/saml", se.url+"/api/v1/auth/saml/"+se.idpID+"/acs"
	admin := keycloakAdmin(t, kc)

	admin.do(t, "POST", "/admin/realms", map[string]any{"realm": realm, "enabled": true})
	t.Cleanup(func() { admin.do(t, "DELETE", "/admin/realms/"+realm, nil) })
	admin.do(t, "POST", "/admin/realms/"+realm+"/clients", map[string]any{
		"clientId": spEntity, "protocol": "saml", "enabled": true, "redirectUris": []string{acs}, "frontchannelLogout": false,
		"attributes": map[string]string{
			"saml.assertion.signature": "true", "saml.server.signature": "true", "saml.signature.algorithm": "RSA_SHA256",
			"saml.client.signature": "false", "saml_name_id_format": "email", "saml.force.name.id.format": "true",
			"saml_assertion_consumer_url_post": acs, "saml_idp_initiated_sso_url_name": "fair",
		},
	})
	admin.do(t, "POST", "/admin/realms/"+realm+"/users", map[string]any{
		"username": "user", "email": "user@example.test", "firstName": "Test", "lastName": "User", "enabled": true, "emailVerified": true,
		"credentials": []map[string]any{{"type": "password", "value": "interop-Pa55word", "temporary": false}},
	})

	// The realm's IdP metadata becomes the platform's IdP configuration.
	descriptor := admin.get(t, "/realms/"+realm+"/protocol/saml/descriptor")
	cert := regexp.MustCompile(`<ds:X509Certificate>([^<]+)</ds:X509Certificate>`).FindStringSubmatch(descriptor)
	sso := regexp.MustCompile(`Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="([^"]+)"`).FindStringSubmatch(descriptor)
	entity := regexp.MustCompile(`entityID="([^"]+)"`).FindStringSubmatch(descriptor)
	if cert == nil || sso == nil || entity == nil {
		t.Fatalf("descriptor %s", descriptor)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(cert[1]), ""))
	if err != nil {
		t.Fatal(err)
	}
	md, _ := json.Marshal(map[string]any{"entity_id": entity[1], "sso_url": html.UnescapeString(sso[1]),
		"certificates": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, "allow_idp_initiated": true})
	e.mustOwner("UPDATE iam.idp SET metadata = '" + strings.ReplaceAll(string(md), "'", "''") + "' WHERE id = '" + se.idpID + "'")

	// SP-initiated: the platform's login, Keycloak's form, back through the ACS.
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), se.url) {
			return http.ErrUseLastResponse // stop at the platform; cookies are checked by hand
		}
		return nil
	}}
	startLogin := func() string {
		start, err := httpGet(se.client, se.url+"/api/v1/auth/saml/"+se.idpID+"/login?return=%2Fposture")
		if err != nil {
			t.Fatal(err)
		}
		loc := start.Header.Get("Location")
		_ = start.Body.Close()
		if start.StatusCode != http.StatusFound || !strings.HasPrefix(loc, kc) {
			t.Fatalf("login redirect: %d %q", start.StatusCode, loc)
		}
		return loc
	}
	// T-18 (AC-05): a password-only login is not MFA, so while MFA is
	// required (the default) it is denied and audited.
	se.keycloakLogin(t, browser, startLogin(), "")
	if got := e.adminQuery("SELECT payload->'attributes'->>'authn_context' FROM iam.event_outbox WHERE payload->>'type' = 'authn.mfa_missing'"); got == "" {
		t.Fatal("the login without MFA was not audited")
	}
	// With MFA required of privileged users only, this user signs in.
	se.mfa.all = false
	jar1, _ := cookiejar.New(nil)
	browser.Jar = jar1
	cookie := se.keycloakLogin(t, browser, startLogin(), "/posture")
	me := se.do(t, "GET", "/api/v1/me", cookie, nil, nil)
	if me.code != 200 || me.body["auth_method"] != "saml" {
		t.Fatalf("/me after Keycloak login: %d %s", me.code, me.raw)
	}

	// IdP-initiated (the realm's SSO URL for the client), a fresh browser.
	jar2, _ := cookiejar.New(nil)
	browser.Jar = jar2
	cookie2 := se.keycloakLogin(t, browser, kc+"/realms/"+realm+"/protocol/saml/clients/fair", "/")
	if cookie2 == "" || cookie2 == cookie {
		t.Fatal("IdP-initiated login gave no new session")
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'authn.login.success'"); got != "2" {
		t.Fatalf("%s successful logins audited", got)
	}
}

// keycloakLogin fills Keycloak's login form at u and posts the SAML
// response to the ACS; it returns the platform's session cookie. With
// wantReturn "" the login must be refused.
func (se *samlEnv) keycloakLogin(t *testing.T, browser *http.Client, u, wantReturn string) string {
	t.Helper()
	page := getPage(t, browser, u)
	action := regexp.MustCompile(`<form id="kc-form-login"[^>]*action="([^"]+)"`).FindStringSubmatch(page)
	if action == nil {
		t.Fatalf("no Keycloak login form at %s:\n%.600s", u, page)
	}
	resp, err := httpPostForm(browser, html.UnescapeString(action[1]), url.Values{"username": {"user"}, "password": {"interop-Pa55word"}, "credentialId": {""}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	post := regexp.MustCompile(`<form name="saml-post-binding" method="post" action="([^"]+)"`).FindStringSubmatch(string(body))
	samlResp := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`).FindStringSubmatch(string(body))
	if post == nil || samlResp == nil {
		t.Fatalf("no SAML POST form after login:\n%.800s", body)
	}
	if got := html.UnescapeString(post[1]); got != se.url+"/api/v1/auth/saml/"+se.idpID+"/acs" {
		t.Fatalf("Keycloak posts to %q", got)
	}
	acsResp := se.post(t, html.UnescapeString(samlResp[1]), map[string]string{"Origin": strings.TrimSuffix(os.Getenv("FAIR_TEST_KEYCLOAK"), "/")})
	page2, _ := io.ReadAll(acsResp.Body)
	_ = acsResp.Body.Close()
	c := sessionCookie(acsResp)
	if wantReturn == "" {
		if acsResp.StatusCode != http.StatusUnauthorized || c != "" {
			t.Fatalf("ACS accepted a login it must refuse: %d %s", acsResp.StatusCode, page2)
		}
		return ""
	}
	if acsResp.StatusCode != 200 || c == "" || !strings.Contains(string(page2), "url="+wantReturn+`"`) {
		t.Fatalf("ACS: %d cookie=%t %s", acsResp.StatusCode, c != "", page2)
	}
	return c
}

func getPage(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	resp, err := httpGet(c, u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

type kcAdmin struct {
	base, token string
}

func keycloakAdmin(t *testing.T, base string) kcAdmin {
	t.Helper()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	for i := 0; ; i++ {
		resp, err := httpPostForm(http.DefaultClient, base+"/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"},
			"client_id": {"admin-cli"}, "username": {"admin"}, "password": {os.Getenv("FAIR_TEST_KEYCLOAK_ADMIN_PASSWORD")}})
		if err == nil && resp.StatusCode == 200 {
			_ = json.NewDecoder(resp.Body).Decode(&tok)
			_ = resp.Body.Close()
			break
		}
		if i > 60 {
			t.Fatalf("Keycloak admin token: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	return kcAdmin{base: base, token: tok.AccessToken}
}

func (k kcAdmin) do(t *testing.T, method, path string, body any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, k.base+path, rd)
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- the test Keycloak
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("Keycloak %s %s: %d %s", method, path, resp.StatusCode, b)
	}
}

func (k kcAdmin) get(t *testing.T, path string) string {
	t.Helper()
	resp, err := httpGet(http.DefaultClient, k.base+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d", path, resp.StatusCode)
	}
	return string(b)
}
