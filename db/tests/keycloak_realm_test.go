package tests

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
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
	"time"
)

// F-001 T-36 (AC-06): the bundled Keycloak realm, live (started by
// scripts/sso-e2e-keycloak.sh): deploy/keycloak/fair-realm.json imports into
// Keycloak 26 as written, its policies read back through the admin API, and
// a password + TOTP login reaches FAIR with amr [pwd otp], which FAIR refuses
// while TOTP is off, accepts for an ordinary user once it is on, and refuses
// for a privileged user (no phishing-resistant method).

const kcOTPSecret = "fair-totp-test-secret-0123456789" // #nosec G101 -- a test credential

// totp is RFC 6238 with HMAC-SHA-256, 6 digits, 30 seconds (the realm's
// policy); Keycloak keys it with the secret's bytes.
func totp(secret string, at time.Time) string {
	m := hmac.New(sha256.New, []byte(secret))
	_ = binary.Write(m, binary.BigEndian, uint64(at.Unix()/30)) // #nosec G115 -- a positive time
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

func TestKeycloakRealmPolicy(t *testing.T) {
	kc := os.Getenv("FAIR_TEST_KEYCLOAK")
	if kc == "" {
		t.Skip("FAIR_TEST_KEYCLOAK not set (scripts/sso-e2e-keycloak.sh)")
	}
	oe := oidcFixture(t)
	e := oe.e
	realm := "fair" + strings.ToLower(e.db[len(e.db)-6:])
	redirect := oe.url + "/api/v1/auth/oidc/" + oe.idpID + "/callback"
	secret := "kc-realm-client-secret-0123456789-abcdef" // #nosec G101 -- a test credential

	// The realm file as shipped, with the install's values filled in, plus
	// three users with a password and TOTP (two ordinary users and a Platform
	// Admin of FAIR).
	raw, err := os.ReadFile("../../deploy/keycloak/fair-realm.json")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.NewReplacer("${FAIR_PUBLIC_ORIGIN}", oe.url, "${FAIR_KEYCLOAK_CLIENT_SECRET}", secret).Replace(string(raw))
	var rep map[string]any
	if err := json.Unmarshal([]byte(doc), &rep); err != nil {
		t.Fatal(err)
	}
	rep["realm"] = realm
	rep["sslRequired"] = "none" // the test Keycloak speaks plain HTTP on the test network
	otpCred, _ := json.Marshal(map[string]any{"subType": "totp", "digits": 6, "counter": 0, "period": 30, "algorithm": "HmacSHA256"})
	otpSecret, _ := json.Marshal(map[string]string{"value": kcOTPSecret})
	var users []any
	for _, u := range []string{"user", "other", "admin"} { // one login each: a TOTP code is never accepted twice
		users = append(users, map[string]any{"username": u, "email": u + "@example.test", "firstName": "Test", "lastName": u, "enabled": true,
			"emailVerified": true, "requiredActions": []string{},
			"credentials": []map[string]any{
				{"type": "password", "value": "realm-test-Pa55word", "temporary": false},
				{"type": "otp", "userLabel": "test", "secretData": string(otpSecret), "credentialData": string(otpCred)},
			}})
	}
	rep["users"] = users
	admin := keycloakAdmin(t, kc)
	admin.do(t, "POST", "/admin/realms", rep)
	t.Cleanup(func() { admin.do(t, "DELETE", "/admin/realms/"+realm, nil) })

	// The policies, as Keycloak holds them after the import.
	var got map[string]any
	_ = json.Unmarshal([]byte(admin.getAuth(t, "/admin/realms/"+realm)), &got)
	for k, want := range map[string]any{"browserFlow": "fair browser", "otpPolicyAlgorithm": "HmacSHA256", "webAuthnPolicyUserVerificationRequirement": "required",
		"bruteForceProtected": true, "failureFactor": float64(3), "registrationAllowed": false, "otpPolicyCodeReusable": false} {
		if got[k] != want {
			t.Errorf("realm %s = %v, want %v", k, got[k], want)
		}
	}
	var execs []map[string]any
	_ = json.Unmarshal([]byte(admin.getAuth(t, "/admin/realms/"+realm+"/authentication/flows/fair%20browser/executions")), &execs)
	refs := map[string]string{}
	for _, x := range execs {
		if id, _ := x["authenticationConfig"].(string); id != "" {
			var cfg struct {
				Config map[string]string `json:"config"`
			}
			_ = json.Unmarshal([]byte(admin.getAuth(t, "/admin/realms/"+realm+"/authentication/config/"+id)), &cfg)
			refs[x["providerId"].(string)] = cfg.Config["default.reference.value"]
		}
	}
	if fmt.Sprint(refs) != "map[auth-otp-form:otp auth-username-password-form:pwd auth-x509-client-username-form:sc webauthn-authenticator:hwk]" {
		t.Fatalf("amr references in Keycloak: %v", refs)
	}

	// FAIR's IdP for the realm (kind keycloak), users matched by email.
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
	e.mustOwner("UPDATE iam.app_user SET idp_id = '" + oe.idpID + "', external_id = email WHERE email IN ('user@example.test', 'other@example.test', 'admin@example.test')")
	denials := func() string {
		return e.adminQuery("SELECT coalesce(string_agg(payload->>'reason', '|' ORDER BY id), '') FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'authn.mfa_missing'")
	}

	// TOTP off (the default): password + TOTP is not MFA.
	if code, cookie := oe.realmLogin(t, redirect, "user"); code != http.StatusUnauthorized || cookie != "" {
		t.Fatalf("password + TOTP while TOTP is off: %d", code)
	}
	if d := denials(); d != "no MFA evidence" {
		t.Fatalf("denials: %q", d)
	}
	// TOTP on: an ordinary user signs in; a privileged one does not.
	oe.mfa.totp = true
	code, cookie := oe.realmLogin(t, redirect, "other")
	if code != 200 || cookie == "" {
		t.Fatalf("password + TOTP while TOTP is on: %d", code)
	}
	if code, cookie := oe.realmLogin(t, redirect, "admin"); code != http.StatusUnauthorized || cookie != "" {
		t.Fatalf("a privileged user with password + TOTP: %d", code)
	}
	if d := denials(); !strings.HasSuffix(d, "|privileged users need phishing-resistant MFA: a security key or smart card (AC-06)") {
		t.Fatalf("denials: %q", d)
	}
}

// getAuth is get with the admin token.
func (k kcAdmin) getAuth(t *testing.T, path string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, k.base+path, nil) //nolint:noctx // test helper
	req.Header.Set("Authorization", "Bearer "+k.token)
	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- the test Keycloak
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	return string(b)
}

// realmLogin signs in as username through the realm's password and TOTP
// forms and returns the platform's answer to the callback.
func (oe *oidcEnv) realmLogin(t *testing.T, redirect, username string) (int, string) {
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
	resp, err := httpPostForm(browser, html.UnescapeString(action[1]), url.Values{"username": {username}, "password": {"realm-test-Pa55word"}, "credentialId": {""}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	otpAction := regexp.MustCompile(`<form id="kc-otp-login-form"[^>]*action="([^"]+)"`).FindStringSubmatch(string(body))
	if otpAction == nil {
		t.Fatalf("no TOTP form after the password (%d):\n%.1200s", resp.StatusCode, body)
	}
	back, err := httpPostForm(browser, html.UnescapeString(otpAction[1]), url.Values{"otp": {totp(kcOTPSecret, time.Now())}})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := io.ReadAll(back.Body)
	_ = back.Body.Close()
	cb := back.Header.Get("Location")
	if back.StatusCode != http.StatusFound || !strings.HasPrefix(cb, redirect+"?") {
		msg := regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>|kc-feedback-text">(.*?)<`).FindAllStringSubmatch(string(after), -1)
		t.Fatalf("Keycloak redirect after TOTP: %d %q %q", back.StatusCode, cb, msg)
	}
	r, err := httpGet(oe.client, cb)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(r.Body)
	_ = r.Body.Close()
	return r.StatusCode, sessionCookie(r)
}

// T-36 (AC-06) without a live Keycloak: the amr the realm sends, signed by
// the test provider, against FAIR's rules for IdPs of kind keycloak.
func TestKeycloakAMRPolicy(t *testing.T) {
	oe := oidcFixture(t)
	e := oe.e
	e.mustOwner("UPDATE iam.app_user SET idp_id = '" + oe.idpID + "', external_id = email WHERE email IN ('user@example.test', 'admin@example.test')")
	login := func(who, amr string) int {
		resp, _ := oe.signIn(t, who+"@example.test", "/", map[string]any{"amr": strings.Fields(amr)})
		_ = resp.Body.Close()
		if (resp.StatusCode == 200) == (sessionCookie(resp) == "") {
			t.Fatalf("%s %q: %d with cookie=%t", who, amr, resp.StatusCode, sessionCookie(resp) != "")
		}
		return resp.StatusCode
	}
	check := func(kind string, totpOn bool, want map[string]int) {
		t.Helper()
		e.mustOwner("UPDATE iam.idp SET kind = '" + kind + "' WHERE id = '" + oe.idpID + "'")
		oe.mfa.totp = totpOn
		for c, code := range want {
			who, amr, _ := strings.Cut(c, ":")
			if got := login(who, amr); got != code {
				t.Errorf("%s, TOTP %t, %s with %q: %d, want %d", kind, totpOn, who, amr, got, code)
			}
		}
	}
	// The bundled Keycloak: TOTP is a factor only while allowed; a
	// privileged user (admin, Platform Admin) needs a key or a smart card.
	check("keycloak", false, map[string]int{"user:pwd otp": 401, "user:pwd hwk": 200, "admin:pwd otp": 401, "admin:pwd hwk": 200})
	check("keycloak", true, map[string]int{"user:pwd otp": 200, "admin:pwd otp": 401, "admin:pwd hwk": 200, "admin:pwd swk": 200,
		"admin:mfa": 401})
	// A smart card alone is one factor by the defaults; the realm guide's
	// rule counts it (the card's PIN is the second).
	check("keycloak", false, map[string]int{"admin:sc": 401})
	e.mustOwner(`UPDATE iam.idp SET mfa_evidence_rule = '{"amr": ["mfa", "sc"], "amr_two_categories": true}' WHERE id = '` + oe.idpID + `'`)
	check("keycloak", false, map[string]int{"admin:sc": 200, "user:sc": 200})
	e.mustOwner(`UPDATE iam.idp SET mfa_evidence_rule = '{}' WHERE id = '` + oe.idpID + `'`)
	// Other OIDC IdPs keep T-18's rules: their amr otp counts, and FAIR does
	// not ask them for phishing-resistant methods (their own policies do).
	check("oidc", false, map[string]int{"user:pwd otp": 200, "admin:pwd otp": 200})
	if got := e.adminQuery("SELECT count(*) FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'reason' LIKE 'privileged users need phishing-resistant MFA%'"); got != "2" { // admin pwd otp and mfa, with TOTP on
		t.Fatalf("phishing-resistant refusals audited: %s", got)
	}
}
