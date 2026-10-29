package tests

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/authn/saml/samltest"
)

// F-001 T-18 (AC-05; design §5.1 step 4): a federated login without MFA
// evidence is denied and audited while MFA is required: by default for
// everyone (auth.mfa_required_all), and for privileged users always
// (auth.mfa_required_privileged, a hard floor).

const singleFactorClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

// samlLogin completes an SP-initiated login with the given evidence and
// returns the status and session cookie.
func (se *samlEnv) samlLogin(t *testing.T, nameID, authnContext string, attrs map[string][]string) (int, string) {
	t.Helper()
	r := se.response(se.startLogin(t, "/"), nameID)
	r.AuthnContextClassRef = authnContext
	r.Attributes = attrs
	resp := se.post(t, se.build(t, r), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, sessionCookie(resp)
}

func TestMFAEvidenceSAML(t *testing.T) {
	se := samlFixture(t, false)
	e := se.e
	missing := func() string {
		return e.adminQuery(`SELECT coalesce(string_agg((payload->>'severity') || ':' || (payload->>'reason') || ':' ||
			(payload->'attributes'->>'user_id') || ':' || coalesce(payload->'attributes'->>'authn_context', ''), '|' ORDER BY id), '')
			FROM iam.event_outbox WHERE topic = 'audit' AND payload->>'type' = 'authn.mfa_missing'`)
	}
	userID := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'user@example.test'")

	// Required by default: a password-only login is denied, audited (high)
	// with the evidence, and gets no session.
	if code, c := se.samlLogin(t, "user@example.test", singleFactorClass, nil); code != http.StatusUnauthorized || c != "" {
		t.Fatalf("password only: %d cookie=%t", code, c != "")
	}
	if got, want := missing(), "high:no MFA evidence:"+userID+":"+singleFactorClass; got != want {
		t.Fatalf("mfa_missing audit %q, want %q", got, want)
	}
	if code, c := se.samlLogin(t, "user@example.test", "", nil); code != http.StatusUnauthorized || c != "" {
		t.Fatalf("no AuthnContext: %d", code)
	}
	// Defaults: MultiFactor, REFEDS MFA, Entra ID's attribute.
	for name, c := range map[string]struct {
		ctx   string
		attrs map[string][]string
	}{
		"MultiFactor": {samltest.MultiFactor, nil},
		"REFEDS MFA":  {"https://refeds.org/profile/mfa", nil},
		"Entra ID": {singleFactorClass, map[string][]string{"http://schemas.microsoft.com/claims/authnmethodsreferences": {
			"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password", "http://schemas.microsoft.com/claims/multipleauthn"}}},
	} {
		code, cookie := se.samlLogin(t, "user@example.test", c.ctx, c.attrs)
		if code != http.StatusOK || cookie == "" {
			t.Fatalf("%s: %d", name, code)
		}
		if got := se.sessionRow(t, cookie, "mfa_evidence->>'satisfied'"); got != "true" {
			t.Fatalf("%s: session MFA evidence satisfied=%q", name, got)
		}
	}

	// An explicit rule replaces the defaults.
	e.mustOwner(`UPDATE iam.idp SET mfa_evidence_rule = '{"attribute": {"name": "amr", "values": ["hwk"]}}' WHERE id = '` + se.idpID + `'`)
	if code, _ := se.samlLogin(t, "user@example.test", samltest.MultiFactor, nil); code != http.StatusUnauthorized {
		t.Fatalf("a default class under an explicit rule: %d", code)
	}
	if code, _ := se.samlLogin(t, "user@example.test", singleFactorClass, map[string][]string{"amr": {"pwd", "hwk"}}); code != http.StatusOK {
		t.Fatalf("the rule's attribute: %d", code)
	}
	e.mustOwner("UPDATE iam.idp SET mfa_evidence_rule = '{}' WHERE id = '" + se.idpID + "'")

	// auth.mfa_required_all off: users without a privileged permission sign
	// in without MFA (recorded as such); privileged ones still need it,
	// whether the permission comes directly or through a group.
	se.mfa.all = false
	code, cookie := se.samlLogin(t, "user@example.test", singleFactorClass, nil)
	if code != http.StatusOK {
		t.Fatalf("non-privileged without MFA, MFA for privileged only: %d", code)
	}
	if got := se.sessionRow(t, cookie, "mfa_evidence->>'satisfied'"); got != "false" {
		t.Fatalf("session MFA evidence satisfied=%q", got)
	}
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Auditors')")
	e.mustOwner("INSERT INTO iam.grp_member (grp_id, user_id) SELECT g.id, " + uid("other") + " FROM iam.grp g WHERE g.display_name = 'Auditors'")
	e.mustOwner(grant("admin", "group:Auditors", "Auditor", "ENTERPRISE"))
	e.drain()
	if code, _ := se.samlLogin(t, "other@example.test", singleFactorClass, nil); code != http.StatusUnauthorized {
		t.Fatalf("privileged (through a group) without MFA: %d", code)
	}
	if code, _ := se.samlLogin(t, "other@example.test", samltest.MultiFactor, nil); code != http.StatusOK {
		t.Fatalf("privileged with MFA: %d", code)
	}
	e.mustOwner("UPDATE iam.assignment SET revoked_at = now(), revoked_by = " + uid("admin") + " WHERE principal_kind = 'group'")
	if code, _ := se.samlLogin(t, "other@example.test", singleFactorClass, nil); code != http.StatusOK {
		t.Fatalf("after the privileged role was revoked: %d", code)
	}
	if n := strings.Count(missing(), "|") + 1; n != 4 {
		t.Fatalf("%d logins without MFA audited, want 4: %s", n, missing())
	}
}

func TestMFAEvidenceOIDC(t *testing.T) {
	oe := oidcFixture(t)
	e := oe.e
	for amr, want := range map[string]int{"pwd": 401, "pwd otp": 200, "mfa": 200, "otp hwk": 401} {
		resp, _ := oe.signIn(t, "user@example.test", "/", map[string]any{"amr": strings.Fields(amr)})
		_ = resp.Body.Close()
		if resp.StatusCode != want || (want == 401) != (sessionCookie(resp) == "") {
			t.Errorf("amr %q: %d, want %d", amr, resp.StatusCode, want)
		}
	}
	// An acr rule (e.g. Keycloak's level of authentication).
	e.mustOwner(`UPDATE iam.idp SET mfa_evidence_rule = '{"acr": ["gold"]}' WHERE id = '` + oe.idpID + `'`)
	for acr, want := range map[string]int{"gold": 200, "silver": 401} {
		resp, _ := oe.signIn(t, "user@example.test", "/", map[string]any{"amr": []string{"pwd", "otp"}, "acr": acr})
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("acr %q: %d, want %d", acr, resp.StatusCode, want)
		}
	}
	got := e.adminQuery("SELECT string_agg(payload->'attributes'->>'acr', ',' ORDER BY id) FROM iam.event_outbox WHERE payload->>'type' = 'authn.mfa_missing'")
	if got != ",,silver" {
		t.Fatalf("mfa_missing audit acr values %q", got)
	}
	// A stored rule the API would refuse fails closed (no session).
	e.mustOwner(`UPDATE iam.idp SET mfa_evidence_rule = '{"authn_contexts": ["x"]}' WHERE id = '` + oe.idpID + `'`)
	resp, _ := oe.signIn(t, "user@example.test", "/", map[string]any{"amr": []string{"mfa"}})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || sessionCookie(resp) != "" {
		t.Fatalf("invalid stored rule: %d", resp.StatusCode)
	}
}

// The rule is set over the IdP API, validated and audited.
func TestIDPMFARuleAPI(t *testing.T) {
	ie := idpFixture(t)
	id := ie.create(t, "oidc", "Partner", "partner.example")
	if r := ie.patch(t, id, map[string]any{"mfa_evidence_rule": map[string]any{"authn_contexts": []string{"x"}}}); r.code != http.StatusBadRequest {
		t.Fatalf("SAML rule on an OIDC IdP: %d %s", r.code, r.raw)
	}
	if r := ie.patch(t, id, map[string]any{"mfa_evidence_rule": map[string]any{"acr": []string{"gold"}, "amr_two_categories": true}}); r.code != http.StatusNoContent {
		t.Fatalf("rule: %d %s", r.code, r.raw)
	}
	got := ie.do(t, "GET", "/api/v1/idps/"+id, ie.admin, nil, nil)
	rule, _ := got.body["mfa_evidence_rule"].(map[string]any)
	if rule["amr_two_categories"] != true || len(rule["acr"].([]any)) != 1 {
		t.Fatalf("stored rule: %s", got.raw)
	}
	if r := ie.patch(t, id, map[string]any{"mfa_evidence_rule": nil}); r.code != http.StatusNoContent {
		t.Fatalf("restore defaults: %d %s", r.code, r.raw)
	}
	if got := ie.e.adminQuery("SELECT mfa_evidence_rule::text FROM iam.idp WHERE id = '" + id + "'"); got != "{}" {
		t.Fatalf("defaults stored as %s", got)
	}
	audit := ie.e.adminQuery(`SELECT count(*) FROM iam.event_outbox WHERE payload->>'type' = 'idp.mfa_rule_changed'
		AND payload->>'severity' = 'high' AND payload->>'reason' = 'change ticket 42'`)
	if audit != "2" {
		t.Fatalf("%s rule changes audited", audit)
	}
}
