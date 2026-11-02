package authn

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// F-001 T-36 (AC-06): the bundled Keycloak realm (deploy/keycloak/
// fair-realm.json) offers only the intended ways in, each reporting the amr
// FAIR's login check relies on (PhishingResistant, KeycloakEvidence).

type realmFile struct {
	Realm                string   `json:"realm"`
	SSLRequired          string   `json:"sslRequired"`
	RegistrationAllowed  bool     `json:"registrationAllowed"`
	ResetPasswordAllowed bool     `json:"resetPasswordAllowed"`
	BruteForceProtected  bool     `json:"bruteForceProtected"`
	FailureFactor        int      `json:"failureFactor"`
	PasswordPolicy       string   `json:"passwordPolicy"`
	OTPAlgorithm         string   `json:"otpPolicyAlgorithm"`
	OTPCodeReusable      bool     `json:"otpPolicyCodeReusable"`
	WebAuthnAlgorithms   []string `json:"webAuthnPolicySignatureAlgorithms"`
	WebAuthnUV           string   `json:"webAuthnPolicyUserVerificationRequirement"`
	EventsEnabled        bool     `json:"eventsEnabled"`
	AdminEventsEnabled   bool     `json:"adminEventsEnabled"`
	BrowserFlow          string   `json:"browserFlow"`
	AuthenticationFlows  []struct {
		Alias      string `json:"alias"`
		TopLevel   bool   `json:"topLevel"`
		Executions []struct {
			Authenticator string `json:"authenticator"`
			Config        string `json:"authenticatorConfig"`
			FlowAlias     string `json:"flowAlias"`
			Requirement   string `json:"requirement"`
		} `json:"authenticationExecutions"`
	} `json:"authenticationFlows"`
	AuthenticatorConfig []struct {
		Alias  string            `json:"alias"`
		Config map[string]string `json:"config"`
	} `json:"authenticatorConfig"`
	RequiredActions []struct {
		Alias         string `json:"alias"`
		Enabled       bool   `json:"enabled"`
		DefaultAction bool   `json:"defaultAction"`
	} `json:"requiredActions"`
	Clients []struct {
		ClientID        string            `json:"clientId"`
		PublicClient    bool              `json:"publicClient"`
		Secret          string            `json:"secret"`
		StandardFlow    bool              `json:"standardFlowEnabled"`
		Implicit        bool              `json:"implicitFlowEnabled"`
		DirectGrants    bool              `json:"directAccessGrantsEnabled"`
		ServiceAccounts bool              `json:"serviceAccountsEnabled"`
		RedirectURIs    []string          `json:"redirectUris"`
		Attributes      map[string]string `json:"attributes"`
		ProtocolMappers []struct {
			ProtocolMapper string            `json:"protocolMapper"`
			Config         map[string]string `json:"config"`
		} `json:"protocolMappers"`
	} `json:"clients"`
}

func TestKeycloakRealm(t *testing.T) {
	b, err := os.ReadFile("../../deploy/keycloak/fair-realm.json")
	if err != nil {
		t.Fatal(err)
	}
	var r realmFile
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.SSLRequired != "all" || r.RegistrationAllowed || r.ResetPasswordAllowed || !r.BruteForceProtected || r.FailureFactor > 3 ||
		!r.EventsEnabled || !r.AdminEventsEnabled {
		t.Errorf("realm basics: %+v", r)
	}
	if !strings.Contains(r.PasswordPolicy, "length(14)") || !strings.Contains(r.PasswordPolicy, "hashAlgorithm(pbkdf2-sha512)") {
		t.Errorf("password policy %q", r.PasswordPolicy)
	}
	if r.OTPCodeReusable {
		t.Error("a TOTP code may be used twice")
	}
	if r.OTPAlgorithm != "HmacSHA256" {
		t.Errorf("TOTP algorithm %q, want HmacSHA256 (FIPS)", r.OTPAlgorithm)
	}
	if r.WebAuthnUV != "required" {
		t.Errorf("WebAuthn user verification %q", r.WebAuthnUV)
	}
	for _, a := range r.WebAuthnAlgorithms {
		if !slices.Contains([]string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}, a) {
			t.Errorf("WebAuthn algorithm %s is not FIPS 186", a)
		}
	}

	// The flows: only these authenticators, each with its amr reference.
	configs := map[string]map[string]string{}
	for _, c := range r.AuthenticatorConfig {
		configs[c.Alias] = c.Config
	}
	wantAMR := map[string]string{
		"auth-username-password-form":    "pwd",
		"webauthn-authenticator":         "hwk",
		"auth-otp-form":                  "otp",
		"auth-x509-client-username-form": "sc",
	}
	flows := map[string]int{}
	for i, f := range r.AuthenticationFlows {
		flows[f.Alias] = i
	}
	top, ok := flows[r.BrowserFlow]
	if !ok || !r.AuthenticationFlows[top].TopLevel {
		t.Fatalf("browser flow %q missing", r.BrowserFlow)
	}
	seen := map[string]string{}
	// ways lists each path through the flow as its amr values.
	var walk func(alias string) [][]string
	walk = func(alias string) [][]string {
		f := r.AuthenticationFlows[flows[alias]]
		var alternatives [][]string
		required := [][]string{{}}
		for _, e := range f.Executions {
			var paths [][]string
			switch {
			case e.FlowAlias != "":
				if _, ok := flows[e.FlowAlias]; !ok {
					t.Fatalf("flow %q missing", e.FlowAlias)
				}
				paths = walk(e.FlowAlias)
			case e.Authenticator == "auth-cookie":
				continue // an existing session, made by one of the others
			default:
				want, known := wantAMR[e.Authenticator]
				if !known {
					t.Errorf("unexpected authenticator %s", e.Authenticator)
					continue
				}
				got := configs[e.Config]["default.reference.value"]
				if got != want {
					t.Errorf("%s reports amr %q, want %q", e.Authenticator, got, want)
				}
				seen[e.Authenticator] = got
				paths = [][]string{{got}}
			}
			switch e.Requirement {
			case "ALTERNATIVE":
				alternatives = append(alternatives, paths...)
			case "REQUIRED":
				var next [][]string
				for _, p := range required {
					for _, q := range paths {
						next = append(next, append(slices.Clone(p), q...))
					}
				}
				required = next
			default:
				t.Errorf("%s: requirement %s (CONDITIONAL and DISABLED steps are not expected)", alias, e.Requirement)
			}
		}
		if len(alternatives) > 0 && len(required[0]) > 0 {
			t.Errorf("flow %s mixes REQUIRED and ALTERNATIVE steps", alias)
		}
		if len(alternatives) > 0 {
			return alternatives
		}
		return required
	}
	ways := walk(r.BrowserFlow)
	if len(seen) != len(wantAMR) {
		t.Errorf("authenticators in the flow: %v", seen)
	}
	// Every way in is MFA, and each is phishing-resistant unless it is
	// password + TOTP, which FAIR counts only while TOTP is allowed and
	// never for privileged users.
	var got []string
	for _, w := range ways {
		got = append(got, strings.Join(w, "+"))
		ev := Evidence{AMR: w}
		mfa := MFARule{AMR: []string{"mfa", "sc"}, AMRTwoCategories: true}.Satisfied("keycloak", ev)
		if !mfa {
			t.Errorf("way in %v is not MFA", w)
		}
		if !PhishingResistant(w) && !slices.Equal(w, []string{"pwd", "otp"}) {
			t.Errorf("way in %v is neither phishing-resistant nor password + TOTP", w)
		}
		if slices.Equal(w, []string{"pwd", "otp"}) && DefaultOIDCRule.Satisfied("keycloak", KeycloakEvidence(ev, false)) {
			t.Error("password + TOTP counted while TOTP is off")
		}
	}
	slices.Sort(got)
	if strings.Join(got, ",") != "pwd+hwk,pwd+otp,sc" {
		t.Errorf("ways in: %v", got)
	}

	// New users register a security key; TOTP only when an administrator
	// asks a user to (CONFIGURE_TOTP is no default action).
	for _, a := range r.RequiredActions {
		switch a.Alias {
		case "webauthn-register":
			if !a.Enabled || !a.DefaultAction {
				t.Error("new users must register a security key")
			}
		case "CONFIGURE_TOTP", "webauthn-register-passwordless", "TERMS_AND_CONDITIONS", "delete_account":
			if a.DefaultAction {
				t.Errorf("%s is a default action", a.Alias)
			}
		}
	}

	// The platform's client: confidential, code + PKCE only, amr in the ID
	// token, no secret in the file.
	if len(r.Clients) != 1 {
		t.Fatalf("clients: %d", len(r.Clients))
	}
	c := r.Clients[0]
	if c.PublicClient || !c.StandardFlow || c.Implicit || c.DirectGrants || c.ServiceAccounts || c.Attributes["pkce.code.challenge.method"] != "S256" {
		t.Errorf("client: %+v", c)
	}
	if c.Secret != "${FAIR_KEYCLOAK_CLIENT_SECRET}" || !slices.Equal(c.RedirectURIs, []string{"${FAIR_PUBLIC_ORIGIN}/api/v1/auth/oidc/*"}) {
		t.Errorf("client secret and redirect must be placeholders: %q %v", c.Secret, c.RedirectURIs)
	}
	if !slices.ContainsFunc(c.ProtocolMappers, func(m struct {
		ProtocolMapper string            `json:"protocolMapper"`
		Config         map[string]string `json:"config"`
	}) bool {
		return m.ProtocolMapper == "oidc-amr-mapper" && m.Config["id.token.claim"] == "true"
	}) {
		t.Error("no amr in the ID token")
	}
}

// T-36: TOTP counts only while allowed; privileged users need a
// phishing-resistant method.
func TestKeycloakEvidence(t *testing.T) {
	pwdOTP := Evidence{AMR: []string{"pwd", "otp"}}
	if DefaultOIDCRule.Satisfied("keycloak", KeycloakEvidence(pwdOTP, false)) {
		t.Error("TOTP counted while off")
	}
	if !DefaultOIDCRule.Satisfied("keycloak", KeycloakEvidence(pwdOTP, true)) {
		t.Error("TOTP not counted while on")
	}
	if got := KeycloakEvidence(pwdOTP, false).AMR; !slices.Equal(pwdOTP.AMR, []string{"pwd", "otp"}) || !slices.Equal(got, []string{"pwd"}) {
		t.Errorf("evidence changed in place, or wrongly: %v %v", pwdOTP.AMR, got)
	}
	for amr, want := range map[string]bool{"pwd hwk": true, "sc": true, "swk": true, "pwd otp": false, "pwd": false, "otp sms": false, "": false} {
		if got := PhishingResistant(strings.Fields(amr)); got != want {
			t.Errorf("PhishingResistant(%q) = %t", amr, got)
		}
	}
}
