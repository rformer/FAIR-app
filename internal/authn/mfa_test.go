package authn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMFADefaults(t *testing.T) {
	var none MFARule
	saml := map[string]bool{
		"https://refeds.org/profile/mfa":                                    true,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor":                true,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract":    true,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI":               true,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken":              true,
		"http://schemas.microsoft.com/claims/multipleauthn":                 true,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport": false,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:Password":                   false,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified":                false,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard":                  false,
		"": false,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor ":                false, // exact values only
		"URN:OASIS:NAMES:TC:SAML:2.0:AC:CLASSES:MULTIFACTOR":                 false,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport2": false,
	}
	for ctx, want := range saml {
		if got := none.Satisfied("saml", Evidence{AuthnContext: ctx}); got != want {
			t.Errorf("SAML %q: %t, want %t", ctx, got, want)
		}
	}
	entra := Evidence{AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		Attributes: map[string][]string{"http://schemas.microsoft.com/claims/authnmethodsreferences": {
			"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password", "http://schemas.microsoft.com/claims/multipleauthn"}}}
	if !none.Satisfied("saml", entra) {
		t.Error("Entra ID's multipleauthn attribute refused")
	}
	entra.Attributes["http://schemas.microsoft.com/claims/authnmethodsreferences"] = entra.Attributes["http://schemas.microsoft.com/claims/authnmethodsreferences"][:1]
	if none.Satisfied("saml", entra) {
		t.Error("a password-only Entra ID login accepted")
	}
	// The OIDC defaults never apply to SAML evidence, nor the reverse.
	if none.Satisfied("saml", Evidence{AMR: []string{"mfa"}}) || none.Satisfied("oidc", Evidence{AuthnContext: "https://refeds.org/profile/mfa"}) {
		t.Error("evidence of the other protocol accepted")
	}

	oidc := map[string]bool{
		"mfa":         true,
		"pwd otp":     true,
		"pin hwk":     true,
		"hwk fpt":     true,
		"pwd sms":     true,
		"pwd":         false,
		"otp":         false,
		"hwk":         false,
		"pwd pin kba": false, // one category
		"otp hwk swk": false,
		"pwd mca":     false, // not a factor
		"pwd rba":     false,
		"pwd user":    false,
		"":            false,
		"MFA":         false,
	}
	for amr, want := range oidc {
		ev := Evidence{AMR: strings.Fields(amr)}
		if got := none.Satisfied("oidc", ev); got != want {
			t.Errorf("OIDC amr %q: %t, want %t", amr, got, want)
		}
		if got := none.Satisfied("keycloak", ev); got != want {
			t.Errorf("Keycloak amr %q: %t, want %t", amr, got, want)
		}
	}
	if none.Satisfied("oidc", Evidence{ACR: "urn:mace:incommon:iap:silver"}) {
		t.Error("an acr accepted without a rule naming it")
	}
}

// A rule replaces the defaults: only what it names is MFA.
func TestMFARules(t *testing.T) {
	r, err := ParseMFARule("oidc", []byte(`{"acr": ["gold"], "amr": ["hwk"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for ev, want := range map[*Evidence]bool{
		{ACR: "gold"}:                       true,
		{AMR: []string{"hwk"}}:              true,
		{ACR: "silver"}:                     false,
		{AMR: []string{"mfa"}}:              false, // a default, not in the rule
		{AMR: []string{"pwd", "otp"}}:       false,
		{AMR: []string{"hwk"}, ACR: "zero"}: true,
	} {
		if got := r.Satisfied("oidc", *ev); got != want {
			t.Errorf("%+v: %t, want %t", *ev, got, want)
		}
	}
	s, err := ParseMFARule("saml", []byte(`{"attribute": {"name": "amr", "values": ["hwk"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Satisfied("saml", Evidence{AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor"}) {
		t.Error("a default class accepted under an explicit rule")
	}
	if !s.Satisfied("saml", Evidence{Attributes: map[string][]string{"amr": {"pwd", "hwk"}}}) {
		t.Error("the rule's attribute refused")
	}
	if r, err := ParseMFARule("saml", []byte(`{}`)); err != nil || !r.empty() {
		t.Errorf("{}: %v %+v", err, r)
	}

	for name, c := range map[string]struct{ kind, rule string }{
		"amr for SAML":        {"saml", `{"amr": ["mfa"]}`},
		"acr for SAML":        {"saml", `{"acr": ["gold"]}`},
		"two categories SAML": {"saml", `{"amr_two_categories": true}`},
		"class for OIDC":      {"oidc", `{"authn_contexts": ["x"]}`},
		"attribute for OIDC":  {"keycloak", `{"attribute": {"name": "a", "values": ["b"]}}`},
		"unknown field":       {"oidc", `{"amr": ["mfa"], "require": false}`},
		"attribute no name":   {"saml", `{"attribute": {"name": " ", "values": ["b"]}}`},
		"attribute no value":  {"saml", `{"attribute": {"name": "a", "values": []}}`},
		"empty value":         {"oidc", `{"acr": [""]}`},
		"not an object":       {"oidc", `["mfa"]`},
	} {
		if _, err := ParseMFARule(c.kind, []byte(c.rule)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type brokenSettings struct{}

func (brokenSettings) Bool(string, string) (bool, error) { return false, errors.New("stale") }

// Without settings, or with settings that cannot be read, MFA is required
// (fail closed) before anything else is asked.
func TestMFARequiredFailsClosed(t *testing.T) {
	for name, h := range map[string]*Logins{"no settings": {}, "unreadable settings": {Settings: brokenSettings{}}} {
		if req, err := h.mfaRequired(context.Background(), "u"); err != nil || !req {
			t.Errorf("%s: required=%t err=%v", name, req, err)
		}
	}
}
