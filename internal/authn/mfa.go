package authn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// MFA evidence (F-001 T-18; AC-05; design §5.1 step 4): a federated login
// that must show MFA is accepted only when the IdP's evidence meets its rule
// (iam.idp.mfa_evidence_rule). An empty rule means the standards defaults
// below. Whether MFA is required comes from the settings
// auth.mfa_required_all and, when that is off, auth.mfa_required_privileged
// for users holding a privileged permission.

// MFARule is an IdP's MFA evidence rule. Any one satisfied condition is
// evidence of MFA.
type MFARule struct {
	// SAML: AuthnContextClassRef values that mean MFA.
	AuthnContexts []string `json:"authn_contexts,omitempty"`
	// SAML: an attribute whose values include one of Values (e.g. Entra's
	// authnmethodsreferences).
	Attribute *MFAAttribute `json:"attribute,omitempty"`
	// OIDC: amr values (RFC 8176) any one of which means MFA.
	AMR []string `json:"amr,omitempty"`
	// OIDC: amr values from two factor categories (knowledge, possession,
	// inherence; RFC 8176) mean MFA.
	AMRTwoCategories bool `json:"amr_two_categories,omitempty"`
	// OIDC: acr values that mean MFA.
	ACR []string `json:"acr,omitempty"`
}

// MFAAttribute names a SAML attribute and the values that mean MFA.
type MFAAttribute struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// Evidence is what an IdP sent about how the user authenticated.
type Evidence struct {
	AuthnContext string              // SAML
	Attributes   map[string][]string // SAML
	AMR          []string            // OIDC
	ACR          string              // OIDC
}

// Standards defaults, used when an IdP has no rule.
var (
	// DefaultSAMLRule: the REFEDS MFA profile, the SAML 2.0 classes that
	// combine two factors, the widely used MultiFactor class, and Microsoft's
	// multipleauthn (AD FS as a class, Entra ID as an attribute).
	DefaultSAMLRule = MFARule{
		AuthnContexts: []string{
			"https://refeds.org/profile/mfa",
			"urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor",
			"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
			"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered",
			"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
			"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
			"http://schemas.microsoft.com/claims/multipleauthn",
		},
		Attribute: &MFAAttribute{Name: "http://schemas.microsoft.com/claims/authnmethodsreferences",
			Values: []string{"http://schemas.microsoft.com/claims/multipleauthn"}},
	}
	// DefaultOIDCRule: amr "mfa", or factors of two categories (e.g. pwd
	// and otp).
	DefaultOIDCRule = MFARule{AMR: []string{"mfa"}, AMRTwoCategories: true}
)

// amrCategory is the factor category of an RFC 8176 amr value ("" for
// values that are not a factor, such as mca, rba or user).
func amrCategory(v string) string {
	switch v {
	case "pwd", "pin", "kba":
		return "knowledge"
	case "otp", "hwk", "swk", "sms", "tel", "sc":
		return "possession"
	case "fpt", "face", "iris", "retina", "vbm":
		return "inherence"
	}
	return ""
}

// ParseMFARule validates a stored or submitted rule for an IdP of kind;
// an empty object is the defaults.
func ParseMFARule(kind string, raw []byte) (MFARule, error) {
	var r MFARule
	if len(bytes.TrimSpace(raw)) == 0 {
		return r, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return MFARule{}, fmt.Errorf("authn: MFA evidence rule: %w", err)
	}
	saml := len(r.AuthnContexts) > 0 || r.Attribute != nil
	oidc := len(r.AMR) > 0 || r.AMRTwoCategories || len(r.ACR) > 0
	switch {
	case kind == "saml" && oidc:
		return MFARule{}, fmt.Errorf("authn: MFA evidence rule: amr and acr apply to OIDC IdPs")
	case kind != "saml" && saml:
		return MFARule{}, fmt.Errorf("authn: MFA evidence rule: authn_contexts and attribute apply to SAML IdPs")
	case r.Attribute != nil && (strings.TrimSpace(r.Attribute.Name) == "" || len(r.Attribute.Values) == 0):
		return MFARule{}, fmt.Errorf("authn: MFA evidence rule: an attribute needs a name and values")
	}
	for _, list := range [][]string{r.AuthnContexts, r.AMR, r.ACR} {
		if slices.Contains(list, "") {
			return MFARule{}, fmt.Errorf("authn: MFA evidence rule: empty value")
		}
	}
	return r, nil
}

// empty: no condition, so the defaults apply.
func (r MFARule) empty() bool {
	return len(r.AuthnContexts) == 0 && r.Attribute == nil && len(r.AMR) == 0 && !r.AMRTwoCategories && len(r.ACR) == 0
}

// Satisfied reports whether e is evidence of MFA under the rule (the
// defaults for kind when the rule is empty).
func (r MFARule) Satisfied(kind string, e Evidence) bool {
	if r.empty() {
		r = DefaultOIDCRule
		if kind == "saml" {
			r = DefaultSAMLRule
		}
	}
	if e.AuthnContext != "" && slices.Contains(r.AuthnContexts, e.AuthnContext) {
		return true
	}
	if a := r.Attribute; a != nil {
		for _, v := range e.Attributes[a.Name] {
			if slices.Contains(a.Values, v) {
				return true
			}
		}
	}
	for _, v := range e.AMR {
		if slices.Contains(r.AMR, v) {
			return true
		}
	}
	if r.AMRTwoCategories {
		cats := map[string]bool{}
		for _, v := range e.AMR {
			if c := amrCategory(v); c != "" {
				cats[c] = true
			}
		}
		if len(cats) >= 2 {
			return true
		}
	}
	return e.ACR != "" && slices.Contains(r.ACR, e.ACR)
}
