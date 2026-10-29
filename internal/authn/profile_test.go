package authn

import (
	"testing"

	"github.com/rformer/fair-app/internal/authn/saml"
)

// T-23: the email and name for just-in-time provisioning, from the
// attribute names the common IdPs use.
func TestSAMLProfile(t *testing.T) {
	for name, c := range map[string]struct {
		login       saml.Login
		email, full string
	}{
		"Entra ID": {saml.Login{NameID: "opaque", Attributes: map[string][]string{
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"a@corp.example"},
			"http://schemas.microsoft.com/identity/claims/displayname":           {"Ann Example"}}}, "a@corp.example", "Ann Example"},
		"Okta": {saml.Login{NameID: "b@corp.example", Attributes: map[string][]string{"firstName": {"Bo"}, "lastName": {"Ex"}}},
			"b@corp.example", "Bo Ex"},
		"eduPerson OIDs": {saml.Login{NameID: "x", Attributes: map[string][]string{"urn:oid:0.9.2342.19200300.100.1.3": {"c@uni.example"},
			"urn:oid:2.16.840.1.113730.3.1.241": {"Cy"}}}, "c@uni.example", "Cy"},
		"NameID only": {saml.Login{NameID: "d@corp.example"}, "d@corp.example", ""},
		"no email":    {saml.Login{NameID: "opaque", Attributes: map[string][]string{"mail": {"  "}}}, "", ""},
	} {
		p := samlProfile(c.login)
		if p.Email != c.email || p.Name != c.full || p.EmailVerified != nil {
			t.Errorf("%s: %+v", name, p)
		}
	}
}
