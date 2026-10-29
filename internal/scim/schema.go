// Package scim is the iam service's SCIM 2.0 service provider (F-001 T-21;
// AC-07, AC-08; RFC 7643, RFC 7644): Users and Groups for the IdP whose
// bearer token calls it, with filtering, PATCH, Bulk (size caps), ETags and
// the discovery endpoints. Storage, the token check and the audit trail are
// the database's (iam.scim_*, migration 0044); resources are documents
// here.
package scim

import "strings"

// Schema URNs.
const (
	SchemaUser       = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaEnterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaList       = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError      = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatch      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaBulkReq    = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	SchemaBulkResp   = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	SchemaSearch     = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
	SchemaSPConfig   = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResType    = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema     = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// Attr describes an attribute (RFC 7643 §2, §7).
type Attr struct {
	Name        string
	Type        string // string, boolean, dateTime, reference, complex, integer, decimal, binary
	Multi       bool
	Required    bool
	CaseExact   bool
	Mutability  string // readWrite (default), readOnly, immutable, writeOnly
	Returned    string // default, always, never, request
	Uniqueness  string // none, server, global
	Sub         []Attr
	RefTypes    []string
	Description string
}

func (a Attr) mutability() string {
	if a.Mutability == "" {
		return "readWrite"
	}
	return a.Mutability
}

// Schema is a resource schema.
type Schema struct {
	ID, Name, Description string
	Attrs                 []Attr
}

func str(name, desc string) Attr { return Attr{Name: name, Type: "string", Description: desc} }

func multiComplex(name, desc string, types ...string) Attr {
	return Attr{Name: name, Type: "complex", Multi: true, Description: desc, Sub: []Attr{
		str("value", "The value"), str("display", "A human-readable name"),
		{Name: "type", Type: "string", Description: "A label: " + strings.Join(types, ", ")},
		{Name: "primary", Type: "boolean", Description: "The primary value (at most one)"},
	}}
}

var userSchema = Schema{ID: SchemaUser, Name: "User", Description: "User Account", Attrs: []Attr{
	{Name: "userName", Type: "string", Required: true, Uniqueness: "server", Description: "Unique identifier for the user at its IdP"},
	{Name: "name", Type: "complex", Description: "The user's name", Sub: []Attr{
		str("formatted", "Full name"), str("familyName", "Family name"), str("givenName", "Given name"),
		str("middleName", "Middle name"), str("honorificPrefix", "Prefix"), str("honorificSuffix", "Suffix"),
	}},
	str("displayName", "The name displayed"), str("nickName", "Casual name"),
	{Name: "profileUrl", Type: "reference", RefTypes: []string{"external"}, Description: "Profile URL"},
	str("title", "Title"), str("userType", "Relationship to the organization"),
	str("preferredLanguage", "Preferred language"), str("locale", "Locale"), str("timezone", "Time zone"),
	{Name: "active", Type: "boolean", Description: "Whether the user may sign in"},
	{Name: "password", Type: "string", Mutability: "writeOnly", Returned: "never", Description: "Not supported: sign-in is federated"},
	multiComplex("emails", "Email addresses", "work", "home", "other"),
	multiComplex("phoneNumbers", "Phone numbers", "work", "home", "mobile", "fax", "pager", "other"),
	multiComplex("ims", "Instant messaging addresses", "aim", "gtalk", "icq", "xmpp", "msn", "skype", "qq", "yahoo"),
	multiComplex("photos", "Photo URLs", "photo", "thumbnail"),
	{Name: "addresses", Type: "complex", Multi: true, Description: "Physical addresses", Sub: []Attr{
		str("formatted", "Full address"), str("streetAddress", "Street"), str("locality", "City"), str("region", "Region"),
		str("postalCode", "Postal code"), str("country", "Country"), {Name: "type", Type: "string", Description: "work, home, other"},
		{Name: "primary", Type: "boolean", Description: "The primary address"},
	}},
	{Name: "groups", Type: "complex", Multi: true, Mutability: "readOnly", Description: "Groups the user belongs to", Sub: []Attr{
		{Name: "value", Type: "string", Mutability: "readOnly", CaseExact: true, Description: "The group's id"},
		{Name: "$ref", Type: "reference", Mutability: "readOnly", RefTypes: []string{"Group"}, Description: "The group's URI"},
		{Name: "display", Type: "string", Mutability: "readOnly", Description: "The group's name"},
		{Name: "type", Type: "string", Mutability: "readOnly", Description: "direct"},
	}},
	multiComplex("entitlements", "Entitlements"), multiComplex("roles", "Roles"),
	multiComplex("x509Certificates", "Certificates"),
}}

var groupSchema = Schema{ID: SchemaGroup, Name: "Group", Description: "Group", Attrs: []Attr{
	{Name: "displayName", Type: "string", Required: true, Description: "The group's name"},
	{Name: "members", Type: "complex", Multi: true, Description: "Members (users of the same IdP)", Sub: []Attr{
		{Name: "value", Type: "string", Mutability: "immutable", CaseExact: true, Description: "The member's id"},
		{Name: "$ref", Type: "reference", Mutability: "immutable", RefTypes: []string{"User"}, Description: "The member's URI"},
		{Name: "display", Type: "string", Mutability: "readOnly", Description: "The member's name"},
		{Name: "type", Type: "string", Mutability: "immutable", Description: "User"},
	}},
}}

var enterpriseSchema = Schema{ID: SchemaEnterprise, Name: "EnterpriseUser", Description: "Enterprise User", Attrs: []Attr{
	str("employeeNumber", "Employee number"), str("costCenter", "Cost center"), str("organization", "Organization"),
	str("division", "Division"), str("department", "Department"),
	{Name: "manager", Type: "complex", Description: "The user's manager", Sub: []Attr{
		str("value", "The manager's id"), {Name: "$ref", Type: "reference", RefTypes: []string{"User"}, Description: "URI"},
		{Name: "displayName", Type: "string", Mutability: "readOnly", Description: "The manager's name"},
	}},
}}

// Attributes common to every resource (RFC 7643 §3.1).
var commonAttrs = []Attr{
	{Name: "id", Type: "string", Mutability: "readOnly", Returned: "always", CaseExact: true, Uniqueness: "server"},
	{Name: "externalId", Type: "string", CaseExact: true},
	{Name: "meta", Type: "complex", Mutability: "readOnly", Sub: []Attr{
		{Name: "resourceType", Type: "string", Mutability: "readOnly", CaseExact: true},
		{Name: "created", Type: "dateTime", Mutability: "readOnly"},
		{Name: "lastModified", Type: "dateTime", Mutability: "readOnly"},
		{Name: "location", Type: "reference", Mutability: "readOnly", CaseExact: true},
		{Name: "version", Type: "string", Mutability: "readOnly", CaseExact: true},
	}},
}

// kind is a resource type.
type kind struct {
	Name, Endpoint string
	Schema         Schema
	Extensions     []Schema
}

var (
	userKind  = kind{Name: "User", Endpoint: "/Users", Schema: userSchema, Extensions: []Schema{enterpriseSchema}}
	groupKind = kind{Name: "Group", Endpoint: "/Groups", Schema: groupSchema}
)

// attr finds a top-level attribute of the kind (case-insensitive; with an
// extension URN, of that extension).
func (k kind) attr(urn, name string) (Attr, bool) {
	schemas := []Schema{k.Schema}
	if urn != "" && !strings.EqualFold(urn, k.Schema.ID) {
		schemas = nil
		for _, e := range k.Extensions {
			if strings.EqualFold(urn, e.ID) {
				schemas = []Schema{e}
			}
		}
	}
	for _, s := range schemas {
		for _, a := range s.Attrs {
			if strings.EqualFold(a.Name, name) {
				return a, true
			}
		}
	}
	if urn == "" || strings.EqualFold(urn, k.Schema.ID) {
		for _, a := range commonAttrs {
			if strings.EqualFold(a.Name, name) {
				return a, true
			}
		}
	}
	return Attr{}, false
}

func (a Attr) sub(name string) (Attr, bool) {
	for _, s := range a.Sub {
		if strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return Attr{}, false
}

// extension reports whether urn is one of the kind's extensions (its
// canonical spelling).
func (k kind) extension(urn string) (string, bool) {
	for _, e := range k.Extensions {
		if strings.EqualFold(urn, e.ID) {
			return e.ID, true
		}
	}
	return "", false
}
