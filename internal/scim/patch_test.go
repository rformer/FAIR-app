package scim

import (
	"encoding/json"
	"errors"
	"testing"
)

func ops(t *testing.T, s string) []PatchOp {
	t.Helper()
	var o []PatchOp
	if err := json.Unmarshal([]byte(s), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func js(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestPatchUser(t *testing.T) {
	pt := patcher{k: userKind}
	base := `{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "bjensen", "active": true,
		"name": {"givenName": "Barbara", "familyName": "Jensen"},
		"emails": [{"value": "bjensen@example.com", "type": "work", "primary": true}],
		"groups": [{"value": "g1"}]}`
	for _, tc := range []struct {
		name, ops, check string
		get              func(map[string]any) any
	}{
		{"replace without a path (Entra deactivation, string boolean)", `[{"op": "Replace", "value": {"active": "False"}}]`, "false",
			func(d map[string]any) any { return d["active"] }},
		{"replace a simple attribute", `[{"op": "replace", "path": "userName", "value": "babs"}]`, `"babs"`,
			func(d map[string]any) any { return d["userName"] }},
		{"replace a sub-attribute", `[{"op": "replace", "path": "name.givenName", "value": "Babs"}]`, `"Babs"`,
			func(d map[string]any) any { return d["name"].(map[string]any)["givenName"] }},
		{"add merges a complex attribute", `[{"op": "add", "path": "name", "value": {"middleName": "Jane"}}]`, `{"familyName":"Jensen","givenName":"Barbara","middleName":"Jane"}`,
			func(d map[string]any) any { return d["name"] }},
		{"add appends to a multi-valued attribute and moves primary", `[{"op": "add", "path": "emails", "value": [{"value": "b@home.org", "type": "home", "primary": true}]}]`,
			`[{"primary":false,"type":"work","value":"bjensen@example.com"},{"primary":true,"type":"home","value":"b@home.org"}]`,
			func(d map[string]any) any { return d["emails"] }},
		{"add of an existing value is a no-op", `[{"op": "add", "path": "emails", "value": [{"value": "bjensen@example.com", "type": "work"}]}]`,
			`[{"primary":true,"type":"work","value":"bjensen@example.com"}]`, func(d map[string]any) any { return d["emails"] }},
		{"replace a filtered element's sub-attribute (Entra)", `[{"op": "replace", "path": "emails[type eq \"work\"].value", "value": "new@example.com"}]`,
			`[{"primary":true,"type":"work","value":"new@example.com"}]`, func(d map[string]any) any { return d["emails"] }},
		{"add to a missing filtered element creates it (Entra)", `[{"op": "add", "path": "phoneNumbers[type eq \"mobile\"].value", "value": "+1 555 0100"}]`,
			`[{"type":"mobile","value":"+1 555 0100"}]`, func(d map[string]any) any { return d["phoneNumbers"] }},
		{"remove a filtered element", `[{"op": "remove", "path": "emails[type eq \"work\"]"}]`, `[]`,
			func(d map[string]any) any { return d["emails"] }},
		{"remove an attribute", `[{"op": "remove", "path": "name"}]`, `null`, func(d map[string]any) any { return d["name"] }},
		{"an extension attribute by URN path", `[{"op": "add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Tours"}]`,
			`{"department":"Tours"}`, func(d map[string]any) any { return d[SchemaEnterprise] }},
		{"an extension object without a path (Entra)", `[{"op": "add", "value": {"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"employeeNumber": "42"}}}]`,
			`{"employeeNumber":"42"}`, func(d map[string]any) any { return d[SchemaEnterprise] }},
		{"the extension's schema is listed", `[{"op": "add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:division", "value": "X"}]`,
			`["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]`,
			func(d map[string]any) any { return d["schemas"] }},
		{"a dotted key without a path", `[{"op": "replace", "value": {"name.familyName": "J"}}]`, `"J"`,
			func(d map[string]any) any { return d["name"].(map[string]any)["familyName"] }},
		{"operations apply in order", `[{"op": "replace", "path": "title", "value": "A"}, {"op": "replace", "path": "title", "value": "B"}]`, `"B"`,
			func(d map[string]any) any { return d["title"] }},
		{"case-insensitive names keep one spelling", `[{"op": "replace", "path": "USERNAME", "value": "x"}]`, `"x"`,
			func(d map[string]any) any { return d["userName"] }},
	} {
		d := doc(t, base)
		if err := pt.Apply(d, ops(t, tc.ops)); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := js(tc.get(d)); got != tc.check {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.check)
		}
		if _, dup := d["USERNAME"]; dup {
			t.Errorf("%s: two spellings of userName", tc.name)
		}
	}

	for name, c := range map[string]struct{ ops, scimType string }{
		"read-only attribute":     {`[{"op": "replace", "path": "groups", "value": []}]`, "mutability"},
		"read-only id":            {`[{"op": "replace", "path": "id", "value": "x"}]`, "mutability"},
		"remove without a path":   {`[{"op": "remove"}]`, "noTarget"},
		"unknown op":              {`[{"op": "move", "path": "title"}]`, "invalidSyntax"},
		"unknown attribute":       {`[{"op": "replace", "path": "shoeSize", "value": 9}]`, "invalidPath"},
		"bad filter":              {`[{"op": "replace", "path": "emails[type eq]", "value": "x"}]`, "invalidPath"},
		"filter on a simple attr": {`[{"op": "replace", "path": "title[value eq \"x\"]", "value": "x"}]`, "invalidPath"},
		"no match to replace":     {`[{"op": "replace", "path": "emails[type eq \"home\" and primary eq true]", "value": {"value": "x"}}]`, "noTarget"},
		"no path, not an object":  {`[{"op": "add", "value": "x"}]`, "invalidSyntax"},
		"unknown extension":       {`[{"op": "add", "path": "urn:example:ext:1.0:User:x", "value": 1}]`, "invalidPath"},
		"no operations":           {`[]`, "invalidSyntax"},
	} {
		err := pt.Apply(doc(t, base), ops(t, c.ops))
		var e *Error
		if !errors.As(err, &e) || e.Status != 400 || e.ScimType != c.scimType {
			t.Errorf("%s: %v, want 400 %s", name, err, c.scimType)
		}
	}
}

func TestPatchGroupMembers(t *testing.T) {
	pt := patcher{k: groupKind}
	g := func() map[string]any {
		return doc(t, `{"displayName": "Tour Guides", "members": [{"value": "a"}, {"value": "b"}]}`)
	}
	members := func(d map[string]any) string {
		var out []any
		for _, m := range asList(d["members"]) {
			out = append(out, m.(map[string]any)["value"])
		}
		return js(out)
	}
	for _, tc := range []struct{ name, ops, want string }{
		{"add members", `[{"op": "add", "path": "members", "value": [{"value": "c"}, {"value": "a"}]}]`, `["a","b","c"]`},
		{"remove by filter (RFC)", `[{"op": "remove", "path": "members[value eq \"a\"]"}]`, `["b"]`},
		{"remove a member that is not there", `[{"op": "remove", "path": "members[value eq \"z\"]"}]`, `["a","b"]`},
		{"remove with a value list (Entra, Okta)", `[{"op": "Remove", "path": "members", "value": [{"value": "b"}]}]`, `["a"]`},
		{"remove all members", `[{"op": "remove", "path": "members"}]`, `null`},
		{"replace members", `[{"op": "replace", "path": "members", "value": [{"value": "x"}]}]`, `["x"]`},
		{"add without a path (Okta)", `[{"op": "add", "value": {"members": [{"value": "d"}]}}]`, `["a","b","d"]`},
	} {
		d := g()
		if err := pt.Apply(d, ops(t, tc.ops)); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := members(d); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

// prepare: read-only attributes ignored, types checked, members are users.
func TestPrepare(t *testing.T) {
	res, _, err := prepare(userKind, doc(t, `{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "id": "x", "meta": {}, "groups": [],
		"username": "a", "password": "secret", "active": "true", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user": {"department": "D"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if js(res) != `{"active":true,"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"D"},"userName":"a"}` {
		t.Fatalf("prepared %s", js(res))
	}
	for name, in := range map[string]string{
		"wrong schema":          `{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "userName": "a"}`,
		"emails not a list":     `{"emails": {"value": "a@b.c"}}`,
		"active not a boolean":  `{"active": "maybe"}`,
		"userName not a string": `{"userName": 5}`,
	} {
		if _, _, err := prepare(userKind, doc(t, in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, members, err := prepare(groupKind, doc(t, `{"displayName": "G", "members": [{"value": "2819C223-7F76-453A-919D-413861904646"}]}`))
	if err != nil || js(members) != `["2819c223-7f76-453a-919d-413861904646"]` {
		t.Fatalf("members %v %v", members, err)
	}
	for name, in := range map[string]string{
		"not an id":      `{"displayName": "G", "members": [{"value": "bob"}]}`,
		"a nested group": `{"displayName": "G", "members": [{"value": "2819c223-7f76-453a-919d-413861904646", "type": "Group"}]}`,
		"no value":       `{"displayName": "G", "members": [{"display": "x"}]}`,
	} {
		if _, _, err := prepare(groupKind, doc(t, in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// userFieldsOf: email from the primary, display name from name, subject.
	f, err := userFieldsOf(doc(t, `{"userName": "bj", "externalId": "E1", "name": {"givenName": "B", "familyName": "J"},
		"emails": [{"value": "x@a.b"}, {"value": "p@a.b", "primary": true}], "active": false}`), "externalId")
	if err != nil || f.Email != "p@a.b" || f.DisplayName != "B J" || f.Subject != "E1" || f.Active {
		t.Fatalf("%+v %v", f, err)
	}
	if f, _ := userFieldsOf(doc(t, `{"userName": "u@a.b"}`), "userName"); f.Email != "u@a.b" || f.Subject != "u@a.b" || !f.Active {
		t.Fatalf("%+v", f)
	}
	if _, err := userFieldsOf(doc(t, `{"userName": "nomail"}`), "userName"); err == nil {
		t.Fatal("a user without any email accepted")
	}
}
