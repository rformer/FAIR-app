package scim

import (
	"encoding/json"
	"errors"
	"testing"
)

func doc(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// RFC 7644 §3.4.2.2: the operators, precedence, value paths, extension
// URNs, case rules and attribute types.
func TestFilterEval(t *testing.T) {
	u := doc(t, `{"id": "2819c223-7f76-453a-919d-413861904646", "externalId": "Ext-1", "userName": "Bjensen@Example.com",
		"name": {"familyName": "Jensen", "givenName": "Barbara"}, "active": true, "title": "Tour Guide",
		"emails": [{"value": "bjensen@example.com", "type": "work", "primary": true}, {"value": "babs@jensen.org", "type": "home"}],
		"meta": {"lastModified": "2011-05-13T04:42:34Z", "created": "2010-01-23T04:56:22Z"},
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"employeeNumber": "701984", "department": "Tours",
			"manager": {"value": "26118915-6090-4610-87e4-49d8ca9f808d"}}}`)
	for f, want := range map[string]bool{
		`userName eq "bjensen@example.com"`:                           true,  // caseExact false
		`USERNAME EQ "BJENSEN@EXAMPLE.COM"`:                           true,  // names and operators are case-insensitive
		`externalId eq "ext-1"`:                                       false, // caseExact true
		`externalId eq "Ext-1"`:                                       true,
		`id eq "2819C223-7F76-453A-919D-413861904646"`:                false,
		`userName ne "x"`:                                             true,
		`name.familyName co "ens"`:                                    true,
		`userName sw "bj"`:                                            true,
		`userName ew ".com"`:                                          true,
		`title pr`:                                                    true,
		`nickName pr`:                                                 false,
		`emails pr`:                                                   true,
		`emails co "jensen.org"`:                                      true, // a multi-valued complex: its values
		`emails.type eq "home"`:                                       true,
		`emails[type eq "work" and value co "@example.com"]`:          true,
		`emails[type eq "home" and value co "@example.com"]`:          false,
		`emails[type eq "work"] and active eq true`:                   true,
		`meta.lastModified gt "2011-05-13T04:42:34Z"`:                 false,
		`meta.lastModified ge "2011-05-13T04:42:34Z"`:                 true,
		`meta.lastModified lt "2011-05-13T04:42:34.5Z"`:               true, // compared as times
		`meta.created le "2010-01-23T04:56:22+00:00"`:                 true,
		`active eq false`:                                             false,
		`active ne false`:                                             true,
		`title pr and userName sw "x" or name.givenName eq "barbara"`: true, // and binds tighter
		`title pr and (userName sw "x" or name.givenName eq "x")`:     false,
		`not (userName sw "x")`:                                       true,
		`not(userName sw "b")`:                                        false,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName sw "bj"`: true,
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "701984"`: true,
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value pr`:           true,
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "Sales"`:      false,
		`nickName eq null`:          true, // absent
		`title eq "Tour \"Guide\""`: false,
	} {
		p, err := parseFilter(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if got := (scope{k: userKind}).eval(p, u); got != want {
			t.Errorf("%s: %t, want %t", f, got, want)
		}
	}
	g := doc(t, `{"displayName": "Tour Guides", "members": [{"value": "2819c223-7f76-453a-919d-413861904646", "display": "Babs"}]}`)
	for f, want := range map[string]bool{
		`members[value eq "2819c223-7f76-453a-919d-413861904646"]`: true,
		`members.value eq "2819c223-7f76-453a-919d-413861904646"`:  true,
		`members[value eq "2819C223-7F76-453A-919D-413861904646"]`: false, // member values are caseExact
		`displayName eq "tour guides"`:                             true,
	} {
		p, err := parseFilter(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if got := (scope{k: groupKind}).eval(p, g); got != want {
			t.Errorf("group %s: %t, want %t", f, got, want)
		}
	}
	n := doc(t, `{"x": 5}`)
	for f, want := range map[string]bool{`x gt 4`: true, `x le 4.5`: false, `x eq 5`: true} {
		p, _ := parseFilter(f)
		if got := (scope{k: userKind}).eval(p, n); got != want {
			t.Errorf("%s: %t", f, got)
		}
	}
}

func TestFilterErrors(t *testing.T) {
	for _, f := range []string{
		``, `userName`, `userName eq`, `userName xx "a"`, `userName eq "a" and`, `(userName eq "a"`, `userName eq "a")`,
		`emails[type eq "work"`, `active gt true`, `title co 5`, `userName eq bareword`, `userName eq "unterminated`,
		`name.givenName.x eq "a"`, `1abc eq "a"`, `not userName eq "a"`, `emails.value[type eq "x"]`,
	} {
		if _, err := parseFilter(f); !errors.Is(err, errFilter) {
			t.Errorf("%q: %v, want invalid filter", f, err)
		}
	}
	deep := ""
	for range 40 {
		deep += "("
	}
	if _, err := parseFilter(deep + `a eq "b"`); err == nil {
		t.Error("deep nesting accepted")
	}
}
