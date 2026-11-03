package authn

import (
	"reflect"
	"strings"
	"testing"
)

func TestSAMLGroups(t *testing.T) {
	for name, c := range map[string]struct {
		attrs map[string][]string
		want  GroupClaim
	}{
		"values":     {map[string][]string{"groups": {"a", "b", "a", ""}}, GroupClaim{groupsPresent, []string{"a", "b"}}},
		"empty":      {map[string][]string{"groups": {}}, GroupClaim{groupsPresent, []string{}}},
		"absent":     {map[string][]string{"other": {"a"}}, GroupClaim{Status: groupsAbsent}},
		"overage":    {map[string][]string{samlOverage: {"https://graph"}}, GroupClaim{Status: groupsOverage}},
		"both":       {map[string][]string{"groups": {"a"}, samlOverage: {"x"}}, GroupClaim{groupsPresent, []string{"a"}}},
		"long value": {map[string][]string{"groups": {strings.Repeat("x", 257)}}, GroupClaim{Status: groupsUnreadable}},
		"256 runes":  {map[string][]string{"groups": {strings.Repeat("é", 256)}}, GroupClaim{groupsPresent, []string{strings.Repeat("é", 256)}}},
		"501 values": {map[string][]string{"groups": make([]string, 501)}, GroupClaim{Status: groupsUnreadable}},
	} {
		if got := SAMLGroups(c.attrs, "groups"); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v, want %+v", name, got, c.want)
		}
	}
}

func TestOIDCGroups(t *testing.T) {
	five := make([]any, 500)
	for i := range five {
		five[i] = "g"
	}
	for name, c := range map[string]struct {
		claims map[string]any
		want   GroupClaim
	}{
		"list":            {map[string]any{"groups": []any{"a", "b"}}, GroupClaim{groupsPresent, []string{"a", "b"}}},
		"string":          {map[string]any{"groups": "a"}, GroupClaim{groupsPresent, []string{"a"}}},
		"null":            {map[string]any{"groups": nil}, GroupClaim{Status: groupsAbsent}},
		"absent":          {map[string]any{}, GroupClaim{Status: groupsAbsent}},
		"_claim_names":    {map[string]any{"_claim_names": map[string]any{"groups": "src1"}}, GroupClaim{Status: groupsOverage}},
		"other claim ref": {map[string]any{"_claim_names": map[string]any{"roles": "src1"}}, GroupClaim{Status: groupsAbsent}},
		"hasgroups":       {map[string]any{"hasgroups": true}, GroupClaim{Status: groupsOverage}},
		"hasgroups text":  {map[string]any{"hasgroups": "True"}, GroupClaim{Status: groupsOverage}},
		"hasgroups false": {map[string]any{"hasgroups": false}, GroupClaim{Status: groupsAbsent}},
		"number":          {map[string]any{"groups": []any{"a", 1.0}}, GroupClaim{Status: groupsUnreadable}},
		"object":          {map[string]any{"groups": map[string]any{}}, GroupClaim{Status: groupsUnreadable}},
		"500":             {map[string]any{"groups": five}, GroupClaim{groupsPresent, []string{"g"}}},
		"501":             {map[string]any{"groups": append(five, "h")}, GroupClaim{Status: groupsUnreadable}},
	} {
		if got := OIDCGroups(c.claims, "groups"); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v, want %+v", name, got, c.want)
		}
	}
}
