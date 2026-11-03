package authn

import (
	"context"
	"strings"
	"unicode/utf8"
)

// Group claims (F-001 T-24b, AC-12, AC-13). An IdP's group_claim setting
// names the SAML attribute or OIDC claim that lists the user's groups. At
// each sign-in the values set the user's membership in the IdP's declared
// claim groups (iam.login_group_claims); the T-24 mappings then grant or
// revoke the mapped roles in the same transaction.

// Claim caps: a claim over them is not read, and memberships stay.
const (
	MaxGroupValues    = 500
	MaxGroupValueSize = 256
)

// Group claim statuses, as iam.login_group_claims takes them.
const (
	groupsPresent    = "present"    // the claim's values (none when empty)
	groupsAbsent     = "absent"     // no claim: no claim groups
	groupsOverage    = "overage"    // the IdP sent a pointer instead of the groups
	groupsUnreadable = "unreadable" // over the caps, or not strings
)

// GroupClaim is a sign-in's group claim.
type GroupClaim struct {
	Status string
	Values []string
}

// samlOverage is the attribute Entra ID sends instead of the groups when a
// user has too many.
const samlOverage = "http://schemas.microsoft.com/claims/groups.link"

// SAMLGroups reads the attribute name from an assertion's attributes.
func SAMLGroups(attrs map[string][]string, name string) GroupClaim {
	vals, ok := attrs[name]
	if !ok {
		if _, over := attrs[samlOverage]; over {
			return GroupClaim{Status: groupsOverage}
		}
		return GroupClaim{Status: groupsAbsent}
	}
	return capped(vals)
}

// OIDCGroups reads the claim name from an ID token's claims: a list of
// strings, or one string. Entra ID signals an overage with _claim_names
// naming the claim, or hasgroups.
func OIDCGroups(claims map[string]any, name string) GroupClaim {
	v, ok := claims[name]
	if !ok || v == nil {
		if names, _ := claims["_claim_names"].(map[string]any); names != nil {
			if _, over := names[name]; over {
				return GroupClaim{Status: groupsOverage}
			}
		}
		switch h := claims["hasgroups"].(type) {
		case bool:
			if h {
				return GroupClaim{Status: groupsOverage}
			}
		case string:
			if strings.EqualFold(h, "true") {
				return GroupClaim{Status: groupsOverage}
			}
		}
		return GroupClaim{Status: groupsAbsent}
	}
	switch x := v.(type) {
	case string:
		return capped([]string{x})
	case []any:
		if len(x) > MaxGroupValues {
			return GroupClaim{Status: groupsUnreadable}
		}
		vals := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return GroupClaim{Status: groupsUnreadable}
			}
			vals = append(vals, s)
		}
		return capped(vals)
	}
	return GroupClaim{Status: groupsUnreadable}
}

// capped: the values, or unreadable over the caps. Duplicates are dropped.
func capped(vals []string) GroupClaim {
	if len(vals) > MaxGroupValues {
		return GroupClaim{Status: groupsUnreadable}
	}
	seen := make(map[string]bool, len(vals))
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if utf8.RuneCountInString(v) > MaxGroupValueSize {
			return GroupClaim{Status: groupsUnreadable}
		}
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return GroupClaim{Status: groupsPresent, Values: out}
}

// applyGroups sets the user's claim-group membership when the IdP names a
// group claim; without one, claim groups are not used and nothing changes.
func (h *Logins) applyGroups(ctx context.Context, userID, idpID, claim string, groups func(string) GroupClaim) error {
	if claim == "" || groups == nil {
		return nil
	}
	g := groups(claim)
	vals := g.Values
	if vals == nil {
		vals = []string{}
	}
	_, err := h.DB.Exec(ctx, "SELECT iam.login_group_claims($1, $2, $3, $4)", userID, idpID, g.Status, vals)
	return err
}
