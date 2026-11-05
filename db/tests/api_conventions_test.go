package tests

import (
	"strings"
	"testing"

	"github.com/rformer/fair-app/pkg/settings"
)

// F-001 T-42 (design §6): the conventions the OpenAPI lint declares hold at
// run time.

// Every Posture API operation on an id answers a missing id with 404, the
// same as an id outside the caller's reach.
func TestPostureAPIUnknownIDs(t *testing.T) {
	ae := apiFixture(t, settings.ProfileEnterpriseBaseline)
	missing := "00000000-0000-4000-8000-00000000dead"
	for _, c := range []struct {
		method, path string
		body         map[string]any
	}{
		{"POST", "/settings/no.such_setting", map[string]any{"value": "10m0s", "explanation": "x"}},
		{"POST", "/exceptions/" + missing + "/renew", map[string]any{"justification": "x"}},
		{"PATCH", "/profiles/no-such-profile", map[string]any{"version": "1", "key": "session.idle_timeout"}},
		{"POST", "/profiles/no-such-profile/submit", map[string]any{"version": "1"}},
		{"GET", "/profiles/no-such-profile/diff?version=1&against=enterprise-baseline@1.3.0", nil},
		{"GET", "/profiles/no-such-profile/export?version=1", nil},
		{"POST", "/switches/" + missing + "/conflicts/session.idle_timeout/resolve", map[string]any{"resolution": "conform"}},
		{"POST", "/switches/" + missing + "/activate", nil},
		{"POST", "/switches/" + missing + "/cancel", nil},
		{"GET", "/switches/" + missing, nil},
		{"POST", "/drift/" + missing + "/acknowledge", map[string]any{"reason": "x"}},
		{"GET", "/exports/" + missing, nil},
	} {
		key := ""
		if c.method != "GET" {
			key = "auto"
		}
		if r := ae.call(t, "admin", c.method, c.path, key, c.body); r.code != 404 {
			t.Errorf("%s %s: %d %s", c.method, c.path, r.code, strings.TrimSpace(r.raw))
		}
	}
}

// Posture mutations that carry no reason field of their own take an
// optional reason, recorded on the events they cause (design §6).
func TestPostureAPIOptionalReason(t *testing.T) {
	ae := apiFixture(t, settings.ProfileEnterpriseBaseline)
	r := ae.call(t, "admin", "POST", "/profiles", "auto", map[string]any{"base_id": settings.ProfileEnterpriseBaseline, "base_version": "1.3.0",
		"id": "acme", "name": "ACME", "reason": "client onboarding, ticket 7"})
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	ev := ae.mem.OfType("profile.created")
	if len(ev) != 1 || ev[0].Reason != "client onboarding, ticket 7" {
		t.Fatalf("profile.created: %+v", ev)
	}
	// Without one, as before.
	if r := ae.call(t, "admin", "POST", "/profiles", "auto", map[string]any{"base_id": settings.ProfileEnterpriseBaseline, "base_version": "1.3.0",
		"id": "acme2", "name": "ACME 2"}); r.code != 201 {
		t.Fatalf("create without a reason: %d %s", r.code, r.raw)
	}
	if ev := ae.mem.OfType("profile.created"); len(ev) != 2 || ev[1].Reason != "" {
		t.Fatalf("a reason leaked between requests: %+v", ev)
	}
}
