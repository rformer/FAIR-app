package tests

import (
	"slices"
	"testing"
)

// F-003 T-12: the BUs a risk page may offer, with names, only in the
// caller's own scope.
func TestRiskScopeBUs(t *testing.T) {
	ra := newRiskAPI(t)
	codes := func(user, perm string) []string {
		t.Helper()
		got := ra.call(t, "GET", user, "/api/v1/risk/bus?permission="+perm, nil)
		if got.code != 200 {
			t.Fatalf("%s %s: %d %s", user, perm, got.code, got.raw)
		}
		var out []string
		for _, b := range got.body["bus"].([]any) {
			m := b.(map[string]any)
			if m["name"] == "" || m["id"] == "" {
				t.Fatalf("a BU without its name: %v", m)
			}
			out = append(out, m["code"].(string))
		}
		slices.Sort(out)
		return out
	}
	// analyst: Risk Analyst at A (A1 below it; R is restricted). erin:
	// Executive Viewer at A and Risk Owner at A1: read only.
	for _, c := range []struct {
		user, perm string
		want       []string
	}{
		{"analyst", "scenario.edit", []string{"A", "A1"}},
		{"analyst", "library.view", []string{"A", "A1"}},
		{"erin", "scenario.view", []string{"A", "A1"}},
		{"erin", "scenario.edit", nil},
		{"mallory", "control.edit", []string{"B"}},
	} {
		if got := codes(c.user, c.perm); !slices.Equal(got, c.want) {
			t.Errorf("%s %s: %v, want %v", c.user, c.perm, got, c.want)
		}
	}
	for _, perm := range []string{"", "audit.view", "scenario.manage", "bu.view"} {
		if got := ra.call(t, "GET", "analyst", "/api/v1/risk/bus?permission="+perm, nil); got.code != 400 {
			t.Errorf("%q: %d", perm, got.code)
		}
	}
	if got := ra.call(t, "GET", "buadmin2", "/api/v1/risk/bus?permission=scenario.view", nil); got.code != 404 {
		t.Fatalf("without risk permissions: %d", got.code)
	}
	// Only through the function; nothing outside the caller's scope.
	ra.mustFail("app_rw", "SELECT * FROM iam.bu", "permission denied")
	if got, err := ra.asCtx(ra.mint("analyst", ctxKey1), "SELECT count(*) FROM risk.scope_bus('scenario', 'write'); SELECT count(*) FROM risk.scope_bus('audit', 'read')"); err != nil || got != "2\n0" {
		t.Fatalf("scope_bus: %q %v", got, err)
	}
}
