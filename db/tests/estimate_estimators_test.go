package tests

import (
	"strings"
	"testing"
)

// F-004 T-13 (F-004-AC-01; design §5, migration 0100): the people an analyst
// may name as estimators at a BU, by name, through the API.
func TestEstimateEstimatorsAPI(t *testing.T) {
	ra := strideF003Fixture(t) // analysts platform2 at ENTERPRISE, analyst at A, buadmin at A1, buadmin3 at R; mallory at B
	ea := estimateAPI(t, ra)
	for _, u := range []string{"dana", "sam", "rhea", "gwen", "olga", "viewer"} {
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + strings.ToUpper(u[:1]) + u[1:] + "')")
	}
	ra.mustOwner(grant("platform", "user:dana", "Estimator", "A"))
	ra.mustOwner(grant("platform", "user:sam", "Estimator", "A1"))
	ra.mustOwner(grant("platform", "user:rhea", "Estimator", "ENTERPRISE"))
	ra.mustOwner(grant("platform", "user:olga", "Estimator", "A"))
	ra.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('Estimators A')")
	ra.mustOwner("INSERT INTO iam.grp_member (grp_id, user_id) SELECT " + grpID("Estimators A") + ", id FROM iam.app_user WHERE email = 'gwen@example.test'")
	ra.mustOwner(grant("platform", "group:Estimators A", "Estimator", "A"))
	ra.mustOwner(grant("platform", "user:viewer", "Executive Viewer", "A"))
	ra.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE email = 'olga@example.test'")
	ra.drain()
	names := func(user, bu string) (int, string) {
		t.Helper()
		got := ea.call(t, "GET", user, "/api/v1/estimates/estimators?bu="+bu, nil)
		if got.code != 200 {
			return got.code, got.raw
		}
		var out []string
		for _, e := range got.body["estimators"].([]any) {
			m := e.(map[string]any)
			if m["user_id"] == "" {
				t.Fatalf("no id: %s", got.raw)
			}
			out = append(out, m["name"].(string))
		}
		return 200, strings.Join(out, ",")
	}

	// At A: direct and group holders and those above, by name; never the
	// disabled, never those holding it only below (sam at A1).
	if code, got := names("analyst", ra.bu["A"]); code != 200 || got != "Dana,Gwen,Rhea" {
		t.Fatalf("at A: %d %s", code, got)
	}
	if code, got := names("buadmin", ra.bu["A1"]); code != 200 || got != "Dana,Gwen,Rhea,Sam" {
		t.Fatalf("at A1: %d %s", code, got)
	}
	// A restricted BU blocks holders above it.
	if code, got := names("buadmin3", ra.bu["R"]); code != 200 || got != "" {
		t.Fatalf("at R: %d %s", code, got)
	}
	// Not the caller's BU, no estimate.request, or a malformed bu.
	for _, c := range []struct {
		user, bu string
		code     int
	}{{"mallory", ra.bu["A"], 404}, {"analyst", ra.bu["B"], 404}, {"viewer", ra.bu["A"], 404}, {"analyst", "x", 400}} {
		if code, raw := names(c.user, c.bu); code != c.code {
			t.Fatalf("%s at %s: %d %s", c.user, c.bu, code, raw)
		}
	}
}
