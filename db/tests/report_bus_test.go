package tests

import (
	"slices"
	"testing"
)

// F-010 T-17 (design §6): GET /api/v1/reports/bus?permission= lists the
// live BUs where the caller holds report.view or report.export, by the rule
// authz.Check applies (subtrees, paths blocked at restricted BUs); any other
// permission is 400, and a caller with neither permission anywhere gets 404.
func TestReportBUs(t *testing.T) {
	ra := strideF003Fixture(t)
	seedPosture(t, ra.env)
	reportUsers(ra)
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('analyst2@example.test', 'Estimator Two')")
	ra.mustOwner(grant("platform", "user:analyst2", "Estimator", "A"))
	ra.drain()
	re := reportAPI(t, ra)
	codes := func(user, perm string) (int, []string) {
		t.Helper()
		got := re.call(t, "GET", user, "/api/v1/reports/bus?permission="+perm, nil)
		var out []string
		if l, ok := got.body["bus"].([]any); ok {
			for _, b := range l {
				out = append(out, b.(map[string]any)["id"].(string))
			}
		}
		return got.code, out
	}
	code, bus := codes("pubroot", "report.export")
	if code != 200 || !slices.Contains(bus, ra.bu["ENTERPRISE"]) || !slices.Contains(bus, ra.bu["A"]) || !slices.Contains(bus, ra.bu["B"]) {
		t.Fatalf("pubroot report.export: %d %v", code, bus)
	}
	if slices.Contains(bus, ra.bu["R"]) || slices.Contains(bus, ra.bu["R1"]) {
		t.Fatalf("a grant at the root does not reach a restricted subtree: %v", bus)
	}
	code, bus = codes("pub", "report.export")
	if code != 200 || !slices.Contains(bus, ra.bu["A"]) || slices.Contains(bus, ra.bu["ENTERPRISE"]) || slices.Contains(bus, ra.bu["B"]) {
		t.Fatalf("pub report.export: %d %v", code, bus)
	}
	code, bus = codes("viewer", "report.view")
	if code != 200 || !slices.Contains(bus, ra.bu["A"]) {
		t.Fatalf("viewer report.view: %d %v", code, bus)
	}
	if code, bus = codes("viewer", "report.export"); code != 200 || len(bus) != 0 {
		t.Fatalf("viewer report.export: %d %v", code, bus)
	}
	if code, _ = codes("pub", "register.view"); code != 400 {
		t.Fatalf("another permission: %d", code)
	}
	if code, _ = codes("analyst2", "report.view"); code != 404 {
		t.Fatalf("without report permissions: %d", code)
	}
	// The function itself refuses other permissions.
	if _, err := ra.as("app_rw", "SELECT * FROM report.scope_bus('register.view')"); err == nil {
		t.Fatal("report.scope_bus('register.view') answered")
	}
}
