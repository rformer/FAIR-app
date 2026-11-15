package tests

import (
	"slices"
	"testing"
)

// F-007 T-08 (F-007-AC-01, AC-19): what the register pages choose from:
// business units by register or treatment permission, who may own a risk
// at a business unit, and the owner's name on a risk.

func TestRegisterPickers(t *testing.T) {
	ra := strideF003Fixture(t) // analyst a Risk Analyst at A, erin a Risk Owner at A1, mallory at B
	registerUsers(ra)          // owen a Risk Owner at A, chief at the root, est an Estimator at A
	seedPosture(t, ra.env)
	rg := registerAPI(t, ra)
	codes := func(user, perm string) []string {
		t.Helper()
		got := rg.call(t, "GET", user, "/api/v1/register/bus?permission="+perm, nil)
		if got.code != 200 {
			t.Fatalf("%s %s: %d %s", user, perm, got.code, got.raw)
		}
		var out []string
		for _, b := range got.body["bus"].([]any) {
			out = append(out, b.(map[string]any)["code"].(string))
		}
		slices.Sort(out)
		return out
	}
	if got := codes("owen", "register.edit"); !slices.Equal(got, []string{"A", "A1"}) {
		t.Errorf("owen edits the register at %v", got)
	}
	if got := codes("analyst", "register.edit"); len(got) != 0 {
		t.Errorf("the analyst edits the register at %v", got)
	}
	if got := codes("analyst", "treatment.view"); !slices.Equal(got, []string{"A", "A1"}) {
		t.Errorf("the analyst reads treatment at %v", got)
	}
	if got := rg.call(t, "GET", "owen", "/api/v1/register/bus?permission=scenario.view", nil); got.code != 400 {
		t.Errorf("another permission: %d", got.code)
	}
	if got := rg.call(t, "GET", "est", "/api/v1/register/bus?permission=register.view", nil); got.code != 404 {
		t.Errorf("no register permission: %d", got.code)
	}

	// Owners: users with register.view at the BU, names only, for editors there.
	got := rg.call(t, "GET", "owen", "/api/v1/register/owners?bu="+ra.bu["A1"], nil)
	if got.code != 200 {
		t.Fatalf("owners: %d %s", got.code, got.raw)
	}
	var names []string
	for _, o := range got.body["owners"].([]any) {
		m := o.(map[string]any)
		if len(m) != 2 || m["user_id"] == nil {
			t.Errorf("an owner entry: %v", m)
		}
		names = append(names, m["name"].(string))
	}
	for _, want := range []string{"Owen", "Chief"} {
		if !slices.Contains(names, want) {
			t.Errorf("owners at A1 %v lack %s", names, want)
		}
	}
	if slices.Contains(names, "Est") {
		t.Errorf("an estimator offered as owner: %v", names)
	}
	if got := rg.call(t, "GET", "analyst", "/api/v1/register/owners?bu="+ra.bu["A1"], nil); got.code != 403 {
		t.Errorf("owners for a viewer: %d", got.code)
	}
	if got := rg.call(t, "GET", "owen", "/api/v1/register/owners?bu="+ra.bu["B"], nil); got.code != 404 {
		t.Errorf("owners at an unseen BU: %d", got.code)
	}

	// The owner's name on a risk.
	owen := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'owen@example.test'")
	created := rg.call(t, "POST", "owen", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "change_note": "x",
		"document": map[string]any{"schema_version": 1, "title": "Claims outage", "owner": owen, "state": "open", "scenarios": []any{}}})
	if created.code != 201 {
		t.Fatalf("create: %d %s", created.code, created.raw)
	}
	if got := rg.call(t, "GET", "analyst", "/api/v1/register/risks/"+created.body["id"].(string), nil); got.body["risk"].(map[string]any)["owner_name"] != "Owen" {
		t.Errorf("the owner's name: %s", got.raw)
	}
}
