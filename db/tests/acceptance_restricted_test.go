package tests

import (
	"slices"
	"testing"
)

// F-008 design §3.4 (amended 2026-11-15): inside a restricted subtree, a
// tier's BU never leaves it: levels up and tier 3 stop at its top (R),
// whose approvers see and decide it; the root's approvers do not.
func TestAcceptanceRestrictedTier(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	for user, role := range map[string]string{"rowner": "Risk Owner", "ranalyst": "Risk Analyst", "appR": "Approver", "appR2": "Approver"} {
		ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + user + "@example.test', '" + user + "')")
		ra.mustOwner(grant("platform", "user:"+user, role, "R"))
	}
	ra.drain()
	rowner := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rowner@example.test'")
	ac := acceptanceAPI(t, ra)
	risk := func(name string) string {
		t.Helper()
		s := scenarioAt(t, ra, "ranalyst", ra.bu["R1"], name)
		run := runWith(t, a.ae, "ranalyst", s, 1, 2000, "7")
		got := a.rg.call(t, "POST", "rowner", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["R1"], "change_note": "x",
			"document": map[string]any{"schema_version": 1, "title": name, "owner": rowner, "state": "open",
				"scenarios": []any{map[string]any{"scenario_id": s, "pin": map[string]any{"run_id": run, "control_set": "Current"}}}}})
		if got.code != 201 {
			t.Fatalf("risk %s: %d %s", name, got.code, got.raw)
		}
		id := got.body["id"].(string)
		if got := a.rg.call(t, "PUT", "rowner", "/api/v1/register/risks/"+id+"/treatment", map[string]any{"expected_version": 0, "change_note": "accept",
			"document": map[string]any{"schema_version": 1, "decision": "accept", "rationale": "Within appetite."}}); got.code != 200 {
			t.Fatalf("treatment: %d %s", got.code, got.raw)
		}
		return id
	}
	request := func(r string) map[string]any {
		t.Helper()
		got := ac.call(t, "POST", "rowner", "/api/v1/acceptances", map[string]any{"risk_id": r, "justification": "Within appetite", "expires_on": days(90).Format("2006-01-02")})
		if got.code != 201 {
			t.Fatalf("request: %d %s", got.code, got.raw)
		}
		return got.body
	}
	code := func(id string) string { return ra.adminQuery("SELECT code FROM iam.bu WHERE id = '" + id + "'") }

	// Tier 1: the risk's own BU (R1).
	if got := request(risk("Casework leak")); got["tier"] != 1.0 || code(got["tier_bu_id"].(string)) != "R1" {
		t.Errorf("tier 1: %v at %s", got["tier"], code(got["tier_bu_id"].(string)))
	}
	// Tier 2, five levels up: capped at R.
	setInstance(ra.env, "acceptance.tier1_max", "1")
	setInstance(ra.env, "acceptance.tier2_levels_up", "5")
	if got := request(risk("Casework fraud")); got["tier"] != 2.0 || code(got["tier_bu_id"].(string)) != "R" {
		t.Errorf("tier 2: %v at %s", got["tier"], code(got["tier_bu_id"].(string)))
	}
	// Tier 3 (the root outside restricted subtrees): R, two approvals there.
	setInstance(ra.env, "acceptance.tier2_max", "2")
	t3 := request(risk("Casework outage"))
	id := t3["id"].(string)
	if t3["tier"] != 3.0 || code(t3["tier_bu_id"].(string)) != "R" || t3["approvals_needed"] != 2.0 {
		t.Errorf("tier 3: %v at %s, %v approvals", t3["tier"], code(t3["tier_bu_id"].(string)), t3["approvals_needed"])
	}
	setInstance(ra.env, "acceptance.tier1_max", "100000")
	setInstance(ra.env, "acceptance.tier2_max", "1000000")
	setInstance(ra.env, "acceptance.tier2_levels_up", "1")
	inbox := func(user string) []string {
		var out []string
		for _, x := range ac.call(t, "GET", user, "/api/v1/acceptances/inbox", nil).body["acceptances"].([]any) {
			out = append(out, x.(map[string]any)["id"].(string))
		}
		return out
	}
	if !slices.Contains(inbox("appR"), id) || slices.Contains(inbox("root1"), id) {
		t.Errorf("inboxes: appR %v, root1 %v", inbox("appR"), inbox("root1"))
	}
	decide := func(user string) int {
		return ac.call(t, "POST", user, "/api/v1/acceptances/"+id+"/decisions", map[string]any{"decision": "approve", "rationale": "Reviewed"}).code
	}
	if got := decide("root1"); got != 404 {
		t.Errorf("the root's approver decides: %d", got)
	}
	if decide("appR") != 200 || decide("appR2") != 200 {
		t.Fatal("R's approvers")
	}
	if got := ac.call(t, "GET", "rowner", "/api/v1/acceptances/"+id, nil).body["state"]; got != "active" {
		t.Errorf("after both: %v", got)
	}
	// Outside restricted subtrees tier 3 is still the root.
	if got := ra.adminQuery("SELECT (SELECT code FROM iam.bu WHERE id = acceptance.tier_bu('" + ra.bu["A1"] + "', NULL))"); got != "ENTERPRISE" {
		t.Errorf("tier 3 outside: %s", got)
	}
}
