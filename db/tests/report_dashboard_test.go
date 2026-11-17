package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/reports"
)

// F-010 T-14 (F-010-AC-01 to AC-05; design §3.1): the dashboard API. Its
// counts equal the register's for the same person; the roll-up is the
// caller's own; restricted units appear by their roll-up mode, as totals
// (report.aggregate_counts) or not at all.
func TestReportDashboard(t *testing.T) {
	a := acceptanceFixture(t)
	ra, rg := a.ra, a.rg
	ctx := context.Background()
	ra.mustOwner("UPDATE iam.bu SET rollup_mode = 'aggregate' WHERE code IN ('R', 'R1')")
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('rown@example.test', 'Rown')")
	ra.mustOwner(grant("platform", "user:rown", "Risk Owner", "R"))
	ra.drain()
	rown := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rown@example.test'")
	mk := func(user, bu, title, owner string) {
		t.Helper()
		got := rg.call(t, "POST", user, "/api/v1/register/risks", map[string]any{"bu_id": bu, "change_note": "x",
			"document": map[string]any{"schema_version": 1, "title": title, "owner": owner, "state": "open", "scenarios": []any{}}})
		if got.code != 201 {
			t.Fatalf("create %s: %d %s", title, got.code, got.raw)
		}
	}
	mk("rown", ra.bu["R"], "Restricted risk", rown)
	mk("rown", ra.bu["R"], "Restricted risk 2", rown)
	mk("chief", ra.bu["B"], "Vendor outage", a.chief)
	risk := a.accepted(t, "Claims leak", "owen")
	acc, code := a.request(t, "owen", risk, "Within appetite", days(20), "")
	if code != "" {
		t.Fatalf("request: %s", code)
	}
	if _, code := a.decide(t, "appA1", acc, "approve"); code != "" {
		t.Fatalf("approve: %s", code)
	}
	if got := rg.call(t, "PUT", "owen", "/api/v1/register/risks/"+a.risk+"/treatment", map[string]any{"expected_version": 0, "change_note": "plan",
		"document": map[string]any{"schema_version": 1, "decision": "transfer", "rationale": "Insure it.", "actions": []any{
			map[string]any{"id": "a1a1a1a1-0000-4000-8000-000000000001", "title": "Buy cover", "owner": a.owen, "due": "2020-01-01", "state": "planned"}}}}); got.code != 200 {
		t.Fatalf("treatment: %d %s", got.code, got.raw)
	}
	re := reportAPI(t, ra, reports.Kinds())
	dash := func(user, bu string) apiResp {
		t.Helper()
		return re.call(t, "GET", user, "/api/v1/reports/dashboard?bu="+ra.bu[bu], nil)
	}

	// Who may: report.view at the BU.
	for _, c := range []struct {
		user, bu string
		code     int
	}{{"est", "A", 404}, {"mallory", "A", 404}, {"chief", "ENTERPRISE", 200}, {"owen", "A1", 200}} {
		if got := dash(c.user, c.bu); got.code != c.code {
			t.Errorf("%s at %s: %d %s", c.user, c.bu, got.code, got.raw)
		}
	}

	// The coverage equals the register's open risks for chief (AC-01).
	got := dash("chief", "ENTERPRISE")
	list := rg.call(t, "GET", "chief", "/api/v1/register/risks?state=open&limit=200&bu="+ra.bu["ENTERPRISE"], nil)
	status := map[string]int{}
	for _, x := range list.body["risks"].([]any) {
		status[x.(map[string]any)["status"].(map[string]any)["status"].(string)]++
	}
	cov := got.body["coverage"].(map[string]any)
	if int(cov["open"].(float64)) != len(list.body["risks"].([]any)) || int(cov["current"].(float64)) != status["current"] ||
		int(cov["unquantified"].(float64)) != status["unquantified"] || cov["open"] != 3.0 {
		t.Errorf("coverage %v, register %v", cov, status)
	}
	largest := got.body["largest"].([]any)
	if len(largest) != 2 || largest[0].(map[string]any)["mean"] != 4.5 || largest[0].(map[string]any)["p90"] != 9.0 {
		t.Errorf("largest: %v", largest)
	}
	acc2 := got.body["acceptances"].(map[string]any)
	tr := got.body["treatment"].(map[string]any)
	if acc2["active"] != 1.0 || acc2["expiring"] != 1.0 || tr["open"] != 1.0 || tr["overdue"] != 1.0 || got.body["rollup"] != nil {
		t.Errorf("acceptances %v, treatment %v, rollup %v", acc2, tr, got.body["rollup"])
	}
	var units []string
	for _, c := range got.body["children"].([]any) {
		units = append(units, c.(map[string]any)["name"].(string))
	}
	if strings.Join(units, ",") != "A,B" {
		t.Errorf("children: %v", units)
	}

	// Restricted units by mode (AC-04): Aggregate only gives totals equal to
	// what rown reads in R, never a risk.
	restricted, _ := got.body["restricted"].(map[string]any)
	inR := rg.call(t, "GET", "rown", "/api/v1/register/risks?state=open&bu="+ra.bu["R"], nil)
	if restricted == nil || restricted["units"] != 2.0 || int(restricted["open_risks"].(float64)) != len(inR.body["risks"].([]any)) ||
		restricted["unquantified"] != 2.0 || strings.Contains(got.raw, "Restricted risk") {
		t.Errorf("restricted (aggregate only): %v; rown reads %d", restricted, len(inR.body["risks"].([]any)))
	}
	if lo := got.body["left_out"].(map[string]any); lo["units_aggregate_only"] != 2.0 {
		t.Errorf("left out: %v", lo)
	}
	ra.mustOwner("UPDATE iam.bu SET rollup_mode = 'excluded' WHERE code IN ('R', 'R1')")
	ra.drain()
	if got := dash("chief", "ENTERPRISE"); got.body["restricted"] != nil || got.body["left_out"].(map[string]any)["units_not_visible"] != 2.0 {
		t.Errorf("restricted (excluded): %v %v", got.body["restricted"], got.body["left_out"])
	}

	// The roll-up is the caller's own: chief's roll-up of A1 shows on
	// chief's dashboard of A1 and as A1's p90 on A's; not on owen's.
	req := rg.call(t, "POST", "chief", "/api/v1/register/rollups", map[string]any{"bu_id": ra.bu["A1"]})
	if req.code != 202 {
		t.Fatalf("roll-up: %d %s", req.code, req.raw)
	}
	if q := ra.adminQuery("SELECT coalesce(string_agg(id::text, ',' ORDER BY seq), '') FROM analysis.aggregate WHERE purpose = 'rollup' AND state = 'queued'"); q != "" {
		for _, id := range strings.Split(q, ",") {
			if err := a.ae.aggregates.Attempt(ctx, id, 1, analysis.Attempts); err != nil {
				t.Fatalf("aggregate %s: %v", id, err)
			}
		}
	}
	got = dash("chief", "A1")
	roll, _ := got.body["rollup"].(map[string]any)
	if roll == nil || roll["covers"] != 2.0 || roll["stale"] != false || roll["summary"] == nil {
		t.Fatalf("chief's roll-up: %s", got.raw)
	}
	if got := dash("owen", "A1"); got.body["rollup"] != nil {
		t.Errorf("owen sees chief's roll-up: %v", got.body["rollup"])
	}
	child := dash("chief", "A").body["children"].([]any)[0].(map[string]any)
	// (The fake engine's aggregate summaries carry no percentiles, so the
	// roll-up's p90 is null here; the field is the summary's ale p90.)
	if _, ok := child["rollup_p90"]; child["name"] != "A1" || !ok || child["open_risks"] != 2.0 || fmt.Sprint(child["mean_sum"]) != "9" {
		t.Errorf("A1 under A: %v", child)
	}
}
