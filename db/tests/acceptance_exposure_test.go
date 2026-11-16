package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// F-008 T-03 (F-008-AC-13, AC-14; design §3.5): a risk's exposure read for
// the acceptance job, with no user: what the risk's owner reads, and closed
// to everyone else.
func TestAcceptanceExposureReads(t *testing.T) {
	f := strideF007Fixture(t) // owen's risk at A1 pinned to one run
	ra, rg := f.ra, f.rg
	// A second risk of two pinned scenarios: an exposure aggregate.
	s3 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims outage")
	r3 := runWith(t, f.ae, "analyst", s3, 1, 2000, "7")
	d := f.doc("Claims outage and fraud", f.s2, f.r2)
	d["scenarios"] = append(d["scenarios"].([]any), map[string]any{"scenario_id": s3, "pin": map[string]any{"run_id": r3, "control_set": "Current"}})
	got := rg.call(t, "POST", "owen", "/api/v1/register/risks", map[string]any{"bu_id": ra.bu["A1"], "change_note": "x", "document": d})
	if got.code != 201 {
		t.Fatalf("two-scenario risk: %d %s", got.code, got.raw)
	}
	multi := got.body["id"].(string)
	agg := ra.adminQuery("SELECT exposure_aggregate_id FROM register.risk WHERE id = '" + multi + "'")
	exposureFor := func(risk string) map[string]any {
		t.Helper()
		var out map[string]any
		if err := json.Unmarshal([]byte(ra.adminQuery("SET ROLE acceptance_definer; SELECT register.exposure_for('"+risk+"')")), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// T-08: register.exposures (set-based, for the sweep) reads what
	// exposure_for reads, for every risk.
	parity := func(what string) {
		t.Helper()
		ids := ra.adminQuery("SELECT string_agg(id::text, ',') FROM register.risk")
		set := ra.adminQuery("SET ROLE acceptance_definer; SELECT string_agg(e.risk_id || ':' || e.status || ':' || coalesce(e.mean::text, '-') || ':' || coalesce(e.p90::text, '-') || ':' || e.bu_id || ':' || e.state || ':' || e.owner, ',' ORDER BY e.risk_id) FROM register.exposures(string_to_array('" + ids + "', ',')::uuid[]) e")
		one := ra.adminQuery("SET ROLE acceptance_definer; SELECT string_agg(x || ':' || (e ->> 'status') || ':' || coalesce(e ->> 'mean', '-') || ':' || coalesce(e ->> 'p90', '-') || ':' || (e ->> 'bu_id') || ':' || (e ->> 'state') || ':' || (e ->> 'owner'), ',' ORDER BY x) FROM unnest(string_to_array('" + ids + "', ',')::uuid[]) x, register.exposure_for(x) e")
		if set != one || set == "" {
			t.Errorf("%s: exposures %s, exposure_for %s", what, set, one)
		}
	}
	// Computing: no mean yet.
	if e := exposureFor(multi); e["status"] != "computing" || e["mean"] != nil {
		t.Errorf("computing: %v", e)
	}
	parity("computing")
	if err := f.ae.aggregates.Attempt(context.Background(), agg, 1, 3); err != nil {
		t.Fatal(err)
	}
	for _, risk := range []string{f.risk, multi} {
		e := exposureFor(risk)
		page := rg.call(t, "GET", "owen", "/api/v1/register/risks/"+risk, nil).body
		mean := page["exposure"].(map[string]any)["summary"].(map[string]any)["ale"].(map[string]any)["mean"]
		status := page["risk"].(map[string]any)["status"].(map[string]any)["status"]
		if e["status"] != status || e["mean"] != mean || e["bu_id"] != ra.bu["A1"] || e["state"] != "open" || e["owner"] != f.owen {
			t.Errorf("risk %s: the job reads %v; owen reads status %v, mean %v", risk, e, status, mean)
		}
	}
	// Unquantified: a status, no mean.
	none := f.create(t, "owen", ra.bu["A1"], "Claims compliance", "", "")
	if e := exposureFor(none); e["status"] != "unquantified" || e["mean"] != nil {
		t.Errorf("unquantified: %v", e)
	}
	// Stale: a link without a pin.
	s4 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims insider")
	if e := exposureFor(f.create(t, "owen", ra.bu["A1"], "Claims insider", s4, "")); e["status"] != "stale" || e["mean"] != nil {
		t.Errorf("stale: %v", e)
	}
	parity("current, unquantified and stale")
	if got := ra.adminState("SET ROLE app_rw; SELECT * FROM register.exposures(ARRAY['" + f.risk + "'::uuid])"); got != "42501" {
		t.Errorf("app_rw reads exposures: %s", got)
	}

	// Closed to the application role and to every other definer.
	if err := ra.tx("owen", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "SELECT register.exposure_for($1)", f.risk)
		return err
	}); !strings.HasPrefix(pgCode(err), "42501 ") {
		t.Errorf("app_rw: %v", pgCode(err))
	}
	for _, c := range []struct{ role, sql string }{
		{"estimate_definer", "SELECT register.exposure_for('" + f.risk + "')"},
		{"analysis_definer", "SELECT register.exposure_for('" + f.risk + "')"},
		{"acceptance_definer", "SELECT analysis.register_summary('" + agg + "')"},
		{"acceptance_definer", "SELECT analysis.pinned_summary('" + f.r1 + "', 'Current')"},
		{"estimate_definer", "SELECT analysis.pinned_summary('" + f.r1 + "', 'Current')"},
	} {
		if got := ra.adminState("SET ROLE " + c.role + "; " + c.sql); got != "42501" {
			t.Errorf("%s: %s: %s", c.role, c.sql, got)
		}
	}
	if got := ra.adminState("SET ROLE app_rw; SELECT analysis.register_summary('" + agg + "')"); got != "42501" {
		t.Errorf("app_rw reads a register summary: %s", got)
	}
}
