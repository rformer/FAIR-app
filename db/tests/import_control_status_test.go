package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-011 T-13 (F-011-AC-23, AC-24; design §3.7): control status from an
// integration; a lapse (in place to anything else, in an accepted version)
// notifies the owners of scenarios using the control as in place in a
// current set, and shows on scenario and risk reads; nothing changes
// automatically.
func TestControlStatus(t *testing.T) {
	im := reviewAllAPI(t)
	ctx := context.Background()
	var grc string
	if err := im.ie.as("platform", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT integration.add($1, 'GRC', 'control_status', 'push', '{}', NULL, NULL, false)::text", im.bu["A"]).Scan(&grc)
	}); err != nil {
		t.Fatal(err)
	}
	ctl := im.create(t, "analyst", "control", im.bu["A"], modeltest.Control())
	asset := modeltest.Asset()
	a := im.create(t, "analyst", "asset", im.bu["A"], asset)
	tc := im.create(t, "analyst", "threat_community", im.bu["A"], modeltest.ThreatCommunity())
	scenario := func(name, owner string, sets []any) string {
		t.Helper()
		d := modeltest.Scenario()
		d["name"] = name
		modeltest.Set(d, "/owner", im.adminQuery("SELECT id FROM iam.app_user WHERE email = '"+owner+"@example.test'"))
		modeltest.Set(d, "/asset", map[string]any{"kind": "asset", "id": a, "version": 1})
		modeltest.Set(d, "/threat_community", map[string]any{"id": tc, "version": 1})
		modeltest.Set(d, "/control_sets", sets)
		got := im.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": im.bu["A"], "document": d, "change_note": "v1"})
		if got.code != 201 {
			t.Fatalf("scenario %s: %d %s", name, got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	use := func(status string) []any {
		return []any{map[string]any{"id": ctl, "version": 1, "status": status}}
	}
	inPlace := scenario("Relies on it", "analyst", []any{map[string]any{"name": "Current", "current": true, "controls": use("in_place")}})
	erins := scenario("Erin's", "erin", []any{map[string]any{"name": "Current", "current": true, "controls": use("in_place")}})
	proposed := scenario("Proposes it", "analyst", []any{map[string]any{"name": "Current", "current": true, "controls": use("proposed")}})
	notCurrent := scenario("Only in a plan", "analyst", []any{
		map[string]any{"name": "Current", "current": true, "controls": []any{}},
		map[string]any{"name": "Plan", "current": false, "controls": use("in_place")}})

	status := func(s, on string) {
		t.Helper()
		body := batchOf(fmt.Sprintf(`{"kind": "control_status", "external_id": "c-1", "control": %q, "status": %q, "assessed_on": %q}`, ctl, s, on))
		if got := im.send(t, "pusher", "/api/v1/imports/"+grc+"/batches", "application/json", body); got.code != 201 {
			t.Fatalf("push: %d %s", got.code, got.raw)
		}
		p := im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = 'c-1' AND state = 'pending'")
		v := im.adminQuery("SELECT current_version FROM risk.control WHERE id = '" + ctl + "'")
		var expected int
		fmt.Sscan(v, &expected)
		if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+p+"/accept", map[string]any{"expected_version": expected}); got.code != 200 {
			t.Fatalf("accept %s: %d %s", s, got.code, got.raw)
		}
	}
	notices := func() string {
		return im.adminQuery(`SELECT coalesce(string_agg(s.name, ',' ORDER BY s.name), '') FROM integration.notice_outbox o JOIN risk.scenario s ON s.id = o.scenario_id
			WHERE o.kind = 'control.lapsed'`)
	}

	// The first status: a proposal of implementation, no lapse.
	status("in_place", "2026-10-01")
	if got := im.adminQuery("SELECT convert_from(document, 'UTF8')::jsonb #>> '{implementation,status}' FROM risk.control_version WHERE control_id = '" + ctl + "' AND version = 2"); got != "in_place" {
		t.Errorf("version 2's status: %s", got)
	}
	if got := notices(); got != "" {
		t.Errorf("notices before a lapse: %s", got)
	}
	// In place to partial: the owners of the scenarios relying on it.
	status("partial", "2026-11-01")
	if got := notices(); got != "Erin's,Relies on it" {
		t.Errorf("lapse notices: %q", got)
	}
	if got := im.adminQuery("SELECT string_agg(DISTINCT a.email, ',') FROM integration.notice_outbox o JOIN iam.app_user a ON a.id = o.user_id WHERE o.kind = 'control.lapsed'"); got != "analyst@example.test,erin@example.test" {
		t.Errorf("notified: %s", got)
	}
	// Partial to not in place: no longer a lapse from in place.
	status("not_in_place", "2026-11-05")
	if got := notices(); got != "Erin's,Relies on it" {
		t.Errorf("a second change notified: %q", got)
	}

	// Shown on read: the scenario using it as in place, not the others.
	for id, want := range map[string]bool{inPlace: true, erins: true, proposed: false, notCurrent: false} {
		got := im.call(t, "GET", "analyst", "/api/v1/scenarios/"+id, nil)
		lapsed := got.body["control_lapsed"].([]any)
		if (len(lapsed) == 1) != want || want && !strings.Contains(got.raw, `"status":"not_in_place"`) {
			t.Errorf("%s control_lapsed: %s", id, fmt.Sprint(got.body["control_lapsed"]))
		}
	}
	// Nothing changed automatically: the scenario still pins version 1,
	// marked newer.
	got := im.call(t, "GET", "analyst", "/api/v1/scenarios/"+inPlace, nil)
	if v := im.adminQuery("SELECT current_version FROM risk.scenario WHERE id = '" + inPlace + "'"); v != "1" || !strings.Contains(got.raw, `"newer":true`) {
		t.Errorf("the scenario changed (version %s) or is not marked newer: %s", v, got.raw)
	}
	// On the risks linked to it.
	got = im.call(t, "POST", "rowner", "/api/v1/register/risks", map[string]any{"bu_id": im.bu["A"], "change_note": "x", "document": map[string]any{
		"schema_version": 1, "title": "Claims fraud", "owner": im.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rowner@example.test'"),
		"state": "open", "scenarios": []any{map[string]any{"scenario_id": inPlace}, map[string]any{"scenario_id": proposed}}}})
	if got.code != 201 {
		t.Fatalf("a risk: %d %s", got.code, got.raw)
	}
	got = im.call(t, "GET", "rowner", "/api/v1/register/risks/"+got.body["id"].(string), nil)
	if lapsed := got.body["risk"].(map[string]any)["control_lapsed"].([]any); len(lapsed) != 1 || lapsed[0].(map[string]any)["scenario_id"] != inPlace {
		t.Errorf("the risk's control_lapsed: %v", lapsed)
	}

	// Only versions accepted in the same transaction queue notices.
	err := im.tx("analyst", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT integration.control_lapsed($1, 3)", ctl)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "was not accepted") {
		t.Errorf("control_lapsed for an earlier accepted version: %v", err)
	}

	// Collected (F-009) to their owners, about the scenario.
	np := rolePool(t, im.env, "app_notify")
	if _, err := np.Exec(ctx, "SELECT notify.collect(false, 1000)"); err != nil {
		t.Fatal(err)
	}
	if got := im.adminQuery("SELECT count(*) FROM notify.notice WHERE kind = 'control.lapsed' AND item_type = 'scenario'"); got != "2" {
		t.Errorf("collected lapse notices: %s", got)
	}
}
