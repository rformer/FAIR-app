package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// lossEvent is a loss_event record of the integration format.
func lossEvent(ext, bu, on, typ, amounts string) string {
	if amounts == "" {
		amounts = "{}"
	}
	return fmt.Sprintf(`{"kind": "loss_event", "external_id": %q, "bu": %q, "occurred_on": %q, "event_type": %q, "amounts": %s}`, ext, bu, on, typ, amounts)
}

// F-011 T-12 (F-011-AC-17 to AC-19; design §3.5 as amended 2026-11-18):
// loss events written directly by runs and read under RLS; reference
// classes derived from them, within one restricted root, proposed only
// when their data changes.
func TestLossEventsAndDerivations(t *testing.T) {
	im := reviewAllAPI(t)
	ctx := context.Background()
	// ranalyst: a Risk Analyst inside R who also pushes R's incidents.
	im.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('ranalyst@example.test', 'ranalyst')")
	im.mustOwner(grant("platform", "user:ranalyst", "Risk Analyst", "R"))
	im.mustOwner(grant("platform", "user:ranalyst", "Integration Pusher", "R"))
	im.drain()
	add := func(user, bu, name string) string {
		t.Helper()
		var id string
		if err := im.ie.as(user, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT integration.add($1, $2, 'loss_events', 'push', '{}', NULL, NULL, false)::text", im.bu[bu], name).Scan(&id)
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	incidents, rIncidents := add("platform", "A", "Incidents"), add("rman", "R", "R incidents")
	push := func(user, id, body string) map[string]any {
		t.Helper()
		got := im.send(t, user, "/api/v1/imports/"+id+"/batches", "application/json", body)
		if got.code != 201 {
			t.Fatalf("push: %d %s", got.code, got.raw)
		}
		return got.body["counts"].(map[string]any)
	}
	events := []string{
		lossEvent("e-1", "A", "2022-03-01", "Ransomware", `{"response": "12.5", "fines_judgments": "100"}`),
		lossEvent("e-2", "A1", "2023-07-15", "Ransomware", `{"response": "40"}`),
		lossEvent("e-3", "A", "2024-02-01", "Phishing", `{"productivity": "5"}`),
	}
	c := push("pusher", incidents, batchOf(events...))
	if c["new"] != 3.0 || c["proposed"] != 0.0 {
		t.Errorf("first run: %v", c)
	}
	c = push("pusher", incidents, batchOf(events...))
	if c["unchanged"] != 3.0 || c["new"] != 0.0 {
		t.Errorf("an unchanged run: %v", c)
	}
	push("ranalyst", rIncidents, batchOf(lossEvent("r-1", "R1", "2023-01-10", "Ransomware", `{"response": "999"}`)))

	// Visibility (AC-19): library.view at the event's BU; restricted
	// units' events only inside their subtree.
	seen := func(user string) string {
		got := im.call(t, "GET", user, "/api/v1/loss-events", nil)
		if got.code != 200 {
			return fmt.Sprint(got.code)
		}
		var ids []string
		for _, e := range got.body["loss_events"].([]any) {
			ids = append(ids, e.(map[string]any)["external_id"].(string))
		}
		return strings.Join(ids, ",")
	}
	for user, want := range map[string]string{"analyst": "e-3,e-2,e-1", "erin": "e-3,e-2,e-1", "ranalyst": "r-1", "rman": "404", "mallory": ""} { // mallory: library.view at B only
		if got := seen(user); got != want {
			t.Errorf("%s sees %s, want %s", user, got, want)
		}
	}
	r1 := im.adminQuery("SELECT id FROM integration.loss_event WHERE external_id = 'r-1'")
	if got := im.call(t, "GET", "analyst", "/api/v1/loss-events/"+r1, nil); got.code != 404 {
		t.Errorf("analyst reads R's event: %d", got.code)
	}
	if got := im.call(t, "GET", "analyst", "/api/v1/loss-events?type=Ransomware&from=2023-01-01", nil); !strings.Contains(got.raw, `"e-2"`) || strings.Contains(got.raw, `"e-1"`) {
		t.Errorf("filters: %s", got.raw)
	}

	// A reference class at A, derived from A's subtree: R's events are in
	// another restricted root and never count.
	got := im.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": im.bu["A"], "kind": "reference_class",
		"document": modeltest.ReferenceClass(), "change_note": "By hand"})
	if got.code != 201 {
		t.Fatalf("create the class: %d %s", got.code, got.raw)
	}
	class := got.body["id"].(string)
	path := "/api/v1/library/" + class + "/derivation"
	filter := map[string]any{"bu_id": im.bu["A"], "event_types": []string{"Ransomware"}, "from": "2022-01-01", "to": "2025-01-01", "granularity": "year"}
	if got := im.call(t, "PUT", "erin", path, map[string]any{"filter": filter, "data_kind": "counts"}); got.code != 403 {
		t.Errorf("erin sets a derivation: %d %s", got.code, got.raw)
	}
	bad := map[string]any{"bu_id": im.bu["B"], "event_types": []string{"Ransomware"}, "from": "2022-01-01", "to": "2025-01-01", "granularity": "year"}
	if got := im.call(t, "PUT", "analyst", path, map[string]any{"filter": bad, "data_kind": "counts"}); got.code != 422 || !strings.Contains(got.raw, "/filter/bu_id") {
		t.Errorf("a filter outside the subtree: %d %s", got.code, got.raw)
	}
	got = im.call(t, "PUT", "analyst", path, map[string]any{"filter": filter, "data_kind": "counts"})
	if got.code != 200 || got.body["proposed"] != true {
		t.Fatalf("set the derivation: %d %s", got.code, got.raw)
	}
	pending := func() string {
		return im.adminQuery("SELECT id FROM integration.proposal WHERE derivation_id = '" + class + "' AND state = 'pending'")
	}
	first := pending()
	counts := func(id string) string {
		return im.adminQuery("SELECT string_agg(x ->> 'count', ',') FROM integration.proposal p, jsonb_array_elements(p.document -> 'data' -> 'series') x WHERE p.id = '" + id + "'")
	}
	if got := counts(first); got != "1,1,0" {
		t.Errorf("derived counts: %s (R's event must not count)", got)
	}
	if got := im.adminQuery("SELECT coalesce(integration_id::text, 'none') || ':' || coalesce(run_id::text, 'none') || ':' || coalesce(external_id, 'none') FROM integration.proposal WHERE id = '" + first + "'"); got != "none:none:none" {
		t.Errorf("a derivation proposal's origin: %s", got)
	}
	// The same derivation again, and a run of unrelated events: nothing new.
	if got := im.call(t, "PUT", "analyst", path, map[string]any{"filter": filter, "data_kind": "counts"}); got.body["proposed"] != false || pending() != first {
		t.Errorf("the same derivation again: %s", got.raw)
	}
	push("pusher", incidents, batchOf(append(events, lossEvent("e-4", "A", "2024-05-01", "Fraud", ""))...))
	if pending() != first {
		t.Error("an unrelated event proposed")
	}
	// A matching event: a new proposal supersedes the pending one.
	push("pusher", incidents, batchOf(append(events, lossEvent("e-4", "A", "2024-05-01", "Fraud", ""), lossEvent("e-5", "A1", "2024-06-01", "Ransomware", ""))...))
	second := pending()
	if second == first || counts(second) != "1,1,1" || im.adminQuery("SELECT state FROM integration.proposal WHERE id = '"+first+"'") != "superseded" {
		t.Errorf("a matching event: %s (%s)", counts(second), second)
	}
	// The reviewer sees and accepts it like any other proposal.
	got = im.call(t, "GET", "analyst", "/api/v1/proposals/"+second, nil)
	if got.code != 200 || got.body["proposed"] == nil || got.body["diff"] == nil {
		t.Fatalf("review the derived proposal: %d %s", got.code, got.raw)
	}
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+second+"/accept", map[string]any{"expected_version": 1}); got.code != 200 {
		t.Fatalf("accept: %d %s", got.code, got.raw)
	}
	doc := im.adminQuery("SELECT convert_from(document, 'UTF8') FROM risk.library_version WHERE entry_id = '" + class + "' AND version = 2")
	if !strings.Contains(doc, `"ref":"derivation:`+class+`"`) || !strings.Contains(doc, `"count":1`) || !strings.Contains(doc, `"Incident register export, 2025-01"`) {
		t.Errorf("the derived version: %s", doc)
	}
	vs := im.call(t, "GET", "analyst", "/api/v1/library/"+class+"/versions", nil)
	if !strings.Contains(vs.raw, `"derivation_id":"`+class+`"`) {
		t.Errorf("provenance names the derivation: %s", vs.raw)
	}
	// A complete run without e-5 archives it: the data changes again.
	c = push("pusher", incidents, `{"format": "fair.integration.v1", "complete": true, "records": [`+strings.Join(events, ",")+`]}`)
	if im.adminQuery("SELECT archived_at IS NOT NULL FROM integration.loss_event WHERE external_id = 'e-5'") != "t" || pending() == "" {
		t.Errorf("a complete run: %v, pending %q", c, pending())
	}
	if got := seen("analyst"); got != "e-3,e-2,e-1" {
		t.Errorf("archived events are hidden by default: %s", got)
	}
	if got := im.call(t, "GET", "analyst", path, nil); got.code != 200 || got.body["computed"] == nil || got.body["pending_proposal"] == nil {
		t.Errorf("read the derivation: %d %s", got.code, got.raw)
	}

	// Losses: each event's total over the chosen forms, sorted.
	losses := modeltest.ReferenceClass()
	losses["data"] = map[string]any{"kind": "losses", "unit": "currency", "amounts": []any{"1"}}
	got = im.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": im.bu["A"], "kind": "reference_class", "document": losses, "change_note": "x"})
	if got.code != 201 {
		t.Fatalf("create the losses class: %d %s", got.code, got.raw)
	}
	lclass := got.body["id"].(string)
	got = im.call(t, "PUT", "analyst", "/api/v1/library/"+lclass+"/derivation", map[string]any{"data_kind": "losses",
		"filter": map[string]any{"bu_id": im.bu["A"], "event_types": []string{"Ransomware"}, "from": "2022-01-01", "to": "2025-01-01", "forms": []string{"response", "fines_judgments"}}})
	if got.code != 200 {
		t.Fatalf("a losses derivation: %d %s", got.code, got.raw)
	}
	amounts := im.adminQuery("SELECT p.document -> 'data' ->> 'amounts' FROM integration.proposal p WHERE p.derivation_id = '" + lclass + "' AND p.state = 'pending'")
	if amounts != `["40", "112.5"]` {
		t.Errorf("derived losses: %s", amounts)
	}

	// Inside R: ranalyst derives from R's events only.
	rc := modeltest.ReferenceClass()
	got = im.call(t, "POST", "ranalyst", "/api/v1/library", map[string]any{"bu_id": im.bu["R"], "kind": "reference_class", "document": rc, "change_note": "x"})
	if got.code != 201 {
		t.Fatalf("create R's class: %d %s", got.code, got.raw)
	}
	rclass := got.body["id"].(string)
	rf := map[string]any{"bu_id": im.bu["R"], "event_types": []string{"Ransomware"}, "from": "2022-01-01", "to": "2025-01-01", "granularity": "year"}
	if got := im.call(t, "PUT", "ranalyst", "/api/v1/library/"+rclass+"/derivation", map[string]any{"filter": rf, "data_kind": "counts"}); got.code != 200 {
		t.Fatalf("R's derivation: %d %s", got.code, got.raw)
	}
	if got := counts(im.adminQuery("SELECT id FROM integration.proposal WHERE derivation_id = '" + rclass + "' AND state = 'pending'")); got != "0,1,0" {
		t.Errorf("R's derived counts: %s", got)
	}
	if got := im.call(t, "GET", "analyst", "/api/v1/library/"+rclass+"/derivation", nil); got.code != 404 {
		t.Errorf("analyst reads R's derivation: %d", got.code)
	}

	// Removing a derivation supersedes its pending proposal.
	if got := im.call(t, "DELETE", "analyst", path, nil); got.code != 204 || pending() != "" {
		t.Errorf("delete: %d %s (pending %q)", got.code, got.raw, pending())
	}
	if got := im.call(t, "GET", "analyst", path, nil); got.code != 404 {
		t.Errorf("a removed derivation: %d", got.code)
	}
	if n := im.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'integration.derivation_changed'"); n == "0" {
		t.Error("no integration.derivation_changed events")
	}
}
