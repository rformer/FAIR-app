package tests

import (
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-003 T-06 (AC-08, AC-12, AC-14, AC-26): the library and controls, shared
// down the BU tree.
func TestRiskLibraryAPI(t *testing.T) {
	ra := newRiskAPI(t)
	ra.setCurrency(t, "USD")
	ra.mustOwner(grant("platform", "user:buadmin", "Risk Analyst", "ENTERPRISE"))
	ra.drain()
	post := func(user, path string, body map[string]any) apiResp {
		t.Helper()
		return ra.call(t, "POST", user, path, body)
	}
	tc := modeltest.ThreatCommunity()

	// The root's threat community and control, written at the root.
	got := post("buadmin", "/api/v1/library", map[string]any{"bu_id": ra.bu["ENTERPRISE"], "kind": "threat_community", "document": tc, "change_note": "Root library"})
	if got.code != 201 {
		t.Fatalf("root entry: %d %s", got.code, got.raw)
	}
	rootTC := got.body["id"].(string)
	got = post("buadmin", "/api/v1/controls", map[string]any{"bu_id": ra.bu["ENTERPRISE"], "document": modeltest.Control(), "change_note": "Root control"})
	if got.code != 201 {
		t.Fatalf("root control: %d %s", got.code, got.raw)
	}
	rootCtl := got.body["id"].(string)

	// The request names the kind of a library entry, and it must match.
	for name, c := range map[string]struct {
		body map[string]any
		code int
	}{
		"no kind":       {map[string]any{"bu_id": ra.bu["A"], "document": tc, "change_note": "x"}, 400},
		"unknown kind":  {map[string]any{"bu_id": ra.bu["A"], "kind": "scenario", "document": tc, "change_note": "x"}, 400},
		"kind mismatch": {map[string]any{"bu_id": ra.bu["A"], "kind": "asset", "document": tc, "change_note": "x"}, 422},
	} {
		if got := post("analyst", "/api/v1/library", c.body); got.code != c.code {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	if got := post("analyst", "/api/v1/controls", map[string]any{"bu_id": ra.bu["A"], "kind": "control", "document": modeltest.Control(), "change_note": "x"}); got.code != 400 {
		t.Errorf("a control with a kind: %d", got.code)
	}

	// A's asset, and A1's asset group of it.
	got = post("analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "asset", "document": modeltest.Asset(), "change_note": "Claims DB"})
	if got.code != 201 {
		t.Fatalf("asset: %d %s", got.code, got.raw)
	}
	asset := got.body["id"].(string)
	group := modeltest.AssetGroup()
	modeltest.Set(group, "/members", []any{map[string]any{"id": asset, "version": 1}})
	got = post("analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A1"], "kind": "asset_group", "document": group, "change_note": "Group"})
	if got.code != 201 {
		t.Fatalf("group: %d %s", got.code, got.raw)
	}
	grp := got.body["id"].(string)
	// A member the writer cannot see is refused by the database (422).
	hidden := post("mallory", "/api/v1/library", map[string]any{"bu_id": ra.bu["B"], "kind": "asset", "document": modeltest.Asset(), "change_note": "B's"})
	if hidden.code != 201 {
		t.Fatalf("B's asset: %d %s", hidden.code, hidden.raw)
	}
	hiddenID := hidden.body["id"].(string)
	modeltest.Set(group, "/members", []any{map[string]any{"id": hiddenID, "version": 1}})
	if got := post("analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "asset_group", "document": group, "change_note": "x"}); got.code != 422 || !strings.Contains(got.raw, "/members/0") {
		t.Fatalf("hidden member: %d %s", got.code, got.raw)
	}

	// Lists: own entries, and the root's marked inherited.
	listed := func(user, path string) map[string]bool {
		t.Helper()
		got := ra.call(t, "GET", user, path, nil)
		if got.code != 200 {
			t.Fatalf("%s %s: %d %s", user, path, got.code, got.raw)
		}
		key := "entries"
		if strings.HasPrefix(path, "/api/v1/controls") {
			key = "controls"
		}
		out := map[string]bool{}
		for _, x := range got.body[key].([]any) {
			m := x.(map[string]any)
			out[m["id"].(string)] = m["inherited"].(bool)
		}
		return out
	}
	if l := listed("analyst", "/api/v1/library"); len(l) != 3 || !l[rootTC] || l[asset] || l[grp] {
		t.Fatalf("analyst's library: %v", l)
	}
	if l := listed("analyst", "/api/v1/library?kind=asset"); len(l) != 1 || l[asset] {
		t.Fatalf("assets: %v", l)
	}
	if l := listed("mallory", "/api/v1/library"); len(l) != 2 || !l[rootTC] || l[hiddenID] {
		t.Fatalf("mallory's library: %v", l)
	}
	if l := listed("erin", "/api/v1/controls"); len(l) != 1 || !l[rootCtl] {
		t.Fatalf("erin's controls: %v", l)
	}
	if got := ra.call(t, "GET", "analyst", "/api/v1/library?kind=scenario", nil); got.code != 400 {
		t.Fatalf("kind filter: %d", got.code)
	}

	// Inherited entries are read, never changed (403).
	got = ra.call(t, "GET", "analyst", "/api/v1/library/"+rootTC, nil)
	if e, _ := got.body["entry"].(map[string]any); got.code != 200 || e["inherited"] != true || e["kind"] != "threat_community" {
		t.Fatalf("read inherited: %d %s", got.code, got.raw)
	}
	save := map[string]any{"document": tc, "expected_version": 1, "change_note": "x"}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/library/"+rootTC, save); got.code != 403 {
		t.Fatalf("save inherited: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/controls/"+rootCtl, map[string]any{"document": modeltest.Control(), "expected_version": 1, "change_note": "x"}); got.code != 403 {
		t.Fatalf("save inherited control: %d", got.code)
	}
	if got := ra.call(t, "PUT", "mallory", "/api/v1/library/"+asset, save); got.code != 404 {
		t.Fatalf("outsider saves: %d", got.code)
	}

	// The group's pins; a save of another kind's document is 422; versions.
	got = ra.call(t, "GET", "erin", "/api/v1/library/"+grp, nil)
	if pins, _ := got.body["pins"].([]any); got.code != 200 || len(pins) != 1 {
		t.Fatalf("group: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/library/"+asset, map[string]any{"document": tc, "expected_version": 1, "change_note": "x"}); got.code != 422 {
		t.Fatalf("another kind's document: %d %s", got.code, got.raw)
	}
	asset2 := modeltest.Set(modeltest.Asset(), "/name", "Claims database v2")
	if got := ra.call(t, "PUT", "analyst", "/api/v1/library/"+asset, map[string]any{"document": asset2, "expected_version": 1, "change_note": "Renamed"}); got.code != 200 {
		t.Fatalf("save asset: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "GET", "erin", "/api/v1/library/"+asset+"/versions", nil); got.code != 200 || len(got.body["versions"].([]any)) != 2 {
		t.Fatalf("asset versions: %d %s", got.code, got.raw)
	}
	got = ra.call(t, "GET", "erin", "/api/v1/controls/"+rootCtl, nil)
	if _, pins := got.body["pins"]; got.code != 200 || pins || got.body["control"] == nil {
		t.Fatalf("control: %d %s", got.code, got.raw)
	}
	// Events, with the kind for library entries.
	if ev := ra.adminQuery(`SELECT string_agg((body ->> 'type') || ':' || coalesce(body -> 'attributes' ->> 'kind', '-'), ',' ORDER BY id) FROM audit.intake
		WHERE body ->> 'type' LIKE 'library.%' OR body ->> 'type' LIKE 'control.%'`); ev !=
		"library.created:threat_community,control.created:-,library.created:asset,library.created:asset_group,library.created:asset,library.version_saved:asset" {
		t.Fatalf("events: %s", ev)
	}
}
