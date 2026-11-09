package tests

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// F-003 T-08 (AC-16, AC-20): a scenario version's input bundle is frozen,
// self-contained (asset group members included) and identified by a digest
// that changes with any input.
func TestRiskBundle(t *testing.T) {
	ra := newRiskAPI(t)
	ra.setCurrency(t, "USD")
	doc := ra.scenarioDoc(t)
	// The scenario's asset is an asset group of an asset, at A.
	got := ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "asset", "document": modeltest.Asset(), "change_note": "x"})
	member := got.body["id"].(string)
	g := modeltest.AssetGroup()
	modeltest.Set(g, "/members", []any{map[string]any{"id": member, "version": 1}})
	got = ra.call(t, "POST", "analyst", "/api/v1/library", map[string]any{"bu_id": ra.bu["A"], "kind": "asset_group", "document": g, "change_note": "x"})
	if got.code != 201 {
		t.Fatalf("group: %d %s", got.code, got.raw)
	}
	group := got.body["id"].(string)
	modeltest.Set(doc, "/asset", map[string]any{"kind": "asset_group", "id": group, "version": 1})
	got = ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatalf("scenario: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)

	bundle := func(user string, v string) (string, map[string]any, string) {
		t.Helper()
		got := ra.call(t, "GET", user, "/api/v1/scenarios/"+id+"/versions/"+v+"/bundle", nil)
		if got.code != 200 {
			t.Fatalf("bundle %s as %s: %d %s", v, user, got.code, got.raw)
		}
		var raw struct {
			Digest string          `json:"digest"`
			Bundle json.RawMessage `json:"bundle"`
		}
		if err := json.Unmarshal([]byte(got.raw), &raw); err != nil {
			t.Fatal(err)
		}
		// Anyone can check the digest: the SHA-256 of the canonical form.
		c, err := canon.Canonicalize(raw.Bundle)
		if err != nil || canon.Digest(c) != raw.Digest {
			t.Fatalf("the digest is not the bundle's: %v", err)
		}
		return raw.Digest, got.body["bundle"].(map[string]any), string(c)
	}
	d1, b1, c1 := bundle("erin", "1")
	if b1["format"] != "fair.scenario-input.v1" || b1["currency"] != "USD" || b1["scenario"].(map[string]any)["version"] != float64(1) {
		t.Fatalf("bundle: %v", b1)
	}
	kinds := map[string]string{}
	for _, p := range b1["pins"].([]any) {
		m := p.(map[string]any)
		kinds[m["pointer"].(string)] = m["kind"].(string)
		if m["pointer"] == "/asset/members/0" && (m["member_of"] != "/asset" || m["id"] != member) {
			t.Fatalf("the group member: %v", m)
		}
		if m["document"] == nil {
			t.Fatalf("a pin without its document: %v", m)
		}
	}
	if len(kinds) != 4 || kinds["/asset"] != "asset_group" || kinds["/asset/members/0"] != "asset" || kinds["/threat_community"] != "threat_community" ||
		kinds["/control_sets/0/controls/0"] != "control" {
		t.Fatalf("pins: %v", kinds)
	}
	// The same inputs: the same bundle.
	if d, _, c := bundle("erin", "1"); d != d1 || c != c1 {
		t.Fatal("the bundle changed between reads")
	}
	// A reader of scenarios only gets the same bundle, and no library.
	ra.mustOwner(`WITH ro AS (INSERT INTO iam.role (name) VALUES ('Scenario Reader') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['scenario.view'], 'test' FROM ro`)
	ra.mustOwner(grant("platform", "user:buadmin2", "Scenario Reader", "A1"))
	ra.drain()
	if d, _, _ := bundle("buadmin2", "1"); d != d1 {
		t.Fatal("a scenario reader's bundle differs")
	}
	if got, err := ra.asCtx(ra.mint("buadmin2", ctxKey1), "SELECT count(*) FROM risk.library_version; SELECT count(*) FROM risk.library_pin"); err != nil || got != "0\n0" {
		t.Fatalf("the scenario reader reads the library: %q %v", got, err)
	}

	// The scenario's pins list the member too; adopt does not take it.
	got = ra.call(t, "GET", "erin", "/api/v1/scenarios/"+id, nil)
	if !strings.Contains(got.raw, `"member_of":"/asset"`) {
		t.Fatalf("pins without the member: %s", got.raw)
	}
	asset2 := modeltest.Set(modeltest.Asset(), "/name", "Claims DB, re-valued")
	if got := ra.call(t, "PUT", "analyst", "/api/v1/library/"+member, map[string]any{"document": asset2, "expected_version": 1, "change_note": "x"}); got.code != 200 {
		t.Fatalf("member v2: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+id+"/adopt", map[string]any{"expected_version": 1, "pins": []string{"/asset/members/0"}, "change_note": "x"}); got.code != 409 {
		t.Fatalf("adopting a member: %d %s", got.code, got.raw)
	}

	// Any change of input changes the digest; earlier bundles stay as they
	// were (frozen).
	modeltest.Set(doc, "/name", "Renamed")
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+id, map[string]any{"document": doc, "expected_version": 1, "change_note": "v2"}); got.code != 200 {
		t.Fatalf("v2: %d %s", got.code, got.raw)
	}
	d2, _, _ := bundle("erin", "2")
	tc2 := modeltest.Set(modeltest.ThreatCommunity(), "/name", "Organised crime")
	if got := ra.call(t, "PUT", "analyst", "/api/v1/library/"+doc["threat_community"].(map[string]any)["id"].(string), map[string]any{"document": tc2, "expected_version": 1, "change_note": "x"}); got.code != 200 {
		t.Fatalf("tc v2: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+id+"/adopt", map[string]any{"expected_version": 2, "pins": []string{"/threat_community"}, "change_note": "v3"}); got.code != 200 {
		t.Fatalf("v3: %d %s", got.code, got.raw)
	}
	d3, _, _ := bundle("erin", "3")
	if d2 == d1 || d3 == d2 || d3 == d1 {
		t.Fatalf("digests %s %s %s", d1, d2, d3)
	}
	if d, _, _ := bundle("erin", "1"); d != d1 {
		t.Fatal("version 1's bundle changed")
	}
	// Unseen and missing: 404.
	for user, path := range map[string]string{"mallory": "/versions/1/bundle", "erin": "/versions/9/bundle"} {
		if got := ra.call(t, "GET", user, "/api/v1/scenarios/"+id+path, nil); got.code != 404 {
			t.Errorf("%s %s: %d", user, path, got.code)
		}
	}
}
