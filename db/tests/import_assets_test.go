package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// F-011 T-11 (F-011-AC-15, AC-16; design §3.5): assets and asset groups end
// to end through the imports API: owner BU from the record, values as
// currency estimates sourced to the integration, groups by their members'
// external IDs (linked or in the same batch), members pinned on accept.
func TestImportAssetsEndToEnd(t *testing.T) {
	im := reviewAllAPI(t)
	ctx := context.Background()
	var cmdb string
	if err := im.ie.as("platform", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT integration.add($1, 'CMDB', 'assets', 'push', '{}', NULL, NULL, false)::text", im.bu["A"]).Scan(&cmdb)
	}); err != nil {
		t.Fatal(err)
	}
	push := func(body string) apiResp {
		t.Helper()
		got := im.send(t, "pusher", "/api/v1/imports/"+cmdb+"/batches", "application/json", body)
		if got.code != 201 {
			t.Fatalf("push: %d %s", got.code, got.raw)
		}
		return got
	}
	pending := func(ext string) string {
		return im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = '" + ext + "' AND state = 'pending'")
	}
	target := func(ext string) string {
		return im.adminQuery("SELECT target_id FROM integration.link WHERE external_id = '" + ext + "'")
	}
	doc := func(id, path string) string {
		return im.adminQuery("SELECT convert_from(v.document, 'UTF8')::jsonb #>> '{" + path + "}' FROM risk.library_version v JOIN risk.library_entry e ON e.id = v.entry_id AND v.version = e.current_version WHERE e.id = '" + id + "'")
	}

	valued := `{"kind": "asset", "external_id": "a-1", "bu": "A1", "name": "Claims platform", "asset_type": "application",
		"description": "Core claims", "value": {"min": "250000", "ml": "1500000", "max": "4000000", "basis": "Replacement cost"}}`
	got := push(batchOf(valued, asset("a-2", "A", "Warehouse"),
		`{"kind": "asset_group", "external_id": "g-1", "bu": "A", "name": "Claims systems", "members": ["a-1", "a-2"]}`,
		`{"kind": "asset_group", "external_id": "g-2", "bu": "A", "name": "Broken", "members": ["a-1", "zz-9"]}`))
	// A member neither linked nor in the batch refuses its group.
	if c := got.body["counts"].(map[string]any); c["refused"] != 1.0 || c["proposed"] != 3.0 || !strings.Contains(got.raw, `/members/1`) {
		t.Errorf("a group with an unknown member: %s", got.raw)
	}

	// The group before its members in one batch accept: assets go first.
	got = im.call(t, "POST", "analyst", "/api/v1/proposals/accept", map[string]any{"proposals": []map[string]any{
		{"id": pending("g-1")}, {"id": pending("a-1")}, {"id": pending("a-2")}}})
	if got.code != 200 {
		t.Fatalf("batch accept: %d %s", got.code, got.raw)
	}
	a1, a2, g1 := target("a-1"), target("a-2"), target("g-1")
	// The asset: owner BU from the record, the value a currency estimate
	// sourced to the integration, the description kept.
	if bu := im.adminQuery("SELECT bu_id FROM risk.library_entry WHERE id = '" + a1 + "'"); bu != im.bu["A1"] {
		t.Errorf("a-1's BU: %s", bu)
	}
	for path, want := range map[string]string{"name": "Claims platform", "asset_type": "application", "description": "Core claims",
		"value,ml": "1500000", "value,unit": "currency", "value,sources,0,type": "integration", "value,sources,0,ref": "CMDB: a-1"} {
		if got := doc(a1, path); got != want {
			t.Errorf("a-1 %s: %q, want %q", path, got, want)
		}
	}
	if got := doc(a2, "value_basis"); !strings.Contains(got, "CMDB") {
		t.Errorf("an unvalued asset's basis: %q", got)
	}
	// The group pins its members at their current versions.
	if got := doc(g1, "members"); !strings.Contains(got, a1) || !strings.Contains(got, a2) || strings.Count(got, `"version": 1`) != 2 {
		t.Errorf("g-1's members: %s", got)
	}

	// A group of linked members in a later batch; a member's new value is
	// a proposal (not descriptive), and the group keeps its pin.
	push(batchOf(`{"kind": "asset_group", "external_id": "g-3", "bu": "A", "name": "Just claims", "members": ["a-1"]}`,
		strings.Replace(valued, `"ml": "1500000"`, `"ml": "2000000"`, 1)))
	if d := im.adminQuery("SELECT descriptive_only FROM integration.proposal WHERE id = '" + pending("a-1") + "'"); d != "f" {
		t.Errorf("a value change is descriptive: %s", d)
	}
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+pending("a-1")+"/accept", map[string]any{"expected_version": 1}); got.code != 200 {
		t.Fatalf("accept a-1's value: %d %s", got.code, got.raw)
	}
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+pending("g-3")+"/accept", map[string]any{}); got.code != 200 {
		t.Fatalf("accept g-3: %d %s", got.code, got.raw)
	}
	if got := doc(target("g-3"), "members"); !strings.Contains(got, `"version": 2`) {
		t.Errorf("g-3 pins a-1's current version: %s", got)
	}
	if got := doc(g1, "members"); strings.Contains(got, `"version": 2`) {
		t.Errorf("g-1 moved with a-1: %s", got)
	}
	// The external reference: the link and the versions' provenance.
	vs := im.call(t, "GET", "analyst", "/api/v1/library/"+a1+"/versions", nil)
	if strings.Count(vs.raw, `"external_id":"a-1"`) != 2 {
		t.Errorf("a-1's provenance: %s", vs.raw)
	}
}
