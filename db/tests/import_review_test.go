package tests

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/importapi"
	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// reviewAPI is importAPI with the risk API behind accepts (cmd/risk's
// wiring) and the currency set.
func reviewAPI(t *testing.T) *importEnv {
	t.Helper()
	im := importAPI(t)
	im.setCurrency(t, "USD")
	pool := im.appPool()
	cache := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)})
	risk := &riskapi.API{Reasons: reason.Static{}, DB: pool, Authz: cache, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	api := &importapi.API{DB: pool, Authz: cache, Risk: risk}
	srv := httptest.NewServer(api.Handler(im.keys, nil))
	t.Cleanup(srv.Close)
	im.url = srv.URL
	return im
}

// F-011 T-10a (F-011-AC-10 to AC-12, AC-14, AC-25, AC-26; design §3.4 as
// amended): proposals reviewed under the reviewer's RLS and accepted
// through the risk API's save code. "analyst" (Risk Analyst at A) reviews
// and decides; "erin" (Executive Viewer at A) reads but cannot decide;
// "mallory" (B) sees none of A's.
func TestProposalReview(t *testing.T) {
	im := reviewAPI(t)
	ctx := context.Background()
	add := func(name, kind string) string {
		t.Helper()
		var id string
		if err := im.ie.as("platform", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT integration.add($1, $2, $3, 'push', '{}', NULL, NULL, false)::text", im.bu["A"], name, kind).Scan(&id)
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	assets, controls := add("CMDB", "assets"), add("GRC", "control_status")
	push := func(id, body string) {
		t.Helper()
		if got := im.send(t, "pusher", "/api/v1/imports/"+id+"/batches", "application/json", body); got.code != 201 {
			t.Fatalf("push: %d %s", got.code, got.raw)
		}
	}
	proposalOf := func(ext string) string {
		return im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = '" + ext + "' AND state = 'pending'")
	}
	valued := `{"kind": "asset", "external_id": "a-1", "bu": "A1", "name": "Claims platform", "asset_type": "application",
		"value": {"min": "250000", "ml": "1500000", "max": "4000000", "basis": "Replacement cost"}}`
	push(assets, batchOf(valued, asset("a-2", "A", "Warehouse"),
		`{"kind": "asset_group", "external_id": "g-1", "bu": "A", "name": "Claims systems", "members": ["a-1", "a-2"]}`))

	// Who reads: the kind's view permission at the proposal's BU.
	for user, want := range map[string]int{"analyst": 3, "erin": 3} {
		got := im.call(t, "GET", user, "/api/v1/proposals", nil)
		if got.code != 200 || len(got.body["proposals"].([]any)) != want {
			t.Errorf("%s lists: %d %s", user, got.code, got.raw)
		}
	}
	if got := im.call(t, "GET", "mallory", "/api/v1/proposals", nil); got.code != 200 || len(got.body["proposals"].([]any)) != 0 {
		t.Errorf("mallory (B only) lists: %d %s", got.code, got.raw)
	}

	// The merged document: a group's members must be accepted first.
	g := im.call(t, "GET", "analyst", "/api/v1/proposals/"+proposalOf("g-1"), nil)
	if g.code != 200 || !strings.Contains(g.raw, "not an accepted asset") || g.body["proposed"] != nil {
		t.Errorf("the group before its members: %s", g.raw)
	}
	a1 := proposalOf("a-1")
	got := im.call(t, "GET", "analyst", "/api/v1/proposals/"+a1, nil)
	proposed, _ := got.body["proposed"].(map[string]any)
	if got.code != 200 || got.body["current"] != nil || proposed["name"] != "Claims platform" ||
		proposed["value"].(map[string]any)["sources"].([]any)[0].(map[string]any)["type"] != "integration" {
		t.Fatalf("a-1: %s", got.raw)
	}

	// Deciding needs the edit permission.
	if got := im.call(t, "POST", "erin", "/api/v1/proposals/"+a1+"/accept", map[string]any{}); got.code != 403 {
		t.Errorf("erin accepts: %d %s", got.code, got.raw)
	}
	accept := func(id string, body map[string]any) apiResp {
		t.Helper()
		return im.call(t, "POST", "analyst", "/api/v1/proposals/"+id+"/accept", body)
	}
	if got := accept(a1, map[string]any{}); got.code != 200 || got.body["state"] != "accepted" {
		t.Fatalf("accept a-1: %d %s", got.code, got.raw)
	}
	entry := im.adminQuery("SELECT target_id FROM integration.link WHERE external_id = 'a-1'")
	if got := im.adminQuery("SELECT e.kind || ':' || b.code || ':' || e.current_version FROM risk.library_entry e JOIN iam.bu b ON b.id = e.bu_id WHERE e.id = '" + entry + "'"); got != "asset:A1:1" {
		t.Errorf("the created entry: %s", got)
	}
	if got := im.adminQuery("SELECT version || ':' || (accepted_by = " + uid("analyst") + ") FROM integration.applied WHERE target_id = '" + entry + "'"); got != "1:true" {
		t.Errorf("provenance: %s", got)
	}
	for typ, target := range map[string]string{"integration.proposal_accepted": "integration_proposal:" + a1, "library.created": "library:" + entry} {
		if n := im.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '" + typ + "' AND body ->> 'target' = '" + target + "'"); n != "1" {
			t.Errorf("%s: %s", typ, n)
		}
	}
	if got := accept(a1, map[string]any{}); got.code != 409 || got.body["error"] != "proposal_decided" {
		t.Errorf("accepting twice: %d %s", got.code, got.raw)
	}
	if got := accept(proposalOf("a-2"), map[string]any{}); got.code != 200 {
		t.Fatalf("accept a-2: %d %s", got.code, got.raw)
	}
	// With both members accepted the group pins them.
	if got := accept(proposalOf("g-1"), map[string]any{}); got.code != 200 {
		t.Fatalf("accept g-1: %d %s", got.code, got.raw)
	}
	group := im.adminQuery("SELECT target_id FROM integration.link WHERE external_id = 'g-1'")
	if got := im.adminQuery("SELECT convert_from(v.document, 'UTF8')::jsonb -> 'members' @> jsonb_build_array(jsonb_build_object('id', '" + entry + "', 'version', 1)) FROM risk.library_version v WHERE v.entry_id = '" + group + "'"); got != "t" {
		t.Errorf("the group's members: %s", got)
	}

	// An update: merged with the current version, the diff by pointer;
	// expected_version is the version reviewed.
	push(assets, batchOf(strings.Replace(valued, "Claims platform", "Claims platform (EU)", 1)))
	up := proposalOf("a-1")
	got = im.call(t, "GET", "analyst", "/api/v1/proposals/"+up, nil)
	if cur, _ := got.body["current"].(map[string]any); cur == nil || cur["version"] != 1.0 || !strings.Contains(got.raw, `"pointer":"/name"`) {
		t.Errorf("the update's view: %s", got.raw)
	}
	if got := accept(up, map[string]any{}); got.code != 400 {
		t.Errorf("an update without expected_version: %d", got.code)
	}
	if got := accept(up, map[string]any{"expected_version": 9}); got.code != 409 || got.body["error"] != "stale_version" {
		t.Errorf("a stale update: %d %s", got.code, got.raw)
	}
	if got := accept(up, map[string]any{"expected_version": 1, "change_note": "EU entity renamed"}); got.code != 200 {
		t.Fatalf("accept the update: %d %s", got.code, got.raw)
	}
	if got := im.adminQuery("SELECT current_version FROM risk.library_entry WHERE id = '" + entry + "'"); got != "2" {
		t.Errorf("version after the update: %s", got)
	}

	// Reject: a reason; the same values are not proposed again.
	push(assets, batchOf(strings.Replace(valued, `"4000000"`, `"9000000"`, 1)))
	rej := proposalOf("a-1")
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+rej+"/reject", map[string]any{"reason": ""}); got.code != 400 {
		t.Errorf("reject without a reason: %d", got.code)
	}
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+rej+"/reject", map[string]any{"reason": "the CMDB's value is wrong"}); got.code != 200 {
		t.Fatalf("reject: %d %s", got.code, got.raw)
	}
	push(assets, batchOf(strings.Replace(valued, `"4000000"`, `"9000000"`, 1)))
	if p := proposalOf("a-1"); p != "" {
		t.Error("the rejected values were proposed again")
	}

	// Control status: a new control version with its implementation.
	ctl := im.create(t, "analyst", "control", im.bu["A"], modeltest.Control())
	push(controls, batchOf(fmt.Sprintf(`{"kind": "control_status", "external_id": "c-1", "control": %q, "status": "not_in_place", "assessed_on": "2026-11-01"}`, ctl)))
	if got := accept(proposalOf("c-1"), map[string]any{"expected_version": 1}); got.code != 200 {
		t.Fatalf("accept the control status: %d %s", got.code, got.raw)
	}
	if got := im.adminQuery("SELECT convert_from(v.document, 'UTF8')::jsonb #>> '{implementation,status}' FROM risk.control_version v WHERE v.control_id = '" + ctl + "' AND v.version = 2"); got != "not_in_place" {
		t.Errorf("the control's implementation: %q", got)
	}

	// A complete batch without a-2: accepting the archive archives it and
	// drops the link.
	push(assets, `{"format": "fair.integration.v1", "complete": true, "records": [`+strings.Replace(valued, `"4000000"`, `"9000000"`, 1)+`, `+
		`{"kind": "asset_group", "external_id": "g-1", "bu": "A", "name": "Claims systems", "members": ["a-1", "a-2"]}]}`)
	arch := proposalOf("a-2")
	a2 := im.adminQuery("SELECT target_id FROM integration.link WHERE external_id = 'a-2'")
	if got := accept(arch, map[string]any{}); got.code != 200 {
		t.Fatalf("accept the archive: %d %s", got.code, got.raw)
	}
	if got := im.adminQuery("SELECT (archived_at IS NOT NULL) FROM risk.library_entry WHERE id = '" + a2 + "'"); got != "t" {
		t.Error("not archived")
	}
	if n := im.adminQuery("SELECT count(*) FROM integration.link WHERE external_id = 'a-2'"); n != "0" {
		t.Errorf("%s links left", n)
	}
}
