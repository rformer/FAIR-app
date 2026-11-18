package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/importapi"
	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/registerapi"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// reviewAllAPI serves the risk, register and imports APIs as cmd/risk
// mounts them, with the register's settings in force and "rowner" (Risk
// Owner at A: register.edit) and "pusher2" (integration.push and Risk
// Analyst at A: library.edit) added.
func reviewAllAPI(t *testing.T) *importEnv {
	t.Helper()
	im := importAPI(t)
	im.setCurrency(t, "USD")
	seedPosture(t, im.env)
	for _, u := range []string{"rowner", "pusher2"} {
		im.mustOwner(fmt.Sprintf("INSERT INTO iam.app_user (email, display_name) VALUES ('%s@example.test', '%s')", u, u))
	}
	im.mustOwner(grant("platform", "user:rowner", "Risk Owner", "A"))
	im.mustOwner(grant("platform", "user:pusher2", "Integration Pusher", "A"))
	im.mustOwner(grant("platform", "user:pusher2", "Risk Analyst", "A"))
	im.drain()
	pool := im.appPool()
	cache := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)})
	emitter := audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})
	risk := &riskapi.API{Reasons: reason.Static{}, DB: pool, Authz: cache, Audit: emitter}
	reg := &registerapi.API{DB: pool, Authz: cache, Audit: emitter}
	imp := &importapi.API{DB: pool, Authz: cache, Risk: risk, Register: reg}
	mux := http.NewServeMux()
	mux.Handle("/", risk.Handler(im.keys, nil))
	for prefixes, h := range map[*[]string]http.Handler{&registerapi.Prefixes: reg.Handler(im.keys, nil), &importapi.Prefixes: imp.Handler(im.keys, nil)} {
		for _, p := range *prefixes {
			mux.Handle(p, h)
			mux.Handle(p+"/", h)
		}
	}
	for _, p := range importapi.Patterns {
		mux.Handle(p, imp.Handler(im.keys, nil))
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	im.url = srv.URL
	return im
}

// F-011 T-10b (F-011-AC-11, AC-13, AC-20, AC-25; design §3.4, §3.8):
// risks through the register's save code, batch accepts, auto_accept,
// provenance on version reads, and the proposals_waiting notice.
func TestProposalReviewMore(t *testing.T) {
	im := reviewAllAPI(t)
	ctx := context.Background()
	add := func(name, kind string, auto bool) string {
		t.Helper()
		var id string
		if err := im.ie.as("platform", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT integration.add($1, $2, $3, 'push', '{}', NULL, NULL, $4)::text", im.bu["A"], name, kind, auto).Scan(&id)
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	push := func(user, id, body string) map[string]any {
		t.Helper()
		got := im.send(t, user, "/api/v1/imports/"+id+"/batches", "application/json", body)
		if got.code != 201 {
			t.Fatalf("push: %d %s", got.code, got.raw)
		}
		return got.body["counts"].(map[string]any)
	}
	pending := func(ext string) string {
		return im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = '" + ext + "' AND state = 'pending'")
	}
	accept := func(user, id string, body map[string]any) apiResp {
		t.Helper()
		return im.call(t, "POST", user, "/api/v1/proposals/"+id+"/accept", body)
	}

	// Risks: the owner by email among the register's readers there, the
	// category by name; created unquantified through the register's code.
	risks := add("Old register", "risks", false)
	risk := func(ext, title, owner string) string {
		return fmt.Sprintf(`{"kind": "risk", "external_id": %q, "bu": "A", "title": %q, "owner": %q, "category": "Cyber"}`, ext, title, owner)
	}
	push("pusher", risks, batchOf(risk("R-1", "Ransomware", "rowner@example.test"), risk("R-2", "Unknown owner", "nobody@example.test")))
	if got := im.call(t, "GET", "rowner", "/api/v1/proposals/"+pending("R-2"), nil); !strings.Contains(got.raw, "not an active user") {
		t.Errorf("an unknown owner: %s", got.raw)
	}
	if got := accept("analyst", pending("R-1"), map[string]any{}); got.code != 403 {
		t.Errorf("a Risk Analyst creates a risk: %d %s", got.code, got.raw)
	}
	if got := accept("rowner", pending("R-1"), map[string]any{}); got.code != 200 {
		t.Fatalf("accept R-1: %d %s", got.code, got.raw)
	}
	riskID := im.adminQuery("SELECT target_id FROM integration.link WHERE external_id = 'R-1'")
	if got := im.adminQuery("SELECT r.state || ':' || (r.owner = " + uid("rowner") + ") || ':' || c.name FROM register.risk r JOIN register.category c ON c.id = r.category_id WHERE r.id = '" + riskID + "'"); got != "open:true:Cyber" {
		t.Errorf("the created risk: %s", got)
	}
	push("pusher", risks, batchOf(risk("R-1", "Ransomware on claims", "rowner@example.test")))
	if got := accept("rowner", pending("R-1"), map[string]any{"expected_version": 1}); got.code != 200 {
		t.Fatalf("accept the update: %d %s", got.code, got.raw)
	}
	// Provenance on the register's version reads (AC-25).
	vs := im.call(t, "GET", "rowner", "/api/v1/register/risks/"+riskID+"/versions", nil)
	if vs.code != 200 || strings.Count(vs.raw, `"integration_name":"Old register"`) != 2 || !strings.Contains(vs.raw, `"external_id":"R-1"`) {
		t.Errorf("risk versions: %d %s", vs.code, vs.raw)
	}

	// Batch accept: all or nothing.
	assets := add("CMDB", "assets", false)
	push("pusher", assets, batchOf(asset("a-1", "A", "One"), asset("a-2", "A", "Two"), asset("a-3", "A", "Three")))
	ids := []string{pending("a-1"), pending("a-2"), pending("a-3")}
	if got := accept("analyst", ids[0], map[string]any{}); got.code != 200 {
		t.Fatal(got.raw)
	}
	got := im.call(t, "POST", "analyst", "/api/v1/proposals/accept", map[string]any{"proposals": []map[string]any{{"id": ids[1]}, {"id": ids[0]}, {"id": ids[2]}}})
	if got.code != 409 || got.hdr.Get("X-Fair-Failed-Proposal") != ids[0] || pending("a-2") == "" {
		t.Errorf("a batch with a decided one: %d %s (a-2 pending: %q)", got.code, got.raw, pending("a-2"))
	}
	got = im.call(t, "POST", "analyst", "/api/v1/proposals/accept", map[string]any{"proposals": []map[string]any{{"id": ids[1]}, {"id": ids[2]}}, "change_note": "Weekly CMDB review"})
	if got.code != 200 || len(got.body["accepted"].([]any)) != 2 {
		t.Fatalf("a batch accept: %d %s", got.code, got.raw)
	}
	entry := im.adminQuery("SELECT target_id FROM integration.link WHERE external_id = 'a-2'")
	if note := im.adminQuery("SELECT change_note FROM risk.library_version WHERE entry_id = '" + entry + "'"); note != "Weekly CMDB review" {
		t.Errorf("the batch's change note: %q", note)
	}
	// Provenance on the library's version reads.
	vs = im.call(t, "GET", "analyst", "/api/v1/library/"+entry+"/versions", nil)
	if vs.code != 200 || !strings.Contains(vs.raw, `"provenance":{"version":1`) || !strings.Contains(vs.raw, `"integration_name":"CMDB"`) {
		t.Errorf("library versions: %d %s", vs.code, vs.raw)
	}
	// A reader without the integration's... sees provenance too: it is
	// the record's (the view permission at the record's BU).
	if vs := im.call(t, "GET", "erin", "/api/v1/library/"+entry+"/versions", nil); !strings.Contains(vs.raw, `"provenance"`) {
		t.Errorf("erin's view of the versions: %s", vs.raw)
	}

	// auto_accept (AC-13): descriptive-only changes at once, as a pusher
	// who may write them; values and pushers who may not still wait.
	auto := add("CMDB auto", "assets", true)
	push("pusher2", auto, batchOf(asset("b-1", "A", "Before")))
	if got := accept("analyst", pending("b-1"), map[string]any{}); got.code != 200 {
		t.Fatal(got.raw)
	}
	c := push("pusher2", auto, batchOf(asset("b-1", "A", "After")))
	if c["applied"] != 1.0 || pending("b-1") != "" {
		t.Errorf("a descriptive change, auto: %v (pending %q)", c, pending("b-1"))
	}
	b1 := im.adminQuery("SELECT target_id FROM integration.link WHERE external_id = 'b-1'")
	if got := im.adminQuery("SELECT (convert_from(document, 'UTF8')::jsonb ->> 'name') || ':' || change_note FROM risk.library_version WHERE entry_id = '" + b1 + "' AND version = 2"); !strings.HasPrefix(got, "After:Accepted automatically") {
		t.Errorf("the automatic version: %s", got)
	}
	c = push("pusher2", auto, batchOf(`{"kind": "asset", "external_id": "b-1", "bu": "A", "name": "After", "asset_type": "application", "value": {"min": "1", "ml": "2", "max": "3"}}`))
	if c["applied"] != 0.0 || pending("b-1") == "" {
		t.Errorf("a value change, auto: %v", c)
	}
	c = push("pusher", auto, batchOf(asset("b-2", "A", "New")))
	if c["applied"] != 0.0 {
		t.Errorf("a create is never automatic: %v", c)
	}

	// Notices (F-009): one per run leaving proposals pending, to the
	// holders of the kind's edit permission at the integration's BU.
	if n := im.adminQuery("SELECT count(*) FROM integration.notice_outbox WHERE kind = 'integration.proposals_waiting'"); n == "0" {
		t.Fatal("no proposals_waiting notices")
	}
	if got := im.adminQuery(`SELECT count(*) FROM integration.notice_outbox o JOIN integration.run r ON r.id = o.run_id
		WHERE NOT EXISTS (SELECT 1 FROM integration.proposal p WHERE p.run_id = r.id)`); got != "0" {
		t.Errorf("%s notices for runs that proposed nothing", got)
	}
	np := rolePool(t, im.env, "app_notify")
	if _, err := np.Exec(ctx, "SELECT notify.collect(false, 1000)"); err != nil {
		t.Fatal(err)
	}
	if got := im.adminQuery("SELECT count(*) FROM notify.notice WHERE source = 'integration' AND item_type = 'integration_run'"); got == "0" {
		t.Error("no notice collected from the integration outbox")
	}
	if got := im.adminQuery("SELECT count(*) FROM integration.notice_outbox WHERE delivered_at IS NULL"); got != "0" {
		t.Errorf("%s notices left in the outbox", got)
	}
}
