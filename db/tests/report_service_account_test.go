package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/rformer/fair-app/internal/reportapi"
	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/internal/reports/doc"
	risksvc "github.com/rformer/fair-app/internal/risk"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// visibleKind is a report of how many BUs the requester reads in the
// register (its delegated context's scope).
var visibleKind = reports.Kind{Name: "register", Title: "Visible units",
	Read: func(ctx context.Context, tx pgx.Tx, r reports.Run) (reports.Built, error) {
		var n int
		if err := tx.QueryRow(ctx, "SELECT cardinality(authz.visible_bus('register', 'read'))").Scan(&n); err != nil {
			return reports.Built{}, err
		}
		d := doc.Document{Metadata: doc.Metadata{Filters: map[string]string{}},
			Sections: []doc.Section{{Heading: "Scope", Level: 1, Blocks: []doc.Block{{Kind: doc.KindParagraph, Text: fmt.Sprintf("%d business units", n)}}}}}
		return reports.Built{Doc: d, Risks: n}, nil
	}}

// F-010 T-09b (F-010-AC-22; F-001 AC-36 as amended): a service account
// holds report.export only after a second administrator approved it, and
// then requests, polls and downloads a JSON report through the gateway,
// under the same rules as a person.
func TestServiceAccountReportExport(t *testing.T) {
	se := saFixture(t)
	e := se.e
	ctx := context.Background()
	buA := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")

	// The scope rule: report.export is the one privileged scope, and it
	// always needs an approval, whoever asks.
	if got := e.mustOwner("SELECT iam.sa_check_scopes(ARRAY['report.export', 'report.view'])"); got != "{report.export,report.view}" {
		t.Errorf("report.export refused: %s", got)
	}
	if got := e.mustOwner("SELECT iam.sa_unheld(" + uid("admin") + ", '" + buA + "', ARRAY['bu.view', 'report.export'])"); got != "{report.export}" {
		t.Errorf("report.export held at once: %s", got)
	}
	for _, scope := range []string{"bu.manage", "audit.export", "entitlement.export"} {
		r := se.do(t, "POST", "/api/v1/service-accounts", se.admin, map[string]any{"name": "X " + scope, "bu_id": buA, "scopes": []string{scope},
			"auth_method": "client_credentials", "reason": "r"}, se.hdr())
		if r.code != http.StatusBadRequest {
			t.Errorf("privileged scope %s: %d %s", scope, r.code, r.raw)
		}
	}

	// Created with report.export: an approval first, then applied.
	pend := se.do(t, "POST", "/api/v1/service-accounts", se.admin, map[string]any{"name": "BI feed", "bu_id": buA,
		"scopes": []string{"register.view", "report.export", "report.view"}, "auth_method": "client_credentials", "reason": "BI dashboards"}, se.hdr())
	approval, _ := pend.body["approval_id"].(string)
	if pend.code != http.StatusAccepted || approval == "" {
		t.Fatalf("create with report.export: %d %s", pend.code, pend.raw)
	}
	if r := se.do(t, "POST", "/api/v1/approvals/"+approval+"/decision", se.admin2, map[string]any{"approve": true, "reason": "BI feed agreed"},
		se.hdrFor(t, se.admin2)); r.code != 200 {
		t.Fatalf("approve: %d %s", r.code, r.raw)
	}
	applied := se.do(t, "POST", "/api/v1/service-accounts/apply", se.admin, map[string]any{"approval_id": approval}, se.hdr())
	sa, _ := applied.body["id"].(string)
	if applied.code != 200 || fmt.Sprint(applied.body["scopes"]) != "[register.view report.export report.view]" {
		t.Fatalf("apply: %d %s", applied.code, applied.raw)
	}
	e.drain()
	if got := e.adminQuery(`SELECT body ->> 'severity' FROM audit.intake WHERE body ->> 'type' = 'service_account.created' AND body ->> 'target' = 'service_account:` + sa + `'`); got != "high" {
		t.Errorf("creation audit: %q", got)
	}
	// Removing it applies at once; adding it back needs an approval again.
	if r := se.do(t, "PATCH", "/api/v1/service-accounts/"+sa, se.admin, map[string]any{"scopes": []string{"register.view", "report.view"}, "reason": "pause"}, se.hdr()); r.code != 200 {
		t.Fatalf("remove report.export: %d %s", r.code, r.raw)
	}
	re := se.do(t, "PATCH", "/api/v1/service-accounts/"+sa, se.admin, map[string]any{"scopes": []string{"register.view", "report.export", "report.view"},
		"reason": "resume"}, se.hdr())
	if re.code != http.StatusAccepted || fmt.Sprint(re.body["unheld_scopes"]) != "[report.export]" {
		t.Fatalf("add report.export again: %d %s", re.code, re.raw)
	}
	again, _ := re.body["approval_id"].(string)
	if r := se.do(t, "POST", "/api/v1/approvals/"+again+"/decision", se.admin2, map[string]any{"approve": true, "reason": "resumed"}, se.hdrFor(t, se.admin2)); r.code != 200 {
		t.Fatalf("approve again: %d %s", r.code, r.raw)
	}
	if r := se.do(t, "POST", "/api/v1/service-accounts/apply", se.admin, map[string]any{"approval_id": again}, se.hdr()); r.code != 200 {
		t.Fatalf("apply again: %d %s", r.code, r.raw)
	}
	e.drain()

	// The reports API behind the gateway (upstream risk).
	pool := e.appPool()
	e.mustOwner(fmt.Sprintf("SELECT authz.add_ctx_key('%s', decode('%s', 'hex'), 'report')", reportKey.ID, hex.EncodeToString(reportKey.Secret)))
	conn, err := pgx.ConnectConfig(ctx, migratorConfig(t, e))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := risksvc.SetCurrency(ctx, conn, audit.WithTrail(audit.NewMemory(), audit.Trail{DB: conn, Role: "fair_owner"}), "EUR", "installer"); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	if err := (settings.DBRegistrar{DB: pool}).Register(ctx, "F-010", "1", settings.F010Defs()); err != nil {
		t.Fatal(err)
	}
	sc := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: pool}, Service: "risk"})
	if err := sc.Register(settings.F010Defs()...); err != nil {
		t.Fatal(err)
	}
	if err := sc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: reports.RiverSchema})
	if err != nil {
		t.Fatal(err)
	}
	store := newMemStore()
	kinds := map[string]reports.Kind{"register": visibleKind}
	api := &reportapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), Kinds: kinds,
		Enqueue: reports.Enqueuer(rc), Store: store, Settings: sc}
	srv := httptest.NewServer(api.Handler(se.keys, nil))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	se.g.Upstreams["risk"] = u
	se.resetHandler(t)
	worker := &reports.Worker{DB: pool, Key: reportKey, Store: store, Kinds: kinds, Marking: func() (string, error) { return "Internal", nil }}

	access := se.accessToken(t, sa, se.secret(t, sa))
	call := func(method, path string, body any) (int, []byte, http.Header) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequestWithContext(ctx, method, se.url+path, rd)
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("X-Forwarded-For", loginIP)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(server.IdempotencyHeader, fmt.Sprintf("sa-report-%d", time.Now().UnixNano()))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b, resp.Header
	}
	code, body, _ := call("POST", "/api/v1/reports", map[string]any{"kind": "register", "bu_id": buA, "formats": []string{"json"}})
	var run struct {
		ID    string `json:"id"`
		State string `json:"state"`
		Files []struct {
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &run); code != http.StatusAccepted || err != nil || run.State != "queued" {
		t.Fatalf("request: %d %s", code, body)
	}
	if got := e.adminQuery("SELECT body ->> 'actor' FROM audit.intake WHERE body ->> 'type' = 'report.requested' AND body ->> 'target' = 'report_run:" + run.ID + "'"); got != sa {
		t.Errorf("report.requested actor: %q, want the service account", got)
	}
	if err := worker.Attempt(ctx, run.ID, 1, reports.Attempts); err != nil {
		t.Fatal(err)
	}
	code, body, _ = call("GET", "/api/v1/reports/"+run.ID, nil)
	if err := json.Unmarshal(body, &run); code != 200 || err != nil || run.State != "succeeded" || len(run.Files) != 1 {
		t.Fatalf("poll: %d %s", code, body)
	}
	code, body, hdr := call("GET", "/api/v1/reports/"+run.ID+"/files/json", nil)
	sum := sha256.Sum256(body)
	if code != 200 || hex.EncodeToString(sum[:]) != run.Files[0].SHA256 || hdr.Get("X-Fair-Digest") != "sha256="+run.Files[0].SHA256 {
		t.Fatalf("download: %d %s", code, body)
	}
	var j struct {
		Metadata doc.Metadata `json:"metadata"`
	}
	if err := json.Unmarshal(body, &j); err != nil || j.Metadata.GeneratedBy != "BI feed" || j.Metadata.Currency != "EUR" {
		t.Errorf("metadata: %+v %v", j.Metadata, err)
	}
	if got := e.adminQuery("SELECT risk_count FROM report.run WHERE id = '" + run.ID + "'"); got != "2" {
		t.Errorf("the account read %s BUs, want A and A1", got)
	}
}
