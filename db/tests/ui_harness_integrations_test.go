package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/egress"
	"github.com/rformer/fair-app/internal/importapi"
	"github.com/rformer/fair-app/internal/integrateapi"
	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/internal/registerapi"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-18: integrations in the UI harness. The imports API is mounted
// beside the risk service's other APIs as cmd/risk does; the integrations
// API is its own upstream ("integrate"), as the integrate service serves
// it, with sources allowed at cmdb.example.test (a fixed TEST-NET address)
// and a stand-in for the connectors' test fetch.

// mountHarnessImports mounts the imports API on mux.
func mountHarnessImports(mux *http.ServeMux, rp *pgxpool.Pool, keys *authz.LocalKeys, risk *riskapi.API, reg *registerapi.API) {
	api := &importapi.API{DB: rp, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(rp), MaxAge: time.Second}), Risk: risk, Register: reg}
	h := api.Handler(keys, nil)
	for _, prefix := range importapi.Prefixes {
		mux.Handle(prefix, h)
		mux.Handle(prefix+"/", h)
	}
	for _, pattern := range importapi.Patterns {
		mux.Handle(pattern, h)
	}
}

// startHarnessIntegrate serves the integrations API as app_integrate and
// answers its upstream URL.
func startHarnessIntegrate(t *testing.T, e *env, keys *authz.LocalKeys) (*url.URL, func()) {
	t.Helper()
	ring, err := integration.NewKeyring(map[string][]byte{"k-20261118": []byte("harness integrate key, 32 bytes!")})
	if err != nil {
		t.Fatal(err)
	}
	guard := egress.Guard{Setting: "integration.allowed_hosts", Cluster: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Allowed: func() []string { return []string{"cmdb.example.test"} }, Resolver: testResolver{"cmdb.example.test": "203.0.113.10"}}
	api := &integrateapi.API{DB: rolePool(t, e, "app_integrate"), Keys: ring, Guard: guard, Tester: &fakeTester{}}
	srv := httptest.NewServer(api.Handler(keys, nil))
	u, _ := url.Parse(srv.URL)
	return u, srv.Close
}

// seedIntegrations (F-011 T-18): "admin" (Platform Admin at the root)
// manages two integrations at the root: "Asset inventory" (pushed), whose
// upload left three asset proposals and one refused record for
// "riskanalyst" (Risk Analyst at the root) to review, and "Incident
// register" (loss events), whose upload wrote three loss events; and a
// connector "CMDB pull" with its source credential set; "riskanalyst"
// keeps a reference class "Phishing incidents, enterprise" to derive.
func seedIntegrations(t *testing.T, e *env, keys *authz.LocalKeys, riskURL, integrateURL string) {
	t.Helper()
	ctx := context.Background()
	root := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'ENTERPRISE'")
	pool := rolePool(t, e, "app_integrate")
	add := func(name, kind, delivery, connector string) string {
		var id string
		var c any
		if connector != "" {
			c = connector
		}
		var sa any
		if delivery == "connector" {
			sa = e.adminQuery("SELECT id FROM iam.service_account WHERE name = 'cmdb-connector'")
		}
		if err := authz.WithDBContext(ctx, pool, e.principal("admin").DBToken, func(tx pgx.Tx) error {
			mapping := "{}"
			if delivery == "connector" {
				mapping = `{"columns": {"/id": "external_id", "/name": "name"}, "defaults": {"asset_type": "application", "bu": "ENTERPRISE"}}`
			}
			return tx.QueryRow(ctx, "SELECT integration.add($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::uuid, false)::text", root, name, kind, delivery, mapping, c, sa).Scan(&id)
		}); err != nil {
			t.Fatalf("seed integration %s: %v", name, err)
		}
		return id
	}
	// The connector's service account, at the root.
	e.mustOwner(`WITH u AS (INSERT INTO iam.app_user (email, display_name, source) VALUES ('cmdb-connector@service.invalid', 'cmdb-connector', 'service') RETURNING id),
		r AS (INSERT INTO iam.role (name) VALUES ('sa role cmdb-connector') RETURNING id)
		INSERT INTO iam.service_account (id, name, bu_id, role_id, auth_method, created_by)
		SELECT u.id, 'cmdb-connector', ` + buID("ENTERPRISE") + `, r.id, 'client_credentials', ` + uid("admin") + ` FROM u, r`)
	assets := add("Asset inventory", "assets", "push", "")
	events := add("Incident register", "loss_events", "push", "")
	cmdb := add("CMDB pull", "assets", "connector", `{"type": "http_json", "source": "https://cmdb.example.test/api/apps", "schedule_minutes": 1440, "settings": {"list": "/items"}}`)

	ra := &riskAPIEnv{riskEnv: riskEnv{e, map[string]string{"ENTERPRISE": root}}, url: riskURL, keys: keys, n: 700000}
	asset := func(ext, name, typ string) string {
		return fmt.Sprintf(`{"kind": "asset", "external_id": %q, "bu": "ENTERPRISE", "name": %q, "asset_type": %q}`, ext, name, typ)
	}
	body := `{"format": "fair.integration.v1", "records": [` + strings.Join([]string{asset("app-101", "Policy administration", "application"),
		asset("app-102", "Claims document store", "data"), asset("app-103", "Agent portal", "application"),
		`{"kind": "asset", "external_id": "app-104", "bu": "ENTERPRISE", "name": "", "asset_type": "application"}`}, ",") + `]}`
	got := ra.call(t, "POST", "admin", "/api/v1/imports/"+assets+"/batches", json.RawMessage(body))
	if got.code != 201 {
		t.Fatalf("seed asset batch: %d %s", got.code, got.raw)
	}
	event := func(ext, on, typ, desc, amount string) string {
		return fmt.Sprintf(`{"kind": "loss_event", "external_id": %q, "bu": "ENTERPRISE", "occurred_on": %q, "event_type": %q, "description": %q, "amounts": {"response": %q}}`,
			ext, on, typ, desc, amount)
	}
	body = `{"format": "fair.integration.v1", "records": [` + strings.Join([]string{event("inc-1", "2026-02-11", "phishing", "Credential phishing of claims staff", "42000"),
		event("inc-2", "2026-05-03", "phishing", "Invoice fraud attempt", "18500"), event("inc-3", "2026-08-19", "outage", "Claims platform outage", "120000")}, ",") + `]}`
	if got := ra.call(t, "POST", "admin", "/api/v1/imports/"+events+"/batches", json.RawMessage(body)); got.code != 201 {
		t.Fatalf("seed loss events: %d %s", got.code, got.raw)
	}
	// A reference class to derive from those events (AC-18).
	rc := modeltest.ReferenceClass()
	rc["name"] = "Phishing incidents, enterprise"
	if got := ra.call(t, "POST", "riskanalyst", "/api/v1/library", map[string]any{"bu_id": root, "kind": "reference_class", "document": rc,
		"change_note": "From the incident register"}); got.code != 201 {
		t.Fatalf("seed reference class: %d %s", got.code, got.raw)
	}
	ia := &riskAPIEnv{riskEnv: ra.riskEnv, url: integrateURL, keys: keys, n: 710000, aud: "integrate"}
	if got := ia.call(t, "PUT", "admin", "/api/v1/integrations/"+cmdb+"/credentials/source", map[string]any{"token": "harness-source-token"}); got.code != 200 {
		t.Fatalf("seed credential: %d %s", got.code, got.raw)
	}
}
