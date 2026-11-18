package tests

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/egress"
	"github.com/rformer/fair-app/internal/importapi"
	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// apiSubmitter stands in for the gateway: it checks the service account's
// client secret, then submits to the imports API with a token for that
// service account, as the gateway's proxy would.
type apiSubmitter struct {
	ia     *integrateEnv
	url    string
	sa     string // the service account's user name in the fixture
	secret string
	mu     sync.Mutex
	subs   []integration.Submission
}

func (s *apiSubmitter) Submit(ctx context.Context, sub integration.Submission) (int, []byte, error) {
	s.mu.Lock()
	s.subs = append(s.subs, sub)
	s.mu.Unlock()
	if sub.ClientSecret != s.secret {
		return 0, nil, fmt.Errorf("integration: the service account's token was refused (401 invalid_client)")
	}
	p := s.ia.principal(s.sa)
	tok, err := authz.MintJWT(s.ia.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(p.DBToken), ServiceAccount: true}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		return 0, nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", s.url+"/api/v1/imports/"+sub.IntegrationID+"/batches?trigger="+sub.Trigger, bytes.NewReader(sub.Body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", sub.Key)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(server.DBContextHeader, p.DBToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

// F-011 T-17 (F-011-AC-04, AC-08, AC-14; design §3.3): the connector runner
// end to end: claims, the service account's submission through the
// imports API, schedules, back-off, three failures notifying the
// managers, refused destinations recorded, lost claims.
func TestConnectorRunner(t *testing.T) {
	ia := integrateAPI(t)
	ctx := context.Background()
	// sa-conn: a service account at A holding integration.push there.
	ia.mustOwner(`WITH u AS (INSERT INTO iam.app_user (email, display_name, source) VALUES ('sa-conn@example.test', 'sa-conn', 'service') RETURNING id),
		r AS (INSERT INTO iam.role (name) VALUES ('sa role sa-conn') RETURNING id),
		v AS (INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['integration.push'], 'test' FROM r)
		INSERT INTO iam.service_account (id, name, bu_id, role_id, auth_method, created_by)
		SELECT u.id, 'sa-conn', ` + buID("A") + `, r.id, 'client_credentials', ` + uid("platform") + ` FROM u, r`)
	ia.mustOwner(grant("platform", "user:sa-conn", "sa role sa-conn", "A"))
	ia.drain()

	// The risk side: the imports API as app_rw.
	pool := ia.appPool()
	imports := httptest.NewServer((&importapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)})}).Handler(ia.keys, nil))
	t.Cleanup(imports.Close)

	// The source: a local HTTPS server whose answer the test sets.
	var mu sync.Mutex
	answer := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"items": [{"id": "app-1", "unit": "A", "name": "Claims"}, {"id": "app-2", "unit": "A1", "name": "Billing"}]}`)
	}
	var auths []string
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		h := answer
		mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(src.Close)
	setAnswer := func(h func(w http.ResponseWriter, r *http.Request)) {
		mu.Lock()
		answer = h
		mu.Unlock()
	}
	roots := x509.NewCertPool()
	roots.AddCert(src.Certificate())
	guard := egress.Guard{Setting: "integration.allowed_hosts", Allowed: func() []string { return []string{"127.0.0.1"} }}.
		AllowingForTest(netip.MustParsePrefix("127.0.0.0/8"))
	keys, err := integration.NewKeyring(map[string][]byte{"k-20261118": []byte("integrate test key, 32 bytes!!!")}) // integrateAPI's
	if err != nil {
		t.Fatal(err)
	}
	sub := &apiSubmitter{ia: ia, url: imports.URL, sa: "sa-conn", secret: "sa-conn-secret"}
	runner := integration.Runner{DB: ia.ie.pool, Keys: keys, Fetch: integration.Fetcher{Guard: guard, TLS: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		Submit: sub}
	step := func() []integration.Outcome {
		t.Helper()
		out, err := runner.Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// A connector integration at A (created in the database: the API's
	// guard does not allow the loopback source), its credentials set
	// through the API.
	add := func(name string) string {
		t.Helper()
		var id string
		if err := ia.ie.as("platform", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT integration.add($1, $2, 'assets', 'connector', $3::jsonb, $4::jsonb, $5, false)::text`, ia.bu["A"], name,
				`{"columns": {"/id": "external_id", "/unit": "bu", "/name": "name"}, "defaults": {"asset_type": "application"}}`,
				fmt.Sprintf(`{"type": "http_json", "source": %q, "schedule_minutes": 60, "settings": {"list": "/items"}}`, src.URL+"/apps"),
				ia.adminQuery("SELECT id FROM iam.service_account WHERE name = 'sa-conn'")).Scan(&id)
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	id := add("CMDB connector")
	for purpose, body := range map[string]map[string]any{"source": {"token": "src-token-1"}, "client": {"client_secret": "sa-conn-secret"}} {
		if got := ia.call(t, "PUT", "platform", "/api/v1/integrations/"+id+"/credentials/"+purpose, body); got.code != 200 {
			t.Fatalf("set %s: %d %s", purpose, got.code, got.raw)
		}
	}
	due := func(id string) {
		t.Helper()
		ia.mustOwner("UPDATE integration.integration SET next_run_at = now() - interval '1 second' WHERE id = '" + id + "'")
	}
	minutesToNext := func(id string) string {
		t.Helper()
		return ia.adminQuery("SELECT coalesce(round(extract(epoch FROM next_run_at - now()) / 60)::text, 'none') FROM integration.integration WHERE id = '" + id + "'")
	}

	// A scheduled run: fetched with the source token, submitted complete as
	// the service account, proposals staged, the next run a schedule away.
	out := step()
	if len(out) != 1 || !out[0].Succeeded || out[0].Run == "" {
		t.Fatalf("first run: %+v", out)
	}
	if got := ia.adminQuery("SELECT trigger || ' ' || complete || ' ' || state || ' ' || (actor = " + uid("sa-conn") + ") || ' ' || (counts ->> 'new') FROM integration.run WHERE id = '" + out[0].Run + "'"); got != "schedule true succeeded true 2" {
		t.Errorf("the run: %s", got)
	}
	if got := ia.adminQuery("SELECT count(*) FROM integration.proposal WHERE integration_id = '" + id + "' AND state = 'pending'"); got != "2" {
		t.Errorf("%s proposals", got)
	}
	if got := minutesToNext(id); got != "60" {
		t.Errorf("next run in %s minutes", got)
	}
	if got := ia.adminQuery("SELECT claim_token IS NULL AND failures = 0 FROM integration.integration WHERE id = '" + id + "'"); got != "t" {
		t.Errorf("after success: %s", got)
	}
	if auths[0] != "Bearer src-token-1" || !strings.HasPrefix(sub.subs[0].Key, "connector-") || sub.subs[0].Trigger != "schedule" {
		t.Errorf("auth %q submission %+v", auths[0], sub.subs[0])
	}
	if out := step(); len(out) != 0 {
		t.Errorf("a run before it was due: %+v", out)
	}

	// Run now: the next step sends a manual run.
	if got := ia.call(t, "POST", "platform", "/api/v1/integrations/"+id+"/run", nil); got.code != 202 {
		t.Fatalf("run now: %d %s", got.code, got.raw)
	}
	out = step()
	if len(out) != 1 || !out[0].Succeeded {
		t.Fatalf("manual run: %+v", out)
	}
	if got := ia.adminQuery("SELECT trigger FROM integration.run WHERE id = '" + out[0].Run + "'"); got != "manual" {
		t.Errorf("trigger %s", got)
	}
	if got := ia.adminQuery("SELECT run_requested_at IS NULL FROM integration.integration WHERE id = '" + id + "'"); got != "t" {
		t.Error("the run request stayed")
	}

	// Failures: recorded as failed runs, backed off, the third notifying
	// the integration's managers once.
	setAnswer(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) })
	for i, want := range []string{"60", "120", "240", "480"} {
		due(id)
		out = step()
		if len(out) != 1 || out[0].Succeeded || out[0].Failures != i+1 || !strings.Contains(out[0].Failure, "503") {
			t.Fatalf("failure %d: %+v", i+1, out)
		}
		if got := minutesToNext(id); got != want {
			t.Errorf("after failure %d: next in %s minutes, want %s", i+1, got, want)
		}
	}
	if got := ia.adminQuery("SELECT count(*) FROM integration.run WHERE integration_id = '" + id + "' AND state = 'failed' AND failure LIKE '%503%' AND trigger = 'schedule'"); got != "4" {
		t.Errorf("%s failed runs recorded", got)
	}
	if got := ia.adminQuery("SELECT count(*) FROM integration.notice_outbox WHERE kind = 'integration.run_failed' AND integration_id = '" + id + "'"); got != "1" {
		t.Errorf("%s run_failed notices", got)
	}
	if got := ia.events(t, "integration.run", "body ->> 'severity' = 'high' AND body -> 'attributes' ->> 'state' = 'failed'"); got != "4" {
		t.Errorf("%s failed run events", got)
	}
	np := notifyPool(t, ia.env)
	if _, _, err := (notify.Collector{DB: np}).Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := (notify.FanOut{DB: np}).Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ia.adminQuery(`SELECT string_agg(u.display_name, ',' ORDER BY u.display_name) FROM notify.recipient r JOIN notify.notice n ON n.id = r.notice_id
		JOIN iam.app_user u ON u.id = r.user_id WHERE n.kind = 'integration.run_failed' AND r.in_app`); !strings.Contains(got, "platform") || strings.Contains(got, "aud") {
		t.Errorf("run_failed delivered to %s", got)
	}
	// A success resets the count.
	setAnswer(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"items": [{"id": "app-1", "unit": "A", "name": "Claims"}]}`)
	})
	due(id)
	if out = step(); len(out) != 1 || !out[0].Succeeded {
		t.Fatalf("recovery: %+v", out)
	}
	if got := ia.adminQuery("SELECT failures || ' ' || coalesce(last_failure, '-') FROM integration.integration WHERE id = '" + id + "'"); got != "0 -" {
		t.Errorf("after recovery: %s", got)
	}

	// AC-04: a next page on another host is refused and recorded.
	setAnswer(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"items": [], "next": "https://198.51.100.7/more"}`)
	})
	ia.mustOwner(`UPDATE integration.integration SET connector = jsonb_set(connector, '{settings}', '{"list": "/items", "paging": {"next": "/next"}}') WHERE id = '` + id + "'")
	due(id)
	if out = step(); len(out) != 1 || out[0].Succeeded || out[0].Refused != "127.0.0.1" {
		t.Fatalf("refused page: %+v", out)
	}
	if got := ia.events(t, "integration.destination_refused", "body -> 'attributes' ->> 'during' = 'run' AND body ->> 'target' = 'integration:"+id+"'"); got != "1" {
		t.Errorf("%s run refusals recorded", got)
	}

	// No client credential: a failure, nothing submitted.
	if got := ia.call(t, "DELETE", "platform", "/api/v1/integrations/"+id+"/credentials/client", nil); got.code != 200 {
		t.Fatal(got.raw)
	}
	n := len(sub.subs)
	due(id)
	if out = step(); len(out) != 1 || out[0].Succeeded || !strings.Contains(out[0].Failure, "client credential") || len(sub.subs) != n {
		t.Errorf("no client credential: %+v", out)
	}

	// A claim is its claimant's: a stale token changes nothing; a paused
	// integration is not rescheduled.
	other := add("Second connector")
	var token string
	if err := ia.ie.pool.QueryRow(ctx, "SELECT token::text FROM integration.claim_due(900, 10) WHERE id = $1", other).Scan(&token); err != nil {
		t.Fatal(err)
	}
	if _, err := ia.ie.pool.Exec(ctx, "SELECT integration.connector_failed($1, gen_random_uuid(), 'x', NULL)", other); pgState(err) != "PF031/claim_lost" {
		t.Errorf("a stale token: %v", err)
	}
	if got := ia.call(t, "POST", "platform", "/api/v1/integrations/"+other+"/pause", nil); got.code != 200 {
		t.Fatal(got.raw)
	}
	if _, err := ia.ie.pool.Exec(ctx, "SELECT integration.connector_failed($1, $2, 'fetch failed', NULL)", other, token); err != nil {
		t.Fatal(err)
	}
	if got := minutesToNext(other); got != "none" {
		t.Errorf("a paused integration rescheduled in %s minutes", got)
	}
	// Only app_integrate claims.
	if _, err := pool.Exec(ctx, "SELECT * FROM integration.claim_due(900, 1)"); pgState(err) != "42501" {
		t.Errorf("app_rw claims: %v", err)
	}
	if strings.Contains(ia.adminQuery("SELECT string_agg(body::text, '') FROM audit.intake"), "sa-conn-secret") {
		t.Error("the client secret reached the audit trail")
	}
}
