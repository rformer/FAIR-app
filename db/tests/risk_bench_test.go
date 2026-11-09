package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-003 T-14 (requirements NFR "Performance"; design §4.4, §6.1): at the
// F-001 target scale (2,011 BUs, 10,000 users), 10,000 scenarios in one
// level-1 subtree and as many elsewhere, each pinning an asset, a threat
// community and a control kept at the root, so every pin of an analyst in
// the subtree is an inherited read. Lists page in <= 500 ms p95 and a
// scenario loads with its pins in <= 300 ms p95, measured through the risk
// API (HTTP, JSON, authorization, the DB context and RLS), as the service
// serves them.

const (
	riskBenchPerSubtree = 10_000
	riskListBudget      = 500 * time.Millisecond
	riskLoadBudget      = 300 * time.Millisecond
	riskBenchRuns       = 20
	riskBenchLibrary    = 50
	riskBenchControls   = 20
)

func TestBenchmarkGateRiskScenarios(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	start := time.Now()
	perSubtree := riskBenchPerSubtree
	if n := os.Getenv("FAIR_BENCH_RISK_SCENARIOS"); n != "" { // a smaller run, by hand
		perSubtree, _ = strconv.Atoi(n)
	}
	(&riskAPIEnv{riskEnv: riskEnv{env: e}}).setCurrency(t, "USD")

	// Three risk analysts: at the root (the seeder), at L1_1 (the measured
	// subtree) and at one leaf of it.
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	l1 := e.mustOwner("SELECT id FROM iam.bu WHERE code = 'L1_1'")
	leaf := e.mustOwner(`SELECT b.id FROM iam.bu b JOIN iam.bu_closure c ON c.descendant_id = b.id AND c.ancestor_id = (SELECT id FROM iam.bu WHERE code = 'L1_1')
		WHERE b.depth = 3 AND NOT b.restricted ORDER BY b.code LIMIT 1`)
	e.mustOwner(`INSERT INTO iam.app_user (email, display_name) VALUES ('benchseed@example.test', 'Bench Seed'),
		('benchsub@example.test', 'Bench Subtree'), ('benchleaf@example.test', 'Bench Leaf')`)
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = 'Risk Analyst'),
		       CASE u.email WHEN 'benchseed@example.test' THEN '%s'::uuid WHEN 'benchsub@example.test' THEN '%s'::uuid ELSE '%s'::uuid END, '%s'
		FROM iam.app_user u WHERE u.email IN ('benchseed@example.test', 'benchsub@example.test', 'benchleaf@example.test')`, root, l1, leaf, granter))
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	e.mustOwner("DELETE FROM iam.outbox")
	e.mustOwner("GRANT EXECUTE ON FUNCTION risk.canonical(jsonb) TO app_rw") // the seeding below only; a test database

	// Writable BUs: unrestricted ones (the seeder's grant at the root does
	// not reach into restricted subtrees).
	inside := e.mustOwner(`SELECT string_agg(b.id::text, ',' ORDER BY b.code) FROM iam.bu b JOIN iam.bu_closure c ON c.descendant_id = b.id
		WHERE c.ancestor_id = (SELECT id FROM iam.bu WHERE code = 'L1_1') AND NOT b.restricted`)
	outside := e.mustOwner(`SELECT string_agg(b.id::text, ',' ORDER BY b.code) FROM iam.bu b WHERE b.depth > 0 AND NOT b.restricted
		AND NOT EXISTS (SELECT 1 FROM iam.bu_closure c WHERE c.descendant_id = b.id AND c.ancestor_id = (SELECT id FROM iam.bu WHERE code = 'L1_1'))`)
	seed := func(sql string) {
		t.Helper()
		if err := (riskEnv{env: e}).tx("benchseed", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), sql)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	tmpl := func(kind string, doc map[string]any) string { return templateJSON(t, kind, doc) }
	// The library at the root, through the version triggers (validation,
	// summaries); asset values need the currency set above.
	seed(fmt.Sprintf(`DO $$
DECLARE id uuid; b bytea; d jsonb;
BEGIN
  FOR i IN 1..%[1]d LOOP
    FOREACH d IN ARRAY ARRAY['%[3]s'::jsonb, '%[4]s'::jsonb] LOOP
      d := d || jsonb_build_object('name', (d->>'name') || ' ' || i);
      INSERT INTO risk.library_entry (bu_id, kind) VALUES ('%[5]s', d->>'kind') RETURNING library_entry.id INTO id;
      b := convert_to(risk.canonical(d), 'UTF8');
      INSERT INTO risk.library_version (entry_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
    END LOOP;
  END LOOP;
  FOR i IN 1..%[2]d LOOP
    d := '%[6]s'::jsonb || jsonb_build_object('name', 'Control ' || i);
    INSERT INTO risk.control (bu_id) VALUES ('%[5]s') RETURNING control.id INTO id;
    b := convert_to(risk.canonical(d), 'UTF8');
    INSERT INTO risk.control_version (control_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
END $$`, riskBenchLibrary, riskBenchControls, tmpl("asset", modeltest.Asset()), tmpl("threat_community", modeltest.ThreatCommunity()),
		root, tmpl("control", modeltest.Control())))
	owner := e.mustOwner("SELECT id FROM iam.app_user WHERE email = 'benchseed@example.test'")
	scenario := tmpl("scenario", modeltest.Scenario())
	// Scenarios in batches (a context lives a minute), round-robin over the
	// BUs and the library, newest last.
	const batch = 2_000
	for _, set := range []struct{ name, bus string }{{"outside", outside}, {"inside", inside}} {
		for lo := 0; lo < perSubtree; lo += batch {
			seed(fmt.Sprintf(`DO $$
DECLARE
  bus uuid[] := string_to_array('%[1]s', ',')::uuid[];
  assets uuid[] := ARRAY(SELECT id FROM risk.library_entry WHERE kind = 'asset' ORDER BY seq);
  tcs uuid[] := ARRAY(SELECT id FROM risk.library_entry WHERE kind = 'threat_community' ORDER BY seq);
  ctls uuid[] := ARRAY(SELECT id FROM risk.control ORDER BY seq);
  id uuid; b bytea; d jsonb;
BEGIN
  FOR i IN %[2]d..%[3]d LOOP
    d := '%[4]s'::jsonb || jsonb_build_object('name', 'Scenario %[6]s ' || i, 'owner', '%[5]s',
      'asset', jsonb_build_object('kind', 'asset', 'id', assets[1 + i %% cardinality(assets)], 'version', 1),
      'threat_community', jsonb_build_object('id', tcs[1 + i %% cardinality(tcs)], 'version', 1),
      'control_sets', jsonb_build_array(jsonb_build_object('name', 'Current', 'current', true,
        'controls', jsonb_build_array(jsonb_build_object('id', ctls[1 + i %% cardinality(ctls)], 'version', 1, 'status', 'in_place')))));
    INSERT INTO risk.scenario (bu_id) VALUES (bus[1 + i %% cardinality(bus)]) RETURNING scenario.id INTO id;
    b := convert_to(risk.canonical(d), 'UTF8');
    INSERT INTO risk.scenario_version (scenario_id, version, document, digest, change_note) VALUES (id, 1, b, encode(sha256(b), 'hex'), 'bench');
  END LOOP;
END $$`, set.bus, lo, min(lo+batch, perSubtree)-1, scenario, owner, set.name))
			t.Logf("%s scenarios to %d: %v", set.name, min(lo+batch, perSubtree), time.Since(start).Round(time.Second))
		}
	}
	e.admin(e.db, "ANALYZE risk.scenario; ANALYZE risk.scenario_version; ANALYZE risk.scenario_pin; ANALYZE risk.library_entry; ANALYZE risk.library_version; ANALYZE risk.control; ANALYZE risk.control_version")
	t.Logf("loaded: %s in %v", e.adminQuery("SELECT (SELECT count(*) FROM risk.scenario) || ' scenarios, ' || (SELECT count(*) FROM risk.scenario_pin) || ' pins'"),
		time.Since(start).Round(time.Second))

	api := newBenchRiskAPI(t, e)
	subIDs := strings.Split(e.adminQuery(fmt.Sprintf(`SELECT string_agg(id::text, ',' ORDER BY seq) FROM (SELECT s.id, s.seq FROM risk.scenario s
		JOIN iam.bu_closure c ON c.descendant_id = s.bu_id AND c.ancestor_id = '%s' ORDER BY md5(s.id::text) LIMIT %d) x`, l1, riskBenchRuns+3)), ",")
	leafIDs := strings.Split(e.adminQuery(fmt.Sprintf("SELECT string_agg(id::text, ',') FROM risk.scenario WHERE bu_id = '%s'", leaf)), ",")
	midSeq := e.adminQuery(fmt.Sprintf(`SELECT seq FROM risk.scenario s JOIN iam.bu_closure c ON c.descendant_id = s.bu_id AND c.ancestor_id = '%s'
		ORDER BY seq OFFSET %d LIMIT 1`, l1, perSubtree/2))
	asset := e.adminQuery("SELECT id FROM risk.library_entry WHERE kind = 'asset' ORDER BY seq LIMIT 1")
	tc := e.adminQuery("SELECT id FROM risk.library_entry WHERE kind = 'threat_community' ORDER BY seq OFFSET 7 LIMIT 1")
	cases := []struct {
		name, user string
		paths      func(i int) string
		budget     time.Duration
	}{
		{"list, subtree, newest", "benchsub", fixed("/api/v1/scenarios"), riskListBudget},
		{"list, subtree, 200 rows", "benchsub", fixed("/api/v1/scenarios?limit=200"), riskListBudget},
		{"list, subtree, deep page", "benchsub", fixed("/api/v1/scenarios?cursor=" + midSeq), riskListBudget},
		{"list, subtree, by asset", "benchsub", fixed("/api/v1/scenarios?asset=" + asset), riskListBudget},
		{"list, subtree, by threat community", "benchsub", fixed("/api/v1/scenarios?threat_community=" + tc), riskListBudget},
		{"list, subtree, by BU", "benchsub", fixed("/api/v1/scenarios?bu=" + leaf), riskListBudget},
		{"list, root, newest", "benchseed", fixed("/api/v1/scenarios"), riskListBudget},
		{"list, one BU, newest", "benchleaf", fixed("/api/v1/scenarios"), riskListBudget},
		{"list, library, subtree (inherited)", "benchsub", fixed("/api/v1/library"), riskListBudget},
		{"load with pins, subtree (inherited)", "benchsub", func(i int) string { return "/api/v1/scenarios/" + subIDs[i%len(subIDs)] }, riskLoadBudget},
		{"load with pins, one BU (inherited)", "benchleaf", func(i int) string { return "/api/v1/scenarios/" + leafIDs[i%len(leafIDs)] }, riskLoadBudget},
		{"load with pins, root", "benchseed", func(i int) string { return "/api/v1/scenarios/" + subIDs[i%len(subIDs)] }, riskLoadBudget},
	}
	var results []benchResult
	failed := false
	for _, c := range cases {
		r := summarize("risk API: "+c.name, api.time(t, c.user, c.paths), c.budget)
		results = append(results, r)
		if r.P95ms > r.Budget {
			failed = true
		}
	}
	var rep strings.Builder
	fmt.Fprintf(&rep, "F-003 risk scenarios: %d scenarios in L1_1's subtree and %d elsewhere, %d library entries and %d controls at the root; GET through the risk API (default page 50 unless stated), %d runs after warm-up\n",
		perSubtree, perSubtree, 2*riskBenchLibrary, riskBenchControls, riskBenchRuns)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.2f | %.2f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("risk API over budget")
	}
}

func fixed(path string) func(int) string { return func(int) string { return path } }

type benchRiskAPI struct {
	e    *env
	url  string
	keys *authz.LocalKeys
}

func newBenchRiskAPI(t *testing.T, e *env) *benchRiskAPI {
	t.Helper()
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(filepath.Join(dir, "gw-1.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := authz.LoadLocalKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	pool := e.appPool()
	api := &riskapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	srv := httptest.NewServer(api.Handler(keys, nil))
	t.Cleanup(srv.Close)
	return &benchRiskAPI{e: e, url: srv.URL, keys: keys}
}

// time GETs path(i) as user: 3 warm-up requests, then riskBenchRuns timed
// ones, each with a fresh token and DB context, the body read in full.
func (b *benchRiskAPI) time(t *testing.T, user string, path func(int) string) []time.Duration {
	t.Helper()
	p := b.e.principal(user)
	out := make([]time.Duration, 0, riskBenchRuns)
	for i := range riskBenchRuns + 3 {
		tok, err := authz.MintJWT(b.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
			DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(context.Background(), "GET", b.url+path(i), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set(server.DBContextHeader, p.DBToken)
		t0 := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		d := time.Since(t0)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s as %s: %d %s", path(i), user, resp.StatusCode, body)
		}
		if strings.Contains(path(i), "/api/v1/scenarios?") || strings.HasSuffix(path(i), "/scenarios") || strings.HasSuffix(path(i), "/library") {
			if !strings.Contains(string(body), `"id"`) {
				t.Fatalf("GET %s as %s: an empty list (the benchmark would measure nothing)", path(i), user)
			}
		} else if !strings.Contains(string(body), `"pins"`) {
			t.Fatalf("GET %s as %s: no pins in %s", path(i), user, body[:min(len(body), 300)])
		}
		if i >= 3 {
			out = append(out, d)
		}
	}
	return out
}
