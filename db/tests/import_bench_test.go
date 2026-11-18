package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/importapi"
	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-19 (requirements NFR "Performance"; design §3.2): the imports gate
// at the F-001 target scale (2,011 BUs, 10,000 users), as "benchimporter"
// (integration.push, library.view and library.edit at the root), through
// the imports API with the risk API wired for accepts. Budgets:
//   - a batch of 10,000 asset records over 100 business units, validated,
//     matched and staged as a run with its proposals, request to answer:
//     <= 60 s; the same batch again, every record matched by external ID
//     (a thousand of them to accepted assets), <= 60 s;
//   - a run's proposals opened, p95: the queue's first page of 200, a deep
//     page, one proposal merged with its diff: <= 1 s;
//   - 1,000 proposals accepted (five batch accepts of 200, each written
//     through the risk API's save code): <= 30 s in all.
// The integration is written directly (its functions' checks are not what
// is measured).

const (
	importBatchBudget  = 60 * time.Second
	importOpenBudget   = time.Second
	importAcceptBudget = 30 * time.Second
	importBenchRecords = integration.MaxRecords
	importBenchAccept  = 1_000
)

func TestBenchmarkGateImports(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	records := importBenchRecords
	if n := os.Getenv("FAIR_BENCH_IMPORT_RECORDS"); n != "" { // a smaller run, by hand
		records, _ = strconv.Atoi(n)
	}
	accepts := min(importBenchAccept, records)
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('benchimporter@example.test', 'Bench Importer')")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Bench Importer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason)
		SELECT id, 1, ARRAY['integration.push', 'library.view', 'library.edit'], 'bench' FROM r`)
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = 'Bench Importer'), '%s', '%s' FROM iam.app_user u WHERE u.email = 'benchimporter@example.test'`, root, granter))
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	e.mustOwner("DELETE FROM iam.outbox")
	integ := e.mustOwner(fmt.Sprintf(`INSERT INTO integration.integration (bu_id, name, kind, delivery, created_by)
		VALUES ('%s', 'Bench CMDB', 'assets', 'push', '%s') RETURNING id`, root, granter))
	// 100 business units of the subtree, by code, for the records.
	codes := strings.Split(e.mustOwner(`SELECT string_agg(code, ',' ORDER BY code) FROM (SELECT code FROM iam.bu WHERE archived_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM iam.bu_closure c JOIN iam.bu x ON x.id = c.ancestor_id WHERE c.descendant_id = iam.bu.id AND x.restricted)
		ORDER BY code LIMIT 100) b`), ",")

	b := newBenchImportAPI(t, e)
	batch := func(suffix string) []byte {
		recs := make([]any, records)
		for i := range records {
			recs[i] = map[string]any{"kind": "asset", "external_id": fmt.Sprintf("app-%05d", i), "bu": codes[i%len(codes)],
				"name": fmt.Sprintf("Application %05d%s", i, suffix), "asset_type": "application",
				"description": "A business application from the configuration database."}
		}
		raw, _ := json.Marshal(map[string]any{"format": integration.Format, "complete": true, "records": recs})
		return raw
	}
	var results []benchResult
	failed := false
	push := func(name string, body []byte) string {
		code, out, took := b.request(t, "benchimporter", "POST", "/api/v1/imports/"+integ+"/batches", body)
		if code != http.StatusCreated {
			t.Fatalf("%s: %d %s", name, code, out[:min(len(out), 400)])
		}
		var res struct {
			Run struct {
				ID string `json:"id"`
			} `json:"run"`
			Counts importapi.Counts `json:"counts"`
		}
		if err := json.Unmarshal(out, &res); err != nil {
			t.Fatal(err)
		}
		ms := float64(took.Milliseconds())
		results = append(results, benchResult{Name: fmt.Sprintf("%s (%d valid, %d proposed), request to answer", name, res.Counts.Valid, res.Counts.Proposed),
			P50ms: ms, P95ms: ms, P99ms: ms, Budget: float64(importBatchBudget.Milliseconds())})
		if took > importBatchBudget {
			failed = true
		}
		return res.Run.ID
	}
	push(fmt.Sprintf("a batch of %d new asset records", records), batch(""))
	e.mustOwner("ANALYZE integration.proposal; ANALYZE integration.link; ANALYZE integration.record")

	// A run's proposals opened.
	ids := strings.Split(e.mustOwner(fmt.Sprintf(`SELECT string_agg(id::text, ',') FROM (SELECT id FROM integration.proposal
		WHERE integration_id = '%s' AND state = 'pending' ORDER BY seq LIMIT %d) p`, integ, registerBenchRuns+3)), ",")
	for _, c := range []struct {
		name string
		path func(int) string
	}{
		{"the queue's first page (200)", fixed("/api/v1/proposals?integration=" + integ + "&limit=200")},
		{"a deep page of the queue", fixed(fmt.Sprintf("/api/v1/proposals?integration=%s&limit=200&offset=%d", integ, max(0, records-400)))},
		{"one proposal, merged with its diff", func(i int) string { return "/api/v1/proposals/" + ids[i%len(ids)] }},
	} {
		r := summarize("imports API: "+c.name, b.time(t, "benchimporter", c.path), importOpenBudget)
		results = append(results, r)
		if r.P95ms > r.Budget {
			failed = true
		}
	}

	// 1,000 accepted, 200 at a time, through the risk API's save code.
	toAccept := strings.Split(e.mustOwner(fmt.Sprintf(`SELECT string_agg(id::text, ',' ORDER BY seq) FROM (SELECT id, seq FROM integration.proposal
		WHERE integration_id = '%s' AND state = 'pending' ORDER BY seq LIMIT %d) p`, integ, accepts)), ",")
	t0 := time.Now()
	for i := 0; i < len(toAccept); i += 200 {
		var items []map[string]any
		for _, id := range toAccept[i:min(i+200, len(toAccept))] {
			items = append(items, map[string]any{"id": id})
		}
		raw, _ := json.Marshal(map[string]any{"proposals": items})
		if code, out, _ := b.request(t, "benchimporter", "POST", "/api/v1/proposals/accept", raw); code != http.StatusOK {
			t.Fatalf("accept %d: %d %s", i, code, out[:min(len(out), 400)])
		}
	}
	took := time.Since(t0)
	ms := float64(took.Milliseconds())
	results = append(results, benchResult{Name: fmt.Sprintf("%d proposals accepted (batches of 200)", len(toAccept)), P50ms: ms, P95ms: ms, P99ms: ms,
		Budget: float64(importAcceptBudget.Milliseconds())})
	if took > importAcceptBudget {
		failed = true
	}
	if got := e.mustOwner("SELECT count(*) FROM integration.link WHERE integration_id = '" + integ + "'"); got != strconv.Itoa(len(toAccept)) {
		t.Fatalf("%s links after accepting %d", got, len(toAccept))
	}

	// The same source again, renamed: every record matched by external ID.
	push(fmt.Sprintf("the same %d records again, renamed (%d linked)", records, len(toAccept)), batch(" (renamed)"))

	var rep strings.Builder
	fmt.Fprintf(&rep, "F-011 imports: batches of %d asset records over %d business units, as a pusher at the root, %d runs after warm-up for reads\n",
		records, len(codes), registerBenchRuns)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.2f | %.2f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("imports over budget")
	}
}

// newBenchImportAPI serves the imports API with the risk API wired for
// accepts, on the bench keys.
func newBenchImportAPI(t *testing.T, e *env) *benchRegisterAPI {
	t.Helper()
	k := newBenchRiskAPI(t, e) // its keys
	pool := e.appPool()
	cache := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)})
	risk := &riskapi.API{Reasons: reason.Static{}, DB: pool, Authz: cache, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	api := &importapi.API{DB: pool, Authz: cache, Risk: risk}
	srv := httptest.NewServer(api.Handler(k.keys, nil))
	t.Cleanup(srv.Close)
	return &benchRegisterAPI{e: e, url: srv.URL, keys: k.keys}
}
