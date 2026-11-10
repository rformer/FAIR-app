package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/estimateapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// estimateAPI is a risk API environment whose calls go to the estimate API
// (the same keys, principals and database).
func estimateAPI(t *testing.T, ra *riskAPIEnv) *riskAPIEnv {
	t.Helper()
	pool := ra.appPool()
	api := &estimateapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	ea := *ra
	ea.url = srv.URL
	return &ea
}

// F-004 T-05 (F-004-AC-11, AC-12): the estimating aids through the API.
func TestEstimateWarningsAPI(t *testing.T) {
	ra := strideF003Fixture(t)
	ea := estimateAPI(t, ra)
	ra.mustOwner(grant("platform", "user:erin", "Estimator", "A1"))
	ra.drain()
	body := map[string]any{"unit": "events_per_year", "estimate": map[string]any{"min": "2", "ml": "2", "max": "12", "confidence": "0.8"}, "requested_confidence": "0.9"}

	// Nobody without a permission that enters estimates: the route does not exist.
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('viewer@example.test', 'viewer')")
	ra.mustOwner(grant("platform", "user:viewer", "Executive Viewer", "A"))
	ra.drain()
	if got := ea.call(t, "POST", "viewer", "/api/v1/estimates/warnings", body); got.code != 404 {
		t.Fatalf("a viewer: %d %s", got.code, got.raw)
	}
	for _, user := range []string{"analyst", "erin"} { // a risk analyst; an estimator
		got := ea.call(t, "POST", user, "/api/v1/estimates/warnings", body)
		if got.code != 200 || !strings.Contains(got.raw, `"ml_at_bound"`) || !strings.Contains(got.raw, `"other_confidence"`) ||
			!strings.Contains(got.raw, `"beta_pert"`) || !strings.Contains(got.raw, "between 2 and 12") {
			t.Fatalf("%s: %d %s", user, got.code, got.raw)
		}
	}
	// Out of order: refused with the reason; an unknown unit or field: 400.
	bad := map[string]any{"unit": "events_per_year", "estimate": map[string]any{"min": "5", "ml": "2", "max": "12", "confidence": "0.9"}}
	if got := ea.call(t, "POST", "analyst", "/api/v1/estimates/warnings", bad); got.code != 422 || !strings.Contains(got.raw, "ordered") {
		t.Fatalf("unordered: %d %s", got.code, got.raw)
	}
	for _, b := range []map[string]any{{"unit": "dollars", "estimate": body["estimate"]}, {"unit": "currency", "estimate": body["estimate"], "colour": "red"}} {
		if got := ea.call(t, "POST", "analyst", "/api/v1/estimates/warnings", b); got.code != 400 {
			t.Errorf("%v: %d", b, got.code)
		}
	}
	// It needs no Idempotency-Key and records nothing.
	before := ra.adminQuery("SELECT count(*) FROM audit.intake")
	p := ra.principal("analyst")
	tok, err := authz.MintJWT(ra.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", ea.url+"/api/v1/estimates/warnings", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(server.DBContextHeader, p.DBToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("without an Idempotency-Key: %d", resp.StatusCode)
	}
	if after := ra.adminQuery("SELECT count(*) FROM audit.intake"); after != before {
		t.Fatalf("events recorded: %s -> %s", before, after)
	}
}
