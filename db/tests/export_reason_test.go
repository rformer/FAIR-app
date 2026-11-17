package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/analysisapi"
	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// callWith sends a request to base as user with extra headers.
func callWith(t *testing.T, ra *riskAPIEnv, base, method, user, path string, body any, hdr map[string]string) apiResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if method != "GET" {
		ra.n++
		req.Header.Set(server.IdempotencyHeader, "reason-test-key-"+time.Now().Format("150405.000000000"))
	}
	p := ra.principal(user)
	tok, err := authz.MintJWT(ra.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(server.DBContextHeader, p.DBToken)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return apiResp{code: resp.StatusCode, body: m, raw: string(raw), hdr: resp.Header}
}

// F-010 T-12 (F-010-AC-16; OQ7; design §3.6): export.reason_required on
// F-003's risk export and F-006's downloads, per BU of the data (here in
// force at A1 only), with the reason recorded on the event.
func TestExportReasons(t *testing.T) {
	ra := strideF003Fixture(t)
	seedPosture(t, ra.env)
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	rules := reason.Static{BUs: []string{ra.bu["A1"]}}
	pool := ra.appPool()
	cache := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)})
	emit := audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})
	rs := httptest.NewServer((&riskapi.API{DB: pool, Authz: cache, Audit: emit, Reasons: rules}).Handler(ra.keys, nil))
	t.Cleanup(rs.Close)
	as := httptest.NewServer((&analysisapi.API{DB: pool, Authz: cache, Settings: fixedLimits(defaultLimits), Audit: emit, Reasons: rules}).Handler(ra.keys, nil))
	t.Cleanup(as.Close)
	sA1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	sA := scenarioAt(t, ra, "analyst", ra.bu["A"], "Head office fraud")
	why := map[string]string{reason.Header: "Q4%20committee%20%E2%80%94%20pack"}
	reasonOf := func(typ string) string {
		return ra.adminQuery("SELECT coalesce(string_agg(coalesce(body ->> 'reason', '-'), '|' ORDER BY id), '') FROM audit.intake WHERE body ->> 'type' = '" + typ + "'")
	}

	// The risk export: by item and by subtree.
	for _, c := range []struct {
		name, path string
		hdr        map[string]string
		code       int
	}{
		{"A1's scenario, no reason", "/api/v1/risk/export?scenarios=" + sA1, nil, 400},
		{"A's subtree holds A1", "/api/v1/risk/export?bu=" + ra.bu["A"], nil, 400},
		{"A's scenario alone", "/api/v1/risk/export?scenarios=" + sA, nil, 200},
		{"A1's scenario, with a reason", "/api/v1/risk/export?scenarios=" + sA1, why, 200},
		{"a reason that is not encoded", "/api/v1/risk/export?scenarios=" + sA, map[string]string{reason.Header: "50%"}, 400},
		{"B's subtree (nothing visible)", "/api/v1/risk/export?bu=" + ra.bu["B"], nil, 200},
	} {
		got := callWith(t, ra, rs.URL, "GET", "analyst", c.path, nil, c.hdr)
		if got.code != c.code || (c.code == 400 && c.hdr == nil && got.body["error"] != "reason_required") {
			t.Errorf("%s: %d %s", c.name, got.code, got.raw)
		}
	}
	if got := reasonOf("risk.exported"); got != "-|Q4 committee — pack|-" {
		t.Errorf("risk.exported reasons: %q", got)
	}

	// The downloads: CSV and images, by the results' BUs.
	rA1 := runWith(t, ae, "analyst", sA1, 1, 2000, "7")
	rA := runWith(t, ae, "analyst", sA, 1, 2000, "7")
	for _, c := range []struct {
		name, method, path string
		body               any
		hdr                map[string]string
		code               int
	}{
		{"A1's run, no reason", "GET", "/api/v1/analyses/runs/" + rA1 + "/data.csv?view=summary", nil, nil, 400},
		{"A1's run, a reason", "GET", "/api/v1/analyses/runs/" + rA1 + "/data.csv?view=summary", nil, why, 200},
		{"A's run", "GET", "/api/v1/analyses/runs/" + rA + "/data.csv?view=summary", nil, nil, 200},
		{"a comparison across A1", "GET", "/api/v1/analyses/compare.csv?view=summary&item=run:" + rA + ":Current&item=run:" + rA1 + ":Current", nil, nil, 400},
		{"an image of A1's run", "POST", "/api/v1/analyses/downloads", map[string]any{"subject": "run", "id": rA1, "view": "curve", "format": "svg"}, nil, 400},
		{"an image, with a reason", "POST", "/api/v1/analyses/downloads", map[string]any{"subject": "run", "id": rA1, "view": "curve", "format": "svg"}, why, 201},
	} {
		got := callWith(t, ra, as.URL, c.method, "analyst", c.path, c.body, c.hdr)
		if got.code != c.code || (c.code == 400 && got.body["error"] != "reason_required") {
			t.Errorf("%s: %d %s", c.name, got.code, got.raw)
		}
	}
	if got := reasonOf("analysis.downloaded"); got != "Q4 committee — pack|-|Q4 committee — pack" {
		t.Errorf("analysis.downloaded reasons: %q", got)
	}
	// Without settings the routes fail closed.
	closed := httptest.NewServer((&analysisapi.API{DB: pool, Authz: cache, Settings: fixedLimits(defaultLimits), Audit: emit}).Handler(ra.keys, nil))
	t.Cleanup(closed.Close)
	if got := callWith(t, ra, closed.URL, "GET", "analyst", "/api/v1/analyses/runs/"+rA+"/data.csv?view=summary", nil, nil); got.code != 503 {
		t.Errorf("no settings: %d %s", got.code, got.raw)
	}
}
