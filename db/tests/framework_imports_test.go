package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/frameworkapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// frameworkEnv serves the framework API as app_rw on the risk env's keys
// (risk serves the risk API);
// imports are queued to a list and worked by the test (worker.Run).
type frameworkEnv struct {
	*riskAPIEnv
	risk   *riskAPIEnv // the risk API itself (controls, scenarios)
	worker *frameworkapi.Worker
	mu     sync.Mutex
	queued []string
}

func frameworkAPI(t *testing.T) *frameworkEnv {
	t.Helper()
	ra := newRiskAPI(t)
	pool := ra.appPool()
	fe := &frameworkEnv{worker: &frameworkapi.Worker{DB: pool}}
	api := &frameworkapi.API{DB: pool, Enqueue: func(_ context.Context, _ pgx.Tx, a frameworkapi.ImportArgs) error {
		fe.mu.Lock()
		fe.queued = append(fe.queued, a.ImportID)
		fe.mu.Unlock()
		return nil
	}}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	fa := *ra
	fa.url = srv.URL
	fe.riskAPIEnv = &fa
	fe.risk = ra
	return fe
}

// upload posts a file with query parameters as user; it answers the
// response and, after the job ran, the import.
func (fe *frameworkEnv) upload(t *testing.T, user, query, contentType string, file []byte) (apiResp, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", fe.url+"/api/v1/frameworks/imports?"+query, bytes.NewReader(file))
	req.Header.Set("Content-Type", contentType)
	fe.n++
	req.Header.Set("Idempotency-Key", fmt.Sprintf("framework-test-key-%04d", fe.n))
	p := fe.principal(user)
	tok, err := authz.MintJWT(fe.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(server.DBContextHeader, p.DBToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	got := apiResp{code: resp.StatusCode, body: m, raw: string(raw)}
	if got.code != 202 {
		return got, nil
	}
	id := m["id"].(string)
	if err := fe.worker.Run(context.Background(), id); err != nil {
		t.Fatalf("the import job: %v", err)
	}
	after := fe.call(t, "GET", user, "/api/v1/frameworks/imports/"+id, nil)
	return got, after.body
}

func pinnedFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "third_party", "oscal", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// F-013 T-05 (F-013-AC-01 to AC-06, AC-19; design §3.1, §3.2, §6): reading
// frameworks; importing a catalog, a simple framework (JSON and CSV) and a
// profile through the job, whole or refused; dry runs; diffs; retiring.
func TestFrameworkImports(t *testing.T) {
	fe := frameworkAPI(t)
	fe.mustOwner(grant("platform", "user:buadmin", "BU Admin", "A")) // a role, but no framework or control permission
	fe.drain()

	// Readers: framework.view (platform, analyst and mallory through their
	// built-in roles) or control.view (erin, an Executive Viewer); others
	// (buadmin, a BU Admin) find nothing.
	list := fe.call(t, "GET", "analyst", "/api/v1/frameworks", nil)
	if list.code != 200 || !strings.Contains(list.raw, `"nist-800-53"`) || !strings.Contains(list.raw, `"5.2.0"`) {
		t.Fatalf("frameworks: %d %s", list.code, list.raw[:min(len(list.raw), 300)])
	}
	for user, code := range map[string]int{"erin": 200, "mallory": 200, "buadmin": 404} {
		if got := fe.call(t, "GET", user, "/api/v1/frameworks", nil); got.code != code {
			t.Errorf("%s lists frameworks: %d", user, got.code)
		}
	}
	v520 := fe.adminQuery("SELECT id FROM framework.version WHERE label = '5.2.0'")
	reqs := fe.call(t, "GET", "analyst", "/api/v1/frameworks/versions/"+v520+"/requirements?q=account%20management&limit=5", nil)
	if reqs.code != 200 || !strings.Contains(reqs.raw, `"ac-2"`) || strings.Contains(reqs.raw, `"statement"`) {
		t.Errorf("search: %d %s", reqs.code, reqs.raw[:min(len(reqs.raw), 300)])
	}
	top := fe.call(t, "GET", "analyst", "/api/v1/frameworks/versions/"+v520+"/requirements?parent=&limit=500", nil)
	if top.code != 200 || len(top.body["requirements"].([]any)) < 300 {
		t.Errorf("top-level requirements: %d", top.code)
	}
	ac2 := fe.adminQuery("SELECT r.id FROM framework.requirement r WHERE r.version_id = '" + v520 + "' AND identifier = 'ac-2'")
	one := fe.call(t, "GET", "erin", "/api/v1/frameworks/requirements/"+ac2, nil)
	if one.code != 200 || !strings.Contains(one.raw, `"ac-2.1"`) || !strings.Contains(one.raw, `"nist-moderate"`) || one.body["statement"] == nil {
		t.Errorf("ac-2: %d %s", one.code, one.raw[:min(len(one.raw), 300)])
	}
	if got := fe.call(t, "GET", "analyst", "/api/v1/frameworks/requirements/00000000-0000-0000-0000-000000000000", nil); got.code != 404 {
		t.Errorf("an unknown requirement: %d", got.code)
	}

	// AC-01, AC-05: an OSCAL catalog, as a new version of a family, by
	// platform (framework.manage). A dry run first: nothing applied.
	cat := pinnedFile(t, "nist/sp800-53r5-oscal-content-v1.3.0/NIST_SP-800-53_rev5_catalog.json")
	cat = bytes.Replace(cat, []byte(`"version": "5.1.1+u4"`), []byte(`"version": "5.1.1-test"`), 1)
	q := "kind=catalog&family=nist-800-53&family_title=NIST%20SP%20800-53"
	got, imp := fe.upload(t, "platform", q+"&dry_run=true", "application/json", cat)
	if got.code != 202 || imp["state"] != "succeeded" || imp["dry_run"] != true {
		t.Fatalf("dry run: %d %s %v", got.code, got.raw, imp)
	}
	summary := imp["result"].(map[string]any)["summary"].(map[string]any)
	if summary["requirements"] != 1193.0 || summary["since"] != "5.2.0" { // the 5.1.1 catalog, against the newer 5.2.0
		t.Errorf("dry run summary %v", summary)
	}
	if n := fe.adminQuery("SELECT count(*) FROM framework.version WHERE family = 'nist-800-53'"); n != "2" {
		t.Errorf("a dry run applied: %s versions", n)
	}
	_, imp = fe.upload(t, "platform", q, "application/json", cat)
	if imp["state"] != "succeeded" || imp["result"].(map[string]any)["version_id"] == nil {
		t.Fatalf("import: %v", imp)
	}
	vid := imp["result"].(map[string]any)["version_id"].(string)
	diff := fe.call(t, "GET", "analyst", "/api/v1/frameworks/versions/"+vid+"/diff", nil)
	if diff.code != 200 || diff.body["since"] != "5.2.0" {
		t.Errorf("diff: %d %s", diff.code, diff.raw[:min(len(diff.raw), 300)])
	}
	// The same version again is refused.
	_, imp = fe.upload(t, "platform", q, "application/json", cat)
	if imp["state"] != "refused" || !strings.Contains(fmt.Sprint(imp["problems"]), "already imported") {
		t.Errorf("a duplicate: %v", imp)
	}

	// AC-03: simple frameworks, JSON and CSV; problems refuse the whole file.
	simple := `{"format": "fair.framework.v1", "family": {"key": "iso-27001", "title": "ISO/IEC 27001"}, "version": {"label": "2022", "title": "ISO/IEC 27001:2022"},
		"requirements": [{"identifier": "A.5", "title": "Organizational controls"}, {"identifier": "A.5.1", "title": "Policies", "parent": "A.5"}]}`
	_, imp = fe.upload(t, "platform", "kind=simple", "application/json", []byte(simple))
	if imp["state"] != "succeeded" {
		t.Fatalf("simple JSON: %v", imp)
	}
	_, imp = fe.upload(t, "platform", "kind=simple&family=soc2&family_title=SOC%202&label=2017&title=Trust%20Services%20Criteria", "text/csv",
		[]byte("identifier,title,parent\nCC6,Logical and Physical Access,\nCC6.1,Logical access security,CC6\n"))
	if imp["state"] != "succeeded" {
		t.Fatalf("simple CSV: %v", imp)
	}
	_, imp = fe.upload(t, "platform", "kind=simple", "application/json", []byte(strings.Replace(simple, `"parent": "A.5"`, `"parent": "A.9"`, 1)))
	if imp["state"] != "refused" || !strings.Contains(fmt.Sprint(imp["problems"]), "/requirements/1/parent") {
		t.Errorf("a refused file: %v", imp)
	}

	// AC-02: a profile, resolved against a version the request names.
	prof := pinnedFile(t, "nist/sp800-53r5/NIST_SP-800-53_rev5_LOW-baseline_profile.json")
	_, imp = fe.upload(t, "platform", "kind=profile&catalog_family=nist-800-53&catalog_version=5.1.1-test&key=my-low", "application/json", prof)
	if imp["state"] != "succeeded" || imp["result"].(map[string]any)["baseline_id"] == nil {
		t.Fatalf("profile: %v", imp)
	}
	// Retiring a baseline (fixed in migration 0165): a reason; twice is 409.
	bid := imp["result"].(map[string]any)["baseline_id"].(string)
	if got := fe.call(t, "POST", "platform", "/api/v1/frameworks/baselines/"+bid+"/retire", map[string]any{"reason": "Test copy"}); got.code != 200 || got.body["state"] != "retired" {
		t.Errorf("retire a baseline: %d %s", got.code, got.raw)
	}
	if got := fe.call(t, "POST", "platform", "/api/v1/frameworks/baselines/"+bid+"/retire", map[string]any{"reason": "Again"}); got.code != 409 {
		t.Errorf("retire a baseline twice: %d", got.code)
	}
	_, imp = fe.upload(t, "platform", "kind=profile&catalog_family=nist-800-53&catalog_version=9.9&key=x", "application/json", prof)
	if imp["state"] != "refused" || !strings.Contains(fmt.Sprint(imp["problems"]), "not imported") {
		t.Errorf("a profile of a missing catalog: %v", imp)
	}

	// Who may import: platform only (readers: 403; buadmin: 404); bad
	// requests are refused before any job.
	for user, code := range map[string]int{"analyst": 403, "erin": 403, "buadmin": 404} {
		if got, _ := fe.upload(t, user, "kind=simple", "application/json", []byte(simple)); got.code != code {
			t.Errorf("%s imports: %d %s", user, got.code, got.raw)
		}
	}
	for name, c := range map[string]struct {
		query, ct string
		code      int
	}{
		"no kind":         {"", "application/json", 400},
		"a CSV catalog":   {"kind=catalog&family=x&family_title=X", "text/csv", 415},
		"XML":             {"kind=simple", "application/xml", 415},
		"a catalog alone": {"kind=catalog", "application/json", 400},
		"a bare profile":  {"kind=profile", "application/json", 400},
	} {
		if got, _ := fe.upload(t, "platform", c.query, c.ct, []byte("{}")); got.code != c.code {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}

	// AC-06: retiring, with a reason; kept readable.
	if got := fe.call(t, "POST", "platform", "/api/v1/frameworks/versions/"+vid+"/retire", map[string]any{"reason": ""}); got.code != 400 {
		t.Errorf("retire without a reason: %d", got.code)
	}
	if got := fe.call(t, "POST", "analyst", "/api/v1/frameworks/versions/"+vid+"/retire", map[string]any{"reason": "x"}); got.code != 403 {
		t.Errorf("analyst retires: %d", got.code)
	}
	if got := fe.call(t, "POST", "platform", "/api/v1/frameworks/versions/"+vid+"/retire", map[string]any{"reason": "Test copy"}); got.code != 200 || got.body["state"] != "retired" {
		t.Errorf("retire: %d %s", got.code, got.raw)
	}
	if got := fe.call(t, "GET", "analyst", "/api/v1/frameworks", nil); strings.Contains(got.raw, `"5.1.1-test"`) {
		t.Error("a retired version is listed")
	}
	if got := fe.call(t, "GET", "analyst", "/api/v1/frameworks?retired=true", nil); !strings.Contains(got.raw, `"5.1.1-test"`) {
		t.Error("a retired version is not listed with retired=true")
	}
	if got := fe.call(t, "GET", "analyst", "/api/v1/frameworks/versions/"+vid, nil); got.code != 200 {
		t.Errorf("a retired version reads: %d", got.code)
	}

	// AC-19: imports, refusals and retirements are recorded with the actor
	// and the file's digest; the uploaded files are not kept.
	for typ, want := range map[string]string{"framework.imported": "3", "framework.baseline_imported": "1", "framework.import_refused": "3", "framework.retired": "1"} {
		if got := fe.adminQuery(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '` + typ + `' AND body ->> 'actor' = (` + uid("platform") + `)::text`); got != want {
			t.Errorf("%s: %s events, want %s", typ, got, want)
		}
	}
	if got := fe.adminQuery("SELECT count(*) FROM framework.import WHERE file IS NOT NULL"); got != "0" {
		t.Errorf("%s files kept after their imports", got)
	}
}
