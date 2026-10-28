package tests

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/postureapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-31 (AC-03, AC-43; design §7): the Posture API over HTTP, with
// internal JWTs as the gateway mints them (F-001 T-14) and the DB context
// tokens they carry.

type apiEnv struct {
	registryEnv
	url       string
	keys      *authz.LocalKeys
	mem       *audit.Memory
	exportKey *ecdsa.PrivateKey // signs OSCAL exports (T-35)
}

func apiFixture(t *testing.T, profile string) apiEnv {
	t.Helper()
	rg := registryFixture(t, profile, "self-hosted")
	e := rg.e
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('auditor@example.test', 'Auditor'), ('nobody@example.test', 'Nobody')")
	e.mustOwner(grant("admin", "user:auditor", "Auditor", "ENTERPRISE"))
	e.mustOwner(grant("admin", "user:nobody", "Executive Viewer", "ENTERPRISE"))
	e.drain()
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
	pool := e.posturePool()
	mem := audit.NewMemory()
	exportKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	api := &postureapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), Audit: mem, ExportKey: exportKey}
	srv := httptest.NewServer(api.Handler(keys, nil))
	t.Cleanup(srv.Close)
	return apiEnv{registryEnv: rg, url: srv.URL, keys: keys, mem: mem, exportKey: exportKey}
}

type apiResp struct {
	code int
	body map[string]any
	raw  string
	hdr  http.Header
}

// call sends a request as user ("" = unauthenticated). key "" means no
// Idempotency-Key; "auto" a fresh one.
func (ae apiEnv) call(t *testing.T, user, method, path, key string, body any) apiResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, ae.url+postureapi.Prefix+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		p := ae.e.principal(user)
		tok, err := authz.MintJWT(ae.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
			DBContext: authz.DBContextHash(p.DBToken)}, "posture", 5*time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set(server.DBContextHeader, p.DBToken)
	}
	if key == "auto" {
		key = "k-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	}
	if key != "" {
		req.Header.Set(server.IdempotencyHeader, key)
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

func TestPostureAPIAccessAndChanges(t *testing.T) {
	ae := apiFixture(t, settings.ProfileEnterpriseBaseline)
	e := ae.e

	// Unauthenticated or wrong credentials: 401.
	if r := ae.call(t, "", "GET", "/registry", "", nil); r.code != 401 {
		t.Fatalf("unauthenticated: %d", r.code)
	}
	// Without posture.view the API does not exist for the caller: 404.
	for _, rq := range [][2]string{{"GET", "/registry"}, {"GET", "/settings"}, {"GET", "/drift"}, {"POST", "/settings/session.idle_timeout"}} {
		if r := ae.call(t, "nobody", rq[0], rq[1], "auto", map[string]any{"value": "10m0s"}); r.code != 404 {
			t.Errorf("nobody %s %s: %d %s", rq[0], rq[1], r.code, r.raw)
		}
	}

	// AC-03: the registry with value, source, bound and deviation.
	r := ae.call(t, "auditor", "GET", "/registry", "", nil)
	list, _ := r.body["settings"].([]any)
	if r.code != 200 || len(list) != 20 {
		t.Fatalf("registry: %d, %d settings", r.code, len(list))
	}
	var idle map[string]any
	for _, x := range list {
		if m := x.(map[string]any); m["key"] == "session.idle_timeout" {
			idle = m
		}
	}
	if idle["value"] != "15m0s" || idle["source"] != "profile" || idle["bound"] != "30m0s" || idle["deviation"] != "in_bounds" ||
		!slices.Contains(idle["controls"].([]any), any("AC-11")) {
		t.Fatalf("idle timeout entry %v", idle)
	}

	// The auditor may look but not change: 403 from the database's check.
	if r := ae.call(t, "auditor", "POST", "/settings/session.idle_timeout", "auto", map[string]any{"value": "10m0s"}); r.code != 403 {
		t.Fatalf("auditor change: %d %s", r.code, r.raw)
	}
	// Tightening applies; loosening needs an explanation (design §7), even in bounds.
	if r := ae.call(t, "admin", "POST", "/settings/session.idle_timeout", "auto", map[string]any{"value": "10m0s"}); r.code != 200 || r.body["outcome"] != "applied" {
		t.Fatalf("tighten: %d %s", r.code, r.raw)
	}
	if r := ae.call(t, "admin", "POST", "/settings/session.idle_timeout", "auto", map[string]any{"value": "20m0s"}); r.code != 422 || r.body["error"] != "explanation_required" {
		t.Fatalf("loosen without explanation: %d %s", r.code, r.raw)
	}
	if r := ae.call(t, "admin", "POST", "/settings/session.idle_timeout", "auto", map[string]any{"value": "20m0s", "explanation": "call centre"}); r.code != 200 {
		t.Fatalf("loosen in bounds: %d %s", r.code, r.raw)
	}
	// Out of bounds: 202 with the approval and the controls warning.
	r = ae.call(t, "admin", "POST", "/settings/session.idle_timeout", "auto", map[string]any{"value": "45m0s", "explanation": "pilot"})
	if r.code != 202 || r.body["outcome"] != "pending_approval" || r.body["approval_id"] == "" || r.body["warning"] == nil {
		t.Fatalf("out of bounds: %d %s", r.code, r.raw)
	}
	if r := ae.call(t, "admin", "POST", "/settings/tls.min_version", "auto", map[string]any{"value": "1.0", "explanation": "legacy"}); r.code != 422 || r.body["error"] != "hard_floor" {
		t.Fatalf("hard floor: %d %s", r.code, r.raw)
	}
	if r := ae.call(t, "admin", "POST", "/settings/session.idle_timeout", "auto", map[string]any{"value": "10m0s", "colour": "red"}); r.code != 400 {
		t.Fatalf("unknown field: %d", r.code)
	}

	// Idempotency: required, replayed, and bound to the request.
	if r := ae.call(t, "admin", "POST", "/settings/auth.lockout_threshold", "", map[string]any{"value": 4}); r.code != 400 {
		t.Fatalf("no key: %d", r.code)
	}
	before := e.adminQuery("SELECT count(*) FROM posture.change")
	first := ae.call(t, "admin", "POST", "/settings/auth.lockout_threshold", "replay-key-1", map[string]any{"value": 4})
	again := ae.call(t, "admin", "POST", "/settings/auth.lockout_threshold", "replay-key-1", map[string]any{"value": 4})
	if first.code != 200 || again.code != 200 || first.raw != again.raw || again.hdr.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %d %s / %d %s", first.code, first.raw, again.code, again.raw)
	}
	if n, _ := strconv.Atoi(before); e.adminQuery("SELECT count(*) FROM posture.change") != strconv.Itoa(n+1) {
		t.Fatalf("the replay applied the change again (before: %s)", before)
	}
	if r := ae.call(t, "admin", "POST", "/settings/auth.lockout_threshold", "replay-key-1", map[string]any{"value": 3}); r.code != 422 {
		t.Fatalf("key reused for another request: %d", r.code)
	}

	// The other read endpoints answer the auditor.
	for _, path := range []string{"/changes", "/exceptions", "/profiles", "/overlay", "/drift", "/k8s-access",
		"/profiles/enterprise-baseline/diff?version=1.1.0&against=fedramp-moderate@1.1.0"} {
		if r := ae.call(t, "auditor", "GET", path, "", nil); r.code != 200 {
			t.Errorf("GET %s: %d %s", path, r.code, r.raw)
		}
	}
	if r := ae.call(t, "auditor", "GET", "/switches/00000000-0000-0000-0000-000000000000", "", nil); r.code != 404 {
		t.Errorf("unknown switch: %d", r.code)
	}
	r = ae.call(t, "auditor", "GET", "/changes", "", nil)
	if cs, _ := r.body["changes"].([]any); len(cs) < 4 {
		t.Fatalf("changes %s", r.raw)
	}
	r = ae.call(t, "auditor", "GET", "/k8s-access", "", nil)
	if r.body["state"] != "undecided" || !strings.Contains(r.body["warning"].(string), "not been decided") || len(r.body["checks"].([]any)) != 10 {
		t.Fatalf("k8s-access %s", r.raw)
	}
}

// Verification for T-31: restricted-BU overrides are hidden from users
// outside the restricted BU, and ?bu= of a BU the caller may not see is 404.
func TestPostureAPIRestrictedBUHidden(t *testing.T) {
	ae := apiFixture(t, settings.ProfileEnterpriseBaseline)
	e := ae.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("R", "ENTERPRISE")
	e.drain()
	id := func(c string) string { return e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + c + "'") }
	a, rb := id("A"), id("R")
	for _, bu := range []string{a, rb} {
		if r := ae.call(t, "admin", "POST", "/settings/session.network_binding", "auto", map[string]any{"value": "reauthenticate", "bu_id": bu}); r.code != 200 {
			t.Fatalf("override at %s: %d %s", bu, r.code, r.raw)
		}
	}
	e.mustOwner("UPDATE iam.bu SET restricted = true WHERE code = 'R'")
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('rauditor@example.test', 'R Auditor')")
	e.mustOwner(grant("admin", "user:rauditor", "Auditor", "R"))
	e.drain()

	overrides := func(user string) []string {
		t.Helper()
		r := ae.call(t, user, "GET", "/settings", "", nil)
		if r.code != 200 {
			if r.code == 404 {
				return nil
			}
			t.Fatalf("%s settings: %d %s", user, r.code, r.raw)
		}
		var out []string
		for _, o := range r.body["overrides"].([]any) {
			out = append(out, o.(map[string]any)["bu_id"].(string))
		}
		return out
	}
	// Assigned at the root: A's override, not the restricted BU's.
	for _, user := range []string{"auditor", "admin"} {
		if got := overrides(user); !slices.Equal(got, []string{a}) {
			t.Errorf("%s sees overrides at %v, want only A", user, got)
		}
		if r := ae.call(t, user, "GET", "/settings?bu="+rb, "", nil); r.code != 404 {
			t.Errorf("%s ?bu=R: %d", user, r.code)
		}
	}
	// Assigned at the restricted BU: its override and its values.
	r := ae.call(t, "rauditor", "GET", "/settings?bu="+rb, "", nil)
	if r.code != 200 || r.body["effective"].(map[string]any)["session.network_binding"] != "reauthenticate" {
		t.Fatalf("rauditor ?bu=R: %d %s", r.code, r.raw)
	}
	// The instance-wide views need posture.view at the root.
	if r := ae.call(t, "rauditor", "GET", "/registry", "", nil); r.code != 404 {
		t.Fatalf("rauditor registry: %d", r.code)
	}
}
