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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	risksvc "github.com/rformer/fair-app/internal/risk"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-003 T-05 (AC-01 to AC-06, AC-15, AC-21, AC-26, AC-28, AC-29): the
// scenarios API against the database.

type riskAPIEnv struct {
	riskEnv
	url  string
	keys *authz.LocalKeys
	n    int
}

func newRiskAPI(t *testing.T) *riskAPIEnv {
	t.Helper()
	r := riskFixture(t)
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
	pool := r.appPool()
	api := &riskapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	srv := httptest.NewServer(api.Handler(keys, nil))
	t.Cleanup(srv.Close)
	return &riskAPIEnv{riskEnv: r, url: srv.URL, keys: keys}
}

// call sends a request as user ("" = unauthenticated); mutations get a
// fresh Idempotency-Key unless key is given.
func (ra *riskAPIEnv) call(t *testing.T, method, user, path string, body any, key ...string) apiResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, ra.url+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if method != "GET" {
		ra.n++
		k := fmt.Sprintf("risk-test-key-%04d", ra.n)
		if len(key) > 0 {
			k = key[0]
		}
		req.Header.Set("Idempotency-Key", k)
	}
	if user != "" {
		p := ra.principal(user)
		tok, err := authz.MintJWT(ra.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
			DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set(server.DBContextHeader, p.DBToken)
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

func (ra *riskAPIEnv) setCurrency(t *testing.T, code string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.ConnectConfig(ctx, migratorConfig(t, ra.env))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := risksvc.SetCurrency(ctx, conn, audit.WithTrail(audit.NewMemory(), audit.Trail{DB: conn, Role: "fair_owner"}), code, "installer"); err != nil {
		t.Fatal(err)
	}
}

// scenarioDoc is a valid scenario pinning library entries created at A.
func (ra *riskAPIEnv) scenarioDoc(t *testing.T) map[string]any {
	t.Helper()
	asset := modeltest.Asset()
	delete(asset, "value")
	asset["value_basis"] = "Replacement cost."
	a := ra.create(t, "analyst", "asset", ra.bu["A"], asset)
	tc := ra.create(t, "analyst", "threat_community", ra.bu["A"], modeltest.ThreatCommunity())
	ctl := ra.create(t, "analyst", "control", ra.bu["A"], modeltest.Control())
	d := modeltest.Scenario()
	modeltest.Set(d, "/owner", ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'analyst@example.test'"))
	modeltest.Set(d, "/asset", map[string]any{"kind": "asset", "id": a, "version": 1})
	modeltest.Set(d, "/threat_community", map[string]any{"id": tc, "version": 1})
	modeltest.Set(d, "/control_sets", []any{map[string]any{"name": "Current", "current": true, "controls": []any{
		map[string]any{"id": ctl, "version": 1, "status": "in_place"}}}})
	return d
}

func TestRiskScenariosAPI(t *testing.T) {
	ra := newRiskAPI(t)
	doc := ra.scenarioDoc(t)
	create := map[string]any{"bu_id": ra.bu["A1"], "document": doc, "change_note": "First analysis"}

	// Without scenario.view anywhere the API does not exist; without a
	// session it refuses.
	for _, p := range []string{"/api/v1/scenarios", "/api/v1/risk/settings"} {
		if got := ra.call(t, "GET", "buadmin2", p, nil); got.code != 404 {
			t.Fatalf("no permission, %s: %d %s", p, got.code, got.raw)
		}
	}
	if got := ra.call(t, "GET", "", "/api/v1/scenarios", nil); got.code != 401 {
		t.Fatalf("unauthenticated: %d", got.code)
	}

	// Amounts wait for the installation currency (design §3.4).
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", create); got.code != 409 || got.body["error"] != "currency_not_set" {
		t.Fatalf("before the currency: %d %s", got.code, got.raw)
	}
	ra.setCurrency(t, "USD")

	// Every problem of an invalid document, by pointer (AC-02 to AC-06).
	bad := map[string]any{"bu_id": ra.bu["A1"], "change_note": "x", "document": modeltest.Set(ra.scenarioDoc(t), "/lef/tef/contact_frequency/min", "50")}
	modeltest.Set(bad["document"].(map[string]any), "/name", "")
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", bad)
	if got.code != 422 || !strings.Contains(got.raw, `"/lef/tef/contact_frequency"`) || !strings.Contains(got.raw, `"/name"`) {
		t.Fatalf("invalid document: %d %s", got.code, got.raw)
	}
	// The envelope: a change note, a BU.
	for name, b := range map[string]map[string]any{
		"no change note":   {"bu_id": ra.bu["A1"], "document": doc},
		"secret note":      {"bu_id": ra.bu["A1"], "document": doc, "change_note": "Bearer abcdefghijklmnopqrstuvwxyz0123456789"},
		"no BU":            {"document": doc, "change_note": "x"},
		"expected_version": {"bu_id": ra.bu["A1"], "document": doc, "change_note": "x", "expected_version": 1},
		"unknown field":    {"bu_id": ra.bu["A1"], "document": doc, "change_note": "x", "colour": "red"},
	} {
		if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", b); got.code != 400 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	// A viewer gets 403; someone who cannot see the BU gets 404.
	if got := ra.call(t, "POST", "erin", "/api/v1/scenarios", create); got.code != 403 {
		t.Fatalf("viewer creates: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "POST", "mallory", "/api/v1/scenarios", create); got.code != 404 {
		t.Fatalf("outsider creates: %d %s", got.code, got.raw)
	}

	// Create; replaying the same key answers the same, without a second
	// scenario.
	got = ra.call(t, "POST", "analyst", "/api/v1/scenarios", create, "create-key-0001")
	if got.code != 201 || got.body["version"] != float64(1) {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	digest := got.body["digest"].(string)
	if again := ra.call(t, "POST", "analyst", "/api/v1/scenarios", create, "create-key-0001"); again.code != 201 || again.raw != got.raw {
		t.Fatalf("replay: %d %s", again.code, again.raw)
	}
	if n := ra.adminQuery("SELECT count(*) FROM risk.scenario"); n != "1" {
		t.Fatalf("%s scenarios after a replay", n)
	}
	analyst := ra.adminQuery("SELECT id FROM iam.app_user WHERE email = 'analyst@example.test'")
	if ev := ra.adminQuery(`SELECT body ->> 'actor' || '|' || (body ->> 'bu_id') || '|' || (body -> 'attributes' ->> 'digest') || '|' || (body -> 'attributes' ->> 'change_note')
		FROM audit.intake WHERE body ->> 'type' = 'scenario.created'`); ev != analyst+"|"+ra.bu["A1"]+"|"+digest+"|First analysis" {
		t.Fatalf("scenario.created: %s", ev)
	}

	// Read: the current version, its pins, the taxonomy view, the currency.
	got = ra.call(t, "GET", "erin", "/api/v1/scenarios/"+id, nil)
	if got.code != 200 || got.body["currency"] != "USD" || len(got.body["pins"].([]any)) != 3 ||
		!strings.Contains(got.raw, `"factor":"contact_frequency","parent":"threat_event_frequency","status":"entered"`) ||
		got.body["version"].(map[string]any)["author"] != analyst {
		t.Fatalf("read: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "GET", "mallory", "/api/v1/scenarios/"+id, nil); got.code != 404 {
		t.Fatalf("outsider reads: %d", got.code)
	}
	for _, p := range []string{"/api/v1/scenarios/00000000-0000-0000-0000-000000000000", "/api/v1/scenarios/not-a-uuid", "/api/v1/scenarios/" + id + "/versions/9"} {
		if got := ra.call(t, "GET", "analyst", p, nil); got.code != 404 {
			t.Errorf("%s: %d", p, got.code)
		}
	}

	// Save versions; a stale one is refused (AC-15).
	doc2 := modeltest.Set(doc, "/name", "Ransomware on claims, revised")
	save := map[string]any{"document": doc2, "expected_version": 1, "change_note": "Revised name"}
	if got := ra.call(t, "PUT", "erin", "/api/v1/scenarios/"+id, save); got.code != 403 {
		t.Fatalf("viewer saves: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+id, map[string]any{"document": doc2, "change_note": "x"}); got.code != 400 {
		t.Fatalf("no expected_version: %d", got.code)
	}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+id, save); got.code != 200 || got.body["version"] != float64(2) {
		t.Fatalf("save: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/scenarios/"+id, save); got.code != 409 || got.body["error"] != "stale_version" {
		t.Fatalf("stale save: %d %s", got.code, got.raw)
	}
	if ev := ra.adminQuery(`SELECT (body -> 'attributes' ->> 'version') || '|' || (body ->> 'target') FROM audit.intake WHERE body ->> 'type' = 'scenario.version_saved'`); ev != "2|scenario:"+id {
		t.Fatalf("scenario.version_saved: %s", ev)
	}

	// History (AC-15).
	got = ra.call(t, "GET", "erin", "/api/v1/scenarios/"+id+"/versions", nil)
	if got.code != 200 || len(got.body["versions"].([]any)) != 2 || strings.Contains(got.raw, `"document"`) {
		t.Fatalf("versions: %d %s", got.code, got.raw)
	}
	got = ra.call(t, "GET", "erin", "/api/v1/scenarios/"+id+"/versions/1", nil)
	if got.code != 200 || got.body["version"].(map[string]any)["document"].(map[string]any)["name"] != "Ransomware on the claims platform" {
		t.Fatalf("version 1: %d %s", got.code, got.raw)
	}

	// Lists: by visibility and filters; mallory sees none.
	list := func(user, q string) []any {
		t.Helper()
		got := ra.call(t, "GET", user, "/api/v1/scenarios"+q, nil)
		if got.code != 200 {
			t.Fatalf("list %s: %d %s", q, got.code, got.raw)
		}
		return got.body["scenarios"].([]any)
	}
	if l := list("erin", ""); len(l) != 1 || l[0].(map[string]any)["name"] != "Ransomware on claims, revised" || l[0].(map[string]any)["current_version"] != float64(2) {
		t.Fatalf("erin's list: %v", l)
	}
	if l := list("mallory", ""); len(l) != 0 {
		t.Fatalf("mallory's list: %v", l)
	}
	for q, n := range map[string]int{"?owner=" + analyst: 1, "?owner=" + ra.bu["A"]: 0, "?bu=" + ra.bu["A1"]: 1, "?bu=" + ra.bu["A"]: 0,
		"?archived=true": 0, "?archived=all": 1, "?asset=" + doc["asset"].(map[string]any)["id"].(string): 1} {
		if l := list("analyst", q); len(l) != n {
			t.Errorf("list %s: %d, want %d", q, len(l), n)
		}
	}
	for _, q := range []string{"?owner=x", "?archived=maybe", "?limit=0", "?limit=201", "?cursor=-1"} {
		if got := ra.call(t, "GET", "analyst", "/api/v1/scenarios"+q, nil); got.code != 400 {
			t.Errorf("list %s: %d", q, got.code)
		}
	}
	if got := ra.call(t, "GET", "erin", "/api/v1/risk/settings", nil); got.code != 200 || got.body["currency"] != "USD" {
		t.Fatalf("settings: %d %s", got.code, got.raw)
	}
}

// Paging: newest first, by cursor, every scenario once.
func TestRiskScenariosAPIPaging(t *testing.T) {
	ra := newRiskAPI(t)
	ra.setCurrency(t, "USD")
	doc := ra.scenarioDoc(t)
	var ids []string
	for i := 0; i < 5; i++ {
		got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A"], "document": modeltest.Set(doc, "/name", fmt.Sprint("S", i)), "change_note": "x"})
		if got.code != 201 {
			t.Fatalf("create %d: %d %s", i, got.code, got.raw)
		}
		ids = append(ids, got.body["id"].(string))
	}
	var seen []string
	cursor := ""
	for page := 0; page < 4; page++ {
		got := ra.call(t, "GET", "analyst", "/api/v1/scenarios?limit=2"+cursor, nil)
		for _, s := range got.body["scenarios"].([]any) {
			seen = append(seen, s.(map[string]any)["id"].(string))
		}
		next, ok := got.body["next_cursor"].(string)
		if !ok {
			break
		}
		cursor = "&cursor=" + next
	}
	want := []string{ids[4], ids[3], ids[2], ids[1], ids[0]}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("pages %v, want %v", seen, want)
	}
}
