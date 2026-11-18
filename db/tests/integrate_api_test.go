package tests

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/egress"
	"github.com/rformer/fair-app/internal/integrateapi"
	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/pkg/authz"
)

// testResolver answers fixed addresses: the guard checks what they are.
type testResolver map[string]string

func (r testResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	a, ok := r[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return []netip.Addr{netip.MustParseAddr(a)}, nil
}

// fakeTester stands in for the connectors (T-17): it answers three records
// and one problem, or a refused destination for a source under /refused.
type fakeTester struct {
	mu   sync.Mutex
	last integration.TestRequest
}

func (f *fakeTester) Test(_ context.Context, req integration.TestRequest) (integration.TestResult, error) {
	f.mu.Lock()
	f.last = req
	f.mu.Unlock()
	if strings.Contains(req.Connector.Source, "/refused") {
		return integration.TestResult{}, fmt.Errorf("next page: %w: 10.1.2.3 is a private address", egress.ErrRefused)
	}
	return integration.TestResult{Records: 3, Problems: []integration.Refusal{{N: 2, Pointer: "/name", Message: "a name is needed"}}}, nil
}

// integrateEnv serves the integrations API as app_integrate, on the risk
// env's keys (audience "integrate"), with the integration users
// (integrationUsers), sources allowed at cmdb.example.test (TEST-NET-3) and
// inside.example.test (an address in the cluster's range, always refused).
type integrateEnv struct {
	*riskAPIEnv
	ie     *integrationEnv
	tester *fakeTester
}

func integrateAPI(t *testing.T) *integrateEnv {
	t.Helper()
	ra := newRiskAPI(t)
	integrationUsers(ra.env)
	keys, err := integration.NewKeyring(map[string][]byte{"k-20261118": []byte("integrate test key, 32 bytes!!!")})
	if err != nil {
		t.Fatal(err)
	}
	ft := &fakeTester{}
	guard := egress.Guard{Setting: "integration.allowed_hosts", Cluster: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, Allowed: func() []string { return []string{"cmdb.example.test", "inside.example.test"} },
		Resolver: testResolver{"cmdb.example.test": "203.0.113.10", "inside.example.test": "10.20.0.5", "other.example.test": "203.0.113.11"}}
	pool := rolePool(t, ra.env, "app_integrate")
	srv := httptest.NewServer((&integrateapi.API{DB: pool, Keys: keys, Guard: guard, Tester: ft}).Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	ia := *ra
	ia.url, ia.aud = srv.URL, "integrate"
	ia.n += 800000
	return &integrateEnv{riskAPIEnv: &ia, ie: &integrationEnv{env: ra.env, pool: pool}, tester: ft}
}

func (ia *integrateEnv) events(t *testing.T, typ, where string) string {
	t.Helper()
	q := "SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '" + typ + "'"
	if where != "" {
		q += " AND " + where
	}
	return ia.adminQuery(q)
}

// F-011 T-16 (F-011-AC-01 to AC-05, AC-08; design §3.1, §6.1): the
// integrations API end to end, as app_integrate.
func TestIntegrationsAPI(t *testing.T) {
	ia := integrateAPI(t)
	connector := func(source string) map[string]any {
		return map[string]any{"type": "http_json", "source": source, "schedule_minutes": 60, "settings": map[string]any{"list": "/items"}}
	}
	saRoot := ia.adminQuery("SELECT id FROM iam.service_account WHERE name = 'sa-root'")
	create := func(user string, body map[string]any, key ...string) apiResp {
		t.Helper()
		return ia.call(t, "POST", user, "/api/v1/integrations", body, key...)
	}

	// AC-01: a push integration and a connector integration at A.
	push := create("platform", map[string]any{"bu_id": ia.bu["A"], "name": "CMDB export", "kind": "assets", "delivery": "push",
		"mapping": map[string]any{"columns": map[string]any{"ID": "external_id", "Name": "name"}}}, "integrate-create-push")
	if push.code != 201 || push.body["version"] != 1.0 || push.body["state"] != "active" || fmt.Sprint(push.body["credentials"]) != "[]" {
		t.Fatalf("create push: %d %s", push.code, push.raw)
	}
	pushID := push.body["id"].(string)
	// The same request again is answered from the idempotency store.
	if again := create("platform", map[string]any{"bu_id": ia.bu["A"], "name": "CMDB export", "kind": "assets", "delivery": "push",
		"mapping": map[string]any{"columns": map[string]any{"ID": "external_id", "Name": "name"}}}, "integrate-create-push"); again.code != 201 || again.body["id"] != pushID {
		t.Errorf("replay: %d %s", again.code, again.raw)
	}
	conn := create("platform", map[string]any{"bu_id": ia.bu["A"], "name": "CMDB pull", "kind": "assets", "delivery": "connector",
		"connector": connector("https://cmdb.example.test/api/apps"), "service_account_id": saRoot})
	if conn.code != 201 || conn.body["next_run_at"] == nil || conn.body["service_account_name"] != "sa-root" {
		t.Fatalf("create connector: %d %s", conn.code, conn.raw)
	}
	connID := conn.body["id"].(string)

	// AC-04: sources off the allow-list, at a refused address, or not
	// resolving are refused on save; refusals are recorded.
	for name, tc := range map[string]struct {
		source, code string
	}{
		"an unlisted host":   {"https://other.example.test/x", "destination_refused"},
		"a cluster address":  {"https://inside.example.test/x", "destination_refused"},
		"a loopback literal": {"https://127.0.0.1/x", "destination_refused"},
		"a look-alike host":  {"https://cmdb.example.test.invalid/x", "destination_refused"},
	} {
		got := create("platform", map[string]any{"bu_id": ia.bu["A"], "name": "Refused " + name, "kind": "assets", "delivery": "connector",
			"connector": connector(tc.source), "service_account_id": saRoot})
		if got.code != 422 || got.body["error"] != tc.code {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	if got := ia.events(t, "integration.destination_refused", "body -> 'attributes' ->> 'during' = 'save' AND body ->> 'severity' = 'high'"); got != "4" {
		t.Errorf("%s save refusals recorded, want 4", got)
	}
	if got := ia.adminQuery("SELECT count(*) FROM integration.integration WHERE name LIKE 'Refused%'"); got != "0" {
		t.Errorf("%s refused integrations saved", got)
	}

	// Bad shapes are refused before the database.
	for name, body := range map[string]map[string]any{
		"a kind":              {"bu_id": ia.bu["A"], "name": "x", "kind": "scenarios", "delivery": "push"},
		"a delivery":          {"bu_id": ia.bu["A"], "name": "x", "kind": "assets", "delivery": "email"},
		"a mapping field":     {"bu_id": ia.bu["A"], "name": "x", "kind": "assets", "delivery": "file", "mapping": map[string]any{"columns": map[string]any{"ID": "external_id", "X": "title"}}},
		"a mapping key":       {"bu_id": ia.bu["A"], "name": "x", "kind": "assets", "delivery": "file", "mapping": map[string]any{"formula": "=1"}},
		"a schedule":          {"bu_id": ia.bu["A"], "name": "x", "kind": "assets", "delivery": "connector", "connector": map[string]any{"type": "http_json", "source": "https://cmdb.example.test/", "schedule_minutes": 1}, "service_account_id": saRoot},
		"a connector on push": {"bu_id": ia.bu["A"], "name": "x", "kind": "assets", "delivery": "push", "connector": connector("https://cmdb.example.test/")},
		"no service account":  {"bu_id": ia.bu["A"], "name": "x", "kind": "assets", "delivery": "connector", "connector": connector("https://cmdb.example.test/")},
		"sa-b at A":           {"bu_id": ia.bu["A"], "name": "x", "kind": "assets", "delivery": "connector", "connector": connector("https://cmdb.example.test/"), "service_account_id": ia.adminQuery("SELECT id FROM iam.service_account WHERE name = 'sa-b'")},
		"a taken name":        {"bu_id": ia.bu["A"], "name": "cmdb EXPORT", "kind": "assets", "delivery": "push"},
	} {
		if got := create("platform", body); got.code != 422 && got.code != 409 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}

	// AC-02: who may create where. aud views but does not manage (403);
	// mallory has neither (404, nothing recorded, even for a refused host);
	// platform's root grants do not reach the restricted R, rman's do.
	if got := create("aud", map[string]any{"bu_id": ia.bu["A"], "name": "Aud's", "kind": "assets", "delivery": "push"}); got.code != 403 {
		t.Errorf("aud: %d %s", got.code, got.raw)
	}
	before := ia.events(t, "integration.destination_refused", "")
	if got := create("mallory", map[string]any{"bu_id": ia.bu["A"], "name": "Mallory's", "kind": "assets", "delivery": "connector",
		"connector": connector("https://other.example.test/"), "service_account_id": saRoot}); got.code != 404 {
		t.Errorf("mallory: %d %s", got.code, got.raw)
	}
	if got := ia.events(t, "integration.destination_refused", ""); got != before {
		t.Errorf("mallory recorded a refusal (%s, was %s)", got, before)
	}
	if got := create("platform", map[string]any{"bu_id": ia.bu["R"], "name": "Restricted", "kind": "risks", "delivery": "file"}); got.code != 404 {
		t.Errorf("platform at R: %d %s", got.code, got.raw)
	}
	rint := create("rman", map[string]any{"bu_id": ia.bu["R"], "name": "Restricted", "kind": "risks", "delivery": "file"})
	if rint.code != 201 {
		t.Fatalf("rman at R: %d %s", rint.code, rint.raw)
	}
	rID := rint.body["id"].(string)
	names := func(user, q string) string {
		t.Helper()
		got := ia.call(t, "GET", user, "/api/v1/integrations"+q, nil)
		if got.code != 200 {
			t.Fatalf("list as %s: %d %s", user, got.code, got.raw)
		}
		var out []string
		for _, x := range got.body["integrations"].([]any) {
			out = append(out, x.(map[string]any)["name"].(string))
		}
		return strings.Join(out, ",")
	}
	if got := names("platform", ""); got != "CMDB export,CMDB pull" {
		t.Errorf("platform lists %s", got)
	}
	if got := names("aud", ""); got != "CMDB export,CMDB pull" {
		t.Errorf("aud lists %s", got)
	}
	if got := names("rman", ""); got != "Restricted" {
		t.Errorf("rman lists %s", got)
	}
	if got := names("mallory", ""); got != "" {
		t.Errorf("mallory lists %s", got)
	}
	for _, c := range []struct{ user, id string }{{"mallory", pushID}, {"platform", rID}, {"rman", pushID}} {
		if got := ia.call(t, "GET", c.user, "/api/v1/integrations/"+c.id, nil); got.code != 404 {
			t.Errorf("%s reads %s: %d", c.user, c.id, got.code)
		}
	}
	if got := ia.call(t, "GET", "platform", "/api/v1/integrations/not-an-id", nil); got.code != 404 {
		t.Errorf("a malformed id: %d", got.code)
	}

	// Changes: expected_version, the fixed fields, the guard again.
	put := func(user, id string, body map[string]any) apiResp {
		t.Helper()
		return ia.call(t, "PUT", user, "/api/v1/integrations/"+id, body)
	}
	if got := put("platform", pushID, map[string]any{"name": "CMDB export (nightly)", "expected_version": 1,
		"mapping": map[string]any{"columns": map[string]any{"ID": "external_id", "Name": "name"}}}); got.code != 200 || got.body["version"] != 2.0 {
		t.Errorf("change: %d %s", got.code, got.raw)
	}
	if got := put("platform", pushID, map[string]any{"name": "Again", "expected_version": 1}); got.code != 409 || got.body["error"] != "stale_version" {
		t.Errorf("stale: %d %s", got.code, got.raw)
	}
	if got := put("platform", pushID, map[string]any{"name": "Again", "kind": "risks", "expected_version": 2}); got.code != 422 || got.body["error"] != "integration_fixed" {
		t.Errorf("kind changed: %d %s", got.code, got.raw)
	}
	if got := put("aud", pushID, map[string]any{"name": "Aud", "expected_version": 2}); got.code != 403 {
		t.Errorf("aud changes: %d %s", got.code, got.raw)
	}
	if got := put("platform", connID, map[string]any{"name": "CMDB pull", "expected_version": 1, "connector": connector("https://inside.example.test/apps"),
		"service_account_id": saRoot}); got.code != 422 || got.body["error"] != "destination_refused" {
		t.Errorf("refused on change: %d %s", got.code, got.raw)
	}
	if got := ia.events(t, "integration.destination_refused", "body ->> 'target' = 'integration:"+connID+"' AND body -> 'attributes' ->> 'host' = 'inside.example.test'"); got != "1" {
		t.Errorf("the change's refusal recorded %s times", got)
	}

	// AC-03: credentials are write-only and sealed.
	cred := func(method, user, id, purpose string, body any) apiResp {
		t.Helper()
		return ia.call(t, method, user, "/api/v1/integrations/"+id+"/credentials/"+purpose, body)
	}
	got := cred("PUT", "platform", connID, "source", map[string]any{"token": "src-token-8c1f"})
	if got.code != 200 || strings.Contains(got.raw, "src-token-8c1f") || !strings.Contains(got.raw, `"purpose":"source"`) {
		t.Errorf("set source: %d %s", got.code, got.raw)
	}
	if got := cred("PUT", "platform", connID, "client", map[string]any{"client_secret": "client-secret-77aa"}); got.code != 200 {
		t.Errorf("set client: %d %s", got.code, got.raw)
	}
	for _, path := range []string{"/api/v1/integrations/" + connID, "/api/v1/integrations"} {
		if got := ia.call(t, "GET", "platform", path, nil); strings.Contains(got.raw, "src-token") || strings.Contains(got.raw, "client-secret") {
			t.Errorf("%s answers a credential: %s", path, got.raw)
		}
	}
	if got := ia.adminQuery("SELECT count(*) FROM integration.secret WHERE position(convert_to('src-token', 'UTF8') IN ciphertext) > 0 OR position(convert_to('client-secret', 'UTF8') IN ciphertext) > 0"); got != "0" {
		t.Error("a credential is stored in clear")
	}
	if got := ia.adminQuery("SELECT count(*) FROM audit.intake WHERE body::text LIKE '%src-token%' OR body::text LIKE '%client-secret%'"); got != "0" {
		t.Error("a credential reached the audit trail")
	}
	for name, c := range map[string]struct {
		user, id, purpose string
		body              any
		code              int
	}{
		"both forms":        {"platform", connID, "source", map[string]any{"token": "t", "username": "u", "password": "p"}, 422},
		"a client token":    {"platform", connID, "client", map[string]any{"token": "t"}, 422},
		"an unknown field":  {"platform", connID, "source", map[string]any{"secret": "t"}, 400},
		"another purpose":   {"platform", connID, "admin", map[string]any{"token": "t"}, 404},
		"a push integation": {"platform", pushID, "source", map[string]any{"token": "t"}, 422},
		"aud":               {"aud", connID, "source", map[string]any{"token": "t"}, 403},
		"mallory":           {"mallory", connID, "source", map[string]any{"token": "t"}, 404},
	} {
		if got := cred("PUT", c.user, c.id, c.purpose, c.body); got.code != c.code {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}

	// Test: the first page, through the guard, with the opened credential.
	test := func(user, id string) apiResp {
		t.Helper()
		return ia.call(t, "POST", user, "/api/v1/integrations/"+id+"/test", nil)
	}
	if got := test("platform", connID); got.code != 200 || got.body["records"] != 3.0 || len(got.body["problems"].([]any)) != 1 {
		t.Errorf("test: %d %s", got.code, got.raw)
	}
	if ia.tester.last.Source == nil || ia.tester.last.Source.Token != "src-token-8c1f" || ia.tester.last.Connector.Host() != "cmdb.example.test" || ia.tester.last.Kind != "assets" {
		t.Errorf("the connector was tested with %+v", ia.tester.last)
	}
	if got := test("aud", connID); got.code != 403 {
		t.Errorf("aud tests: %d", got.code)
	}
	if got := test("platform", pushID); got.code != 422 || got.body["error"] != "invalid_integration" {
		t.Errorf("a push integration tested: %d %s", got.code, got.raw)
	}
	if got := put("platform", connID, map[string]any{"name": "CMDB pull", "expected_version": 1, "connector": connector("https://cmdb.example.test/refused"),
		"service_account_id": saRoot}); got.code != 200 {
		t.Fatalf("change the source: %d %s", got.code, got.raw)
	}
	if got := test("platform", connID); got.code != 422 || got.body["error"] != "destination_refused" {
		t.Errorf("a refused page: %d %s", got.code, got.raw)
	}
	if got := ia.events(t, "integration.destination_refused", "body -> 'attributes' ->> 'during' = 'test' AND body ->> 'target' = 'integration:"+connID+"'"); got != "1" {
		t.Errorf("the test's refusal recorded %s times", got)
	}
	if got := cred("DELETE", "platform", connID, "source", nil); got.code != 200 || strings.Contains(got.raw, `"purpose":"source"`) {
		t.Errorf("remove source: %d %s", got.code, got.raw)
	}
	if got := cred("DELETE", "platform", connID, "source", nil); got.code != 404 {
		t.Errorf("remove it again: %d %s", got.code, got.raw)
	}

	// Run now (AC-08): connector integrations only, while active.
	run := func(user, id string) apiResp {
		t.Helper()
		return ia.call(t, "POST", user, "/api/v1/integrations/"+id+"/run", nil)
	}
	if got := run("platform", connID); got.code != 202 || got.body["run_requested_at"] == nil {
		t.Errorf("run now: %d %s", got.code, got.raw)
	}
	if got := ia.adminQuery("SELECT run_requested_by = " + uid("platform") + " AND next_run_at <= now() FROM integration.integration WHERE id = '" + connID + "'"); got != "t" {
		t.Errorf("run request recorded: %s", got)
	}
	if got := ia.events(t, "integration.changed", "body -> 'attributes' ->> 'changes' = 'run_requested'"); got != "1" {
		t.Errorf("run requests recorded: %s", got)
	}
	if got := run("platform", pushID); got.code != 422 {
		t.Errorf("run a push integration: %d %s", got.code, got.raw)
	}
	if got := run("aud", connID); got.code != 403 {
		t.Errorf("aud runs: %d", got.code)
	}

	// AC-05: pause and resume.
	state := func(user, id, action string) apiResp {
		t.Helper()
		return ia.call(t, "POST", user, "/api/v1/integrations/"+id+"/"+action, nil)
	}
	if got := state("platform", connID, "pause"); got.code != 200 || got.body["state"] != "paused" || got.body["next_run_at"] != nil {
		t.Errorf("pause: %d %s", got.code, got.raw)
	}
	if got := state("platform", connID, "pause"); got.code != 409 || got.body["error"] != "invalid_state" {
		t.Errorf("pause again: %d %s", got.code, got.raw)
	}
	if got := run("platform", connID); got.code != 409 {
		t.Errorf("run a paused integration: %d %s", got.code, got.raw)
	}
	if got := state("platform", connID, "resume"); got.code != 200 || got.body["state"] != "active" || got.body["next_run_at"] == nil {
		t.Errorf("resume: %d %s", got.code, got.raw)
	}
	if got := state("mallory", connID, "pause"); got.code != 404 {
		t.Errorf("mallory pauses: %d", got.code)
	}

	// AC-08: runs, newest first, with their counts; one run with its
	// refusals. Three uploads by platform as app_rw.
	var runIDs []string
	for i := range 3 {
		var rid string
		if err := authz.WithDBContext(context.Background(), ia.appPool(), ia.principal("platform").DBToken, func(tx pgx.Tx) error {
			if err := tx.QueryRow(context.Background(), "SELECT integration.begin_run($1, NULL, false)::text", pushID).Scan(&rid); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), "SELECT integration.finish_run($1, $2::jsonb, $3::jsonb)", rid,
				fmt.Sprintf(`{"received": %d, "valid": %d, "refused": 1}`, i+2, i+1), `[{"n": 1, "pointer": "/name", "message": "a name is needed"}]`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		runIDs = append(runIDs, rid)
	}
	runs := ia.call(t, "GET", "aud", "/api/v1/integrations/"+pushID+"/runs?limit=2", nil)
	if runs.code != 200 || runs.body["more"] != true || len(runs.body["runs"].([]any)) != 2 {
		t.Fatalf("runs: %d %s", runs.code, runs.raw)
	}
	first := runs.body["runs"].([]any)[0].(map[string]any)
	last := runs.body["runs"].([]any)[1].(map[string]any)
	if first["id"] != runIDs[2] || first["trigger"] != "upload" || first["refusals"] != nil || first["counts"].(map[string]any)["received"] != 4.0 {
		t.Errorf("newest run %v", first)
	}
	older := ia.call(t, "GET", "aud", "/api/v1/integrations/"+pushID+"/runs?before="+last["id"].(string), nil)
	if older.code != 200 || older.body["more"] != false || len(older.body["runs"].([]any)) != 1 || older.body["runs"].([]any)[0].(map[string]any)["id"] != runIDs[0] {
		t.Errorf("older runs: %d %s", older.code, older.raw)
	}
	one := ia.call(t, "GET", "aud", "/api/v1/integrations/"+pushID+"/runs/"+runIDs[0], nil)
	if one.code != 200 || len(one.body["refusals"].([]any)) != 1 {
		t.Errorf("one run: %d %s", one.code, one.raw)
	}
	if got := ia.call(t, "GET", "aud", "/api/v1/integrations/"+connID+"/runs/"+runIDs[0], nil); got.code != 404 {
		t.Errorf("a run under another integration: %d", got.code)
	}
	if got := ia.call(t, "GET", "mallory", "/api/v1/integrations/"+pushID+"/runs", nil); got.code != 404 {
		t.Errorf("mallory's runs: %d", got.code)
	}
	if got := ia.call(t, "GET", "aud", "/api/v1/integrations/"+pushID+"/runs?limit=500", nil); got.code != 400 {
		t.Errorf("limit 500: %d", got.code)
	}

	// AC-05: delete needs a reason; runs and the integration stay readable,
	// its credentials go, and it changes no more.
	del := func(user, id string, body any) apiResp {
		t.Helper()
		return ia.call(t, "DELETE", user, "/api/v1/integrations/"+id, body)
	}
	if got := del("platform", connID, map[string]any{"reason": ""}); got.code != 400 || got.body["error"] != "reason_required" {
		t.Errorf("delete without a reason: %d %s", got.code, got.raw)
	}
	if got := del("platform", connID, map[string]any{"reason": "Replaced by the CMDB push"}); got.code != 200 || got.body["state"] != "deleted" || fmt.Sprint(got.body["credentials"]) != "[]" {
		t.Errorf("delete: %d %s", got.code, got.raw)
	}
	if got := del("platform", pushID, map[string]any{"reason": "Retired"}); got.code != 200 {
		t.Errorf("delete push: %d %s", got.code, got.raw)
	}
	if got := ia.adminQuery("SELECT count(*) FROM integration.secret WHERE integration_id = '" + connID + "'"); got != "0" {
		t.Errorf("%s credentials kept after delete", got)
	}
	if got := names("platform", ""); got != "" {
		t.Errorf("deleted integrations listed: %s", got)
	}
	if got := names("platform", "?deleted=true"); got != "CMDB export (nightly),CMDB pull" {
		t.Errorf("with deleted: %s", got)
	}
	if got := ia.call(t, "GET", "aud", "/api/v1/integrations/"+pushID+"/runs", nil); got.code != 200 || len(got.body["runs"].([]any)) != 3 {
		t.Errorf("a deleted integration's runs: %d %s", got.code, got.raw)
	}
	if got := put("platform", pushID, map[string]any{"name": "Back", "expected_version": 3}); got.code != 409 || got.body["error"] != "integration_deleted" {
		t.Errorf("change a deleted integration: %d %s", got.code, got.raw)
	}

	// AC-26: every change was recorded, as the integrate service's events.
	for typ, want := range map[string]string{"integration.created": "3", "integration.changed": "3", "integration.credential_set": "2",
		"integration.credential_removed": "1", "integration.paused": "1", "integration.resumed": "1", "integration.deleted": "2"} {
		if got := ia.events(t, typ, ""); got != want {
			t.Errorf("%s: %s events, want %s", typ, got, want)
		}
	}
}
