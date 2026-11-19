package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/importapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// importEnv serves the imports API on the risk env's keys, with the
// integration users (integrationUsers) and "pusher" (integration.push at A).
type importEnv struct {
	*riskAPIEnv
	ie *integrationEnv
}

func importAPI(t *testing.T) *importEnv {
	t.Helper()
	ra := newRiskAPI(t)
	integrationUsers(ra.env)
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('pusher@example.test', 'Pusher')")
	ra.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Integration Pusher') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['integration.push'], 'test' FROM r`)
	ra.mustOwner(grant("platform", "user:pusher", "Integration Pusher", "A"))
	ra.drain()
	pool := ra.appPool()
	api := &importapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)})}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	ia := *ra
	ia.url = srv.URL
	return &importEnv{riskAPIEnv: &ia, ie: &integrationEnv{env: ra.env, pool: rolePool(t, ra.env, "app_integrate")}}
}

// send posts body with contentType as user.
func (im *importEnv) send(t *testing.T, user, path, contentType, body string) apiResp {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", im.url+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", contentType)
	im.n++
	req.Header.Set("Idempotency-Key", fmt.Sprintf("import-test-key-%04d", im.n))
	p := im.principal(user)
	tok, err := authz.MintJWT(im.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
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
	return apiResp{code: resp.StatusCode, body: m, raw: string(raw), hdr: resp.Header}
}

func counts(r apiResp) map[string]any {
	c, _ := r.body["counts"].(map[string]any)
	return c
}

func asset(ext, bu, name string) string {
	return fmt.Sprintf(`{"kind": "asset", "external_id": %q, "bu": %q, "name": %q, "asset_type": "application"}`, ext, bu, name)
}

func batchOf(records ...string) string {
	return `{"format": "fair.integration.v1", "records": [` + strings.Join(records, ",") + `]}`
}

// F-011 T-08 (F-011-AC-02, AC-06 to AC-09; design §3.2, §6.2).
func TestImportBatches(t *testing.T) {
	im := importAPI(t)
	mapping := `{"columns": {"ID": "external_id", "Unit": "bu", "Name": "name", "Type": "asset_type"}, "defaults": {"asset_type": "application"}}`
	var id string
	if err := im.ie.as("platform", func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT integration.add($1, 'CMDB', 'assets', 'push', $2::jsonb, NULL, NULL, false)::text",
			im.bu["A"], mapping).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/imports/" + id + "/batches"

	// A batch checked record by record; business units inside the
	// integration's subtree only (A1 yes; B, the restricted R, unknown no).
	body := batchOf(asset("a-1", "A1", "Claims platform"), asset("a-2", "A", "Warehouse"), asset("a-3", "B", "Outside"),
		asset("a-4", "R", "Restricted"), asset("a-5", "ZZ", "Unknown"), asset("a-6", "A", ""))
	got := im.send(t, "pusher", path, "application/json", body)
	if got.code != 201 {
		t.Fatalf("push: %d %s", got.code, got.raw)
	}
	c := counts(got)
	if c["received"] != 6.0 || c["valid"] != 2.0 || c["refused"] != 4.0 || c["new"] != 2.0 {
		t.Errorf("counts %v", c)
	}
	var pointers []string
	for _, r := range got.body["refused"].([]any) {
		m := r.(map[string]any)
		pointers = append(pointers, fmt.Sprintf("%v%v", m["n"], m["pointer"]))
	}
	if strings.Join(pointers, ",") != "3/bu,4/bu,5/bu,6/name" {
		t.Errorf("refusals %v", pointers)
	}
	run := got.body["run"].(map[string]any)
	runID := run["id"].(string)
	if run["state"] != "succeeded" || run["trigger"] != "push" {
		t.Errorf("run %v", run)
	}
	if n := im.adminQuery("SELECT count(*) FROM integration.record WHERE run_id = '" + runID + "'"); n != "2" {
		t.Errorf("%s records staged", n)
	}
	if n := im.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'integration.run' AND body #>> '{attributes,run}' = '" + runID + "' AND body #>> '{attributes,refused}' = '4'"); n != "1" {
		t.Errorf("integration.run events: %s", n)
	}

	// Matches by external ID (AC-07): a link with the staged digest is
	// unchanged, with another digest changed.
	digest := im.adminQuery("SELECT digest FROM integration.record WHERE run_id = '" + runID + "' AND external_id = 'a-1'")
	im.mustOwner(fmt.Sprintf(`INSERT INTO integration.link (integration_id, external_id, target_type, target_id, last_digest) VALUES
		('%[1]s', 'a-1', 'asset', gen_random_uuid(), '%[2]s'), ('%[1]s', 'a-2', 'asset', gen_random_uuid(), repeat('0', 64))`, id, digest))

	// A dry run (AC-09): the matches, nothing recorded.
	runs := im.adminQuery("SELECT count(*) FROM integration.run")
	got = im.send(t, "pusher", path+"?dry_run=true", "application/json", batchOf(asset("a-1", "A1", "Claims platform"), asset("a-2", "A", "Warehouse 2"), asset("a-7", "A", "New")))
	if got.code != 200 || got.body["run"] != nil {
		t.Fatalf("dry run: %d %s", got.code, got.raw)
	}
	var matches []string
	for _, m := range got.body["matches"].([]any) {
		x := m.(map[string]any)
		matches = append(matches, x["external_id"].(string)+":"+x["match"].(string))
	}
	if strings.Join(matches, ",") != "a-1:unchanged,a-2:changed,a-7:new" {
		t.Errorf("matches %v", matches)
	}
	if after := im.adminQuery("SELECT count(*) FROM integration.run"); after != runs {
		t.Errorf("a dry run recorded a run: %s -> %s", runs, after)
	}

	// CSV by the integration's mapping, uploaded by an administrator.
	got = im.send(t, "platform", path, "text/csv", "ID,Unit,Name,Type,Extra\na-8,A1,From CSV,,x\na-9,A1,,database,y\n")
	if got.code != 201 || counts(got)["valid"] != 1.0 || got.body["run"].(map[string]any)["trigger"] != "upload" {
		t.Fatalf("CSV: %d %s", got.code, got.raw)
	}
	if r := got.body["refused"].([]any)[0].(map[string]any); r["column"] != "Name" || r["n"] != 2.0 {
		t.Errorf("a CSV refusal: %v", r)
	}

	// Who may: push or manage at the BU; view only 403; neither 404.
	for _, c := range []struct {
		user string
		code int
	}{{"aud", 403}, {"erin", 404}, {"mallory", 404}} {
		if got := im.send(t, c.user, path, "application/json", batchOf(asset("x", "A", "x"))); got.code != c.code {
			t.Errorf("%s pushes: %d %s", c.user, got.code, got.raw)
		}
	}
	// Only the integration's own service account sends connector runs.
	if got := im.send(t, "pusher", path+"?trigger=schedule", "application/json", batchOf(asset("x", "A", "x"))); got.code != 422 {
		t.Errorf("a schedule trigger from a user: %d %s", got.code, got.raw)
	}
	// Refused whole: not the format, another media type, too large.
	for name, c := range map[string]struct {
		ct, body string
		code     int
	}{
		"another format":     {"application/json", `{"format": "fair.risk.v1", "records": []}`, 422},
		"not JSON":           {"application/json", `{`, 422},
		"another media type": {"application/xml", `<x/>`, 415},
		"too large":          {"application/json", strings.Repeat(" ", 20<<20+1), 413},
		// Over the platform's 4 MiB, within the batch's 20 MiB: the body
		// reaches the batch's checks (design §3.2).
		"6 MiB": {"application/json", `{"format": "fair.risk.v1", "records": []}` + strings.Repeat(" ", 6<<20), 422},
	} {
		if got := im.send(t, "pusher", path, c.ct, c.body); got.code != c.code {
			t.Errorf("%s: %d %s", name, got.code, got.raw[:min(len(got.raw), 200)])
		}
	}

	// Runs: the actor and the integration's viewers read them.
	for user, code := range map[string]int{"pusher": 200, "aud": 200, "platform": 200, "erin": 404} {
		if got := im.call(t, "GET", user, "/api/v1/imports/runs/"+runID, nil); got.code != code {
			t.Errorf("%s reads the run: %d", user, got.code)
		}
	}

	// At most 12 batches an hour (429); a paused integration refuses (409).
	im.mustOwner(fmt.Sprintf(`INSERT INTO integration.run (integration_id, trigger, actor, state, finished_at, counts)
		SELECT '%s', 'push', %s, 'succeeded', now(), '{}' FROM generate_series(1, 10)`, id, uid("pusher")))
	if got := im.send(t, "pusher", path, "application/json", batchOf(asset("a-10", "A", "x"))); got.code != 429 || got.body["limit"] != 12.0 {
		t.Errorf("a 13th batch in the hour: %d %s", got.code, got.raw)
	}
	if err := im.ie.exec("platform", "SELECT integration.pause($1)", id); err != nil {
		t.Fatal(err)
	}
	if got := im.send(t, "pusher", path, "application/json", batchOf(asset("a-11", "A", "x"))); got.code != 409 || got.body["error"] != "invalid_state" {
		t.Errorf("a paused integration: %d %s", got.code, got.raw)
	}
}
