package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/rformer/fair-app/internal/objstore"
	"github.com/rformer/fair-app/internal/reportapi"
	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/internal/reports/doc"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-010 T-09 (F-010-AC-14 to AC-18, AC-22, AC-23; design §3.3, §3.6):
// report runs through the API with a fake document: the reason rule per
// BU, the limits, generation under the requester's delegated read-only
// context, digests, downloads re-checked, and the events.

// fakeKind reads iam.sample_doc (RLS type register) as the requester sees
// it; params {"fail": true} make every read fail.
var fakeKind = reports.Kind{Name: "register", Title: "Sample register",
	Params: func(raw json.RawMessage) (json.RawMessage, error) {
		var p struct {
			Fail bool `json:"fail"`
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, errors.New("params: only fail")
		}
		if p.Fail {
			return json.RawMessage(`{"fail":true}`), nil
		}
		return json.RawMessage(`{}`), nil
	},
	Read: func(ctx context.Context, tx pgx.Tx, r reports.Run) (reports.Built, error) {
		if strings.Contains(string(r.Params), "fail") {
			return reports.Built{}, errors.New("the reader failed")
		}
		rows, err := tx.Query(ctx, "SELECT title FROM iam.sample_doc ORDER BY title")
		if err != nil {
			return reports.Built{}, err
		}
		t := &doc.Table{ID: "docs", Caption: "Documents", Columns: []doc.Column{{Key: "title", Title: "Title", Type: doc.ColText}}}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return reports.Built{}, err
			}
			t.Rows = append(t.Rows, []string{s})
		}
		if err := rows.Err(); err != nil {
			return reports.Built{}, err
		}
		d := doc.Document{Metadata: doc.Metadata{Filters: map[string]string{}, LeftOut: map[string]int{"not_visible": 0}},
			Sections: []doc.Section{{Heading: "Documents", Level: 1, Blocks: []doc.Block{{Kind: doc.KindTable, Table: t}}}}}
		return reports.Built{Doc: d, Risks: len(t.Rows)}, nil
	}}

type reportEnv struct {
	*riskAPIEnv
	store    *memStore
	worker   *reports.Worker
	settings *settings.Client
}

var reportEnvs int

// reportAPI serves the reports API on the risk env's keys, with the fake
// kind, an insert-only River client, a memStore and the settings client;
// the report context key is registered (purpose report).
func reportAPI(t *testing.T, ra *riskAPIEnv) *reportEnv {
	t.Helper()
	ctx := context.Background()
	pool := ra.appPool()
	ra.mustOwner(fmt.Sprintf("SELECT authz.add_ctx_key('%s', decode('%s', 'hex'), 'report')", reportKey.ID, hex.EncodeToString(reportKey.Secret)))
	if err := (settings.DBRegistrar{DB: pool}).Register(ctx, "F-010", "1", settings.F010Defs()); err != nil {
		t.Fatal(err)
	}
	sc := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: pool}, Service: "risk"})
	if err := sc.Register(settings.F010Defs()...); err != nil {
		t.Fatal(err)
	}
	if err := sc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: reports.RiverSchema})
	if err != nil {
		t.Fatal(err)
	}
	store := newMemStore()
	kinds := map[string]reports.Kind{"register": fakeKind}
	api := &reportapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}), Kinds: kinds,
		Enqueue: reports.Enqueuer(rc), Store: store, Settings: sc}
	srv := httptest.NewServer(api.Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	rp := *ra
	rp.url = srv.URL
	reportEnvs++
	rp.n += 900000 + 100000*reportEnvs
	w := &reports.Worker{DB: pool, Key: reportKey, Store: store, Kinds: kinds, Marking: func() (string, error) { return sc.Enum(settings.KeyReportMarking, "") }}
	return &reportEnv{riskAPIEnv: &rp, store: store, worker: w, settings: sc}
}

// reportUsers: pub (Report Publisher and Risk Analyst at A), pubroot (both
// at the root), viewer (Executive Viewer at A: report.view only).
func reportUsers(ra *riskAPIEnv) {
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('pub@example.test', 'Pub'), ('pubroot@example.test', 'Pub Root'), ('viewer@example.test', 'Viewer')")
	for _, g := range [][3]string{{"pub", "Report Publisher", "A"}, {"pub", "Risk Analyst", "A"}, {"pubroot", "Report Publisher", "ENTERPRISE"},
		{"pubroot", "Risk Analyst", "ENTERPRISE"}, {"viewer", "Executive Viewer", "A"}} {
		ra.mustOwner(grant("platform", "user:"+g[0], g[1], g[2]))
	}
	ra.drain()
}

func (re *reportEnv) request(t *testing.T, user, bu string, body map[string]any) apiResp {
	t.Helper()
	b := map[string]any{"kind": "register", "bu_id": bu, "formats": []string{"json"}}
	for k, v := range body {
		b[k] = v
	}
	return re.call(t, "POST", user, "/api/v1/reports", b)
}

func (re *reportEnv) attempt(t *testing.T, id string, attempt int) error {
	t.Helper()
	return re.worker.Attempt(context.Background(), id, attempt, reports.Attempts)
}

// download fetches a file as user: the status, body and digest header.
func (re *reportEnv) download(t *testing.T, user, id, format string) (int, []byte, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", re.url+"/api/v1/reports/"+id+"/files/"+format, nil)
	p := re.principal(user)
	tok, err := authz.MintJWT(re.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
		DBContext: authz.DBContextHash(p.DBToken)}, "risk", 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Fair-DB-Context", p.DBToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header.Get("X-Fair-Digest")
}

func reportEvents(ra *riskAPIEnv, run, typ string) string {
	return ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '" + typ + "' AND body ->> 'target' = 'report_run:" + run + "'")
}

func TestReportRuns(t *testing.T) {
	ra := strideF003Fixture(t)
	seedPosture(t, ra.env)
	reportUsers(ra)
	re := reportAPI(t, ra)
	ctx := context.Background()

	// Who may (AC-15): report.export at the BU; 403 with report.view only;
	// 404 without either, or outside one's BUs.
	for name, c := range map[string]struct {
		user, bu string
		code     int
	}{
		"a viewer":            {"viewer", ra.bu["A"], 403},
		"outside their BUs":   {"pub", ra.bu["B"], 404},
		"a malformed BU":      {"pub", "nope", 400},
		"mallory (view at B)": {"mallory", ra.bu["A"], 404},
	} {
		if got := re.request(t, c.user, c.bu, nil); got.code != c.code {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	for name, body := range map[string]map[string]any{
		"an unknown kind":     {"kind": "heatmap"},
		"no formats":          {"formats": []string{}},
		"a repeated format":   {"formats": []string{"json", "json"}},
		"an unknown format":   {"formats": []string{"xlsx"}},
		"unknown parameters":  {"params": map[string]any{"colour": "red"}},
		"a kind without one":  {"kind": "portfolio"},
		"parameters not JSON": {"params": "x"},
	} {
		if got := re.request(t, "pub", ra.bu["A"], body); got.code != 422 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}

	// A request queues the run and its job, recorded (AC-15, AC-23); the
	// formats in their fixed order.
	got := re.request(t, "pub", ra.bu["A1"], map[string]any{"formats": []string{"json", "pdf", "csv"}})
	if got.code != 202 || got.body["state"] != "queued" || fmt.Sprint(got.body["formats"]) != "[pdf csv json]" || got.hdr.Get("Location") == "" {
		t.Fatalf("request: %d %s", got.code, got.raw)
	}
	run := got.body["id"].(string)
	if n := ra.adminQuery("SELECT count(*) FROM risk_river.river_job WHERE kind = 'report.generate' AND queue = 'report' AND args ->> 'run_id' = '" + run + "'"); n != "1" {
		t.Errorf("jobs: %s", n)
	}
	if got := reportEvents(ra, run, "report.requested"); got != "1" {
		t.Errorf("report.requested: %s", got)
	}
	if got := ra.adminQuery("SELECT body -> 'attributes' ->> 'formats' FROM audit.intake WHERE body ->> 'type' = 'report.requested' AND body ->> 'target' = 'report_run:" + run + "'"); got != "pdf csv json" {
		t.Errorf("formats attribute: %s", got)
	}
	// Listed and read by the requester only.
	if got := re.call(t, "GET", "pub", "/api/v1/reports", nil); got.code != 200 || len(got.body["reports"].([]any)) != 1 {
		t.Errorf("list: %d %s", got.code, got.raw)
	}
	for _, user := range []string{"pubroot", "viewer"} {
		if got := re.call(t, "GET", user, "/api/v1/reports/"+run, nil); got.code != 404 {
			t.Errorf("%s reads pub's run: %d", user, got.code)
		}
		if got := re.call(t, "GET", user, "/api/v1/reports", nil); got.code != 200 || len(got.body["reports"].([]any)) != 0 {
			t.Errorf("%s lists: %d %s", user, got.code, got.raw)
		}
	}
	// Not yet generated: no download.
	if code, _, _ := re.download(t, "pub", run, "json"); code != 409 {
		t.Errorf("download before generation: %d", code)
	}

	// Generation under pub's delegated context (AC-11): A and A1's
	// documents, not B's, not the restricted R's; files with digests
	// (AC-14).
	if err := re.attempt(t, run, 1); err != nil {
		t.Fatal(err)
	}
	got = re.call(t, "GET", "pub", "/api/v1/reports/"+run, nil)
	files, _ := got.body["files"].([]any)
	if got.body["state"] != "succeeded" || got.body["progress"] != 100.0 || len(files) != 3 || got.body["data_as_of"] == nil || got.body["risk_count"] != 2.0 {
		t.Fatalf("after generation: %s", got.raw)
	}
	digests := map[string]string{}
	for _, f := range files {
		m := f.(map[string]any)
		digests[m["format"].(string)] = m["sha256"].(string)
	}
	code, body, header := re.download(t, "pub", run, "json")
	sum := sha256.Sum256(body)
	if code != 200 || hex.EncodeToString(sum[:]) != digests["json"] || header != "sha256="+digests["json"] {
		t.Fatalf("download: %d %q %s", code, header, body)
	}
	var j struct {
		Format   string       `json:"format"`
		Metadata doc.Metadata `json:"metadata"`
		Sections []struct {
			Blocks []struct {
				Table struct {
					Rows [][]string `json:"rows"`
				} `json:"table"`
			} `json:"blocks"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(body, &j); err != nil {
		t.Fatal(err)
	}
	if j.Format != "fair.report.v1" || j.Metadata.RunID != run || j.Metadata.GeneratedBy != "Pub" || j.Metadata.Marking != "Confidential" ||
		j.Metadata.Currency != "USD" || j.Metadata.BU.ID != ra.bu["A1"] || j.Metadata.Title != "Sample register" {
		t.Errorf("metadata: %+v", j.Metadata)
	}
	if rows := fmt.Sprint(j.Sections[0].Blocks[0].Table.Rows); rows != "[[a] [a1]]" {
		t.Errorf("read as pub: %s, want a and a1", rows)
	}
	for f, want := range digests {
		key := ra.adminQuery("SELECT object_key || '|' || version_id FROM report.file WHERE run_id = '" + run + "' AND format = '" + f + "'")
		k, v, _ := strings.Cut(key, "|")
		b, err := re.store.read(objstore.Version{Key: k, VersionID: v})
		if s := sha256.Sum256(b); err != nil || hex.EncodeToString(s[:]) != want || !strings.HasSuffix(k, "/"+run+"/"+reports.FileName(f)) {
			t.Errorf("%s stored at %s: %v", f, k, err)
		}
	}
	if got := ra.adminQuery("SELECT body -> 'attributes' ->> 'files' FROM audit.intake WHERE body ->> 'type' = 'report.generated' AND body ->> 'target' = 'report_run:" + run + "'"); got !=
		"csv:"+digests["csv"]+" json:"+digests["json"]+" pdf:"+digests["pdf"] {
		t.Errorf("report.generated files: %s", got)
	}
	if got := ra.adminQuery("SELECT body ->> 'severity' || ' ' || (body -> 'attributes' ->> 'sha256') FROM audit.intake WHERE body ->> 'type' = 'report.downloaded' AND body ->> 'target' = 'report_run:" + run + "'"); got != "high "+digests["json"] {
		t.Errorf("report.downloaded: %s", got)
	}
	// Another user cannot download it (404); a missing format is 404.
	if code, _, _ := re.download(t, "pubroot", run, "json"); code != 404 {
		t.Errorf("pubroot downloads pub's file: %d", code)
	}
	if code, _, _ := re.download(t, "pub", run, "docx"); code != 404 {
		t.Errorf("an unknown format: %d", code)
	}
	// A second attempt of a finished run does nothing.
	if err := re.attempt(t, run, 2); err != nil || reportEvents(ra, run, "report.generated") != "1" {
		t.Errorf("a finished run again: %v", err)
	}

	// The reason rule over the scope's BUs (AC-16): A's subtree and the
	// root's hold the restricted R (the overlay's export.reason_required);
	// A1's does not, until A1 gets an override.
	for _, c := range [][2]string{{"pubroot", "ENTERPRISE"}, {"pub", "A"}} {
		if got := re.request(t, c[0], ra.bu[c[1]], nil); got.code != 400 || got.body["error"] != "reason_required" {
			t.Errorf("%s at %s without a reason: %d %s", c[0], c[1], got.code, got.raw)
		}
	}
	got = re.request(t, "pubroot", ra.bu["ENTERPRISE"], map[string]any{"reason": "Q4 committee pack"})
	if got.code != 202 {
		t.Fatalf("the root with a reason: %d %s", got.code, got.raw)
	}
	rootRun := got.body["id"].(string)
	if got := ra.adminQuery("SELECT body -> 'attributes' ->> 'reason' FROM audit.intake WHERE body ->> 'type' = 'report.requested' AND body ->> 'target' = 'report_run:" + rootRun + "'"); got != "Q4 committee pack" {
		t.Errorf("the reason recorded: %q", got)
	}
	if err := re.attempt(t, rootRun, 1); err != nil {
		t.Fatal(err)
	}
	if rows := ra.adminQuery("SELECT risk_count FROM report.run WHERE id = '" + rootRun + "'"); rows != "3" {
		t.Errorf("pubroot reads a, a1, b (not R's): %s", rows)
	}
	ra.admin(ra.db, `INSERT INTO posture.setting_value (key, bu_id, value, source, row_mac, mac_key_id)
		VALUES ('export.reason_required', '`+ra.bu["A1"]+`', 'true', 'profile', '\x`+strings.Repeat("00", 32)+`', 'k1')`)
	ra.admin(ra.db, "UPDATE posture.state SET version = version + 1")
	if err := re.settings.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := re.request(t, "pub", ra.bu["A1"], nil); got.code != 400 || got.body["error"] != "reason_required" {
		t.Errorf("A1 with its override: %d %s", got.code, got.raw)
	}
	ra.admin(ra.db, "DELETE FROM posture.setting_value WHERE key = 'export.reason_required' AND bu_id IS NOT NULL")
	ra.admin(ra.db, "UPDATE posture.state SET version = version + 1")
	if err := re.settings.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	// Limits (AC-18): at most 3 generating; a scope over 10,000 risks.
	var queued []string
	for i, params := range []map[string]any{{}, {"fail": true}, {}} {
		got := re.request(t, "pub", ra.bu["A1"], map[string]any{"params": params})
		if got.code != 202 {
			t.Fatalf("request %d: %d %s", i, got.code, got.raw)
		}
		queued = append(queued, got.body["id"].(string))
	}
	if got := re.request(t, "pub", ra.bu["A1"], nil); got.code != 409 || got.body["error"] != "too_many_running" || got.body["limit"] != 3.0 {
		t.Errorf("a fourth: %d %s", got.code, got.raw)
	}
	if err := ra.tx("pub", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT report.add_run('register', $1, '{}', '{json}', NULL, 10001)", ra.bu["A"])
		return err
	}); hintOf(err) != "limit_exceeded" {
		t.Errorf("over 10,000 risks: %v", err)
	}

	// A failing reader is retried, then fails the run (report.failed).
	if err := re.attempt(t, queued[0], 1); err != nil {
		t.Fatal(err)
	}
	failing := queued[1]
	for attempt := 1; attempt < reports.Attempts; attempt++ {
		if err := re.attempt(t, failing, attempt); err == nil {
			t.Fatalf("attempt %d of a failing read succeeded", attempt)
		}
	}
	if err := re.attempt(t, failing, reports.Attempts); err == nil {
		t.Error("the last attempt: no error for River (JobCancel)")
	}
	got = re.call(t, "GET", "pub", "/api/v1/reports/"+failing, nil)
	if got.body["state"] != "failed" || !strings.HasPrefix(fmt.Sprint(got.body["failure"]), "generation_failed") || got.body["attempts"] != 3.0 {
		t.Errorf("failed run: %s", got.raw)
	}
	if reportEvents(ra, failing, "report.failed") != "1" {
		t.Error("report.failed not recorded")
	}

	// Losing report.export (AC-17): downloads refused, a queued run fails
	// no_permission when it starts.
	ra.mustOwner(revoke("platform", "pub", "Report Publisher", "A"))
	ra.drain()
	if code, _, _ := re.download(t, "pub", run, "json"); code != 403 && code != 404 {
		t.Errorf("download after losing report.export: %d", code)
	}
	if got := reportEvents(ra, run, "report.downloaded"); got != "1" {
		t.Errorf("downloads recorded: %s", got)
	}
	if err := re.attempt(t, queued[2], 1); err != nil {
		t.Fatal(err)
	}
	if got := ra.adminQuery("SELECT state || ' ' || split_part(failure, ':', 1) FROM report.run WHERE id = '" + queued[2] + "'"); got != "failed no_permission" {
		t.Errorf("a run without the permission: %s", got)
	}
	if got := ra.adminQuery("SELECT body -> 'attributes' ->> 'failure' FROM audit.intake WHERE body ->> 'type' = 'report.failed' AND body ->> 'target' = 'report_run:" + queued[2] + "'"); got != "no_permission" {
		t.Errorf("report.failed: %q", got)
	}
}
