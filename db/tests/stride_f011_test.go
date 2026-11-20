package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-20 (design §7): the STRIDE suite for integrations. Each test
// attacks one threat row; TestSTRIDECatalog ties the rows to these tests
// and to the feature tests that also hold them. Fixtures: reviewAllAPI
// (the risk fixture's ENTERPRISE -> {A -> {A1, R (restricted) -> R1}, B};
// "platform" Platform Admin at the root, "aud" Auditor at the root, "rman"
// integration.manage inside R, "pusher" integration.push at A, "analyst"
// Risk Analyst at A, "mallory" Risk Analyst at B) and integrateAPI.

// strideIntegration adds a push integration of kind at bu as platform (or
// rman inside R).
func strideIntegration(t *testing.T, im *importEnv, user, bu, name, kind string) string {
	t.Helper()
	var id string
	if err := im.ie.as(user, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT integration.add($1, $2, $3, 'push', '{}', NULL, NULL, false)::text", im.bu[bu], name, kind).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// E: an integration writes outside its scope or kind.
func TestSTRIDEF011Scope(t *testing.T) {
	im := reviewAllAPI(t)
	a := strideIntegration(t, im, "platform", "A", "CMDB at A", "assets")
	b := strideIntegration(t, im, "platform", "B", "CMDB at B", "assets")
	// Records naming a BU outside the subtree, the restricted R below it,
	// or another kind are refused; the rest are taken.
	got := im.send(t, "pusher", "/api/v1/imports/"+a+"/batches", "application/json", batchOf(asset("s-1", "A1", "Inside"), asset("s-2", "B", "Outside"),
		asset("s-3", "R", "Restricted"), `{"kind": "risk", "external_id": "s-4", "bu": "A", "title": "A risk"}`))
	if got.code != 201 || counts(got)["valid"] != 1.0 || counts(got)["refused"] != 3.0 {
		t.Fatalf("scope: %d %s", got.code, got.raw)
	}
	var where []string
	for _, r := range got.body["refused"].([]any) {
		m := r.(map[string]any)
		where = append(where, fmt.Sprint(m["n"], m["pointer"]))
	}
	if strings.Join(where, ",") != "2/bu,3/bu,4/kind" {
		t.Errorf("refused at %v", where)
	}
	// A pusher at A cannot send to B's integration.
	if got := im.send(t, "pusher", "/api/v1/imports/"+b+"/batches", "application/json", batchOf(asset("s-5", "B", "x"))); got.code != 404 {
		t.Errorf("a push to another BU's integration: %d", got.code)
	}
	// Inside R only its own managers create integrations.
	if err := im.ie.exec("platform", "SELECT integration.add($1, 'x', 'assets', 'push', '{}', NULL, NULL, false)", im.bu["R"]); pgState(err) != "P0002" {
		t.Errorf("platform creates inside R: %v", err)
	}
	// Accepting runs under the reviewer's own permissions: mallory (B) and
	// the pusher (no library.edit) cannot accept A's proposal.
	p := im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = 's-1' AND state = 'pending'")
	for user, code := range map[string]int{"mallory": 404, "pusher": 404} {
		if got := im.call(t, "POST", user, "/api/v1/proposals/"+p+"/accept", map[string]any{}); got.code != code {
			t.Errorf("%s accepts: %d %s", user, got.code, got.raw)
		}
	}
	if got := im.adminQuery("SELECT count(*) FROM risk.library_entry e JOIN integration.link l ON l.target_id = e.id"); got != "0" {
		t.Errorf("%s records written without a reviewer", got)
	}
}

// T, E: imported data changes an analysis silently.
func TestSTRIDEF011Proposals(t *testing.T) {
	im := reviewAllAPI(t)
	a := strideIntegration(t, im, "platform", "A", "CMDB", "assets")
	entries := im.adminQuery("SELECT count(*) FROM risk.library_entry")
	versions := im.adminQuery("SELECT count(*) FROM risk.library_version")
	push := func(body string) {
		t.Helper()
		if got := im.send(t, "pusher", "/api/v1/imports/"+a+"/batches", "application/json", body); got.code != 201 {
			t.Fatalf("push: %d %s", got.code, got.raw)
		}
	}
	push(batchOf(asset("p-1", "A", "Claims platform")))
	if im.adminQuery("SELECT count(*) FROM risk.library_entry") != entries || im.adminQuery("SELECT count(*) FROM risk.library_version") != versions {
		t.Fatal("a push wrote the library")
	}
	p := im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = 'p-1' AND state = 'pending'")
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+p+"/accept", map[string]any{}); got.code != 200 {
		t.Fatalf("accept: %d %s", got.code, got.raw)
	}
	entry := im.adminQuery("SELECT target_id FROM integration.link WHERE external_id = 'p-1'")
	// A change from the source is a proposal; the entry stays at version 1.
	push(batchOf(`{"kind": "asset", "external_id": "p-1", "bu": "A", "name": "Claims platform", "asset_type": "application",
		"value": {"min": "1000", "ml": "2000", "max": "9000", "confidence": "0.8", "basis": "replacement cost"}}`))
	if got := im.adminQuery("SELECT current_version FROM risk.library_entry WHERE id = '" + entry + "'"); got != "1" {
		t.Errorf("a source change moved the entry to version %s", got)
	}
	p = im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = 'p-1' AND state = 'pending'")
	// The reviewer accepts against the version they reviewed; a change
	// since is refused.
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+p+"/accept", map[string]any{"expected_version": 7}); got.code != 409 || got.body["error"] != "stale_version" {
		t.Errorf("a stale accept: %d %s", got.code, got.raw)
	}
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+p+"/accept", map[string]any{}); got.code != 400 {
		t.Errorf("an update accepted without expected_version: %d %s", got.code, got.raw)
	}
	if got := im.adminQuery("SELECT current_version FROM risk.library_entry WHERE id = '" + entry + "'"); got != "1" {
		t.Errorf("refused accepts moved the entry to version %s", got)
	}
	// A rejected change is not proposed again.
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+p+"/reject", map[string]any{"reason": "The value is wrong"}); got.code != 200 {
		t.Fatalf("reject: %d %s", got.code, got.raw)
	}
	push(batchOf(`{"kind": "asset", "external_id": "p-1", "bu": "A", "name": "Claims platform", "asset_type": "application",
		"value": {"min": "1000", "ml": "2000", "max": "9000", "confidence": "0.8", "basis": "replacement cost"}}`))
	if got := im.adminQuery("SELECT count(*) FROM integration.proposal WHERE external_id = 'p-1' AND state = 'pending'"); got != "0" {
		t.Errorf("a rejected change proposed again (%s)", got)
	}
}

// I, E: a connector is used to reach internal systems (SSRF).
func TestSTRIDEF011Destinations(t *testing.T) {
	ia := integrateAPI(t)
	sa := ia.adminQuery("SELECT id FROM iam.service_account WHERE name = 'sa-root'")
	mapping := map[string]any{"columns": map[string]any{"/id": "external_id", "/name": "name"}}
	for name, source := range map[string]string{ // #nosec G101 -- a test URL, not a credential
		"cloud metadata":         "https://169.254.169.254/latest/meta-data",
		"loopback":               "https://127.0.0.1/admin",
		"the cluster's ranges":   "https://inside.example.test/",
		"a host off the list":    "https://other.example.test/",
		"an IPv6 loopback":       "https://[::1]/",
		"a user in the URL":      "https://u:p@cmdb.example.test/",
		"plain HTTP":             "http://cmdb.example.test/",
		"an unspecified address": "https://0.0.0.0/",
	} {
		got := ia.call(t, "POST", "platform", "/api/v1/integrations", map[string]any{"bu_id": ia.bu["A"], "name": "SSRF " + name, "kind": "assets",
			"delivery": "connector", "service_account_id": sa, "mapping": mapping,
			"connector": map[string]any{"type": "http_json", "source": source, "schedule_minutes": 60}})
		if got.code != 422 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	if got := ia.adminQuery("SELECT count(*) FROM integration.integration WHERE name LIKE 'SSRF%'"); got != "0" {
		t.Errorf("%s refused sources saved", got)
	}
	if got := ia.events(t, "integration.destination_refused", ""); got == "0" {
		t.Error("no refusal recorded")
	}
	// Nothing in the integrate service's role reaches a table directly.
	if _, err := ia.ie.pool.Exec(context.Background(), "SELECT * FROM integration.integration"); pgState(err) != "42501" {
		t.Errorf("app_integrate reads integrations directly: %v", err)
	}
}

// I: credentials disclosed.
func TestSTRIDEF011Secrets(t *testing.T) {
	ia := integrateAPI(t)
	sa := ia.adminQuery("SELECT id FROM iam.service_account WHERE name = 'sa-root'")
	got := ia.call(t, "POST", "platform", "/api/v1/integrations", map[string]any{"bu_id": ia.bu["A"], "name": "CMDB", "kind": "assets",
		"delivery": "connector", "service_account_id": sa, "mapping": map[string]any{"columns": map[string]any{"/id": "external_id", "/name": "name"}},
		"connector": map[string]any{"type": "http_json", "source": "https://cmdb.example.test/apps", "schedule_minutes": 60}})
	if got.code != 201 {
		t.Fatalf("create: %d %s", got.code, got.raw)
	}
	id := got.body["id"].(string)
	const secret = "stride-secret-7f3a91"
	for purpose, body := range map[string]map[string]any{"source": {"username": "svc", "password": secret}, "client": {"client_secret": secret + "-c"}} {
		// Replayed with the same key, the answer is the stored one: no secret.
		got := ia.call(t, "PUT", "platform", "/api/v1/integrations/"+id+"/credentials/"+purpose, body, "stride-cred-"+purpose)
		again := ia.call(t, "PUT", "platform", "/api/v1/integrations/"+id+"/credentials/"+purpose, body, "stride-cred-"+purpose)
		for _, r := range []apiResp{got, again} {
			if r.code != 200 || strings.Contains(r.raw, secret) {
				t.Errorf("set %s: %d %s", purpose, r.code, r.raw)
			}
		}
	}
	for _, path := range []string{"/api/v1/integrations/" + id, "/api/v1/integrations", "/api/v1/integrations/" + id + "/runs"} {
		for _, user := range []string{"platform", "aud"} {
			if got := ia.call(t, "GET", user, path, nil); strings.Contains(got.raw, secret) {
				t.Errorf("%s as %s answers the secret", path, user)
			}
		}
	}
	for _, q := range []string{
		"SELECT count(*) FROM integration.secret WHERE position(convert_to('" + secret + "', 'UTF8') IN ciphertext) > 0",
		"SELECT count(*) FROM audit.intake WHERE body::text LIKE '%" + secret + "%'",
		"SELECT count(*) FROM iam.idempotency WHERE convert_from(body, 'UTF8') LIKE '%" + secret + "%'",
	} {
		if got := ia.adminQuery(q); got != "0" {
			t.Errorf("%s: %s", q, got)
		}
	}
	// Only the integrate service opens credentials, and only to run.
	rw := ia.appPool()
	if _, err := rw.Exec(context.Background(), "SELECT * FROM integration.secret_for_run($1, 'source')", id); pgState(err) != "42501" {
		t.Errorf("app_rw reads a sealed credential: %v", err)
	}
	if err := authz.WithDBContext(context.Background(), ia.ie.pool, ia.principal("platform").DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "SELECT * FROM integration.secret")
		return err
	}); pgState(err) != "42501" {
		t.Errorf("app_integrate reads the secret table: %v", err)
	}
}

// T: injection through imported values.
func TestSTRIDEF011Injection(t *testing.T) {
	im := reviewAllAPI(t)
	a := strideIntegration(t, im, "platform", "A", "CMDB", "assets")
	values := []string{`=HYPERLINK("https://evil.example","x")`, `<script>alert(1)</script>`, `'; DROP TABLE risk.library_entry; --`, `{{7*7}} ${7*7}`}
	var recs []string
	for i, v := range values {
		recs = append(recs, fmt.Sprintf(`{"kind": "asset", "external_id": "i-%d", "bu": "A", "name": %q, "asset_type": "application"}`, i, v))
	}
	recs = append(recs,
		`{"kind": "asset", "external_id": "i-9", "bu": "A", "name": "x", "asset_type": "application", "eval": "1"}`,
		`{"kind": "asset", "external_id": "i-10", "bu": "A", "name": "line\u0000break", "asset_type": "application"}`)
	got := im.send(t, "pusher", "/api/v1/imports/"+a+"/batches", "application/json", batchOf(recs...))
	if got.code != 201 || counts(got)["valid"] != float64(len(values)) || counts(got)["refused"] != 2.0 {
		t.Fatalf("batch: %d %s", got.code, got.raw)
	}
	// Each value is kept as text, exactly, and written as text on accept.
	for i, v := range values {
		p := im.adminQuery(fmt.Sprintf("SELECT id FROM integration.proposal WHERE external_id = 'i-%d' AND state = 'pending'", i))
		view := im.call(t, "GET", "analyst", "/api/v1/proposals/"+p, nil)
		if view.code != 200 || view.body["proposed"].(map[string]any)["name"] != v {
			t.Errorf("value %d: %d %s", i, view.code, view.raw)
		}
		if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+p+"/accept", map[string]any{}); got.code != 200 {
			t.Fatalf("accept %d: %d %s", i, got.code, got.raw)
		}
	}
	if got := im.adminQuery("SELECT count(*) FROM risk.library_entry"); got == "0" {
		t.Error("the library table is gone")
	}
	// A CSV mapping has no expressions: a formula is a value, not code.
	csvInt := strideIntegration(t, im, "platform", "A", "CSV", "assets")
	if err := im.ie.exec("platform", `SELECT integration.change($1, 1, 'CSV', '{"columns": {"ID": "external_id", "Name": "name"}, "defaults": {"asset_type": "application", "bu": "A"}}', NULL, NULL, false)`, csvInt); err != nil {
		t.Fatal(err)
	}
	got = im.send(t, "platform", "/api/v1/imports/"+csvInt+"/batches", "text/csv", "ID,Name\nc-1,\"=1+1\"\n")
	if got.code != 201 || counts(got)["valid"] != 1.0 {
		t.Fatalf("CSV: %d %s", got.code, got.raw)
	}
	if v := im.adminQuery("SELECT data ->> 'name' FROM integration.record WHERE external_id = 'c-1'"); v != "=1+1" {
		t.Errorf("a CSV formula staged as %q", v)
	}
}

// I: loss events or proposals leak across BUs.
func TestSTRIDEF011Visibility(t *testing.T) {
	im := reviewAllAPI(t)
	b := strideIntegration(t, im, "platform", "B", "CMDB at B", "assets")
	r := strideIntegration(t, im, "rman", "R", "Incidents in R", "loss_events")
	im.mustOwner(grant("platform", "user:pusher", "Integration Pusher", "B"))
	im.drain()
	if got := im.send(t, "pusher", "/api/v1/imports/"+b+"/batches", "application/json", batchOf(asset("v-1", "B", "B's application"))); got.code != 201 {
		t.Fatalf("push at B: %d %s", got.code, got.raw)
	}
	if got := im.send(t, "rman", "/api/v1/imports/"+r+"/batches", "application/json", batchOf(
		`{"kind": "loss_event", "external_id": "le-1", "bu": "R", "occurred_on": "2026-03-01", "event_type": "fraud", "amounts": {"response": "5000"}}`)); got.code != 201 {
		t.Fatalf("push in R: %d %s", got.code, got.raw)
	}
	p := im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = 'v-1'")
	// The analyst at A sees neither B's proposal nor R's events.
	if got := im.call(t, "GET", "analyst", "/api/v1/proposals", nil); strings.Contains(got.raw, p) {
		t.Error("A's analyst lists B's proposal")
	}
	if got := im.call(t, "GET", "analyst", "/api/v1/proposals/"+p, nil); got.code != 404 {
		t.Errorf("A's analyst reads B's proposal: %d", got.code)
	}
	ev := im.adminQuery("SELECT id FROM integration.loss_event WHERE external_id = 'le-1'")
	for _, user := range []string{"analyst", "mallory", "platform"} {
		if got := im.call(t, "GET", user, "/api/v1/loss-events", nil); strings.Contains(got.raw, ev) {
			t.Errorf("%s lists R's loss event", user)
		}
		if got := im.call(t, "GET", user, "/api/v1/loss-events/"+ev, nil); got.code != 404 {
			t.Errorf("%s reads R's loss event: %d", user, got.code)
		}
	}
	// B's reviewer sees B's proposal.
	if got := im.call(t, "GET", "mallory", "/api/v1/proposals/"+p, nil); got.code != 200 {
		t.Errorf("B's analyst reads B's proposal: %d", got.code)
	}
}

// S: a forged batch or a replayed upload.
func TestSTRIDEF011Batches(t *testing.T) {
	im := reviewAllAPI(t)
	a := strideIntegration(t, im, "platform", "A", "CMDB", "assets")
	path := im.url + "/api/v1/imports/" + a + "/batches"
	body := batchOf(asset("f-1", "A", "x"))
	// No token, or a DB context without a matching token.
	for name, set := range map[string]func(*http.Request){
		"no token":          func(*http.Request) {},
		"a context, no JWT": func(r *http.Request) { r.Header.Set("X-Fair-DB-Context", im.principal("pusher").DBToken) },
		"a forged JWT":      func(r *http.Request) { r.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.") },
	} {
		req, _ := http.NewRequestWithContext(context.Background(), "POST", path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "stride-forged-"+strings.ReplaceAll(name, " ", "-"))
		set(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	// A replayed request (the same Idempotency-Key) is answered once: one run.
	runs := im.adminQuery("SELECT count(*) FROM integration.run")
	first := im.send(t, "pusher", "/api/v1/imports/"+a+"/batches", "application/json", body)
	im.n-- // send the same key again
	again := im.send(t, "pusher", "/api/v1/imports/"+a+"/batches", "application/json", body)
	if first.code != 201 || again.code != 201 || first.body["run"].(map[string]any)["id"] != again.body["run"].(map[string]any)["id"] {
		t.Errorf("a replay: %d / %d", first.code, again.code)
	}
	if got := im.adminQuery("SELECT count(*) FROM integration.run"); got == runs || got != fmt.Sprint(atoiOr(runs)+1) {
		t.Errorf("runs %s -> %s", runs, got)
	}
	// The same key with another body is refused.
	im.n--
	if got := im.send(t, "pusher", "/api/v1/imports/"+a+"/batches", "application/json", batchOf(asset("f-2", "A", "y"))); got.code < 400 {
		t.Errorf("a key reused for another body: %d", got.code)
	}
	// External IDs are scoped to their integration: the same ID elsewhere
	// is a new record, never a match.
	other := strideIntegration(t, im, "platform", "A", "Another CMDB", "assets")
	if got := im.send(t, "pusher", "/api/v1/imports/"+other+"/batches", "application/json", body); got.code != 201 || counts(got)["new"] != 1.0 {
		t.Errorf("the same external ID in another integration: %d %s", got.code, got.raw)
	}
}

func atoiOr(s string) int {
	n := 0
	_, _ = fmt.Sscan(s, &n)
	return n
}

// R: changes not attributable.
func TestIntegrationAuditEvents(t *testing.T) {
	im := reviewAllAPI(t)
	a := strideIntegration(t, im, "platform", "A", "CMDB", "assets")
	if got := im.send(t, "pusher", "/api/v1/imports/"+a+"/batches", "application/json", batchOf(asset("e-1", "A", "One"), asset("e-2", "A", "Two"))); got.code != 201 {
		t.Fatal(got.raw)
	}
	p1 := im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = 'e-1'")
	p2 := im.adminQuery("SELECT id FROM integration.proposal WHERE external_id = 'e-2'")
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+p1+"/accept", map[string]any{}); got.code != 200 {
		t.Fatal(got.raw)
	}
	if got := im.call(t, "POST", "analyst", "/api/v1/proposals/"+p2+"/reject", map[string]any{"reason": "Not ours"}); got.code != 200 {
		t.Fatal(got.raw)
	}
	if err := im.ie.exec("platform", "SELECT integration.remove($1, 'Retired')", a); err != nil {
		t.Fatal(err)
	}
	for typ, actor := range map[string]string{
		"integration.created": "platform", "integration.run": "pusher", "integration.proposal_accepted": "analyst",
		"integration.proposal_rejected": "analyst", "library.created": "analyst", "integration.deleted": "platform",
	} {
		got := im.adminQuery(fmt.Sprintf(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '%s' AND body ->> 'actor' = (%s)::text
			AND body ->> 'bu_id' = '%s'`, typ, uid(actor), im.bu["A"]))
		if got == "0" {
			t.Errorf("no %s by %s at A", typ, actor)
		}
	}
	if got := im.adminQuery("SELECT body -> 'attributes' ->> 'reason' FROM audit.intake WHERE body ->> 'type' = 'integration.proposal_rejected'"); got != "Not ours" {
		t.Errorf("the rejection's reason: %q", got)
	}
}

// D: huge or frequent batches exhaust the service.
func TestSTRIDEF011Limits(t *testing.T) {
	im := reviewAllAPI(t)
	a := strideIntegration(t, im, "platform", "A", "CMDB", "assets")
	path := "/api/v1/imports/" + a + "/batches"
	// More than 10,000 records is refused whole, before any record is staged.
	recs := make([]string, 10_001)
	for i := range recs {
		recs[i] = asset(fmt.Sprintf("l-%d", i), "A", "x")
	}
	staged := im.adminQuery("SELECT count(*) FROM integration.record")
	if got := im.send(t, "pusher", path, "application/json", batchOf(recs...)); got.code != 422 {
		t.Errorf("10,001 records: %d %s", got.code, got.raw[:min(len(got.raw), 200)])
	}
	if got := im.adminQuery("SELECT count(*) FROM integration.record"); got != staged {
		t.Errorf("records staged from a refused batch: %s -> %s", staged, got)
	}
	// A body over 20 MiB is refused unread.
	if got := im.send(t, "pusher", path, "application/json", strings.Repeat(" ", 20<<20+1)); got.code != 413 {
		t.Errorf("a 20 MiB body: %d", got.code)
	}
	// One run at a time per integration.
	im.mustOwner(fmt.Sprintf("INSERT INTO integration.run (integration_id, trigger, actor) VALUES ('%s', 'push', %s)", a, uid("pusher")))
	if got := im.send(t, "pusher", path, "application/json", batchOf(asset("l-x", "A", "x"))); got.code != 409 || got.body["error"] != "run_in_progress" {
		t.Errorf("a second run at once: %d %s", got.code, got.raw)
	}
	im.mustOwner(fmt.Sprintf("UPDATE integration.run SET state = 'failed', failure = 'test', finished_at = now() WHERE integration_id = '%s' AND state = 'running'", a))
	// At most 12 runs an hour.
	im.mustOwner(fmt.Sprintf(`INSERT INTO integration.run (integration_id, trigger, actor, state, finished_at)
		SELECT '%s', 'push', %s, 'succeeded', now() FROM generate_series(1, 11)`, a, uid("pusher")))
	if got := im.send(t, "pusher", path, "application/json", batchOf(asset("l-y", "A", "x"))); got.code != 429 {
		t.Errorf("a 13th run in the hour: %d %s", got.code, got.raw)
	}
	// At most 50 integrations (PF032).
	for i := 2; i <= 50; i++ {
		strideIntegration(t, im, "platform", "A", fmt.Sprintf("Integration %d", i), "assets")
	}
	if err := im.ie.exec("platform", "SELECT integration.add($1, 'One too many', 'assets', 'push', '{}', NULL, NULL, false)", im.bu["A"]); pgState(err) != "PF032/too_many_integrations" {
		t.Errorf("a 51st integration: %v", pgState(err))
	}
}
