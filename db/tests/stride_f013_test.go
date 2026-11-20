package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-013 T-12 (design §7): the STRIDE suite for control frameworks. Each test
// attacks one threat row; TestSTRIDECatalog ties the rows to these tests and
// to the feature tests that also hold them. Fixture: frameworkAPI (the risk
// fixture's ENTERPRISE -> {A -> {A1, R (restricted)}, B}; "platform"
// Platform Admin at the root, "analyst" Risk Analyst at A, "mallory" Risk
// Analyst at B, "erin" Executive Viewer at A).

func strideFrameworks(t *testing.T) *frameworkEnv {
	t.Helper()
	fe := frameworkAPI(t)
	fe.mustOwner(grant("platform", "user:buadmin", "BU Admin", "A")) // a role, but no framework or control permission
	fe.drain()
	return fe
}

// T: a malicious catalog or profile.
func TestSTRIDEF013Imports(t *testing.T) {
	fe := strideFrameworks(t)
	// Links and back-matter resources are never followed.
	var hits atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer trap.Close()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "framework", "testdata", "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat map[string]any
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	c := cat["catalog"].(map[string]any)
	c["back-matter"] = map[string]any{"resources": []any{map[string]any{"uuid": "8d3b2a1c-5e6f-4a7b-9c8d-0e1f2a3b4c5d", "title": "Remote",
		"rlinks": []any{map[string]any{"href": trap.URL + "/resource.xml"}}}}}
	c["metadata"].(map[string]any)["links"] = []any{map[string]any{"href": trap.URL + "/linked", "rel": "reference"}}
	linked, _ := json.Marshal(cat)
	_, imp := fe.upload(t, "platform", "kind=catalog&family=linked&family_title=Linked", "application/json", linked)
	if imp["state"] != "succeeded" || hits.Load() != 0 {
		t.Errorf("a catalog with links: %v, %d fetches", imp["state"], hits.Load())
	}
	// Not OSCAL, another model, deep nesting, an XML document: refused
	// whole, by pointer, nothing recorded.
	families := fe.adminQuery("SELECT count(*) FROM framework.version")
	for name, body := range map[string]string{
		"not OSCAL":      `{"catalog": {"uuid": "x"}}`,
		"a profile":      strings.Replace(string(linked), `"catalog"`, `"profile"`, 1),
		"deep nesting":   `{"catalog": ` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`,
		"an entity bomb": `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><catalog>&lol;</catalog>`,
	} {
		got, imp := fe.upload(t, "platform", "kind=catalog&family=bad&family_title=Bad", "application/json", []byte(body))
		if got.code != 202 || imp["state"] != "refused" {
			t.Errorf("%s: %d %v", name, got.code, imp)
		}
	}
	if fe.adminQuery("SELECT count(*) FROM framework.version") != families {
		t.Error("a refused import recorded a version")
	}
	// XML is not taken at all; over 50 MiB is refused before work.
	if got, _ := fe.upload(t, "platform", "kind=catalog&family=x&family_title=X", "application/xml", []byte("<catalog/>")); got.code != 415 {
		t.Errorf("XML: %d", got.code)
	}
	if got, _ := fe.upload(t, "platform", "kind=simple", "application/json", make([]byte, 50<<20+1)); got.code != 413 {
		t.Errorf("over 50 MiB: %d", got.code)
	}
}

// T, E: frameworks changed by someone without framework.manage, or shipped
// content altered.
func TestSTRIDEF013Frameworks(t *testing.T) {
	fe := strideFrameworks(t)
	v := fe.adminQuery("SELECT id FROM framework.version WHERE family = 'nist-800-53' AND label = '5.2.0'")
	b := fe.adminQuery("SELECT id FROM framework.baseline WHERE version_id = '" + v + "' AND key = 'nist-low'")
	x := fe.adminQuery("SELECT id FROM framework.crosswalk LIMIT 1")
	simple := `{"format": "fair.framework.v1", "family": {"key": "mine", "title": "Mine"}, "version": {"label": "1", "title": "Mine 1"},
		"requirements": [{"identifier": "M-1", "title": "One"}]}`
	for user, code := range map[string]int{"analyst": 403, "erin": 403, "mallory": 403, "buadmin": 404} {
		if got, _ := fe.upload(t, user, "kind=simple", "application/json", []byte(simple)); got.code != code {
			t.Errorf("%s imports: %d", user, got.code)
		}
		for _, p := range []string{"/versions/" + v, "/baselines/" + b, "/crosswalks/" + x} {
			if got := fe.call(t, "POST", user, "/api/v1/frameworks"+p+"/retire", map[string]any{"reason": "x"}); got.code != code {
				t.Errorf("%s retires %s: %d", user, p, got.code)
			}
		}
	}
	// The application role reaches the tables only through functions.
	for _, sql := range []string{
		"UPDATE framework.version SET title = 'x'", "DELETE FROM framework.requirement", "INSERT INTO framework.family (key, title) VALUES ('x', 'x')",
		"UPDATE framework.baseline SET selected = '{}'", "DELETE FROM framework.relationship", "SELECT count(*) FROM framework.requirement",
		"INSERT INTO framework.control_mapping (control_id, control_version, bu_id, requirement_id, strength) SELECT id, 1, bu_id, '" + v + "', 'full' FROM risk.control LIMIT 1",
	} {
		err := authz.WithDBContext(context.Background(), fe.appPool(), fe.principal("platform").DBToken, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), sql)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "42501") {
			t.Errorf("app_rw %q: %v", sql, err)
		}
	}
	// Imported rows are immutable even to their owner role; a retirement is
	// the only change, once.
	for _, sql := range []string{
		"UPDATE framework.requirement SET title = 'Changed' WHERE version_id = '" + v + "' AND identifier = 'ac-2'",
		"UPDATE framework.version SET sha256 = repeat('0', 64) WHERE id = '" + v + "'",
		"DELETE FROM framework.baseline WHERE id = '" + b + "'",
	} {
		if err := fe.ownerErr(sql); err == nil {
			t.Errorf("owner %q: no error", sql)
		}
	}
	// Shipped content: a different file under a shipped version is refused.
	if err := fe.ownerErr(`SELECT framework.sync_shipped(jsonb_build_object('format', 'fair.shipped-frameworks.v1', 'versions', jsonb_build_array(jsonb_build_object(
		'family', jsonb_build_object('key', 'nist-800-53', 'title', 'x'), 'label', '5.2.0', 'title', 'x', 'format', 'oscal',
		'sha256', repeat('a', 64), 'requirements', '[]'::jsonb))))`); err == nil || !strings.Contains(err.Error(), "shipped") {
		t.Errorf("an altered shipped version: %v", err)
	}
}

// I: coverage leaks controls of business units the viewer cannot see.
func TestSTRIDEF013Coverage(t *testing.T) {
	fe := strideFrameworks(t)
	ra := fe.risk
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('ranalyst@example.test', 'Ranalyst')")
	ra.mustOwner(grant("platform", "user:ranalyst", "Risk Analyst", "R"))
	fe.drain()
	v := fe.adminQuery("SELECT id FROM framework.version WHERE family = 'nist-800-53' AND label = '5.2.0'")
	v511 := fe.adminQuery("SELECT id FROM framework.version WHERE family = 'nist-800-53' AND label = '5.1.1+u4'")
	v171 := fe.adminQuery("SELECT id FROM framework.version WHERE family = 'nist-800-171'")
	mk := func(user, bu, name, version, req string) {
		t.Helper()
		d := modeltest.Control()
		d["name"] = name
		fam := "nist-800-53"
		if version == "Rev 3 (1.1.0)" {
			fam = "nist-800-171"
		}
		d["mappings"] = []any{mapping(fam, version, req, "full")}
		d["implementation"] = map[string]any{"status": "in_place", "assessed_on": "2026-11-01"}
		if got := ra.call(t, "POST", user, "/api/v1/controls", map[string]any{"bu_id": ra.bu[bu], "document": d, "change_note": "x"}); got.code != 201 {
			t.Fatalf("%s: %d %s", name, got.code, got.raw)
		}
	}
	mk("mallory", "B", "B secret control", "5.2.0", "ac-2")
	mk("ranalyst", "R", "R secret control", "5.2.0", "ac-2")
	// A control of B mapped to an 800-171 requirement the shipped crosswalk
	// relates to 800-53 5.1.1: not derived for A's analyst.
	req171 := fe.adminQuery(`SELECT s.identifier FROM framework.relationship r JOIN framework.requirement s ON s.id = r.source_id
		WHERE s.version_id = '` + v171 + `' ORDER BY s.ord LIMIT 1`)
	mk("mallory", "B", "B crosswalked control", "Rev 3 (1.1.0)", req171)
	ra.mustOwner("UPDATE iam.bu SET rollup_mode = 'aggregate' WHERE code = 'R'")
	fe.drain()
	for _, path := range []string{
		"/api/v1/frameworks/versions/" + v + "/coverage?bu=" + ra.bu["A"],
		"/api/v1/frameworks/versions/" + v + "/coverage?bu=" + ra.bu["ENTERPRISE"],
		"/api/v1/frameworks/versions/" + v511 + "/coverage?bu=" + ra.bu["A"],
		"/api/v1/frameworks/versions/" + v + "/coverage.json?bu=" + ra.bu["A"],
		"/api/v1/frameworks/versions/" + v + "/coverage.csv?bu=" + ra.bu["A"],
	} {
		got := fe.call(t, "GET", "analyst", path, nil)
		if strings.Contains(path, "ENTERPRISE") || strings.Contains(path, ra.bu["ENTERPRISE"]) {
			if got.code != 403 {
				t.Errorf("A's analyst at the root: %d", got.code)
			}
			continue
		}
		if got.code != 200 || strings.Contains(got.raw, "secret control") || strings.Contains(got.raw, "crosswalked control") {
			t.Errorf("%s: %d leaks: %.300s", path, got.code, got.raw)
		}
	}
	// The projection itself, as app_rw: only visible rows.
	var n int
	if err := authz.WithDBContext(context.Background(), fe.appPool(), fe.principal("analyst").DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM framework.control_mapping WHERE bu_id <> ALL ($1::uuid[])",
			[]string{ra.bu["A"], ra.bu["A1"], ra.bu["ENTERPRISE"]}).Scan(&n)
	}); err != nil || n != 0 {
		t.Errorf("rows outside A's scope: %d %v", n, err)
	}
	// R's analyst sees their own; requirement pages do not leak either.
	if got := fe.call(t, "GET", "ranalyst", "/api/v1/frameworks/versions/"+v+"/coverage?bu="+ra.bu["R"], nil); !strings.Contains(got.raw, "R secret control") {
		t.Errorf("R's analyst: %.300s", got.raw)
	}
	ac2 := fe.adminQuery("SELECT id FROM framework.requirement WHERE version_id = '" + v + "' AND identifier = 'ac-2'")
	if got := fe.call(t, "GET", "analyst", "/api/v1/frameworks/requirements/"+ac2+"/scenarios", nil); strings.Contains(got.raw, "secret control") {
		t.Errorf("requirement scenarios leak: %.300s", got.raw)
	}
}

// E: a mapping or proposal changes an analysis.
func TestSTRIDEF013Proposals(t *testing.T) {
	fe := strideFrameworks(t)
	ra := fe.risk
	ra.setCurrency(t, "USD")
	doc := ra.scenarioDoc(t) // pins a control at A, version 1
	got := ra.call(t, "POST", "analyst", "/api/v1/scenarios", map[string]any{"bu_id": ra.bu["A"], "document": doc, "change_note": "v1"})
	if got.code != 201 {
		t.Fatal(got.raw)
	}
	sid := got.body["id"].(string)
	ctl := doc["control_sets"].([]any)[0].(map[string]any)["controls"].([]any)[0].(map[string]any)["id"].(string)
	pins := func() string {
		return fe.adminQuery("SELECT string_agg(to_id || ':' || to_version, ',' ORDER BY pointer) FROM risk.scenario_pin WHERE scenario_id = '" + sid + "'")
	}
	before, runs := pins(), fe.adminQuery("SELECT count(*) FROM analysis.run")
	// Mapping the scenario's control (a new control version) moves no pin.
	d := modeltest.Control()
	d["mappings"] = []any{mapping("nist-800-53", "5.2.0", "si-4", "full")}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/controls/"+ctl, map[string]any{"document": d, "expected_version": 1, "change_note": "Mapped"}); got.code != 200 {
		t.Fatalf("map: %d %s", got.code, got.raw)
	}
	// A proposal saves nothing and runs nothing.
	other := ra.create(t, "analyst", "control", ra.bu["A"], modeltest.Set(modeltest.Control(), "/name", "Proposed control"))
	for range 3 {
		if got := ra.call(t, "GET", "analyst", "/api/v1/scenarios/"+sid+"/proposed?add_control="+other, nil); got.code != 200 {
			t.Fatalf("proposed: %d %s", got.code, got.raw)
		}
	}
	if after := pins(); after != before {
		t.Errorf("pins moved: %s -> %s", before, after)
	}
	if v := fe.adminQuery("SELECT current_version FROM risk.scenario WHERE id = '" + sid + "'"); v != "1" {
		t.Errorf("the scenario is at version %s", v)
	}
	if n := fe.adminQuery("SELECT count(*) FROM analysis.run"); n != runs {
		t.Errorf("runs: %s -> %s", runs, n)
	}
	// The proposal route is a GET: no Idempotency-Key, no state.
	if got := ra.call(t, "POST", "analyst", "/api/v1/scenarios/"+sid+"/proposed?add_control="+other, map[string]any{}); got.code != 405 && got.code != 404 {
		t.Errorf("POST proposed: %d", got.code)
	}
}

// T: injection through framework text.
func TestSTRIDEF013Injection(t *testing.T) {
	fe := strideFrameworks(t)
	ra := fe.risk
	evil := `=HYPERLINK("http://x.test","click")`
	html := `<img src=x onerror=alert(1)>`
	simple, _ := json.Marshal(map[string]any{"format": "fair.framework.v1", "family": map[string]any{"key": "evil", "title": "Evil"},
		"version":      map[string]any{"label": "1", "title": "Evil 1"},
		"requirements": []any{map[string]any{"identifier": "E-1", "title": evil, "statement": html}, map[string]any{"identifier": "E-2", "title": "+cmd|' /C calc'!A0"}}})
	if _, imp := fe.upload(t, "platform", "kind=simple", "application/json", simple); imp["state"] != "succeeded" {
		t.Fatalf("import: %v", imp)
	}
	v := fe.adminQuery("SELECT id FROM framework.version WHERE family = 'evil'")
	// Identifiers are constrained: no formula or markup there.
	bad, _ := json.Marshal(map[string]any{"format": "fair.framework.v1", "family": map[string]any{"key": "evil2", "title": "Evil"},
		"version": map[string]any{"label": "1", "title": "Evil 1"}, "requirements": []any{map[string]any{"identifier": "=1+1", "title": "x"}}})
	if _, imp := fe.upload(t, "platform", "kind=simple", "application/json", bad); imp["state"] != "refused" {
		t.Errorf("a formula identifier: %v", imp["state"])
	}
	d := modeltest.Control()
	d["name"] = "=cmd()"
	d["mappings"] = []any{mapping("evil", "1", "E-1", "full")}
	if got := ra.call(t, "POST", "analyst", "/api/v1/controls", map[string]any{"bu_id": ra.bu["A"], "document": d, "change_note": "x"}); got.code != 201 {
		t.Fatal(got.raw)
	}
	// Stored and returned as data.
	r := fe.adminQuery("SELECT id FROM framework.requirement WHERE version_id = '" + v + "' AND identifier = 'E-1'")
	got := fe.call(t, "GET", "analyst", "/api/v1/frameworks/requirements/"+r, nil)
	if got.body["title"] != evil || got.body["statement"] != html {
		t.Errorf("as data: %v / %v", got.body["title"], got.body["statement"])
	}
	// CSV: every text cell that a spreadsheet would read as a formula is
	// neutralized.
	csv := fe.call(t, "GET", "analyst", "/api/v1/frameworks/versions/"+v+"/coverage.csv?bu="+ra.bu["A"], nil)
	for _, want := range []string{`'=HYPERLINK`, `'+cmd`, `'=cmd() (full`} {
		if !strings.Contains(csv.raw, want) {
			t.Errorf("CSV lacks %q: %s", want, csv.raw)
		}
	}
	for _, line := range strings.Split(csv.raw, "\n") {
		for _, cell := range strings.Split(line, ",") {
			c := strings.TrimPrefix(cell, `"`)
			if c != "" && strings.ContainsRune("=+@", rune(c[0])) {
				t.Errorf("a live formula cell: %q", cell)
			}
		}
	}
}

// R: changes not attributable.
func TestFrameworkAuditEvents(t *testing.T) {
	fe := strideFrameworks(t)
	ra := fe.risk
	simple := `{"format": "fair.framework.v1", "family": {"key": "aud", "title": "Audited"}, "version": {"label": "1", "title": "Audited 1"},
		"requirements": [{"identifier": "A-1", "title": "One"}]}`
	_, imp := fe.upload(t, "platform", "kind=simple", "application/json", []byte(simple))
	vid := imp["result"].(map[string]any)["version_id"].(string)
	fe.upload(t, "platform", "kind=simple", "application/json", []byte(`{"format": "fair.framework.v1"}`))
	if got := fe.call(t, "POST", "platform", "/api/v1/frameworks/versions/"+vid+"/retire", map[string]any{"reason": "Superseded"}); got.code != 200 {
		t.Fatal(got.raw)
	}
	d := modeltest.Control()
	d["mappings"] = []any{mapping("nist-800-53", "5.2.0", "ac-2", "full")}
	if got := ra.call(t, "POST", "analyst", "/api/v1/controls", map[string]any{"bu_id": ra.bu["A"], "document": d, "change_note": "x"}); got.code != 201 {
		t.Fatal(got.raw)
	}
	v := fe.adminQuery("SELECT id FROM framework.version WHERE family = 'nist-800-53' AND label = '5.2.0'")
	if got := fe.call(t, "GET", "analyst", "/api/v1/frameworks/versions/"+v+"/coverage.json?bu="+ra.bu["A"], nil); got.code != 200 {
		t.Fatal(got.raw)
	}
	for typ, c := range map[string]struct{ actor, attr, value string }{
		"framework.imported":          {"platform", "sha256", imp["sha256"].(string)},
		"framework.import_refused":    {"platform", "kind", "simple"},
		"framework.retired":           {"platform", "reason", "Superseded"},
		"control.mappings_changed":    {"analyst", "added", "nist-800-53 5.2.0 ac-2 full"},
		"framework.coverage_exported": {"analyst", "format", "json"},
	} {
		got := fe.adminQuery(fmt.Sprintf(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = '%s' AND body ->> 'actor' = (%s)::text
			AND body -> 'attributes' ->> '%s' = '%s'`, typ, uid(c.actor), c.attr, c.value))
		if got == "0" {
			t.Errorf("no %s by %s with %s=%s", typ, c.actor, c.attr, c.value)
		}
	}
}

// D: large imports or coverage reads exhaust the service.
func TestSTRIDEF013Limits(t *testing.T) {
	fe := strideFrameworks(t)
	ra := fe.risk
	// More than 500 mappings on a control: refused before the database.
	d := modeltest.Control()
	ms := make([]any, 501)
	for i := range ms {
		ms[i] = mapping("nist-800-53", "5.2.0", fmt.Sprintf("x-%d", i), "full")
	}
	d["mappings"] = ms
	if got := ra.call(t, "POST", "analyst", "/api/v1/controls", map[string]any{"bu_id": ra.bu["A"], "document": d, "change_note": "x"}); got.code != 422 ||
		!strings.Contains(got.raw, "/mappings") {
		t.Errorf("501 mappings: %d %.200s", got.code, got.raw)
	}
	// More than 20,000 requirements in a version: refused whole.
	reqs := make([]any, 20_001)
	for i := range reqs {
		reqs[i] = map[string]any{"identifier": fmt.Sprintf("R-%d", i), "title": "x"}
	}
	big, _ := json.Marshal(map[string]any{"format": "fair.framework.v1", "family": map[string]any{"key": "big", "title": "Big"},
		"version": map[string]any{"label": "1", "title": "Big 1"}, "requirements": reqs})
	if _, imp := fe.upload(t, "platform", "kind=simple", "application/json", big); imp["state"] != "refused" {
		t.Errorf("20,001 requirements: %v", imp["state"])
	}
	// At most five imports queued at once (call() queues without running them).
	simple := `{"format": "fair.framework.v1", "family": {"key": "q%d", "title": "Q"}, "version": {"label": "1", "title": "Q 1"}, "requirements": [{"identifier": "Q-1", "title": "x"}]}`
	codes := []int{}
	for i := range 6 {
		got := fe.call(t, "POST", "platform", "/api/v1/frameworks/imports?kind=simple", json.RawMessage(fmt.Sprintf(simple, i)))
		codes = append(codes, got.code)
	}
	if codes[5] != 409 {
		t.Errorf("a sixth queued import: %v", codes)
	}
	// Reads are bounded: a page of requirements and a crosswalk page.
	v := fe.adminQuery("SELECT id FROM framework.version WHERE family = 'nist-800-53' AND label = '5.2.0'")
	x := fe.adminQuery("SELECT id FROM framework.crosswalk LIMIT 1")
	for p, code := range map[string]int{
		"/api/v1/frameworks/versions/" + v + "/requirements?limit=501":  400,
		"/api/v1/frameworks/crosswalks/" + x + "?limit=5001":            400,
		"/api/v1/frameworks/requirements/" + v + "/scenarios?limit=201": 400,
	} {
		if got := fe.call(t, "GET", "analyst", p, nil); got.code != code {
			t.Errorf("%s: %d", p, got.code)
		}
	}
}

// ownerErr runs sql as the schema owner and answers its error.
func (fe *frameworkEnv) ownerErr(sql string) error {
	out, err := fe.owner(sql)
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
