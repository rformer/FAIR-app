package tests

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-013 T-07 (F-013-AC-10, AC-11; design §3.3): crosswalks imported as
// fair.crosswalk.v1 JSON or CSV or an OSCAL mapping collection, refused
// whole when a relationship names a requirement not imported; read, retired;
// the derived relationships coverage reads, oriented from the covered
// requirement and never full but for equal or a covering superset.
func TestCrosswalks(t *testing.T) {
	fe := frameworkAPI(t)
	fe.mustOwner(grant("platform", "user:buadmin", "BU Admin", "A")) // a role, but no framework or control permission
	fe.drain()
	const src, tgt = "Rev 3 (1.1.0)", "5.1.1+u4"
	versionID := func(family, label string) string {
		return fe.adminQuery("SELECT id FROM framework.version WHERE family = '" + family + "' AND label = '" + label + "'")
	}
	v171, v53 := versionID("nist-800-171", src), versionID("nist-800-53", tgt)
	head := url.Values{"kind": {"crosswalk"}, "source_family": {"nist-800-171"}, "source_version": {src},
		"target_family": {"nist-800-53"}, "target_version": {tgt}}

	// The shipped crosswalk is listed, from or to either version.
	list := fe.call(t, "GET", "analyst", "/api/v1/frameworks/crosswalks?version="+v53, nil)
	if list.code != 200 || !strings.Contains(list.raw, `"relationships":157`) {
		t.Fatalf("list: %d %.400s", list.code, list.raw)
	}

	// An OSCAL mapping collection, as a dry run, then for real.
	mc, err := os.ReadFile(filepath.Join("..", "..", "internal", "framework", "testdata", "mapping-collection.json"))
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	for k, v := range head {
		q[k] = v
	}
	q.Set("dry_run", "true")
	got, imp := fe.upload(t, "platform", q.Encode(), "application/json", mc)
	if got.code != 202 || imp["state"] != "succeeded" || !strings.Contains(mustJSON(imp["result"]), `"relationships":4`) {
		t.Fatalf("dry run: %d %v", got.code, imp)
	}
	if n := fe.adminQuery("SELECT count(*) FROM framework.crosswalk WHERE label = 'test-1'"); n != "0" {
		t.Errorf("a dry run recorded %s crosswalks", n)
	}
	q.Del("dry_run")
	_, imp = fe.upload(t, "platform", q.Encode(), "application/json", mc)
	if imp["state"] != "succeeded" {
		t.Fatalf("import: %v", imp)
	}
	xid := imp["result"].(map[string]any)["crosswalk_id"].(string)
	x := fe.call(t, "GET", "analyst", "/api/v1/frameworks/crosswalks/"+xid+"?limit=2", nil)
	if x.code != 200 || x.body["relationships"] != float64(4) || x.body["more"] != true || len(x.body["relationship_list"].([]any)) != 2 ||
		!strings.Contains(x.raw, `"source":"SP_800_171_03.01.01"`) || !strings.Contains(x.raw, `"relationship":"equal"`) {
		t.Errorf("crosswalk: %d %s", x.code, x.raw)
	}
	if n := fe.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'framework.crosswalk_imported' AND body ->> 'target' = 'framework_crosswalk:" + xid + "' AND body -> 'attributes' ->> 'relationships' = '4'"); n != "1" {
		t.Errorf("%s crosswalk_imported events", n)
	}
	// The same crosswalk again is refused.
	if _, again := fe.upload(t, "platform", q.Encode(), "application/json", mc); again["state"] != "refused" || !strings.Contains(mustJSON(again["problems"]), "/label") {
		t.Errorf("a repeat: %v", again)
	}

	// fair.crosswalk.v1 JSON with a requirement neither version has: refused
	// whole, by pointer, nothing recorded.
	bad := map[string]any{"format": "fair.crosswalk.v1", "title": "Bad", "label": "bad-1",
		"source": map[string]any{"family": "nist-800-171", "version": src}, "target": map[string]any{"family": "nist-800-53", "version": tgt},
		"relationships": []any{
			map[string]any{"source": "SP_800_171_03.01.01", "target": "ac-2", "relationship": "equal"},
			map[string]any{"source": "SP_800_171_99.99.99", "target": "ac-2", "relationship": "intersects"},
			map[string]any{"source": "SP_800_171_03.01.01", "target": "zz-9", "relationship": "subset_of"},
		}}
	_, imp = fe.upload(t, "platform", "kind=crosswalk", "application/json", []byte(mustJSON(bad)))
	if p := mustJSON(imp["problems"]); imp["state"] != "refused" || !strings.Contains(p, "/relationships/1/source") || !strings.Contains(p, "/relationships/2/target") ||
		strings.Contains(p, "/relationships/0") {
		t.Errorf("unknown requirements: %v", imp)
	}
	// A version not imported.
	bad["target"] = map[string]any{"family": "nist-800-53", "version": "4.0"}
	if _, imp = fe.upload(t, "platform", "kind=crosswalk", "application/json", []byte(mustJSON(bad))); imp["state"] != "refused" || !strings.Contains(mustJSON(imp["problems"]), `"/target"`) {
		t.Errorf("unknown version: %v", imp)
	}
	if n := fe.adminQuery("SELECT count(*) FROM framework.crosswalk WHERE label IN ('bad-1')"); n != "0" {
		t.Errorf("a refused crosswalk was recorded")
	}

	// CSV, with the header from the query; and a mapping collection without
	// one is refused.
	csvQ := url.Values{}
	for k, v := range head {
		csvQ[k] = v
	}
	csvQ.Set("title", "CSV crosswalk")
	csvQ.Set("label", "csv-1")
	_, imp = fe.upload(t, "platform", csvQ.Encode(), "text/csv", []byte("source,target,relationship\nSP_800_171_03.01.05,ac-6,subset_of\n"))
	if imp["state"] != "succeeded" {
		t.Errorf("CSV: %v", imp)
	}
	if _, imp = fe.upload(t, "platform", "kind=crosswalk", "application/json", mc); imp["state"] != "refused" {
		t.Errorf("a mapping collection without versions: %v", imp)
	}
	// Who may import or retire: framework.manage at the root only.
	if got, _ := fe.upload(t, "analyst", csvQ.Encode(), "text/csv", []byte("source,target,relationship\n")); got.code != 403 {
		t.Errorf("analyst imports: %d", got.code)
	}

	// Derived relationships, from 800-53's side (the crosswalks run
	// 800-171 to 800-53): ac-2 equal (equivalent), ac-3 by a superset
	// (equivalent), ac-4 intersects (partial), ac-6 by a subset (partial).
	derived := func() string {
		return fe.adminQuery(`SELECT string_agg(r.identifier || ' ' || d.relationship || ' ' || d.reach, ', ' ORDER BY r.identifier)
			FROM framework.derived('` + v53 + `') d JOIN framework.requirement r ON r.id = d.requirement_id
			JOIN framework.crosswalk x ON x.id = d.crosswalk_id WHERE x.label IN ('test-1', 'csv-1')`)
	}
	if got := derived(); got != "ac-14 superset_of equivalent, ac-2 equal equivalent, ac-3 superset_of equivalent, ac-4 intersects partial, ac-6 subset_of partial" {
		t.Errorf("derived to 800-53: %s", got)
	}
	// From 800-171's side the relationships are inverted: covering ac-3 does
	// not cover the larger 03.01.02.
	if got := fe.adminQuery(`SELECT string_agg(r.identifier || ' ' || d.relationship || ' ' || d.reach, ', ' ORDER BY r.identifier, d.relationship)
			FROM framework.derived('` + v171 + `') d JOIN framework.requirement r ON r.id = d.requirement_id
			JOIN framework.crosswalk x ON x.id = d.crosswalk_id WHERE x.label = 'test-1'`); got !=
		"SP_800_171_03.01.01 equal equivalent, SP_800_171_03.01.02 subset_of partial, SP_800_171_03.01.02 subset_of partial, SP_800_171_03.01.03 intersects partial" {
		t.Errorf("derived to 800-171: %s", got)
	}

	// Retiring: a reason, framework.manage; a retired crosswalk derives
	// nothing and is listed only with retired=true.
	if got := fe.call(t, "POST", "analyst", "/api/v1/frameworks/crosswalks/"+xid+"/retire", map[string]any{"reason": "x"}); got.code != 403 {
		t.Errorf("analyst retires: %d", got.code)
	}
	if got := fe.call(t, "POST", "platform", "/api/v1/frameworks/crosswalks/"+xid+"/retire", map[string]any{"reason": ""}); got.code != 400 {
		t.Errorf("no reason: %d", got.code)
	}
	if got := fe.call(t, "POST", "platform", "/api/v1/frameworks/crosswalks/"+xid+"/retire", map[string]any{"reason": "Test only"}); got.code != 200 || got.body["state"] != "retired" {
		t.Errorf("retire: %d %s", got.code, got.raw)
	}
	if got := fe.call(t, "POST", "platform", "/api/v1/frameworks/crosswalks/"+xid+"/retire", map[string]any{"reason": "Again"}); got.code != 409 {
		t.Errorf("retire twice: %d", got.code)
	}
	if got := derived(); got != "ac-6 subset_of partial" {
		t.Errorf("derived after retiring: %s", got)
	}
	if strings.Contains(fe.call(t, "GET", "analyst", "/api/v1/frameworks/crosswalks", nil).raw, xid) ||
		!strings.Contains(fe.call(t, "GET", "analyst", "/api/v1/frameworks/crosswalks?retired=true", nil).raw, xid) {
		t.Error("retired crosswalk listing")
	}
	if got := fe.call(t, "GET", "buadmin", "/api/v1/frameworks/crosswalks/"+xid, nil); got.code != 404 {
		t.Errorf("a user without any framework permission: %d", got.code)
	}
}
