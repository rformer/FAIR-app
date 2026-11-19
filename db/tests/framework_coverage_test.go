package tests

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-013 T-08 (F-013-AC-12 to AC-15, AC-20; design §3.5, §3.7): coverage of
// a framework for a business unit: direct and crosswalk-derived controls,
// states and counts (never a score), under row-level security with
// restricted units by roll-up mode, as of a past date, and exported with
// the reason rule and an audit record.
func TestFrameworkCoverage(t *testing.T) {
	fe := frameworkAPI(t)
	ra := fe.risk
	ra.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('ranalyst@example.test', 'Ranalyst')")
	ra.mustOwner(grant("platform", "user:ranalyst", "Risk Analyst", "R"))
	ra.mustOwner("UPDATE iam.bu SET rollup_mode = 'aggregate' WHERE code = 'R'")
	fe.drain()

	// Two small frameworks and a crosswalk: G1 equal T4, G2 intersects T5.
	for _, f := range []string{
		`{"format": "fair.framework.v1", "family": {"key": "tf", "title": "Test framework"}, "version": {"label": "1", "title": "TF 1"},
		  "requirements": [{"identifier": "T1", "title": "One"}, {"identifier": "T2", "title": "Two"}, {"identifier": "T3", "title": "Three"},
		                   {"identifier": "T4", "title": "Four"}, {"identifier": "T5", "title": "Five"}]}`,
		`{"format": "fair.framework.v1", "family": {"key": "tg", "title": "Other framework"}, "version": {"label": "1", "title": "TG 1"},
		  "requirements": [{"identifier": "G1", "title": "Gee one"}, {"identifier": "G2", "title": "Gee two"}]}`,
	} {
		if _, imp := fe.upload(t, "platform", "kind=simple", "application/json", []byte(f)); imp["state"] != "succeeded" {
			t.Fatalf("framework: %v", imp)
		}
	}
	xw := `{"format": "fair.crosswalk.v1", "title": "TG to TF", "label": "1", "source": {"family": "tg", "version": "1"}, "target": {"family": "tf", "version": "1"},
	  "relationships": [{"source": "G1", "target": "T4", "relationship": "equal"}, {"source": "G2", "target": "T5", "relationship": "intersects"}]}`
	if _, imp := fe.upload(t, "platform", "kind=crosswalk", "application/json", []byte(xw)); imp["state"] != "succeeded" {
		t.Fatalf("crosswalk: %v", imp)
	}
	vid := ra.adminQuery("SELECT id FROM framework.version WHERE family = 'tf'")

	control := func(user, bu, name, impl string, maps ...map[string]any) string {
		t.Helper()
		d := modeltest.Control()
		d["name"] = name
		d["mappings"] = toAny(maps)
		if impl != "" {
			d["implementation"] = map[string]any{"status": impl, "assessed_on": "2026-11-01"}
		}
		got := ra.call(t, "POST", user, "/api/v1/controls", map[string]any{"bu_id": ra.bu[bu], "document": d, "change_note": "x"})
		if got.code != 201 {
			t.Fatalf("%s: %d %s", name, got.code, got.raw)
		}
		return got.body["id"].(string)
	}
	c1 := control("analyst", "A", "Access reviews", "in_place", mapping("tf", "1", "T1", "full"), mapping("tf", "1", "T2", "full"))
	control("analyst", "A1", "Provisioning", "not_in_place", mapping("tf", "1", "T2", "full"))
	c3 := control("analyst", "A", "Logging", "in_place", mapping("tf", "1", "T3", "partial"))
	control("analyst", "A", "Segmentation", "in_place", mapping("tg", "1", "G1", "full"))
	control("ranalyst", "R", "Restricted monitoring", "in_place", mapping("tf", "1", "T5", "full"))

	coverage := func(user, bu, extra string) apiResp {
		t.Helper()
		return fe.call(t, "GET", user, "/api/v1/frameworks/versions/"+vid+"/coverage?bu="+ra.bu[bu]+extra, nil)
	}
	states := func(r apiResp) string {
		t.Helper()
		var out []string
		for _, q := range r.body["requirements"].([]any) {
			m := q.(map[string]any)
			s := m["identifier"].(string) + ":" + m["state"].(string)
			for _, d := range m["direct"].([]any) {
				s += " " + d.(map[string]any)["name"].(string)
			}
			for _, d := range m["derived"].([]any) {
				dm := d.(map[string]any)
				s += " ~" + dm["name"].(string) + "(" + dm["relationship"].(string) + "," + dm["reach"].(string) + ")"
			}
			out = append(out, s)
		}
		return strings.Join(out, "; ")
	}
	counts := func(m any) string {
		c := m.(map[string]any)
		return fmt.Sprintf("%v/%v/%v/%v", c["in_place"], c["not_in_place"], c["partial"], c["not_covered"])
	}

	// AC-12, AC-13: the analyst at A (A1 below; R restricted, aggregate).
	got := coverage("analyst", "A", "")
	if got.code != 200 {
		t.Fatalf("coverage: %d %s", got.code, got.raw)
	}
	want := "T1:in_place Access reviews; T2:not_in_place Access reviews Provisioning; T3:partial Logging; T4:partial ~Segmentation(equal,equivalent); T5:not_covered"
	if s := states(got); s != want {
		t.Errorf("states\n got %s\nwant %s", s, want)
	}
	if c := counts(got.body["counts"]); c != "1/1/2/1" {
		t.Errorf("counts %s", c)
	}
	// AC-13: no score, percentage or rating anywhere.
	for _, word := range []string{"score", "percent", "rating", "%"} {
		if strings.Contains(strings.ToLower(got.raw), word) {
			t.Errorf("the coverage carries %q", word)
		}
	}
	// AC-14: R's control is not listed; R counts as totals only.
	if strings.Contains(got.raw, "Restricted monitoring") {
		t.Error("a restricted unit's control is listed")
	}
	r, _ := got.body["restricted"].(map[string]any)
	if r == nil || r["units"] != float64(2) || counts(r["counts"]) != "1/0/0/4" { // R and its child R1
		t.Errorf("restricted: %v", got.body["restricted"])
	}
	// The restricted unit's own analyst sees its control.
	if s := states(coverage("ranalyst", "R", "")); !strings.Contains(s, "T5:in_place Restricted monitoring") {
		t.Errorf("ranalyst at R: %s", s)
	}
	// Excluded: not even counts; the answer says a unit was left out.
	ra.mustOwner("UPDATE iam.bu SET rollup_mode = 'excluded' WHERE code = 'R'")
	fe.drain()
	if got := coverage("analyst", "A", ""); got.body["restricted"] != nil || got.body["left_out"].(float64) < 1 {
		t.Errorf("excluded: restricted %v, left_out %v", got.body["restricted"], got.body["left_out"])
	}
	// A1 alone; B's analyst; a stranger.
	if s := states(coverage("analyst", "A1", "")); !strings.HasPrefix(s, "T1:not_covered; T2:not_in_place Provisioning;") {
		t.Errorf("A1: %s", s)
	}
	if got := coverage("mallory", "A", ""); got.code != 403 {
		t.Errorf("mallory at A: %d", got.code)
	}
	if got := coverage("mallory", "B", ""); got.code != 200 || counts(got.body["counts"]) != "0/0/0/5" {
		t.Errorf("mallory at B: %d %s", got.code, got.raw)
	}
	if got := coverage("buadmin", "A", ""); got.code != 404 && got.code != 401 {
		t.Errorf("no control permission: %d", got.code)
	}

	// AC-20: as of a past date. Access reviews lapses (version 2), Logging
	// is archived; before that, coverage is as it was.
	d := modeltest.Control()
	d["name"] = "Access reviews"
	d["mappings"] = toAny([]map[string]any{mapping("tf", "1", "T1", "full"), mapping("tf", "1", "T2", "full")})
	d["implementation"] = map[string]any{"status": "not_in_place", "assessed_on": "2026-11-18"}
	if got := ra.call(t, "PUT", "analyst", "/api/v1/controls/"+c1, map[string]any{"document": d, "expected_version": 1, "change_note": "Lapsed"}); got.code != 200 {
		t.Fatalf("save: %d %s", got.code, got.raw)
	}
	if got := ra.call(t, "POST", "analyst", "/api/v1/controls/"+c3+"/archive", map[string]any{"reason": "Replaced"}); got.code != 200 {
		t.Fatalf("archive: %d %s", got.code, got.raw)
	}
	if s := states(coverage("analyst", "A", "")); !strings.HasPrefix(s, "T1:not_in_place Access reviews; T2:not_in_place Access reviews Provisioning; T3:not_covered;") {
		t.Errorf("now: %s", s)
	}
	before := ra.adminQuery("SELECT to_json(created_at - interval '1 millisecond') #>> '{}' FROM risk.control_version WHERE control_id = '" + c1 + "' AND version = 2")
	if s := states(coverage("analyst", "A", "&as_of="+url.QueryEscape(before))); !strings.HasPrefix(s, "T1:in_place Access reviews; T2:not_in_place Access reviews Provisioning; T3:partial Logging;") {
		t.Errorf("as of %s: %s", before, s)
	}
	for q, code := range map[string]int{"&as_of=2000-01-01": 409, "&as_of=2999-01-01": 400, "&as_of=yesterday": 400, "&baseline=" + vid: 404} {
		if got := coverage("analyst", "A", q); got.code != code {
			t.Errorf("%s: %d %s", q, got.code, got.raw)
		}
	}

	// A baseline: its selection only (800-53 5.2.0 low).
	v520 := ra.adminQuery("SELECT id FROM framework.version WHERE family = 'nist-800-53' AND label = '5.2.0'")
	low := ra.adminQuery("SELECT b.id FROM framework.baseline b WHERE b.version_id = '" + v520 + "' AND b.key = 'nist-low'")
	n := ra.adminQuery("SELECT cardinality(selected) FROM framework.baseline WHERE id = '" + low + "'")
	got = fe.call(t, "GET", "analyst", "/api/v1/frameworks/versions/"+v520+"/coverage?bu="+ra.bu["A"]+"&baseline="+low, nil)
	if got.code != 200 || fmt.Sprint(len(got.body["requirements"].([]any))) != n || got.body["baseline"].(map[string]any)["key"] != "nist-low" {
		t.Errorf("baseline: %d (want %s requirements) %.300s", got.code, n, got.raw)
	}

	// AC-15: exports, with the reason rule over the subtree and an audit
	// record in the same transaction; none without the trail.
	path := "/api/v1/frameworks/versions/" + vid + "/coverage"
	csv := callWith(t, fe.riskAPIEnv, fe.url, "GET", "analyst", path+".csv?bu="+ra.bu["A"], nil, nil)
	if csv.code != 200 || !strings.HasPrefix(csv.raw, "\uFEFFformat,fair.coverage.v1\r\n") || !strings.Contains(csv.raw, "count_not_in_place,2") ||
		!strings.Contains(csv.raw, `T4,,Four,partial,,"Segmentation (full, in_place) via tg 1 G1 (TG to TF: equal, equivalent)"`) {
		t.Errorf("csv: %d %s", csv.code, csv.raw)
	}
	js := callWith(t, fe.riskAPIEnv, fe.url, "GET", "analyst", path+".json?bu="+ra.bu["A"], nil, nil)
	if js.code != 200 || js.body["format"] != "fair.coverage.v1" || !strings.Contains(js.hdr.Get("Content-Disposition"), "coverage-tf-1-") {
		t.Errorf("json: %d %.300s", js.code, js.raw)
	}
	exported := func() string {
		return ra.adminQuery(`SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'framework.coverage_exported' AND body ->> 'bu_id' = '` + ra.bu["A"] + `'`)
	}
	if n := exported(); n != "2" {
		t.Errorf("%s coverage_exported events", n)
	}
	fe.api.Reasons = reason.Static{BUs: []string{ra.bu["A1"]}} // in force below A
	if got := callWith(t, fe.riskAPIEnv, fe.url, "GET", "analyst", path+".csv?bu="+ra.bu["A"], nil, nil); got.code != 400 || got.body["error"] != "reason_required" {
		t.Errorf("no reason: %d %s", got.code, got.raw)
	}
	if got := callWith(t, fe.riskAPIEnv, fe.url, "GET", "analyst", path+".csv?bu="+ra.bu["A"], nil, map[string]string{reason.Header: "Audit%20pack"}); got.code != 200 {
		t.Errorf("with a reason: %d %s", got.code, got.raw)
	}
	if got := ra.adminQuery(`SELECT body ->> 'reason' FROM audit.intake WHERE body ->> 'type' = 'framework.coverage_exported' ORDER BY id DESC LIMIT 1`); got != "Audit pack" {
		t.Errorf("reason recorded: %q", got)
	}
	fe.api.Audit, fe.api.Reasons = nil, reason.Static{}
	if got := callWith(t, fe.riskAPIEnv, fe.url, "GET", "analyst", path+".csv?bu="+ra.bu["A"], nil, nil); got.code != 503 || strings.Contains(got.raw, "T1") {
		t.Errorf("no audit trail: %d %s", got.code, got.raw)
	}
	fe.api.Audit = audit.NewMemory()
	if got := callWith(t, fe.riskAPIEnv, fe.url, "GET", "erin", path+".csv?bu="+ra.bu["B"], nil, nil); got.code != 403 {
		t.Errorf("erin exports B: %d", got.code)
	}
}

func toAny(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}
