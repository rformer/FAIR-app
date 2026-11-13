package tests

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/analysis"
)

// F-006 T-03 (F-006-AC-17 to AC-20; design §3.3, §6.2, §6.3, §8): CSV
// downloads and image download records through the analysis API, each
// recorded as analysis.downloaded in its transaction.

// compareCSV is the CSV of the comparison of items.
func compareCSV(view string, items ...string) string {
	return "/api/v1/analyses/compare.csv?" + url.Values{"view": {view}, "item": items}.Encode()
}

// parsedCSV is a downloaded CSV: metadata, header and rows.
type parsedCSV struct {
	meta   map[string]string
	header []string
	rows   [][]string
}

func parseDownload(t *testing.T, got apiResp) parsedCSV {
	t.Helper()
	if got.code != 200 {
		t.Fatalf("download: %d %s", got.code, got.raw)
	}
	if ct := got.hdr.Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Errorf("content type %q", ct)
	}
	if got.hdr.Get("Cache-Control") != "no-store" {
		t.Error("a download may be cached")
	}
	raw := []byte(got.raw)
	if !bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("no byte-order mark")
	}
	parts := bytes.SplitN(raw[3:], []byte("\r\n\r\n"), 2)
	if len(parts) != 2 {
		t.Fatalf("no blank row after the metadata: %q", got.raw)
	}
	p := parsedCSV{meta: map[string]string{}}
	r := csv.NewReader(bytes.NewReader(parts[0]))
	meta, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range meta {
		p.meta[m[0]] = m[1]
	}
	rows, err := csv.NewReader(bytes.NewReader(parts[1])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	p.header, p.rows = rows[0], rows[1:]
	return p
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// downloadEvents are the analysis.downloaded events of a download, as
// "bu|subject|ids|view|format" sorted by BU.
func downloadEvents(ra *riskAPIEnv, id string) []string {
	got := ra.adminQuery(`SELECT coalesce(string_agg(body ->> 'bu_id' || '|' || (body -> 'attributes' ->> 'subject') || '|' || (body -> 'attributes' ->> 'ids') || '|' ||
		(body -> 'attributes' ->> 'view') || '|' || (body -> 'attributes' ->> 'format'), ',' ORDER BY body ->> 'bu_id'), '')
		FROM audit.intake WHERE body ->> 'type' = 'analysis.downloaded' AND body -> 'attributes' ->> 'download_id' = '` + id + `'`)
	if got == "" {
		return nil
	}
	return strings.Split(got, ",")
}

func TestAnalysisCSV(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B, erin an Executive Viewer at A
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	r1 := runWith(t, ae, "analyst", s1, 1, 2000, "7")
	rq := runOf(t, ae, "analyst", s1, 2000, true)
	currency := ra.adminQuery("SELECT currency FROM risk.instance")
	data := func(user, path string) apiResp {
		t.Helper()
		return ae.call(t, "GET", user, path, nil)
	}
	run := "/api/v1/analyses/runs/" + r1 + "/data.csv"

	// The curve: every set's points, as stored (AC-18).
	got := data("erin", run+"?view=curve")
	c := parseDownload(t, got)
	if cd := got.hdr.Get("Content-Disposition"); cd != `attachment; filename="run-`+r1[:8]+`-curve.csv"` {
		t.Errorf("content disposition %q", cd)
	}
	if !uuidPattern.MatchString(c.meta["download"]) || c.meta["subject"] != "run" || c.meta["id"] != r1 || c.meta["scenario"] != "Claims ransomware" ||
		c.meta["scenario_version"] != "1" || c.meta["control_sets"] != "Current; Proposed" || c.meta["currency"] != currency || c.meta["seed"] != "7" ||
		c.meta["independence"] != "Every input is sampled independently." || len(c.meta["result_digest"]) != 64 || len(c.meta["bundle_digest"]) != 64 ||
		c.meta["engine_version"] != "0.1.0" {
		t.Errorf("metadata %v", c.meta)
	}
	if strings.Join(c.header, ",") != "control_set,annual_loss,probability_of_exceeding" || len(c.rows) != 6 ||
		strings.Join(c.rows[4], ",") != "Proposed,10,0.1" {
		t.Errorf("curve %v %v", c.header, c.rows)
	}
	if ev := downloadEvents(ra, c.meta["download"]); len(ev) != 1 || ev[0] != ra.bu["A1"]+"|run|"+r1+"|curve|csv" {
		t.Errorf("events %v", ev)
	}

	// The histogram: the bins of the JSON route, then the years apart.
	hj := data("analyst", "/api/v1/analyses/runs/"+r1+"/histogram?set=Proposed&relative_to=Current")
	c = parseDownload(t, data("analyst", run+"?view=histogram&set=Proposed&relative_to=Current"))
	if len(c.rows) != analysis.HistogramBins+2 || c.meta["relative_to"] != "Current" || c.meta["scale"] != "linear" || c.meta["control_sets"] != "Proposed" {
		t.Fatalf("difference histogram %v %d rows", c.meta, len(c.rows))
	}
	for i, n := range hj.body["counts"].([]any) {
		if c.rows[i][5] != fmt.Sprint(n) || c.rows[i][2] != "bin" {
			t.Fatalf("bin %d: %v, JSON %v", i, c.rows[i], n)
		}
	}
	if strings.Join(c.rows[60], ",") != "Proposed,Current,no_difference,,,200" || strings.Join(c.rows[61], ",") != "Proposed,Current,neither_lost,,,200" {
		t.Errorf("years apart %v", c.rows[60:])
	}
	if c = parseDownload(t, data("analyst", run+"?view=histogram&set=Current&scale=linear")); c.rows[0][3] != "0" || c.rows[60][2] != "no_loss" || c.meta["scale"] != "linear" {
		t.Errorf("loss histogram %v %v", c.rows[0], c.rows[60])
	}

	// Breakdown, summary, comparison and sensitivity.
	c = parseDownload(t, data("analyst", run+"?view=breakdown"))
	if len(c.rows) != 8 || strings.Join(c.rows[0], ",") != "Current,primary,primary,3,0.6666666666666666" {
		t.Errorf("breakdown %v", c.rows)
	}
	c = parseDownload(t, data("analyst", run+"?view=summary"))
	if c.rows[0][1] != "ale" || c.rows[0][2] != "mean" || c.rows[0][3] != "4.5" {
		t.Errorf("summary %v", c.rows)
	}
	c = parseDownload(t, data("analyst", run+"?view=comparison"))
	if len(c.rows) == 0 || c.rows[0][0] != "Proposed" || c.rows[0][1] != "Current" {
		t.Errorf("comparison %v", c.rows)
	}
	c = parseDownload(t, data("analyst", run+"?view=sensitivity&set=Proposed"))
	if len(c.rows) != 1 || c.rows[0][1] != "'=Contact frequency" || c.rows[0][8] != "-5" || c.rows[0][13] != "0.5" {
		t.Errorf("sensitivity: a formula-like input name, a negative number %v", c.rows)
	}

	// An aggregate and a comparison.
	got = ae.call(t, "POST", "analyst", "/api/v1/analyses/aggregates", map[string]any{"bu_id": ra.bu["A1"], "name": "Claims portfolio",
		"members": []map[string]any{{"run_id": r1, "control_set": "Current"}, {"run_id": r1, "control_set": "Proposed"}}, "seed": "11"})
	a1 := got.body["id"].(string)
	if err := ae.aggregates.Attempt(t.Context(), a1, 1, analysis.Attempts); err != nil {
		t.Fatal(err)
	}
	c = parseDownload(t, data("analyst", "/api/v1/analyses/aggregates/"+a1+"/data.csv?view=histogram"))
	if c.meta["subject"] != "aggregate" || c.meta["aggregate"] != "Claims portfolio" || len(c.rows) != analysis.HistogramBins+1 {
		t.Errorf("aggregate %v", c.meta)
	}
	got = data("analyst", "/api/v1/analyses/compare.csv?view=summary&item=run:"+r1+":Current&item=aggregate:"+a1)
	c = parseDownload(t, got)
	if c.meta["subject"] != "comparison" || c.meta["items"] != "run:"+r1+":Current aggregate:"+a1 || c.meta["sampling_noise"] != analysis.SamplingNoise ||
		len(c.meta["item_2_result_digest"]) != 64 || !strings.HasPrefix(got.hdr.Get("Content-Disposition"), `attachment; filename="comparison-`) {
		t.Errorf("comparison %v", c.meta)
	}
	if ev := downloadEvents(ra, c.meta["download"]); len(ev) != 1 || ev[0] != ra.bu["A1"]+"|comparison|"+min(r1, a1)+" "+max(r1, a1)+"|summary|csv" {
		t.Errorf("comparison events %v", ev)
	}

	// Refusals: nothing is recorded for them.
	before := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.downloaded'")
	for name, c := range map[string]struct {
		user, path string
		code       int
	}{
		"no view":                      {"analyst", run, 422},
		"an unknown view":              {"analyst", run + "?view=pdf", 422},
		"a histogram without a set":    {"analyst", run + "?view=histogram", 422},
		"a set on the summary":         {"analyst", run + "?view=summary&set=Current", 422},
		"relative_to on the curve":     {"analyst", run + "?view=curve&relative_to=Current", 422},
		"relative to another set":      {"analyst", run + "?view=histogram&set=Current&relative_to=Proposed", 422},
		"a log difference":             {"analyst", run + "?view=histogram&set=Proposed&relative_to=Current&scale=log", 422},
		"an unknown scale":             {"analyst", run + "?view=histogram&set=Current&scale=cubic", 422},
		"a queued run":                 {"analyst", "/api/v1/analyses/runs/" + rq + "/data.csv?view=curve", 409},
		"mallory":                      {"mallory", run + "?view=curve", 404},
		"an aggregate's run view":      {"analyst", "/api/v1/analyses/aggregates/" + a1 + "/data.csv?view=breakdown", 422},
		"a comparison's other view":    {"analyst", "/api/v1/analyses/compare.csv?view=histogram&item=run:" + r1 + ":Current&item=aggregate:" + a1, 422},
		"a comparison mallory can't":   {"mallory", "/api/v1/analyses/compare.csv?view=summary&item=run:" + r1 + ":Current&item=aggregate:" + a1, 404},
		"a comparison of one":          {"analyst", "/api/v1/analyses/compare.csv?view=summary&item=run:" + r1 + ":Current", 422},
		"no such aggregate":            {"analyst", "/api/v1/analyses/aggregates/00000000-0000-4000-8000-000000000000/data.csv?view=curve", 404},
		"an aggregate, an unknown one": {"analyst", "/api/v1/analyses/aggregates/" + a1 + "/data.csv?view=pdf", 422},
	} {
		if got := data(c.user, c.path); got.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, got.code, got.raw, c.code)
		}
	}
	if after := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.downloaded'"); after != before {
		t.Errorf("refusals recorded downloads: %s then %s", before, after)
	}
}

func TestAnalysisDownloadEvents(t *testing.T) {
	ra := strideF003Fixture(t) // analyst at A, mallory at B, erin an Executive Viewer at A, platform2 at ENTERPRISE
	ae := analysisAPI(t, ra, defaultLimits, true)
	ae.engine.set("ramp", true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	s0 := scenarioAt(t, ra, "analyst", ra.bu["A"], "Head office fraud")
	sb := scenarioAt(t, ra, "mallory", ra.bu["B"], "Branch outage")
	r1, r0, rb := runWith(t, ae, "analyst", s1, 1, 2000, "7"), runWith(t, ae, "analyst", s0, 1, 2000, "7"), runWith(t, ae, "mallory", sb, 1, 2000, "7")
	rq := runOf(t, ae, "analyst", s1, 2000, true)
	record := func(user string, body map[string]any) apiResp {
		t.Helper()
		return ae.call(t, "POST", user, "/api/v1/analyses/downloads", body)
	}

	// An image of a run: recorded, its id returned for the footer (AC-17).
	got := record("erin", map[string]any{"subject": "run", "id": r1, "view": "curve", "format": "png"})
	if got.code != 201 || !uuidPattern.MatchString(fmt.Sprint(got.body["download_id"])) {
		t.Fatalf("record: %d %s", got.code, got.raw)
	}
	if ev := downloadEvents(ra, got.body["download_id"].(string)); len(ev) != 1 || ev[0] != ra.bu["A1"]+"|run|"+r1+"|curve|png" {
		t.Errorf("events %v", ev)
	}
	actor := ra.adminQuery("SELECT body ->> 'actor' FROM audit.intake WHERE body -> 'attributes' ->> 'download_id' = '" + got.body["download_id"].(string) + "'")
	if actor != ra.principal("erin").UserID {
		t.Errorf("actor %s", actor)
	}

	// A comparison across A1, A and B: one event per business unit, each
	// naming only its own results (design §8).
	items := []string{"run:" + r1 + ":Current", "run:" + r0 + ":Current", "run:" + rb + ":Current", "run:" + r1 + ":Proposed"}
	got = record("platform2", map[string]any{"subject": "comparison", "items": items, "view": "curve", "format": "svg"})
	if got.code != 201 {
		t.Fatalf("comparison: %d %s", got.code, got.raw)
	}
	ev := downloadEvents(ra, got.body["download_id"].(string))
	want := map[string]string{ra.bu["A1"]: r1, ra.bu["A"]: r0, ra.bu["B"]: rb}
	if len(ev) != 3 {
		t.Fatalf("comparison events %v", ev)
	}
	for _, e := range ev {
		f := strings.Split(e, "|")
		if want[f[0]] != f[2] || f[1] != "comparison" || f[4] != "svg" {
			t.Errorf("event %s", e)
		}
	}
	// A CSV of the same comparison: likewise.
	c := parseDownload(t, ae.call(t, "GET", "platform2", compareCSV("curve", items...), nil))
	if ev := downloadEvents(ra, c.meta["download"]); len(ev) != 3 {
		t.Errorf("CSV comparison events %v", ev)
	}

	// Refusals record nothing.
	before := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.downloaded'")
	for name, c := range map[string]struct {
		user string
		body map[string]any
		code int
	}{
		"mallory, A1's run":       {"mallory", map[string]any{"subject": "run", "id": r1, "view": "curve", "format": "png"}, 404},
		"a queued run":            {"analyst", map[string]any{"subject": "run", "id": rq, "view": "curve", "format": "png"}, 409},
		"a hidden comparison":     {"analyst", map[string]any{"subject": "comparison", "items": items, "view": "curve", "format": "png"}, 404},
		"an unknown format":       {"analyst", map[string]any{"subject": "run", "id": r1, "view": "curve", "format": "pdf"}, 422},
		"an unknown view":         {"analyst", map[string]any{"subject": "run", "id": r1, "view": "contributions", "format": "png"}, 422},
		"an unknown subject":      {"analyst", map[string]any{"subject": "scenario", "id": r1, "view": "curve", "format": "png"}, 422},
		"items on a run":          {"analyst", map[string]any{"subject": "run", "id": r1, "items": items, "view": "curve", "format": "png"}, 422},
		"an id on a comparison":   {"analyst", map[string]any{"subject": "comparison", "id": r1, "items": items[:2], "view": "curve", "format": "png"}, 422},
		"an unknown field":        {"analyst", map[string]any{"subject": "run", "id": r1, "view": "curve", "format": "png", "reason": "x"}, 400},
		"no such aggregate":       {"analyst", map[string]any{"subject": "aggregate", "id": "00000000-0000-4000-8000-000000000000", "view": "curve", "format": "png"}, 404},
		"a comparison of one":     {"analyst", map[string]any{"subject": "comparison", "items": items[:1], "view": "curve", "format": "png"}, 422},
		"a run id that is no id":  {"analyst", map[string]any{"subject": "run", "id": "x", "view": "curve", "format": "png"}, 404},
		"a viewer elsewhere (B)":  {"mallory", map[string]any{"subject": "comparison", "items": items[:2], "view": "curve", "format": "png"}, 404},
		"the comparison's 7 runs": {"analyst", map[string]any{"subject": "comparison", "items": []string{"a", "b", "c", "d", "e", "f", "g"}, "view": "curve", "format": "png"}, 422},
	} {
		if got := record(c.user, c.body); got.code != c.code {
			t.Errorf("%s: %d %s, want %d", name, got.code, got.raw, c.code)
		}
	}
	if after := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.downloaded'"); after != before {
		t.Errorf("refusals recorded downloads: %s then %s", before, after)
	}

	// Audit fails closed: no file, no record, 503 (design §6.2).
	ae.api.Audit = failingEmitter{}
	for _, path := range []string{"/api/v1/analyses/runs/" + r1 + "/data.csv?view=curve", "/api/v1/analyses/compare.csv?view=curve&item=run:" + r1 + ":Current&item=run:" + r0 + ":Current"} {
		got := ae.call(t, "GET", "analyst", path, nil)
		if got.code != 503 || strings.Contains(got.raw, "annual_loss") || got.hdr.Get("Content-Disposition") != "" {
			t.Errorf("%s with the trail failing: %d %s", path, got.code, got.raw)
		}
	}
	if got := record("analyst", map[string]any{"subject": "run", "id": r1, "view": "curve", "format": "png"}); got.code != 503 || got.body["download_id"] != nil {
		t.Errorf("an image with the trail failing: %d %s", got.code, got.raw)
	}
	if after := ra.adminQuery("SELECT count(*) FROM audit.intake WHERE body ->> 'type' = 'analysis.downloaded'"); after != before {
		t.Errorf("failed downloads recorded: %s then %s", before, after)
	}
}

// D: the downloads' bounds (design §7): at most six items, bodies of 64
// KiB, the views and scales listed.
func TestAnalysisResultViewLimits(t *testing.T) {
	ra := strideF003Fixture(t)
	ae := analysisAPI(t, ra, defaultLimits, true)
	s1 := scenarioAt(t, ra, "analyst", ra.bu["A1"], "Claims ransomware")
	r1 := runWith(t, ae, "analyst", s1, 1, 2000, "7")
	seven := []string{}
	for _, set := range []string{"Current", "Proposed"} {
		seven = append(seven, "run:"+r1+":"+set)
	}
	for i := range 5 {
		seven = append(seven, fmt.Sprintf("aggregate:00000000-0000-4000-8000-%012d", i))
	}
	if got := ae.call(t, "GET", "analyst", compareURL(seven...), nil); got.code != 422 {
		t.Errorf("seven items: %d", got.code)
	}
	if got := ae.call(t, "GET", "analyst", compareCSV("curve", seven...), nil); got.code != 422 {
		t.Errorf("seven items as CSV: %d", got.code)
	}
	if got := ae.call(t, "POST", "analyst", "/api/v1/analyses/downloads", map[string]any{"subject": "comparison", "items": seven, "view": "curve", "format": "png"}); got.code != 422 {
		t.Errorf("seven items recorded: %d", got.code)
	}
	big := strings.Repeat("x", 70<<10)
	if got := ae.call(t, "POST", "analyst", "/api/v1/analyses/downloads", map[string]any{"subject": "run", "id": r1, "view": big, "format": "png"}); got.code != 400 {
		t.Errorf("a body over 64 KiB: %d", got.code)
	}
	long := "run:" + r1 + ":" + strings.Repeat("x", 201)
	if got := ae.call(t, "GET", "analyst", compareURL(long, "run:"+r1+":Current"), nil); got.code != 422 {
		t.Errorf("a set name over 200 characters: %d", got.code)
	}
}
