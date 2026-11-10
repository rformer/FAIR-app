package estimate_test

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/estimate"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// at returns the value at a JSON pointer of a decoded document.
func at(doc any, ptr string) any {
	cur := doc
	for _, p := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[p]
		case []any:
			i, _ := strconv.Atoi(p)
			cur = c[i]
		default:
			return nil
		}
	}
	return cur
}

// F-004 T-05 (AC-01, AC-02): for every valid scenario of the corpus (every
// level combination), the requestable factors are exactly the estimates the
// levels require, each with the unit its estimate has and a definition.
func TestFactorsMatchTaxonomy(t *testing.T) {
	n := 0
	for _, c := range modeltest.Corpus() {
		if !c.Valid || c.Kind != "scenario" {
			continue
		}
		n++
		d, problems := model.Validate("scenario", c.Doc)
		if problems != nil {
			t.Fatalf("%s: %v", c.Name, problems)
		}
		s := d.Value.(*model.Scenario)
		var doc any
		_ = json.Unmarshal(d.Canonical, &doc)
		var entered []string
		for _, node := range model.Taxonomy(s) {
			if node.Status == model.NodeEntered {
				entered = append(entered, node.Pointer)
			}
		}
		var got []string
		for _, f := range estimate.Factors(s) {
			got = append(got, f.Pointer)
			e, _ := at(doc, f.Pointer).(map[string]any)
			if e == nil || e["unit"] != f.Unit {
				t.Errorf("%s: %s unit %q, the document's estimate is %v", c.Name, f.Pointer, f.Unit, e)
			}
			if f.Name == "" || f.Name == f.Factor || len(f.Definition) < 40 || strings.Contains(f.Definition, "%!") {
				t.Errorf("%s: %s is described as %q / %q", c.Name, f.Pointer, f.Name, f.Definition)
			}
			if g, ok := estimate.FactorAt(s, f.Pointer); !ok || g != f {
				t.Errorf("%s: FactorAt(%s) = %+v %v", c.Name, f.Pointer, g, ok)
			}
		}
		if !slices.Equal(got, entered) {
			t.Errorf("%s: factors %v, entered nodes %v", c.Name, got, entered)
		}
	}
	if n < 5 {
		t.Fatalf("only %d valid scenarios in the corpus", n)
	}
	d, _ := model.Validate("scenario", []byte(mustJSON(modeltest.Scenario())))
	if _, ok := estimate.FactorAt(d.Value.(*model.Scenario), "/lef/estimate"); ok {
		t.Fatal("a factor the levels do not use is requestable")
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// AC-02, AC-07: the snapshot holds the chosen context and no estimate.
func TestSnapshot(t *testing.T) {
	d, _ := model.Validate("scenario", []byte(mustJSON(modeltest.Scenario())))
	s := d.Value.(*model.Scenario)
	asset, tc := modeltest.Asset(), modeltest.ThreatCommunity()
	got, err := estimate.Snapshot(s, asset, tc, estimate.ContextFields)
	if err != nil {
		t.Fatal(err)
	}
	b := mustJSON(got)
	for _, want := range []string{`"name":"Ransomware on the claims platform"`, `"asset_type":"Database"`, `"name":"Cyber criminals"`, `"loss_event":`, `"in":"Claims platform production."`} {
		if !strings.Contains(b, want) {
			t.Errorf("snapshot lacks %s: %s", want, b)
		}
	}
	for _, never := range []string{`"min"`, `"ml"`, `"max"`, `"threat_capability"`, `"value"`, `"confidence"`} {
		if strings.Contains(b, never) {
			t.Errorf("snapshot holds %s: %s", never, b)
		}
	}
	if only, _ := estimate.Snapshot(s, asset, tc, []string{"name", "loss_event"}); len(only) != 2 {
		t.Fatalf("chosen fields: %v", only)
	}
	if _, err := estimate.Snapshot(s, asset, tc, []string{"primary_loss"}); err == nil {
		t.Fatal("an estimate shared as context")
	}
}

// AC-12: each warning at its threshold, none on ordinary estimates, and
// warnings never refuse.
func TestWarnings(t *testing.T) {
	r := func(lo, ml, hi string) estimate.Range {
		return estimate.Range{Min: lo, ML: ml, Max: hi, Confidence: "0.9"}
	}
	for _, c := range []struct {
		name, unit string
		r          estimate.Range
		requested  string
		want       []string
	}{
		{"ordinary frequency", model.UnitEventsPerYear, r("2", "6", "12"), "0.9", nil},
		{"ordinary loss", model.UnitCurrency, r("100000", "400000", "2000000"), "", nil},
		{"ordinary probability", model.UnitProbability, r("0.1", "0.3", "0.5"), "", nil},
		{"ordinary percentile", model.UnitPercentile, r("40", "60", "85"), "", nil},
		{"most likely at the minimum", model.UnitEventsPerYear, r("2", "2", "12"), "", []string{estimate.WarnMLAtBound}},
		{"most likely at the maximum", model.UnitPercentile, r("40", "85", "85"), "", []string{estimate.WarnMLAtBound}},
		{"a single value is not at a bound", model.UnitCurrency, r("5", "5", "5"), "", []string{estimate.WarnNarrow}},
		{"narrow frequency", model.UnitEventsPerYear, r("10", "10.5", "10.99"), "", []string{estimate.WarnNarrow}},
		{"frequency just wide enough", model.UnitEventsPerYear, r("10", "10.5", "11"), "", nil},
		{"wide loss", model.UnitCurrency, r("1", "500", "1001"), "", []string{estimate.WarnWide}},
		{"loss just narrow enough", model.UnitCurrency, r("1", "500", "1000"), "", nil},
		{"a zero minimum has no ratio", model.UnitCurrency, r("0", "500", "100000000"), "", nil},
		{"narrow probability", model.UnitProbability, r("0.3", "0.31", "0.315"), "", []string{estimate.WarnNarrow}},
		{"probability reaching 0", model.UnitProbability, r("0", "0.1", "0.4"), "", []string{estimate.WarnCertain}},
		{"probability reaching 1", model.UnitProbability, r("0.5", "0.9", "1"), "", []string{estimate.WarnCertain}},
		{"a fraction may reach 0", model.UnitFraction, r("0", "0.2", "0.4"), "", nil},
		{"narrow percentile", model.UnitPercentile, r("60", "60.5", "61.9"), "", []string{estimate.WarnNarrow}},
		{"wide percentile", model.UnitPercentile, r("5", "50", "96"), "", []string{estimate.WarnWide}},
		{"another confidence", model.UnitEventsPerYear, estimate.Range{Min: "2", ML: "6", Max: "12", Confidence: "0.8"}, "0.9", []string{estimate.WarnOtherConfidence}},
		{"JSON-number spelling", model.UnitEventsPerYear, estimate.Range{Min: "2.0", ML: "6", Max: "1.2e1", Confidence: "0.90"}, "0.9", nil},
	} {
		ws, err := estimate.Warnings(c.unit, c.r, c.requested)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		var got []string
		for _, w := range ws {
			got = append(got, w.Code)
			if w.Message == "" {
				t.Errorf("%s: %s without a message", c.name, w.Code)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: warnings %v, want %v", c.name, got, c.want)
		}
	}
	for _, bad := range []estimate.Range{{Min: "x", ML: "1", Max: "2", Confidence: "0.9"}, {Min: "3", ML: "1", Max: "2", Confidence: "0.9"}} {
		if _, err := estimate.Warnings(model.UnitEventsPerYear, bad, ""); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
	if b := estimate.Bet(r("2", "6", "12")); !strings.Contains(b, "between 2 and 12") || !strings.Contains(b, "90%") {
		t.Fatalf("bet: %s", b)
	}
}

// AC-11: the preview spans the range and is a density.
func TestPreview(t *testing.T) {
	p, err := estimate.PreviewOf(estimate.Range{Min: "2", ML: "6", Max: "12", Confidence: "0.9"}, 200)
	if err != nil || p.Shape != "beta_pert" || len(p.Points) != 201 || p.Points[0][0] != 2 || p.Points[200][0] != 12 {
		t.Fatalf("preview %v %v", p.Shape, err)
	}
	area, peak := 0.0, 0.0
	for i := 1; i < len(p.Points); i++ {
		area += (p.Points[i][0] - p.Points[i-1][0]) * (p.Points[i][1] + p.Points[i-1][1]) / 2
		if p.Points[i][1] > p.Points[int(peak)][1] {
			peak = float64(i)
		}
	}
	if math.Abs(area-1) > 0.01 {
		t.Fatalf("area %v", area)
	}
	if x := p.Points[int(peak)][0]; math.Abs(x-6) > 0.2 {
		t.Fatalf("mode at %v, want near 6", x)
	}
	if p, _ := estimate.PreviewOf(estimate.Range{Min: "5", ML: "5", Max: "5", Confidence: "0.9"}, 10); p.Shape != "point" {
		t.Fatalf("a single value: %v", p.Shape)
	}
}
