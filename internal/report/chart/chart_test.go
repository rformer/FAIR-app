package chart

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/report"
	"github.com/rformer/fair-app/internal/reports/doc"
	"github.com/rformer/fair-app/internal/reports/doc/doctest"
)

// ADR-015: the scales agree with web/src/charts/scale.ts through the
// shared vectors (scripts/chart-vectors.mjs writes them from the web side).
func TestScalesMatchTheWeb(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "scales.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		NiceStep    [][3]float64         `json:"nice_step"`
		LinearTicks [][4]json.RawMessage `json:"linear_ticks"`
		LogTicks    [][4]json.RawMessage `json:"log_ticks"`
		LinearMap   [][6]float64         `json:"linear_map"`
		LogMap      [][6]float64         `json:"log_map"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	closeTo := func(a, b float64) bool { return math.Abs(a-b) <= 1e-9*math.Max(1, math.Abs(b)) }
	for _, c := range v.NiceStep {
		if got := NiceStep(c[0], int(c[1])); got != c[2] {
			t.Errorf("NiceStep(%v, %v) = %v, want %v", c[0], c[1], got, c[2])
		}
	}
	ticks := func(name string, cases [][4]json.RawMessage, f func(a, b float64, n int) []float64) {
		for _, c := range cases {
			var a, bb, n float64
			var want []float64
			_ = json.Unmarshal(c[0], &a)
			_ = json.Unmarshal(c[1], &bb)
			_ = json.Unmarshal(c[2], &n)
			_ = json.Unmarshal(c[3], &want)
			got := f(a, bb, int(n))
			ok := len(got) == len(want)
			for i := range min(len(got), len(want)) {
				ok = ok && closeTo(got[i], want[i])
			}
			if !ok {
				t.Errorf("%s(%v, %v, %v) = %v, want %v", name, a, bb, n, got, want)
			}
		}
	}
	ticks("LinearTicks", v.LinearTicks, LinearTicks)
	ticks("LogTicks", v.LogTicks, LogTicks)
	for _, c := range v.LinearMap {
		if got := Linear([2]float64{c[0], c[1]}, [2]float64{c[2], c[3]}).Map(c[4]); !closeTo(got, c[5]) {
			t.Errorf("linear %v: %v", c, got)
		}
	}
	for _, c := range v.LogMap {
		s, ok := LogScale([2]float64{c[0], c[1]}, [2]float64{c[2], c[3]})
		if got := s.Map(c[4]); !ok || !closeTo(got, c[5]) {
			t.Errorf("log %v: %v", c, got)
		}
	}
	if _, ok := LogScale([2]float64{0, 10}, [2]float64{0, 1}); ok {
		t.Error("a log scale over zero")
	}
}

func TestFormats(t *testing.T) {
	for v, want := range map[float64]string{2_100_000: "2.1M", 950: "950", 1500: "1.5K", 12_345: "12.3K", 1e9: "1B", 3.2e12: "3.2T", 0: "0", -2500: "-2.5K"} {
		if got := Compact(v); got != want {
			t.Errorf("Compact(%v) = %q, want %q", v, got, want)
		}
	}
	for p, want := range map[float64]string{0.1: "10%", 0.0123: "1.2%", 0.00001: "<0.01%", 1: "100%", 0: "0%", 0.5: "50%"} {
		if got := Percent(p); got != want {
			t.Errorf("Percent(%v) = %q, want %q", p, got, want)
		}
	}
}

// Every chart kind draws: its legend and tick labels are text in the
// figure; data it cannot draw gives no drawing.
func TestDraw(t *testing.T) {
	d := doctest.Charts()
	var charts []*doc.Chart
	for _, s := range d.Sections {
		for _, b := range s.Blocks {
			if b.Chart != nil {
				charts = append(charts, b.Chart)
			}
		}
	}
	if len(charts) != 4 {
		t.Fatalf("%d charts", len(charts))
	}
	for _, ch := range charts {
		draw := Draw(ch)
		if draw == nil {
			t.Fatalf("%s: no drawing", ch.Title)
		}
		pdf, err := report.Doc{Title: ch.Title, Blocks: []report.Block{{Kind: report.FigureBlock, Figure: &report.Figure{Alt: ch.Alt, Height: 220, Draw: draw}}}}.PDF()
		if err != nil {
			t.Fatal(err)
		}
		text, err := report.Text(pdf, true)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(text, "\n")
		for _, s := range ch.Series {
			if !slices.Contains(lines, s.Name) {
				t.Errorf("%s: no legend for %s in %q", ch.Title, s.Name, lines)
			}
		}
		switch {
		case ch.Kind == doc.ChartExceedance && len(ch.Series) == 2:
			for _, want := range []string{"10K", "100K", "1M", "10M", "0%", "100%", "Annual loss"} {
				if !slices.Contains(lines, want) {
					t.Errorf("exceedance: no %q tick in %q", want, lines)
				}
			}
		case ch.Kind == doc.ChartBars:
			if !strings.Contains(text, "Ransomware on claims") || !strings.Contains(text, "…") || !slices.Contains(lines, "1M") {
				t.Errorf("bars: %q", lines)
			}
		}
	}
	bars := charts[3]
	for name, ch := range map[string]*doc.Chart{
		"no data":         {Kind: doc.ChartExceedance, XKey: "x", Series: []doc.Ref{{ID: "y"}}},
		"an unknown axis": {Kind: doc.ChartBars, XKey: "nope", Series: []doc.Ref{{ID: "mean"}}, Data: bars.Data},
		"an unknown kind": {Kind: "pie", XKey: "risk", Series: []doc.Ref{{ID: "mean"}}, Data: bars.Data},
	} {
		if Draw(ch) != nil {
			t.Errorf("%s: drawn", name)
		}
	}
	// Text in the data reaches the figure as text, not as operators.
	ch := *bars
	data := *ch.Data
	data.Rows = [][]string{{") Tj (evil", "100"}}
	ch.Data = &data
	pdf, err := report.Doc{Title: "x", Blocks: []report.Block{{Kind: report.FigureBlock, Figure: &report.Figure{Alt: "x", Draw: Draw(&ch)}}}}.PDF()
	if err != nil {
		t.Fatal(err)
	}
	if text, _ := report.Text(pdf, true); !strings.Contains(text, ") Tj (evil") {
		t.Errorf("label %q", text)
	}
}
