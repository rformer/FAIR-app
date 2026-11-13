package analysis

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
)

// F-006 T-03 (F-006-AC-18; design §3.3): data downloads as CSV. RFC 4180,
// UTF-8 with a byte-order mark, CRLF; a metadata block of key,value rows,
// a blank row, then the table. Text cells that a spreadsheet would read as
// a formula are neutralized; numbers are written by the service from
// float64 and never come from a user's text, so a negative number stays a
// number.

// Cell is a CSV cell: text, a number, or empty.
type Cell struct {
	text  string
	num   float64
	isNum bool
}

// Text is a text cell (neutralized when written).
func Text(s string) Cell { return Cell{text: s} }

// Num is a number cell.
func Num(v float64) Cell { return Cell{num: v, isNum: true} }

// Empty is an empty cell.
var Empty = Cell{}

// numOf is a number cell from a decoded JSON value, or empty.
func numOf(v any) Cell {
	switch x := v.(type) {
	case float64:
		return Num(x)
	case bool:
		if x {
			return Num(1)
		}
		return Num(0)
	}
	return Empty
}

func (c Cell) String() string {
	if c.isNum {
		if math.IsNaN(c.num) || math.IsInf(c.num, 0) {
			return ""
		}
		return strconv.FormatFloat(c.num, 'g', -1, 64)
	}
	return Neutralize(c.text)
}

// Neutralize makes a text cell inert in spreadsheets: one beginning with
// =, +, -, @, a tab or a carriage return gets a leading apostrophe.
func Neutralize(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// Table is a CSV download: its metadata rows, header and rows.
type Table struct {
	Meta   [][2]string
	Header []string
	Rows   [][]Cell
}

// Write writes the table.
func (t Table) Write(w io.Writer) error {
	var b bytes.Buffer
	b.WriteString("\uFEFF")
	cw := csv.NewWriter(&b)
	cw.UseCRLF = true
	for _, m := range t.Meta {
		if err := cw.Write([]string{Neutralize(m[0]), Neutralize(m[1])}); err != nil {
			return err
		}
	}
	if err := cw.Write([]string{""}); err != nil {
		return err
	}
	header := make([]string, len(t.Header))
	for i, h := range t.Header {
		header[i] = Neutralize(h)
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, r := range t.Rows {
		row := make([]string, len(r))
		for i, c := range r {
			row[i] = c.String()
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return err
	}
	_, err := w.Write(b.Bytes())
	return err
}

// Summary is a decoded stored summary (F-005 design §3.4).
type Summary = map[string]any

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// flatten lists a summary's numeric and boolean leaves as (dotted path,
// value), sorted by path; an interval [low, high] gives .low and .high.
func flatten(prefix string, v any, out *[][2]any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, x[k], out)
		}
	case []any:
		if len(x) == 2 {
			flatten(prefix+".low", x[0], out)
			flatten(prefix+".high", x[1], out)
		}
	case float64, bool, nil:
		*out = append(*out, [2]any{prefix, x})
	}
}

// Set is a control set's stored summary.
type Set struct {
	Name    string
	Summary Summary
}

// SummaryTable lists, per set, every statistic of the ALE, LEF, loss per
// event and convergence summaries.
func SummaryTable(sets []Set) ([]string, [][]Cell) {
	var rows [][]Cell
	for _, s := range sets {
		for _, q := range []string{"ale", "lef", "loss_per_event", "convergence"} {
			if s.Summary[q] == nil {
				continue
			}
			var leaves [][2]any
			flatten("", s.Summary[q], &leaves)
			for _, l := range leaves {
				rows = append(rows, []Cell{Text(s.Name), Text(q), Text(l[0].(string)), numOf(l[1])})
			}
		}
	}
	return []string{"control_set", "quantity", "statistic", "value"}, rows
}

// CurveTable lists each set's loss exceedance curve points.
func CurveTable(sets []Set) ([]string, [][]Cell) {
	var rows [][]Cell
	for _, s := range sets {
		pts, _ := obj(s.Summary["curve"])["points"].([]any)
		for _, p := range pts {
			xy, _ := p.([]any)
			if len(xy) == 2 {
				rows = append(rows, []Cell{Text(s.Name), numOf(xy[0]), numOf(xy[1])})
			}
		}
	}
	return []string{"control_set", "annual_loss", "probability_of_exceeding"}, rows
}

// BreakdownTable lists each set's mean annual loss by part, with its share
// of the total (primary plus secondary).
func BreakdownTable(sets []Set) ([]string, [][]Cell) {
	var rows [][]Cell
	for _, s := range sets {
		b := obj(s.Summary["breakdown"])
		p, _ := b["primary"].(float64)
		q, _ := b["secondary"].(float64)
		total := p + q
		share := func(v any) Cell {
			x, ok := v.(float64)
			if !ok || total == 0 {
				return Empty
			}
			return Num(x / total)
		}
		for _, part := range []string{"primary", "secondary"} {
			rows = append(rows, []Cell{Text(s.Name), Text(part), Text(part), numOf(b[part]), share(b[part])})
		}
		for _, group := range []struct{ key, part string }{{"forms", "form"}, {"stakeholders", "stakeholder_group"}} {
			m := obj(b[group.key])
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				rows = append(rows, []Cell{Text(s.Name), Text(group.part), Text(k), numOf(m[k]), share(m[k])})
			}
		}
	}
	return []string{"control_set", "part", "name", "mean_annual_loss", "share_of_total"}, rows
}

// SensitivityTable lists a set's inputs from the strongest (F-005 §3.4).
func SensitivityTable(s Set) ([]string, [][]Cell) {
	var rows [][]Cell
	inputs, _ := obj(s.Summary["sensitivity"])["inputs"].([]any)
	str := func(v any) Cell {
		if x, ok := v.(string); ok {
			return Text(x)
		}
		return Empty
	}
	for _, in := range inputs {
		m := obj(in)
		lo, hi := obj(m["low"]), obj(m["high"])
		rows = append(rows, []Cell{Text(s.Name), str(m["input"]), str(m["pointer"]), str(m["kind"]), str(m["control"]), str(m["factor"]),
			numOf(lo["value"]), numOf(lo["mean"]), numOf(lo["change"]), numOf(hi["value"]), numOf(hi["mean"]), numOf(hi["change"]),
			numOf(m["swing"]), numOf(m["spearman"])})
	}
	return []string{"control_set", "input", "pointer", "kind", "control", "factor", "low_value", "low_mean", "low_change",
		"high_value", "high_mean", "high_change", "swing", "spearman"}, rows
}

// ComparisonTable lists each set's differences from the current set
// (AC-09): mean and percentiles, and the per-year difference's summary.
func ComparisonTable(sets []Set) ([]string, [][]Cell) {
	var rows [][]Cell
	for _, s := range sets {
		c := obj(s.Summary["comparison"])
		if c == nil {
			continue
		}
		against, _ := c["against"].(string)
		var leaves [][2]any
		flatten("", map[string]any{"mean": c["mean"], "percentiles": c["percentiles"], "difference": c["difference"]}, &leaves)
		for _, l := range leaves {
			rows = append(rows, []Cell{Text(s.Name), Text(against), Text(l[0].(string)), numOf(l[1])})
		}
	}
	return []string{"control_set", "against", "statistic", "value"}, rows
}

// HistogramTable lists a histogram's bins, then its years outside them.
func HistogramTable(set, relativeTo string, h Histogram) ([]string, [][]Cell) {
	var rows [][]Cell
	for i, c := range h.Counts {
		rows = append(rows, []Cell{Text(set), Text(relativeTo), Text("bin"), Num(h.Edges[i]), Num(h.Edges[i+1]), Num(float64(c))})
	}
	zero := "no_loss"
	if relativeTo != "" {
		zero = "no_difference"
	}
	rows = append(rows, []Cell{Text(set), Text(relativeTo), Text(zero), Empty, Empty, Num(float64(h.Zero))})
	if h.BothNone != nil {
		rows = append(rows, []Cell{Text(set), Text(relativeTo), Text("neither_lost"), Empty, Empty, Num(float64(*h.BothNone))})
	}
	return []string{"control_set", "relative_to", "kind", "bin_low", "bin_high", "years"}, rows
}

// ContributionsTable lists an aggregate's members' contributions.
func ContributionsTable(s Summary) ([]string, [][]Cell) {
	var rows [][]Cell
	cs, _ := s["contributions"].([]any)
	for _, c := range cs {
		m := obj(c)
		label, _ := m["label"].(string)
		rows = append(rows, []Cell{numOf(m["position"]), Text(label), numOf(m["mean"]), numOf(m["share_of_p95_year"])})
	}
	return []string{"position", "member", "mean_annual_loss", "share_of_p95_year"}, rows
}

// ComparisonSummaryTable lists a comparison's items with their ALE
// statistics and differences from the first.
func ComparisonSummaryTable(c map[string]any) ([]string, [][]Cell) {
	var rows [][]Cell
	items, _ := c["items"].([]map[string]any)
	for i, it := range items {
		label, _ := it["label"].(string)
		var leaves [][2]any
		flatten("", it["ale"], &leaves)
		diff := obj(it["differences"])
		for _, l := range leaves {
			name := l[0].(string)
			var d map[string]any
			if name == "mean" {
				d = obj(diff["mean"])
			} else if p, ok := strings.CutPrefix(name, "percentiles."); ok {
				d = obj(obj(diff["percentiles"])[p])
			}
			rows = append(rows, []Cell{Num(float64(i + 1)), Text(label), Text(name), numOf(l[1]), numOf(d["amount"]), numOf(d["share"])})
		}
	}
	return []string{"item", "label", "statistic", "value", "difference_from_first", "difference_share"}, rows
}

// ComparisonCurveTable lists each item's curve points.
func ComparisonCurveTable(c map[string]any) ([]string, [][]Cell) {
	var rows [][]Cell
	items, _ := c["items"].([]map[string]any)
	for i, it := range items {
		label, _ := it["label"].(string)
		pts, _ := obj(it["curve"])["points"].([]any)
		for _, p := range pts {
			xy, _ := p.([]any)
			if len(xy) == 2 {
				rows = append(rows, []Cell{Num(float64(i + 1)), Text(label), numOf(xy[0]), numOf(xy[1])})
			}
		}
	}
	return []string{"item", "label", "annual_loss", "probability_of_exceeding"}, rows
}

// FileName is a download's ASCII file name: no user text.
func FileName(subject, id, view, ext string) string {
	short := id
	if len(short) > 8 {
		short = short[:8]
	}
	return fmt.Sprintf("%s-%s-%s.%s", subject, short, view, ext)
}
