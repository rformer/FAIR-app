package reports

import (
	"fmt"
	"math/big"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/report"
	"github.com/rformer/fair-app/internal/report/chart"
	"github.com/rformer/fair-app/internal/reports/doc"
)

// PDF renders a report document as PDF/UA-1 (F-010-AC-12, design §3.5):
// the title, what the report is (scope, filters, who and when, the data's
// time, the currency, what it leaves out), its sections, and the analyses
// its figures come from. Characters the fonts lack are noted.
func PDF(d doc.Document) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	m := d.Metadata
	out := report.Doc{Title: m.Title, Author: m.GeneratedBy, Subject: "FAIR report: " + m.Kind, Created: m.GeneratedAt, Marking: m.Marking}
	add := func(b report.Block) { out.Blocks = append(out.Blocks, b) }
	add(report.Block{Kind: report.Heading, Level: 1, Text: m.Title})
	about := [][]string{
		{"Business unit", m.BU.Name + " and the business units below it"},
		{"Generated", stamp(m.GeneratedAt) + " by " + m.GeneratedBy},
		{"Data as of", stamp(m.DataAsOf)},
		{"Currency", m.Currency},
	}
	if len(m.Filters) > 0 {
		keys := make([]string, 0, len(m.Filters))
		for k := range m.Filters {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = strings.ReplaceAll(k, "_", " ") + ": " + m.Filters[k]
		}
		about = append(about, []string{"Filters", strings.Join(parts, "; ")})
	}
	if lo := leftOut(m.LeftOut); lo != "" {
		about = append(about, []string{"Left out", lo})
	}
	add(report.Block{Kind: report.TableBlock, Table: &report.Table{Caption: "About this report", NoHeader: true, RowHeaders: true,
		Columns: []report.Column{{Title: "Item", Weight: 1}, {Title: "Value", Weight: 4}}, Rows: about}})
	notes := slices.Clone(m.Notes)
	if miss := report.Missing(texts(d)...); len(miss) > 0 {
		codes := make([]string, len(miss))
		for i, r := range miss {
			codes[i] = fmt.Sprintf("U+%04X", r)
		}
		notes = append(notes, "Some characters cannot be shown in this file's font and are drawn as a replacement mark: "+strings.Join(codes, ", ")+".")
	}
	if len(notes) > 0 {
		add(report.Block{Kind: report.List, Items: notes})
	}
	level := 1
	for _, s := range d.Sections {
		lv := min(s.Level+1, 3, level+1)
		level = lv
		add(report.Block{Kind: report.Heading, Level: lv, Text: s.Heading})
		for _, b := range s.Blocks {
			switch b.Kind {
			case doc.KindParagraph:
				add(report.Block{Kind: report.Paragraph, Text: b.Text})
			case doc.KindList:
				add(report.Block{Kind: report.List, Items: b.Items})
			case doc.KindPairs:
				rows := make([][]string, len(b.Pairs))
				for i, p := range b.Pairs {
					rows[i] = []string{p.Label, p.Value}
				}
				add(report.Block{Kind: report.TableBlock, Table: &report.Table{NoHeader: true, RowHeaders: true,
					Columns: []report.Column{{Title: "Item", Weight: 1}, {Title: "Value", Weight: 3}}, Rows: rows}})
			case doc.KindTable:
				add(report.Block{Kind: report.TableBlock, Table: pdfTable(b.Table, m.Currency)})
			case doc.KindChart:
				// ADR-015: vector charts; a chart whose data cannot be drawn
				// stays a blank figure, its data table and alternative text
				// carrying it.
				height := 220.0
				if b.Chart.Kind == doc.ChartBars { // a row per bar
					height = min(220, 50+18*float64(len(b.Chart.Data.Rows)))
				}
				add(report.Block{Kind: report.FigureBlock, Figure: &report.Figure{Alt: b.Chart.Alt, Caption: b.Chart.Title, Height: height, Draw: chart.Draw(b.Chart)}})
				add(report.Block{Kind: report.TableBlock, Table: pdfTable(b.Chart.Data, m.Currency)})
			}
		}
	}
	if len(m.Runs) > 0 {
		add(report.Block{Kind: report.Heading, Level: 2, Text: "Analyses used"})
		rows := make([][]string, len(m.Runs))
		for i, r := range m.Runs {
			rows[i] = []string{r.Scenario, r.ID, r.EngineVersion, r.Seed, r.InputDigest}
		}
		add(report.Block{Kind: report.TableBlock, Table: &report.Table{Caption: "The simulation runs this report's figures come from (each reproducible from its seed and input digest)",
			Columns: []report.Column{{Title: "Scenario", Weight: 2}, {Title: "Run", Weight: 2.2}, {Title: "Engine", Weight: 0.7}, {Title: "Seed", Weight: 1.2},
				{Title: "Input digest", Weight: 3.6}}, Rows: rows}})
	}
	return out.PDF()
}

func pdfTable(t *doc.Table, currency string) *report.Table {
	cols := make([]report.Column, len(t.Columns))
	for i, c := range t.Columns {
		w := c.Width
		if w <= 0 {
			w = 1
		}
		title := c.Title
		if c.Type == doc.ColAmount {
			title += " (" + currency + ")"
		}
		cols[i] = report.Column{Title: title, Weight: w, Right: c.Type == doc.ColAmount || c.Type == doc.ColNumber || c.Type == doc.ColPercent}
	}
	rows := make([][]string, len(t.Rows))
	for i, r := range t.Rows {
		rows[i] = make([]string, len(r))
		for j, cell := range r {
			rows[i][j] = Display(t.Columns[j].Type, cell)
		}
	}
	return &report.Table{Caption: t.Caption, Columns: cols, Rows: rows}
}

// Display formats a cell for reading: amounts and numbers with thousands
// separators, percents as percentages (two decimals at most), times in
// UTC to the minute.
func Display(typ, cell string) string {
	if cell == "" {
		return ""
	}
	switch typ {
	case doc.ColAmount, doc.ColNumber:
		return group(cell)
	case doc.ColPercent:
		r, ok := new(big.Rat).SetString(cell)
		if !ok {
			return cell
		}
		r.Mul(r, big.NewRat(100, 1))
		s := strings.TrimRight(strings.TrimRight(r.FloatString(2), "0"), ".")
		return group(s) + "%"
	case doc.ColTime:
		if t, err := time.Parse(time.RFC3339, cell); err == nil {
			return stamp(t)
		}
	}
	return cell
}

// group puts thousands separators into a decimal string.
func group(s string) string {
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	in, frac, _ := strings.Cut(s, ".")
	var b strings.Builder
	for i, c := range in {
		if i > 0 && (len(in)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if frac != "" {
		return sign + b.String() + "." + frac
	}
	return sign + b.String()
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

var leftOutLabels = map[string]string{"not_visible": "not visible to you", "restricted": "in restricted business units (by their roll-up mode)",
	"unquantified": "without a quantified analysis", "stale": "with a stale analysis"}

func leftOut(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k, n := range m {
		if n > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		label := leftOutLabels[k]
		if label == "" {
			label = strings.ReplaceAll(k, "_", " ")
		}
		parts[i] = fmt.Sprintf("%d risks %s", m[k], label)
	}
	return strings.Join(parts, "; ")
}

// texts is every piece of text the document shows.
func texts(d doc.Document) []string {
	m := d.Metadata
	out := []string{m.Title, m.GeneratedBy, m.BU.Name, m.Marking}
	out = append(out, m.Notes...)
	for k, v := range m.Filters {
		out = append(out, k, v)
	}
	for _, r := range m.Runs {
		out = append(out, r.Scenario)
	}
	for _, s := range d.Sections {
		out = append(out, s.Heading)
		for _, b := range s.Blocks {
			out = append(out, b.Text)
			out = append(out, b.Items...)
			for _, p := range b.Pairs {
				out = append(out, p.Label, p.Value)
			}
			if b.Chart != nil {
				out = append(out, b.Chart.Title, b.Chart.Alt)
			}
		}
	}
	for _, t := range d.Tables() {
		out = append(out, t.Caption)
		for _, c := range t.Columns {
			out = append(out, c.Title)
		}
		for _, r := range t.Rows {
			out = append(out, r...)
		}
	}
	return out
}
