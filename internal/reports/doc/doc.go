// Package doc is F-010's report document (design §1, §3.5): one model,
// built from one consistent read of the data, from which every format is
// rendered (PDF in internal/report; CSV and JSON here), so the formats agree.
//
// Values are text. Numbers are canonical decimal strings (F-003's canon),
// never JSON numbers or floats, so a document renders identically wherever
// it is rendered, and its JSON form is canonical.
package doc

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// Format is the JSON format's name and version.
const Format = "fair.report.v1"

// Limits on a document (design §3.6: files at most 100 MiB; these keep a
// document well inside).
const (
	MaxSections  = 500
	MaxTables    = 1000
	MaxRows      = 200_000 // per table
	MaxColumns   = 40
	MaxCellRunes = 4000
)

// Document is a report.
type Document struct {
	Metadata Metadata  `json:"metadata"`
	Sections []Section `json:"sections"`
}

// Metadata is what every report states about itself (F-010-AC-10, AC-11).
type Metadata struct {
	RunID       string            `json:"run_id"`
	Kind        string            `json:"kind"` // register, portfolio, acceptances, treatment, risk
	Title       string            `json:"title"`
	BU          Ref               `json:"bu"`
	Filters     map[string]string `json:"filters"`
	GeneratedAt time.Time         `json:"generated_at"`
	GeneratedBy string            `json:"generated_by"` // the requester's display name
	DataAsOf    time.Time         `json:"data_as_of"`
	Currency    string            `json:"currency"`
	Marking     string            `json:"marking"`
	Runs        []RunRef          `json:"runs"`     // the analysis runs the figures come from
	LeftOut     map[string]int    `json:"left_out"` // not_visible, restricted, unquantified, ...
	Notes       []string          `json:"notes"`
}

// Ref names an item.
type Ref struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RunRef is one analysis run used (F-005's identifiers and digests).
type RunRef struct {
	ID            string `json:"id"`
	Scenario      string `json:"scenario"`
	EngineVersion string `json:"engine_version"`
	Seed          string `json:"seed"`
	InputDigest   string `json:"input_digest"`
}

// Section is a heading (level 1 to 3) and its blocks.
type Section struct {
	Heading string  `json:"heading"`
	Level   int     `json:"level"`
	Blocks  []Block `json:"blocks"`
}

// Block kinds.
const (
	KindParagraph = "paragraph"
	KindList      = "list"
	KindPairs     = "pairs"
	KindTable     = "table"
	KindChart     = "chart"
)

// Block is one of a paragraph, a list, key-value pairs, a table or a chart.
type Block struct {
	Kind  string   `json:"kind"`
	Text  string   `json:"text,omitempty"`
	Items []string `json:"items,omitempty"`
	Pairs []Pair   `json:"pairs,omitempty"`
	Table *Table   `json:"table,omitempty"`
	Chart *Chart   `json:"chart,omitempty"`
}

// Pair is a label and its value.
type Pair struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Column types: text is neutralized in CSV; the others hold canonical
// decimal strings (amount, number, percent), dates (YYYY-MM-DD) or times
// (RFC 3339), or are empty.
const (
	ColText    = "text"
	ColAmount  = "amount" // in the document's currency
	ColNumber  = "number"
	ColPercent = "percent" // a fraction, 0.25 for 25%
	ColDate    = "date"
	ColTime    = "time"
)

// Column is a table column.
type Column struct {
	Key   string  `json:"key"`
	Title string  `json:"title"`
	Type  string  `json:"type"`
	Width float64 `json:"-"` // a PDF layout hint, not part of the format
}

// Table is a captioned table; ID names it uniquely in the document (and
// its CSV file).
type Table struct {
	ID      string     `json:"id"`
	Caption string     `json:"caption"`
	Columns []Column   `json:"columns"`
	Rows    [][]string `json:"rows"`
}

// Chart kinds (ADR-015).
const (
	ChartExceedance = "exceedance"
	ChartHistogram  = "histogram"
	ChartBars       = "bars"
)

// Chart is a figure: its kind, title, alternative text and the data table
// it draws (which every format carries, F-010-AC-12).
type Chart struct {
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Alt    string `json:"alt"`
	Log    bool   `json:"log,omitempty"` // a logarithmic amount axis
	Data   *Table `json:"data"`
	XKey   string `json:"x"`      // the column on the x axis (or the bars' labels)
	Series []Ref  `json:"series"` // ID: the column of each series; Name: its label
}

var (
	idRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	dateRE    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	kinds     = []string{"register", "portfolio", "acceptances", "treatment", "risk"}
	colTypes  = []string{ColText, ColAmount, ColNumber, ColPercent, ColDate, ColTime}
	chartKind = []string{ChartExceedance, ChartHistogram, ChartBars}
)

// Validate checks a document: its metadata, every block's shape, every
// table's cells against their column types, unique table ids, and charts
// whose series and axis name their data table's columns.
func (d Document) Validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf("doc: "+f, a...)) }
	m := d.Metadata
	if !slices.Contains(kinds, m.Kind) {
		bad("unknown kind %q", m.Kind)
	}
	for name, v := range map[string]string{"run_id": m.RunID, "title": m.Title, "bu": m.BU.ID, "generated_by": m.GeneratedBy, "marking": m.Marking} {
		if v == "" {
			bad("metadata %s is required", name)
		}
	}
	if utf8.RuneCountInString(m.Marking) > 60 {
		bad("the marking is longer than 60 characters")
	}
	if m.GeneratedAt.IsZero() || m.DataAsOf.IsZero() {
		bad("generated_at and data_as_of are required")
	}
	if len(m.Currency) != 3 {
		bad("currency %q is not an ISO 4217 code", m.Currency)
	}
	if len(d.Sections) > MaxSections {
		bad("%d sections, at most %d", len(d.Sections), MaxSections)
	}
	ids := map[string]bool{}
	tables := 0
	checkTable := func(where string, t *Table) {
		tables++
		if !idRE.MatchString(t.ID) {
			bad("%s: table id %q", where, t.ID)
		} else if ids[t.ID] {
			bad("%s: table id %q used twice", where, t.ID)
		}
		ids[t.ID] = true
		if t.Caption == "" {
			bad("table %s: a caption is required", t.ID)
		}
		if len(t.Columns) == 0 || len(t.Columns) > MaxColumns {
			bad("table %s: %d columns", t.ID, len(t.Columns))
		}
		keys := map[string]bool{}
		for _, c := range t.Columns {
			if !idRE.MatchString(c.Key) || keys[c.Key] || c.Title == "" || !slices.Contains(colTypes, c.Type) {
				bad("table %s: column %+v", t.ID, c)
			}
			keys[c.Key] = true
		}
		if len(t.Rows) > MaxRows {
			bad("table %s: %d rows, at most %d", t.ID, len(t.Rows), MaxRows)
		}
		for i, r := range t.Rows {
			if len(r) != len(t.Columns) {
				bad("table %s row %d: %d cells for %d columns", t.ID, i, len(r), len(t.Columns))
				continue
			}
			for j, cell := range r {
				if err := checkCell(t.Columns[j].Type, cell); err != nil {
					bad("table %s row %d %s: %v", t.ID, i, t.Columns[j].Key, err)
				}
			}
		}
	}
	for si, s := range d.Sections {
		where := fmt.Sprintf("section %d", si)
		if s.Heading == "" || s.Level < 1 || s.Level > 3 {
			bad("%s: heading %q at level %d", where, s.Heading, s.Level)
		}
		for bi, b := range s.Blocks {
			w := fmt.Sprintf("%s block %d", where, bi)
			switch b.Kind {
			case KindParagraph:
				if b.Text == "" {
					bad("%s: an empty paragraph", w)
				}
			case KindList:
				if len(b.Items) == 0 {
					bad("%s: an empty list", w)
				}
			case KindPairs:
				if len(b.Pairs) == 0 {
					bad("%s: no pairs", w)
				}
			case KindTable:
				if b.Table == nil {
					bad("%s: no table", w)
					continue
				}
				checkTable(w, b.Table)
			case KindChart:
				c := b.Chart
				if c == nil || c.Data == nil {
					bad("%s: a chart needs its data table", w)
					continue
				}
				if !slices.Contains(chartKind, c.Kind) || c.Title == "" || c.Alt == "" || len(c.Series) == 0 {
					bad("%s: chart %q needs a kind, title, alternative text and series", w, c.Title)
				}
				checkTable(w, c.Data)
				cols := map[string]bool{}
				for _, col := range c.Data.Columns {
					cols[col.Key] = true
				}
				if !cols[c.XKey] {
					bad("%s: chart axis %q is not a column", w, c.XKey)
				}
				for _, s := range c.Series {
					if !cols[s.ID] || s.Name == "" {
						bad("%s: chart series %+v", w, s)
					}
				}
			default:
				bad("%s: unknown block kind %q", w, b.Kind)
			}
		}
	}
	if tables > MaxTables {
		bad("%d tables, at most %d", tables, MaxTables)
	}
	return errors.Join(errs...)
}

func checkCell(typ, cell string) error {
	if utf8.RuneCountInString(cell) > MaxCellRunes {
		return fmt.Errorf("longer than %d characters", MaxCellRunes)
	}
	if !utf8.ValidString(cell) {
		return errors.New("not UTF-8")
	}
	if cell == "" || typ == ColText {
		return nil
	}
	switch typ {
	case ColAmount, ColNumber, ColPercent:
		c, err := canon.Decimal(cell)
		if err != nil || c != cell {
			return fmt.Errorf("%q is not a canonical decimal", cell)
		}
	case ColDate:
		if _, err := time.Parse("2006-01-02", cell); err != nil || !dateRE.MatchString(cell) {
			return fmt.Errorf("%q is not a date", cell)
		}
	case ColTime:
		if _, err := time.Parse(time.RFC3339, cell); err != nil {
			return fmt.Errorf("%q is not an RFC 3339 time", cell)
		}
	}
	return nil
}

// Tables returns every table in order, charts' data tables included.
func (d Document) Tables() []*Table {
	var out []*Table
	for _, s := range d.Sections {
		for _, b := range s.Blocks {
			switch {
			case b.Kind == KindTable && b.Table != nil:
				out = append(out, b.Table)
			case b.Kind == KindChart && b.Chart != nil && b.Chart.Data != nil:
				out = append(out, b.Chart.Data)
			}
		}
	}
	return out
}
