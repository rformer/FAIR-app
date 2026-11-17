package doc

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// file is the JSON form: the document with its format.
type file struct {
	Format   string    `json:"format"`
	Metadata Metadata  `json:"metadata"`
	Sections []Section `json:"sections"`
}

// normalized gives empty collections their empty form and times their UTC
// second, so equal documents render to equal bytes.
func (d Document) normalized() Document {
	m := d.Metadata
	m.GeneratedAt, m.DataAsOf = m.GeneratedAt.UTC().Truncate(time.Second), m.DataAsOf.UTC().Truncate(time.Second)
	if m.Filters == nil {
		m.Filters = map[string]string{}
	}
	if m.LeftOut == nil {
		m.LeftOut = map[string]int{}
	}
	if m.Runs == nil {
		m.Runs = []RunRef{}
	}
	if m.Notes == nil {
		m.Notes = []string{}
	}
	out := Document{Metadata: m, Sections: make([]Section, len(d.Sections))}
	fix := func(t *Table) *Table {
		if t == nil {
			return nil
		}
		c := *t
		if c.Rows == nil {
			c.Rows = [][]string{}
		}
		return &c
	}
	for i, s := range d.Sections {
		s.Blocks = append([]Block{}, s.Blocks...)
		for j, b := range s.Blocks {
			b.Table = fix(b.Table)
			if b.Chart != nil {
				ch := *b.Chart
				ch.Data = fix(ch.Data)
				b.Chart = &ch
			}
			s.Blocks[j] = b
		}
		out.Sections[i] = s
	}
	return out
}

// JSON renders the document as fair.report.v1, canonical (F-003's canon:
// sorted keys, no floats), after validating it.
func (d Document) JSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	n := d.normalized()
	raw, err := json.Marshal(file{Format: Format, Metadata: n.Metadata, Sections: n.Sections})
	if err != nil {
		return nil, err
	}
	return canon.Canonicalize(raw)
}

// CSV renders the document's tables (charts' data tables included) as a
// ZIP of NNN-<table id>.csv, one per table, and manifest.json (the
// metadata). Each CSV is UTF-8 with a byte-order mark, starts with the
// marking, then the column titles and the rows. Text cells a spreadsheet
// would run as a formula get a leading apostrophe; the other cells are
// validated decimals, dates or times. Deterministic for a given document.
func (d Document) CSV() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	n := d.normalized()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	add := func(name string, body []byte) error {
		w, err := z.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: n.Metadata.GeneratedAt})
		if err != nil {
			return err
		}
		_, err = w.Write(body)
		return err
	}
	for i, t := range n.Tables() {
		body, err := tableCSV(n.Metadata.Marking, t)
		if err != nil {
			return nil, err
		}
		if err := add(fmt.Sprintf("%03d-%s.csv", i+1, t.ID), body); err != nil {
			return nil, err
		}
	}
	manifest, err := json.Marshal(struct {
		Format   string   `json:"format"`
		Metadata Metadata `json:"metadata"`
	}{Format, n.Metadata})
	if err != nil {
		return nil, err
	}
	if manifest, err = canon.Canonicalize(manifest); err != nil {
		return nil, err
	}
	if err := add("manifest.json", manifest); err != nil {
		return nil, err
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func tableCSV(marking string, t *Table) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("\uFEFF")
	w := csv.NewWriter(&b)
	titles := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		titles[i] = Neutral(c.Title)
	}
	if err := w.Write([]string{Neutral(marking)}); err != nil {
		return nil, err
	}
	if err := w.Write(titles); err != nil {
		return nil, err
	}
	for _, r := range t.Rows {
		out := make([]string, len(r))
		for i, cell := range r {
			if t.Columns[i].Type == ColText {
				cell = Neutral(cell)
			}
			out[i] = cell
		}
		if err := w.Write(out); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return b.Bytes(), w.Error()
}

// Neutral makes a text cell inert in a spreadsheet: one starting with =, +,
// -, @, a tab or a carriage return gets a leading apostrophe.
func Neutral(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
