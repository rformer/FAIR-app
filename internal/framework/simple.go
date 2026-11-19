package framework

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// F-013 T-03 (F-013-AC-03, AC-10; design §3.3): frameworks without an OSCAL
// publication, and crosswalks, in documented simple formats
// (docs/formats/fair-framework-v1.md, fair-crosswalk-v1.md): JSON with
// unknown members refused, or CSV with a header row. Both are checked as
// strictly as OSCAL.

// simpleFile is fair.framework.v1 as JSON.
type simpleFile struct {
	Format  string `json:"format"`
	Family  Family `json:"family"`
	Version struct {
		Label     string `json:"label"`
		Title     string `json:"title"`
		Published string `json:"published,omitempty"`
	} `json:"version"`
	Requirements []Requirement `json:"requirements"`
}

// Meta is what a CSV file cannot carry: its family and version.
type Meta struct {
	Family    Family
	Label     string
	Title     string
	Published string
}

func strict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return Problems{{Pointer: "", Message: "not the format: " + clip(err.Error(), 300)}}
	}
	if dec.More() {
		return Problems{{Pointer: "", Message: "one JSON object only"}}
	}
	return nil
}

// ParseSimple reads a fair.framework.v1 JSON file.
func ParseSimple(raw []byte) (*Version, error) {
	if len(raw) > MaxFile {
		return nil, Problems{{Pointer: "", Message: fmt.Sprintf("the file is larger than %d bytes", MaxFile)}}
	}
	var f simpleFile
	if err := strict(raw, &f); err != nil {
		return nil, err
	}
	c := &checker{}
	if f.Format != FrameworkFormat {
		c.add("/format", "is %q", FrameworkFormat)
	}
	v := &Version{Family: f.Family, Label: f.Version.Label, Title: f.Version.Title, Published: f.Version.Published, Format: "simple", Requirements: f.Requirements}
	for i, r := range v.Requirements {
		if r.Withdrawn || len(r.IncorporatedInto) > 0 {
			c.add(fmt.Sprintf("/requirements/%d", i), "withdrawn and incorporated_into are OSCAL's; a simple file lists current requirements")
		}
	}
	checkVersion(v, c)
	if err := c.err(); err != nil {
		return nil, err
	}
	return v, nil
}

// SimpleColumns are the CSV columns of fair.framework.v1.
var SimpleColumns = []string{"identifier", "label", "title", "statement", "parent"}

// ParseSimpleCSV reads fair.framework.v1 as CSV (a header naming the
// columns, in any order; identifier and title required) for meta.
func ParseSimpleCSV(raw []byte, meta Meta) (*Version, error) {
	if len(raw) > MaxFile {
		return nil, Problems{{Pointer: "", Message: fmt.Sprintf("the file is larger than %d bytes", MaxFile)}}
	}
	rows, index, err := readCSV(raw, SimpleColumns, []string{"identifier", "title"})
	if err != nil {
		return nil, err
	}
	v := &Version{Family: meta.Family, Label: meta.Label, Title: meta.Title, Published: meta.Published, Format: "simple"}
	for _, row := range rows {
		v.Requirements = append(v.Requirements, Requirement{Identifier: cell(row, index, "identifier"), Label: cell(row, index, "label"),
			Title: cell(row, index, "title"), Statement: cell(row, index, "statement"), Parent: cell(row, index, "parent")})
	}
	c := &checker{}
	checkVersion(v, c)
	if err := c.err(); err != nil {
		return nil, err
	}
	return v, nil
}

func readCSV(raw []byte, columns, required []string) ([][]string, map[string]int, error) {
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, nil, Problems{{Pointer: "row 1", Message: "no header row"}}
	}
	index := map[string]int{}
	c := &checker{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		if !slices.Contains(columns, h) {
			c.add(fmt.Sprintf("row 1, column %d", i+1), "%q is not a column (%s)", h, strings.Join(columns, ", "))
			continue
		}
		if _, dup := index[h]; dup {
			c.add(fmt.Sprintf("row 1, column %d", i+1), "%q appears twice", h)
		}
		index[h] = i
	}
	for _, req := range required {
		if _, ok := index[req]; !ok {
			c.add("row 1", "the column %q is required", req)
		}
	}
	if err := c.err(); err != nil {
		return nil, nil, err
	}
	var rows [][]string
	for n := 2; ; n++ {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, Problems{{Pointer: fmt.Sprintf("row %d", n), Message: clip(err.Error(), 200)}}
		}
		rows = append(rows, row)
	}
	return rows, index, nil
}

func cell(row []string, index map[string]int, col string) string {
	if i, ok := index[col]; ok && i < len(row) {
		return strings.TrimSpace(row[i])
	}
	return ""
}

// Ref names a framework version: its family key and version label.
type Ref struct {
	Family  string `json:"family"`
	Version string `json:"version"`
}

// Link is one crosswalk relationship, by requirement identifier.
type Link struct {
	Source       string `json:"source"`
	Target       string `json:"target"`
	Relationship string `json:"relationship"`
}

// Crosswalk is a parsed crosswalk between two framework versions.
type Crosswalk struct {
	Format        string `json:"format"`
	Title         string `json:"title"`
	Publisher     string `json:"publisher,omitempty"`
	Label         string `json:"label"`
	Source        Ref    `json:"source"`
	Target        Ref    `json:"target"`
	Relationships []Link `json:"relationships"`
}

// ParseCrosswalk reads a fair.crosswalk.v1 JSON file.
func ParseCrosswalk(raw []byte) (*Crosswalk, error) {
	if len(raw) > MaxFile {
		return nil, Problems{{Pointer: "", Message: fmt.Sprintf("the file is larger than %d bytes", MaxFile)}}
	}
	var x Crosswalk
	if err := strict(raw, &x); err != nil {
		return nil, err
	}
	c := &checker{}
	if x.Format != CrosswalkFormat {
		c.add("/format", "is %q", CrosswalkFormat)
	}
	checkCrosswalk(&x, c)
	if err := c.err(); err != nil {
		return nil, err
	}
	return &x, nil
}

// CrosswalkColumns are the CSV columns of fair.crosswalk.v1.
var CrosswalkColumns = []string{"source", "target", "relationship"}

// ParseCrosswalkCSV reads fair.crosswalk.v1 as CSV for the given header.
func ParseCrosswalkCSV(raw []byte, head Crosswalk) (*Crosswalk, error) {
	if len(raw) > MaxFile {
		return nil, Problems{{Pointer: "", Message: fmt.Sprintf("the file is larger than %d bytes", MaxFile)}}
	}
	rows, index, err := readCSV(raw, CrosswalkColumns, CrosswalkColumns)
	if err != nil {
		return nil, err
	}
	x := head
	x.Format = CrosswalkFormat
	x.Relationships = nil
	for _, row := range rows {
		x.Relationships = append(x.Relationships, Link{Source: cell(row, index, "source"), Target: cell(row, index, "target"),
			Relationship: strings.ToLower(cell(row, index, "relationship"))})
	}
	c := &checker{}
	checkCrosswalk(&x, c)
	if err := c.err(); err != nil {
		return nil, err
	}
	return &x, nil
}

func checkCrosswalk(x *Crosswalk, c *checker) {
	c.text("/title", x.Title, 1, 300)
	c.text("/publisher", x.Publisher, 0, 300)
	c.text("/label", x.Label, 1, 100)
	for name, r := range map[string]Ref{"/source": x.Source, "/target": x.Target} {
		if !keyRE.MatchString(r.Family) {
			c.add(name+"/family", "is a framework family key")
		}
		c.text(name+"/version", r.Version, 1, 100)
	}
	if x.Source == x.Target {
		c.add("/target", "is the source version; a crosswalk relates two versions")
	}
	if len(x.Relationships) == 0 {
		c.add("/relationships", "a crosswalk has at least one relationship")
	}
	if len(x.Relationships) > MaxRelationships {
		c.add("/relationships", "at most %d relationships", MaxRelationships)
		return
	}
	seen := map[[2]string]int{}
	for i, l := range x.Relationships {
		ptr := fmt.Sprintf("/relationships/%d", i)
		if !identifierRE.MatchString(l.Source) {
			c.add(ptr+"/source", "is a requirement identifier")
		}
		if !identifierRE.MatchString(l.Target) {
			c.add(ptr+"/target", "is a requirement identifier")
		}
		if !slices.Contains(Relationships, l.Relationship) {
			c.add(ptr+"/relationship", "is %s", strings.Join(Relationships, ", "))
		}
		k := [2]string{l.Source, l.Target}
		if j, dup := seen[k]; dup {
			c.add(ptr, "repeats relationship %d", j)
		}
		seen[k] = i
	}
}

// Diff is what changed between two versions of a family (AC-05).
type Diff struct {
	Added      []string          `json:"added"`
	Changed    []string          `json:"changed"`
	Withdrawn  []string          `json:"withdrawn"`
	Renumbered map[string]string `json:"renumbered"` // withdrawn identifier -> the one it was incorporated into
}

// Compare diffs next against prev by identifier.
func Compare(prev, next *Version) Diff {
	d := Diff{Added: []string{}, Changed: []string{}, Withdrawn: []string{}, Renumbered: map[string]string{}}
	old := map[string]Requirement{}
	for _, r := range prev.Requirements {
		old[r.Identifier] = r
	}
	for _, r := range next.Requirements {
		o, ok := old[r.Identifier]
		switch {
		case !ok && !r.Withdrawn:
			d.Added = append(d.Added, r.Identifier)
		case ok && r.Withdrawn && !o.Withdrawn:
			d.Withdrawn = append(d.Withdrawn, r.Identifier)
			if len(r.IncorporatedInto) == 1 {
				d.Renumbered[r.Identifier] = r.IncorporatedInto[0]
			}
		case ok && !r.Withdrawn && (o.Title != r.Title || o.Statement != r.Statement):
			d.Changed = append(d.Changed, r.Identifier)
		}
	}
	present := map[string]bool{}
	for _, r := range next.Requirements {
		present[r.Identifier] = true
	}
	for _, r := range prev.Requirements {
		if !present[r.Identifier] && !r.Withdrawn {
			d.Withdrawn = append(d.Withdrawn, r.Identifier)
		}
	}
	return d
}
