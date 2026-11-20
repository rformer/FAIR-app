package doc_test

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rformer/fair-app/internal/reports/doc"
	"github.com/rformer/fair-app/internal/reports/doc/doctest"
	"github.com/rformer/fair-app/internal/risk/canon"
)

func TestValidate(t *testing.T) {
	if err := doctest.Sample().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*doc.Document){
		"an unknown kind":     func(d *doc.Document) { d.Metadata.Kind = "board" },
		"no marking":          func(d *doc.Document) { d.Metadata.Marking = "" },
		"a long marking":      func(d *doc.Document) { d.Metadata.Marking = strings.Repeat("x", 61) },
		"no currency":         func(d *doc.Document) { d.Metadata.Currency = "" },
		"a level 4 heading":   func(d *doc.Document) { d.Sections[0].Level = 4 },
		"a float amount":      func(d *doc.Document) { d.Sections[1].Blocks[0].Table.Rows[0][2] = "1e6" },
		"a padded amount":     func(d *doc.Document) { d.Sections[1].Blocks[0].Table.Rows[0][2] = "1000000.0" },
		"a bad date":          func(d *doc.Document) { d.Sections[1].Blocks[0].Table.Rows[0][6] = "1 March 2027" },
		"a short row":         func(d *doc.Document) { d.Sections[1].Blocks[0].Table.Rows[0] = []string{"x"} },
		"a duplicate table":   func(d *doc.Document) { d.Sections[2].Blocks[0].Chart.Data.ID = "risks" },
		"a bad table id":      func(d *doc.Document) { d.Sections[1].Blocks[0].Table.ID = "../etc" },
		"a chart without alt": func(d *doc.Document) { d.Sections[2].Blocks[0].Chart.Alt = "" },
		"an unknown series":   func(d *doc.Document) { d.Sections[2].Blocks[0].Chart.Series[0].ID = "future" },
		"an unknown block":    func(d *doc.Document) { d.Sections[0].Blocks[0].Kind = "html" },
		"invalid UTF-8":       func(d *doc.Document) { d.Sections[1].Blocks[0].Table.Rows[0][0] = "\xff" },
	} {
		d := doctest.Sample()
		mutate(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
		if _, err := d.JSON(); err == nil {
			t.Errorf("%s: rendered as JSON", name)
		}
	}
}

func TestJSON(t *testing.T) {
	out, err := doctest.Sample().JSON()
	if err != nil {
		t.Fatal(err)
	}
	if c, err := canon.Canonicalize(out); err != nil || !bytes.Equal(c, out) {
		t.Fatalf("not canonical: %v", err)
	}
	again, _ := doctest.Sample().JSON()
	if !bytes.Equal(out, again) {
		t.Fatal("not deterministic")
	}
	golden(t, "sample.json", out)

	// The published schema.
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "formats", "fair-report-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	sd, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("fair-report-v1.schema.json", sd); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("fair-report-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(out))
	if err := s.Validate(inst); err != nil {
		t.Fatalf("the file does not follow its schema: %v", err)
	}
	// An empty document (no runs, filters, notes) still follows it.
	d := doctest.Sample()
	d.Metadata.Runs, d.Metadata.Filters, d.Metadata.Notes, d.Metadata.LeftOut = nil, nil, nil, nil
	d.Sections = d.Sections[:1]
	out, err = d.JSON()
	if err != nil {
		t.Fatal(err)
	}
	inst, _ = jsonschema.UnmarshalJSON(bytes.NewReader(out))
	if err := s.Validate(inst); err != nil || !strings.Contains(string(out), `"runs":[]`) {
		t.Fatalf("an empty document: %v %s", err, out)
	}
}

func TestCSV(t *testing.T) {
	out, err := doctest.Sample().CSV()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := doctest.Sample().CSV(); !bytes.Equal(out, again) {
		t.Fatal("not deterministic")
	}
	z, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	files := map[string]string{}
	for _, f := range z.File {
		names = append(names, f.Name)
		r, _ := f.Open()
		b, _ := io.ReadAll(r)
		_ = r.Close()
		files[f.Name] = string(b)
	}
	if want := []string{"001-risks.csv", "002-lec-ransomware.csv", "manifest.json"}; !slices.Equal(names, want) {
		t.Fatalf("files %v", names)
	}
	risks := files["001-risks.csv"]
	if !strings.HasPrefix(risks, "\uFEFFConfidential\r\n") && !strings.HasPrefix(risks, "\uFEFFConfidential\n") {
		t.Fatalf("no marking first: %q", risks[:40])
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(risks, "\uFEFF"))).ReadAll()
	if err != nil {
		r := csv.NewReader(strings.NewReader(strings.TrimPrefix(risks, "\uFEFF")))
		r.FieldsPerRecord = -1
		if rows, err = r.ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	if rows[1][0] != "Risk" || rows[2][5] != "-0.125" || rows[3][0] != `'=HYPERLINK("https://evil.example")` || rows[3][1] != "Иван Петров" {
		t.Fatalf("rows %q", rows)
	}
	if !strings.Contains(files["manifest.json"], `"format":"fair.report.v1"`) || strings.Contains(files["manifest.json"], `"sections"`) {
		t.Fatalf("manifest %s", files["manifest.json"])
	}
	// The marking is neutralized like any text.
	d := doctest.Sample()
	d.Metadata.Marking = "=CMD"
	out, _ = d.CSV()
	z, _ = zip.NewReader(bytes.NewReader(out), int64(len(out)))
	r, _ := z.File[0].Open()
	b, _ := io.ReadAll(r)
	if !strings.HasPrefix(string(b), "\uFEFF'=CMD") {
		t.Errorf("marking %q", b[:12])
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if os.Getenv("FAIR_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p) // #nosec G304 -- the package's own golden file
	if err != nil {
		t.Fatalf("%v (FAIR_UPDATE_GOLDEN=1 writes it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file (FAIR_UPDATE_GOLDEN=1 updates it)\n%s", name, got)
	}
}
