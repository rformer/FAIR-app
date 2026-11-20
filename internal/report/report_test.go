package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sample(rows int) Document {
	var r [][]string
	for i := range rows {
		r = append(r, []string{fmt.Sprintf("user%03d@example.test", i), "Risk Analyst",
			"analysis.edit, analysis.run, analysis.view, control.edit, control.view, library.edit, library.view, register.view, report.view, scenario.edit",
			"EMEA-01", fmt.Sprintf("2026-11-%02d", i%28+1)})
	}
	return Document{Title: "Entitlement report", Subtitle: "As of 2026-11-02 for Ann (ann@example.test)", Author: "FAIR",
		Created: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC),
		Sections: []Section{
			{Heading: "Entitlements", Note: "One row per user and assignment.", Columns: []Column{{Title: "User", Weight: 2}, {Title: "Role", Weight: 1.2}, {Title: "Permissions", Weight: 4}, {Title: "BU", Weight: 1}, {Title: "Granted", Weight: 1}}, Rows: r},
			{Heading: "Restricted BUs", Columns: []Column{{Title: "BU", Weight: 1}, {Title: "Who", Weight: 2}}, Rows: nil},
		}}
}

// objects returns each object's body by number, checking the xref table.
func objects(t *testing.T, pdf []byte) map[int]string {
	t.Helper()
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.7\n")) || !bytes.HasSuffix(pdf, []byte("%%EOF\n")) {
		t.Fatal("not a PDF 1.7 file")
	}
	m := regexp.MustCompile(`startxref\n(\d+)\n`).FindSubmatch(pdf)
	if m == nil {
		t.Fatal("no startxref")
	}
	xref, _ := strconv.Atoi(string(m[1]))
	if !bytes.HasPrefix(pdf[xref:], []byte("xref\n")) {
		t.Fatal("startxref does not point at the xref table")
	}
	lines := strings.Split(string(pdf[xref:]), "\n")
	var size int
	if _, err := fmt.Sscanf(lines[1], "0 %d", &size); err != nil {
		t.Fatal(err)
	}
	out := map[int]string{}
	objRE := regexp.MustCompile(`(?s)^(\d+) 0 obj\n(.*?)\nendobj\n`)
	for n := 1; n < size; n++ {
		off, _ := strconv.Atoi(strings.Fields(lines[2+n])[0])
		mm := objRE.FindSubmatch(pdf[off:])
		if mm == nil || string(mm[1]) != strconv.Itoa(n) {
			t.Fatalf("xref entry %d points at %.30q", n, pdf[off:])
		}
		out[n] = string(mm[2])
	}
	return out
}

// structure counts struct elements by type and returns the catalog.
func structure(t *testing.T, objs map[int]string) (map[string]int, string) {
	t.Helper()
	count := map[string]int{}
	catalog := ""
	for _, b := range objs {
		if m := regexp.MustCompile(`/Type /StructElem /S /(\w+)`).FindStringSubmatch(b); m != nil {
			count[m[1]]++
		}
		if strings.Contains(b, "/Type /Catalog") {
			catalog = b
		}
	}
	return count, catalog
}

func TestPDFStructure(t *testing.T) {
	d := sample(120) // several pages
	pdf, err := d.PDF()
	if err != nil {
		t.Fatal(err)
	}
	objs := objects(t, pdf)
	count, catalog := structure(t, objs)
	for _, want := range []string{"/MarkInfo << /Marked true >>", "/Lang (en-US)", "/StructTreeRoot ", "/DisplayDocTitle true", "/Metadata "} {
		if !strings.Contains(catalog, want) {
			t.Fatalf("catalog lacks %s: %s", want, catalog)
		}
	}
	// The structure: one TR per row plus the header, a TD per cell, TH with
	// column scope.
	if count["TD"] != 120*5 || count["TH"] != 5+2 || count["TR"] != 121+1 || count["Table"] != 2 || count["H1"] != 1 || count["H2"] != 2 || count["Document"] != 1 {
		t.Fatalf("structure: %v", count)
	}
	pages := 0
	for _, b := range objs {
		if strings.Contains(b, "/S /TH ") && !strings.Contains(b, "/Scope /Column") {
			t.Fatal("a header cell without column scope")
		}
		if strings.Contains(b, "/Type /Page /Parent") {
			pages++
			if !strings.Contains(b, "/Tabs /S") {
				t.Fatal("a page without structure tab order")
			}
		}
	}
	if pages < 3 {
		t.Fatalf("%d pages", pages)
	}
	// Fonts embedded, with ToUnicode maps; no standard fonts.
	if strings.Contains(string(pdf), "/Helvetica") || strings.Count(string(pdf), "/FontFile2 ") != 2 || strings.Count(string(pdf), "/ToUnicode ") != 2 {
		t.Fatal("fonts not embedded as expected")
	}
	if !strings.Contains(string(pdf), "<pdfuaid:part>1</pdfuaid:part>") {
		t.Fatal("no PDF/UA identifier")
	}
	// The text reads back in order; the repeated header is an artifact, so
	// the column titles are content once.
	text, err := Text(pdf, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(text, "Permissions") != 1 {
		t.Fatalf("the header is content %d times", strings.Count(text, "Permissions"))
	}
	all, _ := Text(pdf, false)
	if strings.Count(all, "Permissions") < pages || !strings.Contains(all, fmt.Sprintf("Page %d of %d", pages, pages)) {
		t.Fatal("repeated headers or page numbers missing")
	}
	last := -1
	for i := range 120 {
		at := strings.Index(text, fmt.Sprintf("user%03d@example.test", i))
		if at < last {
			t.Fatalf("row %d out of order", i)
		}
		last = at
	}
	if !strings.Contains(text, "No rows.") || !strings.HasPrefix(text, "Entitlement report"+nl) {
		t.Fatalf("text starts %.80q", text)
	}
	// Deterministic.
	again, _ := d.PDF()
	if !bytes.Equal(pdf, again) {
		t.Fatal("not deterministic")
	}
}

// F-010 T-07: Unicode text reads back as written; characters the fonts lack
// are drawn as U+FFFD and listed; headings may not skip a level; figures
// need alternative text.
const unicodeText = "Zoë Ångström, Иван Петров, Ελένη: € 1,250,000 – “quoted” (a)" + string(rune(92)) + "b"

func unicodeDoc() Doc {
	return Doc{Title: "Unicode", Marking: "Confidential", Created: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC), Blocks: []Block{
		{Kind: Heading, Level: 1, Text: "Unicode"},
		{Kind: Paragraph, Text: unicodeText},
		{Kind: List, Items: []string{"one", "two"}},
		{Kind: Heading, Level: 2, Text: "Table"},
		{Kind: TableBlock, Table: &Table{Caption: "Pairs", NoHeader: true, RowHeaders: true, Columns: []Column{{Title: "Label", Weight: 1}, {Title: "Value", Weight: 2}},
			Rows: [][]string{{"Owner", "Zoë"}, {"Mean", "1,000,000"}}}},
		{Kind: FigureBlock, Figure: &Figure{Alt: "A line rising to the right.", Caption: "Figure 1", Height: 100, Draw: func(c *Canvas) {
			c.Stroke(0, 0.3, 0.6, 1)
			c.Line(0, 0, c.W/2, c.H/2, c.W, c.H)
			c.Text(10, 10, "axis label", 7, false, "left")
		}}},
		{Kind: Paragraph, Text: "Not in the font: 東京"},
	}}
}

func TestDocUnicodeAndRules(t *testing.T) {
	text := unicodeText
	pdf, err := unicodeDoc().PDF()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Text(pdf, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, text) || !strings.HasPrefix(got, "Confidential"+nl+"Unicode"+nl) {
		t.Fatalf("text %q", got)
	}
	objs := objects(t, pdf)
	count, _ := structure(t, objs)
	if count["L"] != 1 || count["LI"] != 2 || count["Lbl"] != 2 || count["LBody"] != 2 || count["Figure"] != 1 || count["Caption"] != 1 {
		t.Fatalf("structure %v", count)
	}
	for _, b := range objs {
		if strings.Contains(b, "/S /Figure ") && !strings.Contains(b, "/Alt <FEFF") {
			t.Fatal("a figure without Alt")
		}
	}
	all, _ := Text(pdf, false)
	// The marking: the first page's header is content (once), the footer an
	// artifact.
	if strings.Count(all, "Confidential") != 2 || strings.Count(got, "Confidential") != 1 {
		t.Fatalf("the marking: %d in all, %d as content", strings.Count(all, "Confidential"), strings.Count(got, "Confidential"))
	}
	// A character the fonts lack.
	if m := Missing("ok 日本 ok"); len(m) != 2 || m[0] != '日' {
		t.Fatalf("missing %q", m)
	}
	pdf, err = Doc{Title: "x", Blocks: []Block{{Kind: Paragraph, Text: "日本"}}}.PDF()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := Text(pdf, true); got != "��" {
		t.Fatalf("a missing glyph reads %q", got)
	}
	for name, d := range map[string]Doc{
		"a skipped level":      {Title: "x", Blocks: []Block{{Kind: Heading, Level: 1, Text: "a"}, {Kind: Heading, Level: 3, Text: "b"}}},
		"a figure without alt": {Title: "x", Blocks: []Block{{Kind: FigureBlock, Figure: &Figure{}}}},
		"no title":             {Blocks: []Block{{Kind: Paragraph, Text: "x"}}},
		"no blocks":            {Title: "x"},
	} {
		if _, err := d.PDF(); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	if _, err := (Document{Title: "x", Sections: []Section{{Heading: "h"}}}).PDF(); err == nil {
		t.Fatal("a section without columns")
	}
	if got := utf16String("é日"); got != "<FEFF00E965E5>" {
		t.Fatalf("utf16String: %s", got)
	}
}

// FAIR_PDF_OUT=<dir> writes sample PDFs for veraPDF (CI job pdfua).
func TestWriteSamples(t *testing.T) {
	dir := os.Getenv("FAIR_PDF_OUT")
	if dir == "" {
		t.Skip("set FAIR_PDF_OUT to write the PDF/UA samples")
	}
	for name, d := range map[string]interface{ PDF() ([]byte, error) }{"entitlements.pdf": sample(60), "unicode.pdf": unicodeDoc()} {
		b, err := d.PDF()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil { // #nosec G703 -- a test output directory
			t.Fatal(err)
		}
	}
}

func TestCSV(t *testing.T) {
	b, err := CSV([]string{"user", "note"}, [][]string{{"=HYPERLINK(1)", "plain"}, {"a,b", `quote "x"`}, {"-1", "@x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
		t.Fatal("no BOM")
	}
	recs, err := csv.NewReader(bytes.NewReader(b[3:])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"user", "note"}, {"'=HYPERLINK(1)", "plain"}, {"a,b", `quote "x"`}, {"'-1", "'@x"}}
	if fmt.Sprint(recs) != fmt.Sprint(want) {
		t.Fatalf("%v", recs)
	}
}

// nl is a line break (the text extractor joins lines with it).
const nl = string(rune(10))

// The embedded fonts are the ones fonts/README.md records.
func TestFontDigests(t *testing.T) {
	for name, want := range map[string]string{
		"NotoSans-Regular.ttf": "b092b091c904c12a96c9189e3d66a9eabe0818fdf0572fcc5f23f1d37efbc76f",
		"NotoSans-Bold.ttf":    "01a869026d170ee232c7ed2f5254e482de1dcc7de91ad1310e6c6ca6b008a947",
		"OFL.txt":              "cee9892f9f0cc8fe882c9e9537ee6a89621d86ee7ceaf70b02e2b2b1c25c061a",
	} {
		b, err := os.ReadFile(filepath.Join("fonts", name)) // #nosec G304 -- a test output directory
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
	reg, bold, err := fonts()
	if err != nil || reg.unitsPerEm == 0 || bold.unitsPerEm == 0 || len(reg.cmap) < 2000 {
		t.Fatalf("fonts: %v", err)
	}
	for _, r := range "AZaz09ÄäÖöÜüßØøÅåÉéÑñĞğŁłЖжЯяΩωΣσ€£¥–—“”‘’…•" {
		if _, ok := reg.cmap[r]; !ok {
			t.Errorf("Regular lacks %q", r)
		}
		if _, ok := bold.cmap[r]; !ok {
			t.Errorf("Bold lacks %q", r)
		}
	}
}
