package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
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
			{Heading: "Entitlements", Note: "One row per user and assignment.", Columns: []Column{{"User", 2}, {"Role", 1.2}, {"Permissions", 4}, {"BU", 1}, {"Granted", 1}}, Rows: r},
			{Heading: "Restricted BUs", Columns: []Column{{"BU", 1}, {"Who", 2}}, Rows: nil},
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

func TestPDFStructure(t *testing.T) {
	d := sample(120) // several pages
	pdf, err := d.PDF()
	if err != nil {
		t.Fatal(err)
	}
	objs := objects(t, pdf)
	if !strings.Contains(objs[1], "/MarkInfo << /Marked true >>") || !strings.Contains(objs[1], "/Lang (en-US)") ||
		!strings.Contains(objs[1], "/StructTreeRoot 6 0 R") || !strings.Contains(objs[1], "/DisplayDocTitle true") {
		t.Fatalf("catalog: %s", objs[1])
	}
	var pages int
	if _, err := fmt.Sscanf(regexp.MustCompile(`/Count \d+`).FindString(objs[2]), "/Count %d", &pages); err != nil || pages < 3 {
		t.Fatalf("pages: %d %v", pages, err)
	}
	// The structure: one TR per row plus the header, a TD per cell, TH with
	// column scope.
	count := map[string]int{}
	for _, b := range objs {
		if m := regexp.MustCompile(`/Type /StructElem /S /(\w+)`).FindStringSubmatch(b); m != nil {
			count[m[1]]++
		}
	}
	if count["TD"] != 120*5 || count["TH"] != 5+2 || count["TR"] != 121+1 || count["Table"] != 2 || count["H1"] != 1 || count["H2"] != 2 || count["Document"] != 1 {
		t.Fatalf("structure: %v", count)
	}
	for _, b := range objs {
		if strings.Contains(b, "/S /TH ") && !strings.Contains(b, "/Scope /Column") {
			t.Fatal("a header cell without column scope")
		}
	}
	// Every MCID on every page is owned by an element in the parent tree,
	// and the tagged text reads in order; repeated headers are artifacts.
	parents := regexp.MustCompile(`(\d+) \[([^\]]*)\]`).FindAllStringSubmatch(objs[7], -1)
	if len(parents) != pages {
		t.Fatalf("parent tree entries %d, pages %d", len(parents), pages)
	}
	var tagged []string
	mcid := regexp.MustCompile(`(?s)/(\w+) <</MCID (\d+)>> BDC\n(.*?)EMC\n`)
	tj := regexp.MustCompile(`\(((?:[^()\\]|\\.)*)\) Tj`)
	pageNo := 0
	for n := 8; n < 8+2*pages; n += 2 {
		content := objs[n+1]
		marks := mcid.FindAllStringSubmatch(content, -1)
		refs := strings.Fields(parents[pageNo][2])
		if len(marks) != len(refs)/3 {
			t.Fatalf("page %d: %d marked sequences, %d parent refs", pageNo, len(marks), len(refs)/3)
		}
		for i, m := range marks {
			if m[2] != strconv.Itoa(i) {
				t.Fatalf("page %d: MCIDs out of order", pageNo)
			}
			el, _ := strconv.Atoi(refs[3*i])
			if !strings.Contains(objs[el], "/S /"+m[1]+" ") {
				t.Fatalf("page %d MCID %d tagged %s but owned by %s", pageNo, i, m[1], objs[el])
			}
			var parts []string
			for _, s := range tj.FindAllStringSubmatch(m[3], -1) {
				parts = append(parts, s[1])
			}
			tagged = append(tagged, strings.Join(parts, " "))
		}
		if pageNo > 0 && !strings.Contains(content, "/Artifact BMC\nBT /F2") {
			t.Fatalf("page %d does not repeat the header as an artifact", pageNo)
		}
		if !strings.Contains(content, fmt.Sprintf("(Page %d of %d) Tj", pageNo+1, pages)) {
			t.Fatalf("page %d has no page number", pageNo)
		}
		pageNo++
	}
	text := strings.Join(tagged, "|")
	if strings.Count(text, "Permissions") != 1 {
		t.Fatalf("the header is tagged %d times", strings.Count(text, "Permissions"))
	}
	last := -1
	for i := range 120 {
		at := strings.Index(text, fmt.Sprintf("user%03d@example.test", i))
		if at < last {
			t.Fatalf("row %d out of order", i)
		}
		last = at
	}
	if !strings.Contains(text, "No rows.") || !strings.HasPrefix(text, "Entitlement report|") {
		t.Fatalf("tagged text starts %.80q", text)
	}
	// Deterministic.
	again, _ := d.PDF()
	if !bytes.Equal(pdf, again) {
		t.Fatal("not deterministic")
	}
}

func TestWrapAndEncoding(t *testing.T) {
	for _, l := range wrap("analysis.edit, analysis.run, analysis.view, a-very-long-unbroken-permission-key-that-cannot-fit", 60, 7, false) {
		if width(l, 7, false) > 60 {
			t.Errorf("line %q is %.1f wide", l, width(l, 7, false))
		}
	}
	if got := pdfString(`a(b)c\d é € 日本`); got != `(a\(b\)c\\d \351 \200 ??)` {
		t.Fatalf("pdfString: %s", got)
	}
	if got := utf16String("é日"); got != "<FEFF00E965E5>" {
		t.Fatalf("utf16String: %s", got)
	}
	if _, err := (Document{Title: "x", Sections: []Section{{Heading: "h"}}}).PDF(); err == nil {
		t.Fatal("a section without columns")
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
