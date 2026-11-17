package reports

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/report"
	"github.com/rformer/fair-app/internal/reports/doc/doctest"
)

// F-010 T-07 (F-010-AC-10, AC-12): a report document as PDF/UA-1 reads back
// with its metadata, its tables formatted and its markup as text.
func TestPDF(t *testing.T) {
	pdf, err := PDF(doctest.Sample())
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := PDF(doctest.Sample()); !bytes.Equal(pdf, again) {
		t.Fatal("not deterministic")
	}
	text, err := report.Text(pdf, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Confidential", "Risk register: Claims", "Claims and the business units below it", "2026-11-16 14:30 UTC by Zoë Ångström",
		"Data as of", "2026-11-16 14:28 UTC", "category: Cyber; status: stale", "3 risks not visible to you; 1 risks without a quantified analysis",
		"1,000,000", "120,000.5", "-12.5%", "4%", "Mean (USD)", "Иван Петров", `=HYPERLINK("https://evil.example")`, "<script>alert(1)</script>",
		"Analyses used", "4f9a1c0e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a19", "Loss exceedance", "95%"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in the text", want)
		}
	}
	// The chart is a tagged figure with its alternative text.
	if !strings.Contains(string(pdf), "/S /Figure ") || !strings.Contains(string(pdf), "/Alt <FEFF") {
		t.Error("no figure with alternative text")
	}
	// Missing characters are noted.
	d := doctest.Sample()
	d.Sections[0].Blocks[1].Text = "Tokyo 東京"
	pdf, err = PDF(d)
	if err != nil {
		t.Fatal(err)
	}
	if text, _ := report.Text(pdf, true); !strings.Contains(text, "cannot be shown") || !strings.Contains(text, "U+6771, U+4EAC") {
		t.Errorf("missing characters not noted: %q", text)
	}
	// An invalid document is refused.
	d = doctest.Sample()
	d.Metadata.Marking = ""
	if _, err := PDF(d); err == nil {
		t.Error("an invalid document rendered")
	}
}

func TestDisplay(t *testing.T) {
	for _, c := range []struct{ typ, in, want string }{
		{"amount", "1250000", "1,250,000"}, {"amount", "-999", "-999"}, {"amount", "1000.25", "1,000.25"}, {"number", "12", "12"},
		{"percent", "0.125", "12.5%"}, {"percent", "1", "100%"}, {"percent", "0.00001", "0%"}, {"time", "2026-11-16T14:30:59Z", "2026-11-16 14:30 UTC"},
		{"date", "2027-03-01", "2027-03-01"}, {"text", "x", "x"}, {"amount", "", ""},
	} {
		if got := Display(c.typ, c.in); got != c.want {
			t.Errorf("%s %q: %q, want %q", c.typ, c.in, got, c.want)
		}
	}
}

// FAIR_PDF_OUT=<dir> writes the sample report for veraPDF (CI job pdfua).
func TestWriteSampleReport(t *testing.T) {
	dir := os.Getenv("FAIR_PDF_OUT")
	if dir == "" {
		t.Skip("set FAIR_PDF_OUT to write the PDF/UA sample")
	}
	pdf, err := PDF(doctest.Sample())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.pdf"), pdf, 0o600); err != nil {
		t.Fatal(err)
	}
}
