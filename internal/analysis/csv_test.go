package analysis

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

// F-006 T-03 (AC-18; design §3.3, §7): the CSV writer.

func readCSV(t *testing.T, b []byte) [][]string {
	t.Helper()
	if !bytes.HasPrefix(b, []byte("\uFEFF")) {
		t.Fatal("no byte-order mark")
	}
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(b, []byte("\uFEFF"))))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// T/E: text that a spreadsheet would run as a formula is made inert;
// numbers, negative ones included, stay numbers.
func TestAnalysisCSVNeutralized(t *testing.T) {
	names := []string{"=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)", "\tTab", "\rReturn", "Plain, with a comma", "\"Quoted\""}
	var rows [][]Cell
	for _, n := range names {
		rows = append(rows, []Cell{Text(n), Num(-1250.5), Num(1e-7), Empty})
	}
	tb := Table{Meta: [][2]string{{"scenario", "=cmd|' /C calc'!A0"}, {"download", "d"}}, Header: []string{"name", "value", "small", "none"}, Rows: rows}
	var b bytes.Buffer
	if err := tb.Write(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "\r\n") {
		t.Error("not CRLF")
	}
	got := readCSV(t, b.Bytes())
	if got[0][0] != "scenario" || got[0][1] != "'=cmd|' /C calc'!A0" || got[1][1] != "d" {
		t.Errorf("metadata %v", got[:2])
	}
	if got[2][0] != "name" {
		t.Errorf("header %v (readers skip the blank row)", got[2])
	}
	for i, n := range names {
		row := got[3+i]
		want := n
		if strings.ContainsRune("=+-@\t\r", rune(n[0])) {
			want = "'" + n
		}
		if n[0] == '\r' {
			want = "'Return" // the writer drops a lone CR (UseCRLF)
		}
		if row[0] != want {
			t.Errorf("%q written as %q", n, row[0])
		}
		if row[1] != "-1250.5" || row[2] != "1e-07" || row[3] != "" {
			t.Errorf("numbers %v", row[1:])
		}
	}
}

func TestAnalysisCSVTables(t *testing.T) {
	cur := Set{Name: "Current", Summary: Summary{
		"ale":         map[string]any{"mean": 10.0, "percentiles": map[string]any{"p50": 8.0}},
		"convergence": map[string]any{"se": 0.5, "converged": true, "intervals": map[string]any{"p50": []any{7.0, 9.0}}},
		"curve":       map[string]any{"points": []any{[]any{1.0, 0.9}, []any{100.0, 0.01}}},
		"breakdown":   map[string]any{"primary": 6.0, "secondary": 4.0, "forms": map[string]any{"response": 6.0}, "stakeholders": map[string]any{"=Regulators": 4.0}},
		"sensitivity": map[string]any{"inputs": []any{map[string]any{"input": "Contact frequency", "pointer": "/lef/tef/contact_frequency", "kind": "estimate",
			"low": map[string]any{"value": 1.0, "mean": 5.0, "change": -5.0}, "high": map[string]any{"value": 9.0, "mean": 15.0, "change": 5.0}, "swing": 10.0, "spearman": nil}}},
	}}
	mfa := Set{Name: "MFA", Summary: Summary{"comparison": map[string]any{"against": "Current", "mean": -4.0, "percentiles": map[string]any{"p90": -6.0},
		"difference": map[string]any{"mean": -4.0}}}}

	h, rows := SummaryTable([]Set{cur})
	if len(h) != 4 || len(rows) != 6 { // mean, p50; converged, intervals.p50.low, .high, se
		t.Fatalf("summary %v", rows)
	}
	if rows[2][2].String() != "converged" || rows[2][3].String() != "1" || rows[3][2].String() != "intervals.p50.low" || rows[3][3].String() != "7" {
		t.Errorf("convergence rows %v", rows[2:])
	}
	if _, rows = CurveTable([]Set{cur}); len(rows) != 2 || rows[1][1].String() != "100" || rows[1][2].String() != "0.01" {
		t.Errorf("curve %v", rows)
	}
	_, rows = BreakdownTable([]Set{cur})
	if len(rows) != 4 || rows[0][4].String() != "0.6" || rows[3][2].String() != "'=Regulators" || rows[3][1].String() != "stakeholder_group" {
		t.Errorf("breakdown %v", rows)
	}
	_, rows = SensitivityTable(cur)
	if len(rows) != 1 || rows[0][8].String() != "-5" || rows[0][13].String() != "" || rows[0][2].String() != "/lef/tef/contact_frequency" {
		t.Errorf("sensitivity %v", rows)
	}
	_, rows = ComparisonTable([]Set{cur, mfa})
	if len(rows) != 3 || rows[0][1].String() != "Current" || rows[0][2].String() != "difference.mean" || rows[1][3].String() != "-4" {
		t.Errorf("comparison %v", rows)
	}
	both := 1
	_, rows = HistogramTable("MFA", "Current", Histogram{Edges: []float64{-2, 0.5}, Counts: []int{3}, Zero: 4, BothNone: &both})
	if len(rows) != 3 || rows[0][3].String() != "-2" || rows[1][2].String() != "no_difference" || rows[2][5].String() != "1" {
		t.Errorf("histogram %v", rows)
	}
	_, rows = ContributionsTable(Summary{"contributions": []any{map[string]any{"position": 0.0, "label": "-Claims", "mean": 2.0, "share_of_p95_year": 0.25}}})
	if len(rows) != 1 || rows[0][1].String() != "'-Claims" || rows[0][3].String() != "0.25" {
		t.Errorf("contributions %v", rows)
	}
	if FileName("run", "0123456789abcdef", "curve", "csv") != "run-01234567-curve.csv" {
		t.Error("file name")
	}
}
