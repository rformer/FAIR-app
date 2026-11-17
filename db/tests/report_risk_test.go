package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/internal/reports/doc"
)

// F-010 T-11 (F-010-AC-08 to AC-11; design §3.1, §3.4): the risk and
// portfolio reports, read under the requester's RLS, with the pinned runs'
// views and charts, provenance without calibration, treatment and the
// acceptance history; the portfolio from the requester's own roll-up.
func TestReportRiskAndPortfolio(t *testing.T) {
	a := acceptanceFixture(t)
	ra, rg := a.ra, a.rg
	ctx := context.Background()
	risk := a.accepted(t, "Claims leak", "owen")
	acc, code := a.request(t, "owen", risk, "Within appetite", days(200), "")
	if code != "" {
		t.Fatalf("request: %s", code)
	}
	if _, code := a.decide(t, "appA1", acc, "approve"); code != "" {
		t.Fatalf("approve: %s", code)
	}

	// The risk report (AC-09, AC-10).
	params := `{"risk":"` + risk + `"}`
	b := build(t, ra, "chief", ra.bu["ENTERPRISE"], "Enterprise", reports.RiskKind, params)
	d := b.Doc
	if !strings.HasPrefix(d.Metadata.Title, "Risk: Claims leak") || len(d.Metadata.Runs) != 1 || b.Risks != 1 {
		t.Fatalf("metadata: %+v", d.Metadata)
	}
	sum := tableOf(d, "s1-summary")
	if sum == nil || len(sum.Rows) == 0 || sum.Rows[0][0] != "Current" || sum.Rows[0][1] != "4.5" || sum.Rows[0][4] != "9" {
		t.Fatalf("summary: %+v", sum)
	}
	for _, id := range []string{"s1-curve", "s1-histogram", "s1-breakdown", "s1-drivers", "s1-estimates", "s1-requests", "acceptance-history"} {
		if tableOf(d, id) == nil {
			t.Errorf("no %s table", id)
		}
	}
	charts := 0
	for _, s := range d.Sections {
		for _, bl := range s.Blocks {
			if bl.Chart != nil {
				charts++
			}
		}
	}
	if charts != 2 || len(tableOf(d, "s1-curve").Rows) != 3 || len(tableOf(d, "s1-drivers").Rows) == 0 || len(tableOf(d, "s1-estimates").Rows) == 0 {
		t.Errorf("charts %d, curve %v, drivers %v", charts, tableOf(d, "s1-curve").Rows, tableOf(d, "s1-drivers").Rows)
	}
	outlines := outline("risk", d)
	hist := tableOf(d, "acceptance-history")
	if steps := column(hist, "step"); !slices.Contains(steps, "requested") || !slices.Contains(steps, "approved") || !slices.Contains(column(hist, "by"), "appA1") {
		t.Errorf("acceptance history: %v", hist.Rows)
	}
	// Provenance never carries calibration records or answer weights.
	j, err := d.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.ToLower(string(j)); strings.Contains(s, "calibration") && !strings.Contains(s, "calibration records and answer weights are never included") ||
		strings.Contains(s, `"weight"`) || strings.Contains(s, "range_rate") {
		t.Errorf("calibration data in the report: %.400s", j)
	}
	// Not visible to mallory, nor inside B's scope for chief: not_found, final.
	for _, c := range []struct{ user, bu string }{{"mallory", "ENTERPRISE"}, {"chief", "B"}} {
		p, _ := reports.RiskKind.CheckParams(json.RawMessage(params))
		var err error
		readAs(t, ra, c.user, func(tx pgx.Tx) error {
			_, err = reports.RiskKind.Read(ctx, tx, reports.Run{BU: doc.Ref{ID: ra.bu[c.bu]}, Params: p})
			return nil
		})
		if err == nil || !strings.HasPrefix(err.Error(), reports.FailNotFound) {
			t.Errorf("%s at %s: %v", c.user, c.bu, err)
		}
	}
	if _, err := reports.RiskKind.CheckParams(json.RawMessage(`{}`)); err == nil {
		t.Error("a risk report without a risk")
	}

	// The portfolio without a roll-up says so; with chief's roll-up of A1
	// it carries the total's distribution (AC-01 to AC-04 as a document).
	b = build(t, ra, "chief", ra.bu["A1"], "A1", reports.PortfolioKind, "")
	if tableOf(b.Doc, "rollup") != nil || len(tableOf(b.Doc, "largest").Rows) != 2 {
		t.Errorf("portfolio before a roll-up: %+v", b.Doc.Sections)
	}
	got := rg.call(t, "POST", "chief", "/api/v1/register/rollups", map[string]any{"bu_id": ra.bu["A1"]})
	if got.code != 202 {
		t.Fatalf("roll-up: %d %s", got.code, got.raw)
	}
	if q := ra.adminQuery("SELECT coalesce(string_agg(id::text, ',' ORDER BY seq), '') FROM analysis.aggregate WHERE purpose = 'rollup' AND state = 'queued'"); q != "" {
		for _, id := range strings.Split(q, ",") {
			if err := a.ae.aggregates.Attempt(ctx, id, 1, analysis.Attempts); err != nil {
				t.Fatalf("aggregate %s: %v", id, err)
			}
		}
	}
	b = build(t, ra, "chief", ra.bu["A1"], "A1", reports.PortfolioKind, `{"period_days":90}`)
	roll := tableOf(b.Doc, "rollup")
	// (The fake engine's aggregates carry no curve; the risk report above
	// checks the charts.)
	var covered string
	for _, p := range b.Doc.Sections[0].Blocks[0].Pairs {
		if p.Label == "Risks included" {
			covered = p.Value
		}
	}
	if roll == nil || roll.Rows[0][1] == "" || covered != "2" || len(b.Doc.Metadata.Runs) != 2 || b.Doc.Metadata.Filters["period_days"] != "90" {
		t.Fatalf("portfolio with a roll-up: %+v %v %q", roll, b.Doc.Metadata.Runs, covered)
	}
	outlines += outline("portfolio", b.Doc)
	golden(t, "report_outline.golden", outlines)
	// Another user's roll-up is not theirs: owen's portfolio has none.
	b = build(t, ra, "owen", ra.bu["A1"], "A1", reports.PortfolioKind, "")
	if tableOf(b.Doc, "rollup") != nil {
		t.Error("owen's portfolio shows chief's roll-up")
	}
	// The root's portfolio lists A and B below it, not the restricted R.
	b = build(t, ra, "chief", ra.bu["ENTERPRISE"], "Enterprise", reports.PortfolioKind, "")
	if units := column(tableOf(b.Doc, "by-unit"), "unit"); strings.Join(units, ",") != "A,B" {
		t.Errorf("units below the root: %v", units)
	}
	if _, err := reports.PortfolioKind.CheckParams(json.RawMessage(`{"period_days":0}`)); err == nil {
		t.Error("a period of 0 days")
	}
}

// outline is a document's shape: its sections, and each block's kind,
// table (id, columns, rows) or chart (kind, axis, series); no values, so
// it is the same on every run.
func outline(name string, d doc.Document) string {
	var b strings.Builder
	fmt.Fprintf(&b, "== %s: %d runs, left out %v\n", name, len(d.Metadata.Runs), d.Metadata.LeftOut)
	for _, s := range d.Sections {
		fmt.Fprintf(&b, "%s %s\n", strings.Repeat("#", s.Level), s.Heading)
		for _, bl := range s.Blocks {
			switch {
			case bl.Table != nil:
				var cols []string
				for _, c := range bl.Table.Columns {
					cols = append(cols, c.Key+":"+c.Type)
				}
				fmt.Fprintf(&b, "  table %s [%s] %d rows\n", bl.Table.ID, strings.Join(cols, " "), len(bl.Table.Rows))
			case bl.Chart != nil:
				var series []string
				for _, r := range bl.Chart.Series {
					series = append(series, r.ID)
				}
				fmt.Fprintf(&b, "  chart %s x=%s series=%v log=%v, data %s %d rows\n", bl.Chart.Kind, bl.Chart.XKey, series, bl.Chart.Log, bl.Chart.Data.ID, len(bl.Chart.Data.Rows))
			case bl.Kind == doc.KindPairs:
				var labels []string
				for _, p := range bl.Pairs {
					labels = append(labels, p.Label)
				}
				fmt.Fprintf(&b, "  pairs %s\n", strings.Join(labels, " | "))
			default:
				fmt.Fprintf(&b, "  %s\n", bl.Kind)
			}
		}
	}
	return b.String()
}

// golden compares got with testdata/name (FAIR_UPDATE_GOLDEN=1 writes it).
func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if os.Getenv("FAIR_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p) // #nosec G304 -- the package's golden files
	if err != nil {
		t.Fatalf("%v (FAIR_UPDATE_GOLDEN=1 writes it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden file (FAIR_UPDATE_GOLDEN=1 updates it)\n%s", name, got)
	}
}
