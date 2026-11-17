package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/reports/doc"
)

// F-010 T-11 (F-010-AC-08, AC-10, AC-11; design §3.1, §3.4): the portfolio
// report: the dashboard's content as a document. The requester's latest
// succeeded roll-up of the BU (its summary, curve and distribution, time,
// staleness, what it covers and leaves out); the largest open risks; each
// child BU's open risks and summed means; coverage; acceptances; treatment.
// The trend over the period comes from the snapshots (T-15).

// PortfolioParams: the period, in days, the trend covers (1 to 3,650; 365).
type PortfolioParams struct {
	PeriodDays *int `json:"period_days,omitempty"`
}

// PortfolioKind is the portfolio report.
var PortfolioKind = Kind{Name: "portfolio", Title: "Portfolio",
	Params: func(raw json.RawMessage) (json.RawMessage, error) {
		var p PortfolioParams
		out, err := strictParams(raw, &p)
		if err != nil {
			return nil, err
		}
		if p.PeriodDays != nil && (*p.PeriodDays < 1 || *p.PeriodDays > 3650) {
			return nil, errors.New("period_days is 1 to 3,650")
		}
		return out, nil
	},
	Read: readPortfolio}

// LargestRisks is how many risks the portfolio lists.
const LargestRisks = 10

func readPortfolio(ctx context.Context, tx pgx.Tx, r Run) (Built, error) {
	var p PortfolioParams
	if err := json.Unmarshal(r.Params, &p); err != nil {
		return Built{}, err
	}
	period := 365
	if p.PeriodDays != nil {
		period = *p.PeriodDays
	}
	d, err := ReadDashboard(ctx, tx, r.BU.ID)
	if err != nil {
		return Built{}, err
	}
	sections := []doc.Section{rollupSection(d.Rollup)}

	// The largest open risks by mean annualized loss.
	var owners []string
	for _, x := range d.Largest {
		owners = append(owners, x.Owner)
	}
	who, err := names(ctx, tx, owners)
	if err != nil {
		return Built{}, err
	}
	top := &doc.Table{ID: "largest", Caption: fmt.Sprintf("The %d largest open risks by mean annualized loss", LargestRisks), Columns: []doc.Column{
		{Key: "risk", Title: "Risk", Type: doc.ColText, Width: 3}, {Key: "owner", Title: "Owner", Type: doc.ColText, Width: 1.5},
		{Key: "mean", Title: "Mean", Type: doc.ColAmount}, {Key: "p10", Title: "10th percentile", Type: doc.ColAmount},
		{Key: "p90", Title: "90th percentile", Type: doc.ColAmount}, {Key: "status", Title: "Exposure status", Type: doc.ColText}}}
	for _, x := range d.Largest {
		top.Rows = append(top.Rows, []string{x.Title, nameOf(who, x.Owner), numPtr(x.Mean), numPtr(x.P10), numPtr(x.P90), x.Status})
	}
	sections = append(sections, doc.Section{Heading: "Largest risks", Level: 1, Blocks: []doc.Block{table(top)}})

	byChild := &doc.Table{ID: "by-unit", Caption: "Open risks by business unit below", Columns: []doc.Column{
		{Key: "unit", Title: "Business unit", Type: doc.ColText, Width: 2.5}, {Key: "risks", Title: "Open risks", Type: doc.ColNumber},
		{Key: "quantified", Title: "With an exposure", Type: doc.ColNumber},
		{Key: "sum", Title: "Sum of means (not a percentile of the total)", Type: doc.ColAmount, Width: 1.5},
		{Key: "p90", Title: "90th percentile of the unit's roll-up", Type: doc.ColAmount, Width: 1.5}}}
	for _, c := range d.Children {
		byChild.Rows = append(byChild.Rows, []string{c.Name, strconv.Itoa(c.Open), strconv.Itoa(c.Quantified), num(c.MeanSum), numPtr(c.RollupP90)})
	}
	unitBlocks := []doc.Block{table(byChild)}
	if d.Restricted != nil {
		v := func(k string) string { return fmt.Sprint(d.Restricted[k]) }
		mean, _ := d.Restricted["mean_sum"].(float64)
		unitBlocks = append(unitBlocks, para("Restricted business units appear as totals only (their roll-up mode)."), pairs(
			doc.Pair{Label: "Restricted units (totals only)", Value: v("units")}, doc.Pair{Label: "Their open risks", Value: v("open_risks")},
			doc.Pair{Label: "With a current analysis", Value: v("current")}, doc.Pair{Label: "Stale", Value: v("stale")},
			doc.Pair{Label: "Unquantified", Value: v("unquantified")},
			doc.Pair{Label: "Sum of their means (not a percentile of the total)", Value: Display(doc.ColAmount, num(mean))}))
	}
	sections = append(sections, doc.Section{Heading: "By business unit", Level: 1, Blocks: unitBlocks})

	c := d.Coverage
	sections = append(sections, doc.Section{Heading: "Coverage", Level: 1, Blocks: []doc.Block{pairs(
		doc.Pair{Label: "Open risks", Value: strconv.Itoa(c.Open)}, doc.Pair{Label: "With a current analysis", Value: strconv.Itoa(c.Current)},
		doc.Pair{Label: "Stale", Value: strconv.Itoa(c.Stale)}, doc.Pair{Label: "Computing", Value: strconv.Itoa(c.Computing)},
		doc.Pair{Label: "Unquantified", Value: strconv.Itoa(c.Unquantified)})}})
	ac := d.Acceptances
	sections = append(sections, doc.Section{Heading: "Acceptances", Level: 1, Blocks: []doc.Block{pairs(
		doc.Pair{Label: "Active", Value: strconv.Itoa(ac["active"])}, doc.Pair{Label: "Expiring within 30 days", Value: strconv.Itoa(ac["expiring"])},
		doc.Pair{Label: "Expired", Value: strconv.Itoa(ac["expired"])}, doc.Pair{Label: "Suspended", Value: strconv.Itoa(ac["suspended"])},
		doc.Pair{Label: "Awaiting decision", Value: strconv.Itoa(ac["pending"])})}})
	sections = append(sections, doc.Section{Heading: "Treatment", Level: 1, Blocks: []doc.Block{pairs(
		doc.Pair{Label: "Open actions", Value: strconv.Itoa(d.Treatment["open"])}, doc.Pair{Label: "Overdue actions", Value: strconv.Itoa(d.Treatment["overdue"])})}})
	// T-15: the trend over the period, from the snapshots the requester may see.
	points, err := ReadTrend(ctx, tx, r.BU.ID, d.AsOf.AddDate(0, 0, -period), d.AsOf)
	if err != nil {
		return Built{}, err
	}
	sections = append(sections, trendSection(points, period))

	notes := []string{
		"Exposures are distributions: each figure gives its mean with percentiles; nothing is scored or rated.",
		"Sums of means are sums of each risk's mean, not percentiles of the total; the roll-up gives the total's distribution."}
	if n := d.LeftOut["units_not_visible"]; n > 0 {
		notes = append(notes, fmt.Sprintf("%d business units in the scope are not visible to the requester (or are restricted and excluded from roll-ups); their records are left out.", n))
	}
	if n := d.LeftOut["units_aggregate_only"]; n > 0 {
		notes = append(notes, fmt.Sprintf("%d restricted business units in the scope appear as totals only; their risks are not listed.", n))
	}
	out := doc.Document{Metadata: doc.Metadata{Title: "Portfolio: " + r.BU.Name, Filters: map[string]string{"period_days": strconv.Itoa(period)},
		Runs: d.Runs, LeftOut: d.LeftOut, Notes: notes}, Sections: sections}
	return Built{Doc: out, Risks: c.Open}, nil
}

// childBUs are bu's direct children the requester reads in the register.
func childBUs(ctx context.Context, tx pgx.Tx, bu string) ([]doc.Ref, error) {
	rows, err := tx.Query(ctx, "SELECT id::text, name FROM report.child_bus($1)", bu)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []doc.Ref
	for rows.Next() {
		var c doc.Ref
		if err := rows.Scan(&c.ID, &c.Name); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// rollupSection is the requester's latest succeeded roll-up of the BU: its
// summary, curve and distribution, its time and staleness (F-007-AC-12),
// what it covers and leaves out (F-007-AC-13).
func rollupSection(r *RollupView) doc.Section {
	sec := doc.Section{Heading: "Exposure", Level: 1}
	if r == nil {
		sec.Blocks = append(sec.Blocks, para("The requester has no roll-up of this business unit. A roll-up (Register, Roll-ups) gives the total exposure's distribution."))
		return sec
	}
	stale := "no"
	if r.Stale {
		stale = "yes: the register has changed since; request a new roll-up"
	}
	var s map[string]any
	_ = json.Unmarshal(r.Summary, &s)
	sec.Blocks = append(sec.Blocks, pairs(doc.Pair{Label: "Roll-up", Value: r.ID}, doc.Pair{Label: "Computed", Value: r.FinishedAt.UTC().Format("2006-01-02 15:04 UTC")},
		doc.Pair{Label: "Stale", Value: stale}, doc.Pair{Label: "Risks included", Value: strconv.Itoa(r.Covers)},
		doc.Pair{Label: "Risks left out", Value: strconv.Itoa(r.LeftOutTotal)}, doc.Pair{Label: "Business units excluded", Value: strconv.Itoa(r.ExcludedBUs)}))
	t := summaryTable("rollup", "Total annualized loss (risks combined as independent)", "Roll-up")
	t.Rows = append(t.Rows, aleRow("Total", s))
	sec.Blocks = append(sec.Blocks, table(t))
	if b, ok := curveBlock("rollup-curve", "Loss exceedance curve of the total", "the total", s); ok {
		sec.Blocks = append(sec.Blocks, b)
	}
	if b, ok := histBlock("rollup-histogram", "Distribution of the total annual loss", r.series, r.iterations); ok {
		sec.Blocks = append(sec.Blocks, b)
	}
	return sec
}
