package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/reports/doc"
)

// F-010 T-11 (F-010-AC-08, AC-10, AC-11; design §3.1, §3.4): the portfolio
// report: the dashboard's content as a document. The requester's latest
// succeeded roll-up of the BU (its summary, curve and distribution, time,
// staleness, what it covers and leaves out); the largest open risks; each
// child BU's open risks and summed means; coverage; acceptances; treatment.
// The trend over the period joins it with the snapshots (T-15).

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
	risks, err := RegisterRows(ctx, tx, r.BU.ID, RegisterParams{})
	if err != nil {
		return Built{}, err
	}
	var sections []doc.Section
	exposure, runs, err := rollupSection(ctx, tx, r.BU.ID)
	if err != nil {
		return Built{}, err
	}
	sections = append(sections, exposure)

	// The largest open risks by mean annualized loss (RegisterRows' order).
	var owners []string
	for _, x := range risks {
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
	count := map[string]int{}
	for _, x := range risks {
		count[x.Status]++
		if x.Mean != nil && len(top.Rows) < LargestRisks {
			top.Rows = append(top.Rows, []string{x.Title, nameOf(who, x.Owner), numPtr(x.Mean), numPtr(x.P10), numPtr(x.P90), x.Status})
		}
	}
	sections = append(sections, doc.Section{Heading: "Largest risks", Level: 1, Blocks: []doc.Block{table(top)}})

	// Each child BU's subtree.
	children, err := childBUs(ctx, tx, r.BU.ID)
	if err != nil {
		return Built{}, err
	}
	byChild := &doc.Table{ID: "by-unit", Caption: "Open risks by business unit below", Columns: []doc.Column{
		{Key: "unit", Title: "Business unit", Type: doc.ColText, Width: 2.5}, {Key: "risks", Title: "Open risks", Type: doc.ColNumber},
		{Key: "quantified", Title: "With an exposure", Type: doc.ColNumber},
		{Key: "sum", Title: "Sum of means (not a percentile of the total)", Type: doc.ColAmount, Width: 1.5}}}
	for _, c := range children {
		rows, err := RegisterRows(ctx, tx, c.ID, RegisterParams{})
		if err != nil {
			return Built{}, err
		}
		var sum float64
		n := 0
		for _, x := range rows {
			if x.Mean != nil {
				sum += *x.Mean
				n++
			}
		}
		byChild.Rows = append(byChild.Rows, []string{c.Name, strconv.Itoa(len(rows)), strconv.Itoa(n), num(sum)})
	}
	sections = append(sections, doc.Section{Heading: "By business unit", Level: 1, Blocks: []doc.Block{table(byChild)}})

	// Coverage, acceptances, treatment.
	sections = append(sections, doc.Section{Heading: "Coverage", Level: 1, Blocks: []doc.Block{pairs(
		doc.Pair{Label: "Open risks", Value: strconv.Itoa(len(risks))}, doc.Pair{Label: "With a current analysis", Value: strconv.Itoa(count["current"])},
		doc.Pair{Label: "Stale", Value: strconv.Itoa(count["stale"])}, doc.Pair{Label: "Computing", Value: strconv.Itoa(count["computing"])},
		doc.Pair{Label: "Unquantified", Value: strconv.Itoa(count["unquantified"])})}})
	day, err := today(ctx, tx)
	if err != nil {
		return Built{}, err
	}
	accs, err := AcceptanceRows(ctx, tx, r.BU.ID)
	if err != nil {
		return Built{}, err
	}
	ac := map[string]int{}
	for _, a := range accs {
		ac[a.State]++
		if a.State == "active" && !a.Expires.After(day.AddDate(0, 0, 30)) {
			ac["expiring"]++
		}
	}
	sections = append(sections, doc.Section{Heading: "Acceptances", Level: 1, Blocks: []doc.Block{pairs(
		doc.Pair{Label: "Active", Value: strconv.Itoa(ac["active"])}, doc.Pair{Label: "Expiring within 30 days", Value: strconv.Itoa(ac["expiring"])},
		doc.Pair{Label: "Expired", Value: strconv.Itoa(ac["expired"])}, doc.Pair{Label: "Suspended", Value: strconv.Itoa(ac["suspended"])},
		doc.Pair{Label: "Awaiting decision", Value: strconv.Itoa(ac["pending"])})}})
	acts, err := ActionRows(ctx, tx, r.BU.ID, "", day)
	if err != nil {
		return Built{}, err
	}
	open, overdue := 0, 0
	for _, a := range acts {
		if a.State == "planned" || a.State == "in_progress" {
			open++
		}
		if a.Overdue {
			overdue++
		}
	}
	sections = append(sections, doc.Section{Heading: "Treatment", Level: 1, Blocks: []doc.Block{pairs(
		doc.Pair{Label: "Open actions", Value: strconv.Itoa(open)}, doc.Pair{Label: "Overdue actions", Value: strconv.Itoa(overdue)})}})

	cov, err := coverage(ctx, tx, "register", r.BU.ID)
	if err != nil {
		return Built{}, err
	}
	left, notes := map[string]int{"unquantified": count["unquantified"]}, []string{
		"Exposures are distributions: each figure gives its mean with percentiles; nothing is scored or rated.",
		"Sums of means are sums of each risk's mean, not percentiles of the total; the roll-up gives the total's distribution."}
	cov.leftOutUnits(left, &notes)
	d := doc.Document{Metadata: doc.Metadata{Title: "Portfolio: " + r.BU.Name, Filters: map[string]string{"period_days": strconv.Itoa(period)},
		Runs: runs, LeftOut: left, Notes: notes}, Sections: sections}
	return Built{Doc: d, Risks: len(risks)}, nil
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

// rollupSection is the requester's latest succeeded roll-up of bu: its
// summary, curve and distribution, its time and staleness (F-007-AC-12),
// what it covers and leaves out (F-007-AC-13); the runs of the risks it
// covers for the metadata.
func rollupSection(ctx context.Context, tx pgx.Tx, bu string) (doc.Section, []doc.RunRef, error) {
	sec := doc.Section{Heading: "Exposure", Level: 1}
	var (
		id, digest       string
		finished         time.Time
		summary, incl    []byte
		left             []byte
		rootAgg, rootRun *string
		rootSet          *string
		excluded         int
	)
	err := tx.QueryRow(ctx, `SELECT id::text, finished_at, summary, digest, included, left_out, root_aggregate_id::text, root_run_id::text, root_control_set,
		excluded_bus FROM register.rollup WHERE bu_id = $1 AND state = 'succeeded' ORDER BY finished_at DESC, seq DESC LIMIT 1`, bu).
		Scan(&id, &finished, &summary, &digest, &incl, &left, &rootAgg, &rootRun, &rootSet, &excluded)
	if errors.Is(err, pgx.ErrNoRows) {
		sec.Blocks = append(sec.Blocks, para("The requester has no roll-up of this business unit. A roll-up (Register, Roll-ups) gives the total exposure's distribution."))
		return sec, []doc.RunRef{}, nil
	}
	if err != nil {
		return sec, nil, err
	}
	var now string
	if err := tx.QueryRow(ctx, "SELECT register.rollup_plan($1) ->> 'digest'", bu).Scan(&now); err != nil {
		return sec, nil, err
	}
	var items []struct {
		RiskID string `json:"risk_id"`
	}
	if err := json.Unmarshal(incl, &items); err != nil {
		return sec, nil, err
	}
	var leftOut map[string]int
	if err := json.Unmarshal(left, &leftOut); err != nil {
		return sec, nil, err
	}
	leftTotal := 0
	for _, n := range leftOut {
		leftTotal += n
	}
	stale := "no"
	if now != digest {
		stale = "yes: the register has changed since; request a new roll-up"
	}
	var s map[string]any
	if summary != nil {
		if err := json.Unmarshal(summary, &s); err != nil {
			return sec, nil, err
		}
	}
	sec.Blocks = append(sec.Blocks, pairs(doc.Pair{Label: "Roll-up", Value: id}, doc.Pair{Label: "Computed", Value: finished.UTC().Format("2006-01-02 15:04 UTC")},
		doc.Pair{Label: "Stale", Value: stale}, doc.Pair{Label: "Risks included", Value: strconv.Itoa(len(items))},
		doc.Pair{Label: "Risks left out", Value: strconv.Itoa(leftTotal)}, doc.Pair{Label: "Business units excluded", Value: strconv.Itoa(excluded)}))
	t := summaryTable("rollup", "Total annualized loss (risks combined as independent)", "Roll-up")
	t.Rows = append(t.Rows, aleRow("Total", s))
	sec.Blocks = append(sec.Blocks, table(t))
	if b, ok := curveBlock("rollup-curve", "Loss exceedance curve of the total", "the total", s); ok {
		sec.Blocks = append(sec.Blocks, b)
	}
	var series []byte
	var n int
	switch {
	case rootAgg != nil:
		err = tx.QueryRow(ctx, "SELECT ale, iterations FROM analysis.aggregate WHERE id = $1", *rootAgg).Scan(&series, &n)
	case rootRun != nil && rootSet != nil:
		err = tx.QueryRow(ctx, `SELECT s.ale, a.iterations FROM analysis.series s JOIN analysis.run a ON a.id = s.run_id
			WHERE s.run_id = $1 AND s.control_set = $2`, *rootRun, *rootSet).Scan(&series, &n)
	default:
		err = pgx.ErrNoRows
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return sec, nil, err
	}
	if b, ok := histBlock("rollup-histogram", "Distribution of the total annual loss", series, n); ok {
		sec.Blocks = append(sec.Blocks, b)
	}
	ids := make([]string, 0, len(items))
	for _, x := range items {
		ids = append(ids, x.RiskID)
	}
	runs, err := runRefs(ctx, tx, ids)
	return sec, runs, err
}
