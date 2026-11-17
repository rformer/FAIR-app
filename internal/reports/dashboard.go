package reports

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/reports/doc"
)

// F-010 T-14 (F-010-AC-01 to AC-05; design §3.1): the portfolio dashboard
// of a BU's subtree, read in one snapshot as the caller sees it. The
// portfolio report is this as a document (T-11).

// Dashboard is a BU subtree's portfolio.
type Dashboard struct {
	BU          string         `json:"bu_id"`
	AsOf        time.Time      `json:"as_of"`
	Rollup      *RollupView    `json:"rollup"`
	Largest     []RiskView     `json:"largest"`
	Children    []ChildView    `json:"children"`
	Coverage    Coverage4      `json:"coverage"`
	Acceptances map[string]int `json:"acceptances"` // active, expiring (30 days), expired, suspended, pending
	Treatment   map[string]int `json:"treatment"`   // open, overdue
	Restricted  map[string]any `json:"restricted"`  // report.aggregate_counts; null without aggregate-only units
	LeftOut     map[string]int `json:"left_out"`
	Runs        []doc.RunRef   `json:"-"`
	risks       []RegisterRow
}

// Coverage4 counts open risks by exposure status (F-007-AC-08).
type Coverage4 struct {
	Open         int `json:"open"`
	Current      int `json:"current"`
	Stale        int `json:"stale"`
	Computing    int `json:"computing"`
	Unquantified int `json:"unquantified"`
}

// RiskView is one of the largest risks.
type RiskView struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Owner  string   `json:"owner"`
	Mean   *float64 `json:"mean"`
	P10    *float64 `json:"p10"`
	P90    *float64 `json:"p90"`
	Status string   `json:"status"`
}

// ChildView is a child BU's subtree: its open risks and the sum of their
// means (labelled as such), and the p90 of the caller's own roll-up of it.
type ChildView struct {
	ID         string   `json:"bu_id"`
	Name       string   `json:"name"`
	Open       int      `json:"open_risks"`
	Quantified int      `json:"quantified"`
	MeanSum    float64  `json:"mean_sum"`
	RollupP90  *float64 `json:"rollup_p90"`
}

// RollupView is the caller's latest succeeded roll-up of the BU (F-007).
type RollupView struct {
	ID           string          `json:"id"`
	FinishedAt   time.Time       `json:"finished_at"`
	Stale        bool            `json:"stale"`
	Summary      json.RawMessage `json:"summary"`
	Covers       int             `json:"covers"`
	LeftOut      map[string]int  `json:"left_out"`
	LeftOutTotal int             `json:"left_out_total"`
	ExcludedBUs  int             `json:"excluded_bus"`
	series       []byte
	iterations   int
	riskIDs      []string
}

// ReadDashboard reads bu's dashboard in tx (the caller's context).
func ReadDashboard(ctx context.Context, tx pgx.Tx, bu string) (*Dashboard, error) {
	d := &Dashboard{BU: bu, Acceptances: map[string]int{}, Treatment: map[string]int{}, Largest: []RiskView{}, Children: []ChildView{}, Runs: []doc.RunRef{}}
	if err := tx.QueryRow(ctx, "SELECT now()").Scan(&d.AsOf); err != nil {
		return nil, err
	}
	risks, err := RegisterRows(ctx, tx, bu, RegisterParams{})
	if err != nil {
		return nil, err
	}
	d.risks = risks
	for _, x := range risks {
		d.Coverage.Open++
		switch x.Status {
		case "current":
			d.Coverage.Current++
		case "stale":
			d.Coverage.Stale++
		case "computing":
			d.Coverage.Computing++
		case "unquantified":
			d.Coverage.Unquantified++
		}
		if x.Mean != nil && len(d.Largest) < LargestRisks {
			d.Largest = append(d.Largest, RiskView{ID: x.ID, Title: x.Title, Owner: x.Owner, Mean: x.Mean, P10: x.P10, P90: x.P90, Status: x.Status})
		}
	}
	if d.Rollup, err = latestRollup(ctx, tx, bu); err != nil {
		return nil, err
	}
	if d.Rollup != nil {
		if d.Runs, err = runRefs(ctx, tx, d.Rollup.riskIDs); err != nil {
			return nil, err
		}
	}
	children, err := childBUs(ctx, tx, bu)
	if err != nil {
		return nil, err
	}
	for _, c := range children {
		rows, err := RegisterRows(ctx, tx, c.ID, RegisterParams{})
		if err != nil {
			return nil, err
		}
		cv := ChildView{ID: c.ID, Name: c.Name, Open: len(rows)}
		for _, x := range rows {
			if x.Mean != nil {
				cv.MeanSum += *x.Mean
				cv.Quantified++
			}
		}
		if r, err := latestRollup(ctx, tx, c.ID); err != nil {
			return nil, err
		} else if r != nil {
			var s struct {
				ALE struct {
					Percentiles map[string]*float64 `json:"percentiles"`
				} `json:"ale"`
			}
			if json.Unmarshal(r.Summary, &s) == nil {
				cv.RollupP90 = s.ALE.Percentiles["p90"]
			}
		}
		d.Children = append(d.Children, cv)
	}
	day, err := today(ctx, tx)
	if err != nil {
		return nil, err
	}
	accs, err := AcceptanceRows(ctx, tx, bu)
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"active", "expiring", "expired", "suspended", "pending"} {
		d.Acceptances[k] = 0
	}
	for _, a := range accs {
		d.Acceptances[a.State]++
		if a.State == "active" && !a.Expires.After(day.AddDate(0, 0, 30)) {
			d.Acceptances["expiring"]++
		}
	}
	acts, err := ActionRows(ctx, tx, bu, "", day)
	if err != nil {
		return nil, err
	}
	d.Treatment["open"], d.Treatment["overdue"] = 0, 0
	for _, a := range acts {
		if a.State == "planned" || a.State == "in_progress" {
			d.Treatment["open"]++
		}
		if a.Overdue {
			d.Treatment["overdue"]++
		}
	}
	var restricted []byte
	if err := tx.QueryRow(ctx, "SELECT report.aggregate_counts($1)", bu).Scan(&restricted); err != nil {
		return nil, err
	}
	if restricted != nil {
		if err := json.Unmarshal(restricted, &d.Restricted); err != nil {
			return nil, err
		}
	}
	cov, err := coverage(ctx, tx, "register", bu)
	if err != nil {
		return nil, err
	}
	d.LeftOut = map[string]int{"unquantified": d.Coverage.Unquantified}
	var notes []string
	cov.leftOutUnits(d.LeftOut, &notes)
	return d, nil
}

// latestRollup is the caller's latest succeeded roll-up of bu (nil without
// one), with its staleness (F-007-AC-12).
func latestRollup(ctx context.Context, tx pgx.Tx, bu string) (*RollupView, error) {
	r := &RollupView{}
	var digest string
	var incl, left []byte
	var rootAgg, rootRun, rootSet *string
	err := tx.QueryRow(ctx, `SELECT id::text, finished_at, summary, digest, included, left_out, root_aggregate_id::text, root_run_id::text, root_control_set,
		excluded_bus FROM register.rollup WHERE bu_id = $1 AND state = 'succeeded' ORDER BY finished_at DESC, seq DESC LIMIT 1`, bu).
		Scan(&r.ID, &r.FinishedAt, &r.Summary, &digest, &incl, &left, &rootAgg, &rootRun, &rootSet, &r.ExcludedBUs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var now string
	if err := tx.QueryRow(ctx, "SELECT register.rollup_plan($1) ->> 'digest'", bu).Scan(&now); err != nil {
		return nil, err
	}
	r.Stale = now != digest
	var items []struct {
		RiskID string `json:"risk_id"`
	}
	if err := json.Unmarshal(incl, &items); err != nil {
		return nil, err
	}
	r.Covers = len(items)
	for _, x := range items {
		r.riskIDs = append(r.riskIDs, x.RiskID)
	}
	if err := json.Unmarshal(left, &r.LeftOut); err != nil {
		return nil, err
	}
	for _, n := range r.LeftOut {
		r.LeftOutTotal += n
	}
	switch {
	case rootAgg != nil:
		err = tx.QueryRow(ctx, "SELECT ale, iterations FROM analysis.aggregate WHERE id = $1", *rootAgg).Scan(&r.series, &r.iterations)
	case rootRun != nil && rootSet != nil:
		err = tx.QueryRow(ctx, `SELECT s.ale, a.iterations FROM analysis.series s JOIN analysis.run a ON a.id = s.run_id
			WHERE s.run_id = $1 AND s.control_set = $2`, *rootRun, *rootSet).Scan(&r.series, &r.iterations)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return r, nil
}
