package reports

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/reports/doc"
)

// F-010 T-15 (F-010-AC-06, AC-07; OQ6; design §3.2): portfolio snapshots
// and trends.

// Snapshots is the leader's snapshot job: every Every it takes a snapshot
// when none was taken within report.snapshot_interval_days and purges
// those older than report.snapshot_retention_days
// (report.snapshot_tick).
type Snapshots struct {
	DB       *pgxpool.Pool // app_rw
	Settings func() (intervalDays, retentionDays int, err error)
	Every    time.Duration // default an hour
	OnError  func(error)
}

// Tick runs one snapshot tick; it returns the snapshot taken (0: none) and
// how many were purged.
func (s *Snapshots) Tick(ctx context.Context) (taken int64, purged int, err error) {
	interval, retention, err := s.Settings()
	if err != nil {
		return 0, 0, fmt.Errorf("reports: the snapshot settings: %w", err)
	}
	var out struct {
		Taken  *int64 `json:"taken"`
		Purged int    `json:"purged"`
	}
	var raw []byte
	if err := s.DB.QueryRow(ctx, "SELECT report.snapshot_tick($1, $2)", interval, retention).Scan(&raw); err != nil {
		return 0, 0, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, 0, err
	}
	if out.Taken != nil {
		taken = *out.Taken
	}
	return taken, out.Purged, nil
}

// Run ticks every Every until ctx ends.
func (s *Snapshots) Run(ctx context.Context) error {
	every := s.Every
	if every <= 0 {
		every = time.Hour
	}
	for {
		if _, _, err := s.Tick(ctx); err != nil && s.OnError != nil && ctx.Err() == nil {
			s.OnError(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(every):
		}
	}
}

// TrendPoint is one snapshot of a BU subtree as the caller may see it.
type TrendPoint struct {
	SnapshotID int64     `json:"snapshot_id"`
	TakenAt    time.Time `json:"taken_at"`
	Counts     struct {
		Open           int            `json:"open"`
		Current        int            `json:"current"`
		Stale          int            `json:"stale"`
		Unquantified   int            `json:"unquantified"`
		MeanSum        float64        `json:"mean_sum"`
		OpenActions    int            `json:"open_actions"`
		OverdueActions int            `json:"overdue_actions"`
		Acceptances    map[string]int `json:"acceptances"`
	} `json:"counts"`
	Rollup *struct {
		FinishedAt time.Time `json:"finished_at"`
		Mean       *float64  `json:"mean"`
		P10        *float64  `json:"p10"`
		P50        *float64  `json:"p50"`
		P90        *float64  `json:"p90"`
		P99        *float64  `json:"p99"`
	} `json:"rollup"`
}

// ReadTrend is bu's trend from from to to, in tx (the caller's context;
// report.trend decides what the caller may see).
func ReadTrend(ctx context.Context, tx pgx.Tx, bu string, from, to time.Time) ([]TrendPoint, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT report.trend($1, $2, $3)", bu, from, to).Scan(&raw); err != nil {
		return nil, err
	}
	out := []TrendPoint{}
	return out, json.Unmarshal(raw, &out)
}

// trendSection is the portfolio report's trend over the period.
func trendSection(points []TrendPoint, days int) doc.Section {
	sec := doc.Section{Heading: "Trend", Level: 1}
	t := &doc.Table{ID: "trend", Caption: fmt.Sprintf("Snapshots over the last %d days", days), Columns: []doc.Column{
		{Key: "taken", Title: "Snapshot", Type: doc.ColTime}, {Key: "open", Title: "Open risks", Type: doc.ColNumber},
		{Key: "current", Title: "Current", Type: doc.ColNumber}, {Key: "stale", Title: "Stale", Type: doc.ColNumber},
		{Key: "unquantified", Title: "Unquantified", Type: doc.ColNumber},
		{Key: "sum", Title: "Sum of means", Type: doc.ColAmount, Width: 1.3},
		{Key: "rollup_mean", Title: "Roll-up mean", Type: doc.ColAmount, Width: 1.3}, {Key: "rollup_p90", Title: "Roll-up 90th", Type: doc.ColAmount, Width: 1.3},
		{Key: "accepted", Title: "Active acceptances", Type: doc.ColNumber}, {Key: "overdue", Title: "Overdue actions", Type: doc.ColNumber}}}
	for _, p := range points {
		mean, p90 := "", ""
		if p.Rollup != nil {
			mean, p90 = numPtr(p.Rollup.Mean), numPtr(p.Rollup.P90)
		}
		c := p.Counts
		t.Rows = append(t.Rows, []string{p.TakenAt.UTC().Format(time.RFC3339), strconv.Itoa(c.Open), strconv.Itoa(c.Current), strconv.Itoa(c.Stale),
			strconv.Itoa(c.Unquantified), num(c.MeanSum), mean, p90, strconv.Itoa(c.Acceptances["active"]), strconv.Itoa(c.OverdueActions)})
	}
	if len(points) == 0 {
		sec.Blocks = append(sec.Blocks, para("No snapshot was taken in the period."))
	} else {
		sec.Blocks = append(sec.Blocks, para("A roll-up appears at the snapshots after it was computed, and only when the requester sees every risk it covers."))
	}
	sec.Blocks = append(sec.Blocks, table(t))
	return sec
}
