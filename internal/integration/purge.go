package integration

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// F-011 T-17b (design §3.2, §5): staged records are kept for diagnosis for
// integration.records_retention_days, then purged by the integrate
// service's leader (integration.purge_records); runs, proposals, links and
// provenance remain.

// PurgeBatch is how many runs one purge step clears.
const PurgeBatch = 100

// Purger purges staged records past their retention.
type Purger struct {
	DB *pgxpool.Pool // app_integrate
	// Retention gives integration.records_retention_days in force.
	Retention func() (int, error)
	Batch     int           // runs a step (default PurgeBatch)
	Every     time.Duration // default a day
}

// Purged is what a step did.
type Purged struct {
	Runs    int  `json:"runs"`
	Records int  `json:"records"`
	More    bool `json:"more"`
}

// Step purges at most one batch of runs' records.
func (p Purger) Step(ctx context.Context) (Purged, error) {
	days, err := p.Retention()
	if err != nil {
		return Purged{}, err // nothing is purged until the setting is read
	}
	n := p.Batch
	if n <= 0 {
		n = PurgeBatch
	}
	var raw []byte
	if err := p.DB.QueryRow(ctx, "SELECT integration.purge_records($1, $2)", days, n).Scan(&raw); err != nil {
		return Purged{}, err
	}
	var out Purged
	err = json.Unmarshal(raw, &out)
	return out, err
}

// Run purges every interval (and again at once while batches stay full)
// until ctx ends.
func (p Purger) Run(ctx context.Context, onErr func(error)) error {
	every := p.Every
	if every <= 0 {
		every = 24 * time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for {
			got, err := p.Step(ctx)
			if err != nil {
				if ctx.Err() == nil {
					onErr(err)
				}
				break
			}
			if !got.More {
				break
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
