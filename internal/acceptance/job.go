package acceptance

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// F-008 T-06 (F-008-AC-09, AC-10, AC-13; design §3.2, §3.6).

// Swept is what one sweep did.
type Swept struct {
	Expired   int `json:"expired"`
	Notices   int `json:"notices"`
	Suspended int `json:"suspended"`
}

// Job is the risk service leader's acceptance job: every minute,
// acceptance.sweep ends acceptances past their expiry, queues the notices
// before and on expiry, and suspends acceptances whose exposure entered a
// higher tier. It catches up after an outage: every due change is made on
// the next sweep.
type Job struct {
	DB      *pgxpool.Pool // app_rw
	Every   time.Duration // default one minute
	OnError func(error)
}

// Sweep runs acceptance.sweep once.
func (j Job) Sweep(ctx context.Context) (Swept, error) {
	var s Swept
	if err := j.DB.QueryRow(ctx, "SELECT (r->>'expired')::int, (r->>'notices')::int, (r->>'suspended')::int FROM acceptance.sweep() r").
		Scan(&s.Expired, &s.Notices, &s.Suspended); err != nil {
		return Swept{}, fmt.Errorf("acceptance: sweeping: %w", err)
	}
	return s, nil
}

// Run sweeps until ctx ends (while this replica leads).
func (j Job) Run(ctx context.Context) error {
	every := j.Every
	if every <= 0 {
		every = time.Minute
	}
	for {
		if _, err := j.Sweep(ctx); err != nil && ctx.Err() == nil && j.OnError != nil {
			j.OnError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
