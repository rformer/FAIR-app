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
	// More: the sweep stopped at its batch (acceptance.sweep_batch), with
	// acceptances left to handle; Run sweeps again at once.
	More bool `json:"more"`
}

// Job is the risk service leader's acceptance job: every minute,
// acceptance.sweep ends acceptances past their expiry, queues the notices
// before and on expiry, and suspends acceptances whose exposure entered a
// higher tier. It catches up after an outage: every due change is made by
// the next sweeps, run back to back while one stops at its batch.
type Job struct {
	DB      *pgxpool.Pool // app_rw
	Every   time.Duration // default one minute
	OnError func(error)
}

// Sweep runs acceptance.sweep once.
func (j Job) Sweep(ctx context.Context) (Swept, error) {
	var s Swept
	if err := j.DB.QueryRow(ctx, "SELECT (r->>'expired')::int, (r->>'notices')::int, (r->>'suspended')::int, (r->>'more')::boolean FROM acceptance.sweep() r").
		Scan(&s.Expired, &s.Notices, &s.Suspended, &s.More); err != nil {
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
		s, err := j.Sweep(ctx)
		if err != nil && ctx.Err() == nil && j.OnError != nil {
			j.OnError(err)
		}
		if err == nil && s.More && ctx.Err() == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
