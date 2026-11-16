package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// F-009 T-04 (design §3.1, §3.3): the leader's collection of the features'
// outboxes into notices.

// Collector takes pending outbox rows into notices (notify.collect).
type Collector struct {
	DB     *pgxpool.Pool // app_notify
	Titles func() bool   // the setting notification.detail is "titles"
	Batch  int           // rows per outbox per step; default 500
}

// Collect runs notify.collect once and says how many rows became notices
// and how many have kinds the release does not know (left pending).
func (c Collector) Collect(ctx context.Context) (collected, unknown int, err error) {
	batch := c.Batch
	if batch <= 0 {
		batch = 500
	}
	titles := c.Titles != nil && c.Titles()
	err = c.DB.QueryRow(ctx, "SELECT (r->>'collected')::int, (r->>'unknown')::int FROM notify.collect($1, $2) r", titles, batch).Scan(&collected, &unknown)
	if err != nil {
		return 0, 0, fmt.Errorf("notify: collecting: %w", err)
	}
	return collected, unknown, nil
}

// Every is how often the leader collects (design §1).
const Every = 10 * time.Second
