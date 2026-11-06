package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	events "github.com/rformer/fair-app/pkg/audit"
)

// CapacityEvery is how often the leader measures audit storage (design
// §6.8).
const CapacityEvery = 5 * time.Minute

// ParseSize reads a storage size: a whole number of bytes, or with a unit
// KiB, MiB, GiB, TiB (1024-based) or KB, MB, GB, TB (1000-based), as in
// FAIR_AUDIT_STORAGE_QUOTA=200GiB.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40},
		{"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12}, {"B", 1}}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("a size is a positive whole number with an optional unit (KiB, MiB, GiB, TiB, KB, MB, GB, TB), not %q", s)
	}
	if n > (1<<62)/mult {
		return 0, errors.New("the size is too large")
	}
	return n * mult, nil
}

// capacityRank orders the levels.
var capacityRank = map[string]int{"ok": 0, "warning": 1, "critical": 2, "full": 3}

// CapacityResult is one measurement.
type CapacityResult struct {
	Used, Quota     int64
	Level, Previous string
	Finding         string // opened, refreshed, resolved or unchanged
}

// CapacityMonitor measures audit storage against the quota (F-002 T-20,
// AC-30, AC-31; design §6.8): the level follows usage (ok, warning at 75%,
// critical at 90%, full at 100%); rising to warning records
// audit.capacity_warning (high), to critical or full
// audit.capacity_critical (critical), each once per rise; the Posture
// finding audit_capacity follows the level. At full the database refuses
// events from every producer but the audit service (PF015). Run it on the
// leader.
type CapacityMonitor struct {
	DB    *pgxpool.Pool // app_audit
	Audit events.Emitter
	Quota int64 // FAIR_AUDIT_STORAGE_QUOTA, bytes
}

// Step measures once.
func (c CapacityMonitor) Step(ctx context.Context) (CapacityResult, error) {
	res := CapacityResult{Quota: c.Quota}
	if c.Quota <= 0 || c.Audit == nil {
		return res, errors.New("audit capacity: no quota or audit emitter")
	}
	err := pgx.BeginFunc(ctx, c.DB, func(tx pgx.Tx) error {
		var prev *string
		if err := tx.QueryRow(ctx, "SELECT used, level, previous FROM audit.capacity_measure($1)", c.Quota).Scan(&res.Used, &res.Level, &prev); err != nil {
			return err
		}
		if prev != nil {
			res.Previous = *prev
		}
		pct := fmt.Sprintf("%.1f", float64(res.Used)*100/float64(c.Quota))
		detail, _ := json.Marshal(map[string]any{"level": res.Level, "used_bytes": res.Used, "quota_bytes": c.Quota, "percent": pct})
		if err := tx.QueryRow(ctx, "SELECT posture.audit_capacity_finding($1, $2)", res.Level, detail).Scan(&res.Finding); err != nil {
			return err
		}
		if capacityRank[res.Level] <= capacityRank[res.Previous] || res.Level == "ok" {
			return nil // only a rise is recorded
		}
		ev := events.Event{Type: "audit.capacity_warning", Severity: events.SeverityHigh, Actor: "system:audit", Target: "audit:storage",
			Attributes: map[string]string{"level": res.Level, "percent": pct,
				"used_bytes": strconv.FormatInt(res.Used, 10), "quota_bytes": strconv.FormatInt(c.Quota, 10)}}
		if res.Level != "warning" {
			ev.Type, ev.Severity = "audit.capacity_critical", events.SeverityCritical
		}
		return c.Audit.Emit(events.WithTx(ctx, tx), ev)
	})
	if err != nil {
		return res, fmt.Errorf("audit capacity: %w", err)
	}
	return res, nil
}

// Run measures at start and then every interval (CapacityEvery when zero),
// until ctx ends. Errors go to onErr.
func (c CapacityMonitor) Run(ctx context.Context, every time.Duration, onErr func(error)) error {
	if every <= 0 {
		every = CapacityEvery
	}
	for {
		if _, err := c.Step(ctx); err != nil && onErr != nil && ctx.Err() == nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
