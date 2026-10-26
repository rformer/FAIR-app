package settings

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go"
)

// Querier is the subset of pgx used by DBSource (*pgxpool.Pool, *pgx.Conn).
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// DBSource reads the posture state through posture.effective_settings and
// posture.settings_version (design §5 access model: services have no table
// privileges). Connect as app_rw.
type DBSource struct{ DB Querier }

// Snapshot implements StateSource.
func (s DBSource) Snapshot(ctx context.Context) (Snapshot, error) {
	var b []byte
	if err := s.DB.QueryRow(ctx, "SELECT posture.effective_settings()").Scan(&b); err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	return snap, nil
}

// Version implements StateSource.
func (s DBSource) Version(ctx context.Context) (int64, error) {
	var v int64
	err := s.DB.QueryRow(ctx, "SELECT posture.settings_version()").Scan(&v)
	return v, err
}

// SubscribeNATS feeds posture.setting.changed into the client. If messages
// are missed, the TTL poll still bounds staleness.
func (c *Client) SubscribeNATS(nc *nats.Conn) (*nats.Subscription, error) {
	return nc.Subscribe(SubjectChanged, func(m *nats.Msg) { _ = c.HandleChanged(m.Data) })
}

// NATSHeartbeat returns a ClientOptions.Publish that sends heartbeats on
// posture.settings.heartbeat (core NATS: a lost heartbeat is replaced by the
// next one).
func NATSHeartbeat(nc *nats.Conn) func(context.Context, Heartbeat) error {
	return func(_ context.Context, h Heartbeat) error {
		b, err := json.Marshal(h)
		if err != nil {
			return err
		}
		return nc.Publish(SubjectHeartbeat, b)
	}
}
