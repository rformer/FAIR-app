package authz

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go"
)

// ErrNoDBContext is returned by WithDBContext when no token is supplied.
var ErrNoDBContext = errors.New("authz: no database context token")

// TxBeginner starts transactions; *pgxpool.Pool and *pgx.Conn implement it.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// WithDBContext runs fn in a transaction whose row-level security sees the
// caller's scope (ADR-007): it sets authz.ctx to token for that transaction
// only. The token is passed as a parameter, never spliced into SQL. fn's
// error rolls the transaction back.
func WithDBContext(ctx context.Context, db TxBeginner, token string, fn func(pgx.Tx) error) error {
	if token == "" {
		return ErrNoDBContext
	}
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('authz.ctx', $1, true)", token); err != nil {
			return err
		}
		return fn(tx)
	})
}

// DBLoader loads snapshots with authz.grant_snapshot() (migration 0010),
// which answers only for the user named by the principal's DBToken.
func DBLoader(db TxBeginner) Loader {
	return func(ctx context.Context, p Principal) (Snapshot, error) {
		snap := Snapshot{Grants: map[Permission]map[string]struct{}{}}
		err := WithDBContext(ctx, db, p.DBToken, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, "SELECT scope_version, permission, bus::text[] FROM authz.grant_snapshot()")
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var perm string
				var bus []string
				if err := rows.Scan(&snap.Version, &perm, &bus); err != nil {
					return err
				}
				set := make(map[string]struct{}, len(bus))
				for _, b := range bus {
					set[b] = struct{}{}
				}
				snap.Grants[Permission(perm)] = set
			}
			return rows.Err()
		})
		return snap, err
	}
}

// SubjectScopeChanged carries scope changes from the scope worker.
const SubjectScopeChanged = "iam.scope.changed"

// SubscribeNATS keeps the cache current from iam.scope.changed. If messages
// are missed, CacheOptions.MaxAge still bounds staleness.
func (c *Cache) SubscribeNATS(nc *nats.Conn) (*nats.Subscription, error) {
	return nc.Subscribe(SubjectScopeChanged, func(m *nats.Msg) { _ = c.HandleScopeChanged(m.Data) })
}
