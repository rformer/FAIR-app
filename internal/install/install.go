// Package install reads the installation records of F-014 (schema install,
// design §5). fairctl writes them as app_migrator; services read the state
// through install.state() (internal/server's installation-state gate).
package install

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Querier is the part of a pgx pool or transaction the readers use.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// StateReader reads the installation state (install.state(): 'open' before
// an installation is recorded), for server.Server.UseInstallState.
func StateReader(db Querier) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var s string
		err := db.QueryRow(ctx, "SELECT install.state()").Scan(&s)
		return s, err
	}
}
