package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ContextSetting is the PostgreSQL custom setting RLS policies read.
const ContextSetting = "authz.ctx"

// ErrNoContext is returned when a scoped transaction is requested without a
// DB context token. Callers must never fall back to an unscoped transaction.
var ErrNoContext = errors.New("authz: missing database context token")

// TxBeginner is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// BeginScoped starts a transaction and binds the signed DB context token to
// it, equivalent to SET LOCAL authz.ctx = '<token>' (ADR-007 step 2).
//
// The token is passed as a bind parameter to set_config(..., is_local => true)
// rather than interpolated into SQL, so a malformed token cannot inject SQL.
// The setting is transaction-local and disappears at COMMIT/ROLLBACK, so a
// pooled connection never carries one caller's context into the next.
//
// Verification of the token happens inside PostgreSQL (authz.visible_bus,
// T-09); an invalid token yields an empty scope (fail closed).
func BeginScoped(ctx context.Context, db TxBeginner, token string) (pgx.Tx, error) {
	if token == "" {
		return nil, ErrNoContext
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("authz: begin: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", ContextSetting, token); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("authz: set context: %w", err)
	}
	return tx, nil
}
