package keys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/audit"
)

// ErrKeyMismatch means the database already holds a different secret under
// the key id (a key directory from another installation, or a reused id).
var ErrKeyMismatch = errors.New("keys: authz.ctx_key holds a different secret under this id")

// RegisterDBContext adds the gateway's DB-context key
// (gateway/secrets/db-context.id and .key in dir) to authz.ctx_key, the database's copy that verifies the
// gateway's signed contexts (ADR-007). conn is app_migrator's; it acts as
// fair_owner. Registering a key the database already holds is a no-op
// (registered = false). Audited to emit (the install log).
func RegisterDBContext(ctx context.Context, conn *pgx.Conn, emit audit.Emitter, dir string) (id string, registered bool, err error) {
	id, err = ReadID(filepath.Join(dir, Gateway, SecretsDir, DBContextID))
	if err != nil {
		return "", false, err
	}
	sec, err := ReadSecret(filepath.Join(dir, Gateway, SecretsDir, DBContextKey), SecretLen)
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", DBContextKey, err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE fair_owner"); err != nil {
		return "", false, err
	}
	var have []byte
	switch err := tx.QueryRow(ctx, "SELECT secret FROM authz.ctx_key WHERE key_id = $1", id).Scan(&have); {
	case err == nil && bytes.Equal(have, sec):
		return id, false, nil
	case err == nil:
		return "", false, ErrKeyMismatch
	case !errors.Is(err, pgx.ErrNoRows):
		return "", false, err
	}
	if _, err := tx.Exec(ctx, "SELECT authz.add_ctx_key($1, $2)", id, sec); err != nil {
		return "", false, err
	}
	if err := emit.Emit(ctx, audit.Event{Type: "key.db_context_registered", Severity: audit.SeverityHigh, Actor: "system:installer",
		Target: "authz.ctx_key:" + id}); err != nil {
		return "", false, err // audit failures fail closed
	}
	return id, true, tx.Commit(ctx)
}

// RetireDBContext retires a DB-context key once no gateway signs with it:
// contexts it signed stay valid for ten minutes (authz.retire_ctx_key).
// Refuses the newest active key, which would leave the gateway none.
func RetireDBContext(ctx context.Context, conn *pgx.Conn, emit audit.Emitter, id string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE fair_owner"); err != nil {
		return err
	}
	var others int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM authz.ctx_key WHERE retired_at IS NULL AND key_id <> $1", id).Scan(&others); err != nil {
		return err
	}
	if others == 0 {
		return fmt.Errorf("keys: %s is the only active DB-context key; register its successor first", id)
	}
	if _, err := tx.Exec(ctx, "SELECT authz.retire_ctx_key($1)", id); err != nil {
		return err
	}
	if err := emit.Emit(ctx, audit.Event{Type: "key.db_context_retired", Severity: audit.SeverityHigh, Actor: "system:installer",
		Target: "authz.ctx_key:" + id}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
