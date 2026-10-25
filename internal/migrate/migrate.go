// Package migrate applies forward-only SQL migrations (F-001 T-02).
//
// Rules:
//   - Runs as app_migrator, which owns nothing. Each migration runs in its own
//     transaction under SET LOCAL ROLE fair_owner, so every object is owned by
//     the non-login owner role (AC-27).
//   - Forward-only (ADR-005 upgrade policy). There are no down migrations;
//     rollback is restore-from-backup.
//   - Applied migrations are checksummed. If a file that already ran has been
//     edited, or the database is at a newer version than this binary knows,
//     the runner refuses to continue.
//   - A session advisory lock serialises concurrent runners (e.g. two Helm
//     hook pods during a rolling upgrade).
package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// OwnerRole owns platform objects.
const OwnerRole = "fair_owner"

// lockKey is an arbitrary constant for pg_advisory_lock.
const lockKey int64 = 0x4641495231 // "FAIR1"

var nameRe = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// Migration is one SQL file.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// Errors.
var (
	ErrChecksumMismatch = errors.New("migrate: an applied migration has been modified")
	ErrDatabaseNewer    = errors.New("migrate: database schema is newer than this release")
	ErrBadFileName      = errors.New("migrate: migration file name must be NNNN_name.sql")
)

// Load reads migrations from fsys, sorted by version. Versions must be
// contiguous from 1 so a missing file is caught at build time.
func Load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || e.Name() == "embed.go" {
			continue
		}
		m := nameRe.FindStringSubmatch(e.Name())
		if m == nil {
			if len(e.Name()) > 4 && e.Name()[len(e.Name())-4:] == ".sql" {
				return nil, fmt.Errorf("%w: %s", ErrBadFileName, e.Name())
			}
			continue
		}
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		v, _ := strconv.Atoi(m[1])
		sum := sha256.Sum256(b)
		out = append(out, Migration{Version: v, Name: m[2], SQL: string(b), Checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migrate: versions must be contiguous from 0001; found %04d at position %d", m.Version, i+1)
		}
	}
	return out, nil
}

// Applied is a row in fair_meta.schema_migrations.
type Applied struct {
	Version  int
	Name     string
	Checksum string
}

// Up applies pending migrations on conn and returns the versions applied.
func Up(ctx context.Context, conn *pgx.Conn, migs []Migration, log *slog.Logger) ([]int, error) {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockKey); err != nil {
		return nil, fmt.Errorf("migrate: lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lockKey)
	}()

	if err := ensureMeta(ctx, conn); err != nil {
		return nil, err
	}
	applied, err := ListApplied(ctx, conn)
	if err != nil {
		return nil, err
	}
	known := map[int]Migration{}
	for _, m := range migs {
		known[m.Version] = m
	}
	for _, a := range applied {
		m, ok := known[a.Version]
		if !ok {
			return nil, fmt.Errorf("%w: database has %04d_%s", ErrDatabaseNewer, a.Version, a.Name)
		}
		if m.Checksum != a.Checksum {
			return nil, fmt.Errorf("%w: %04d_%s", ErrChecksumMismatch, a.Version, a.Name)
		}
	}
	done := map[int]bool{}
	for _, a := range applied {
		done[a.Version] = true
	}
	var ran []int
	for _, m := range migs {
		if done[m.Version] {
			continue
		}
		if err := apply(ctx, conn, m); err != nil {
			return ran, err
		}
		log.Info("migration applied", "version", m.Version, "name", m.Name)
		ran = append(ran, m.Version)
	}
	return ran, nil
}

func ensureMeta(ctx context.Context, conn *pgx.Conn) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	stmts := []string{
		"SET LOCAL ROLE " + OwnerRole,
		"CREATE SCHEMA IF NOT EXISTS fair_meta",
		"REVOKE ALL ON SCHEMA fair_meta FROM PUBLIC",
		`CREATE TABLE IF NOT EXISTS fair_meta.schema_migrations (
			version    integer     PRIMARY KEY,
			name       text        NOT NULL,
			checksum   text        NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now(),
			applied_by text        NOT NULL DEFAULT session_user
		)`,
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("migrate: meta: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ListApplied returns applied migrations in order.
func ListApplied(ctx context.Context, conn *pgx.Conn) ([]Applied, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+OwnerRole); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, "SELECT version, name, checksum FROM fair_meta.schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("migrate: list: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Applied, error) {
		var a Applied
		err := r.Scan(&a.Version, &a.Name, &a.Checksum)
		return a, err
	})
}

func apply(ctx context.Context, conn *pgx.Conn, m Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+OwnerRole); err != nil {
		return fmt.Errorf("migrate: %04d: set role: %w", m.Version, err)
	}
	// No bind arguments: pgx uses the simple protocol, so a file may hold
	// several statements.
	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return fmt.Errorf("migrate: %04d_%s: %w", m.Version, m.Name, err)
	}
	// The migration may have switched roles; record as the owner.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+OwnerRole); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO fair_meta.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
		m.Version, m.Name, m.Checksum); err != nil {
		return fmt.Errorf("migrate: record %04d: %w", m.Version, err)
	}
	return tx.Commit(ctx)
}
