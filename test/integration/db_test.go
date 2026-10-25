//go:build integration

// Integration tests for F-001 T-02 (DB roles + migrations) and the authz
// DB-context helper. They need a PostgreSQL 16+ server and psql:
//
//	FAIR_TEST_PG_ADMIN_URL=postgres://admin:pw@127.0.0.1:5432/postgres \
//	  go test -tags integration ./test/integration/...
//
// Each run creates a throwaway database. Roles are cluster-wide, so run
// against a dedicated test server, never a shared one.
package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/migrations"
	"github.com/rformer/fair-app/pkg/authz"
)

var (
	adminURL string
	dbName   string
	pw       = map[string]string{}
	discard  = slog.New(slog.NewTextHandler(io.Discard, nil))
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// urlFor returns a connection URL for role on the test database.
func urlFor(role string) string {
	u, _ := url.Parse(adminURL)
	u.User = url.UserPassword(role, pw[role])
	u.Path = "/" + dbName
	return u.String()
}

func adminDBURL() string {
	u, _ := url.Parse(adminURL)
	u.Path = "/" + dbName
	return u.String()
}

func TestMain(m *testing.M) {
	adminURL = os.Getenv("FAIR_TEST_PG_ADMIN_URL")
	if adminURL == "" {
		fmt.Println("FAIR_TEST_PG_ADMIN_URL not set; skipping integration tests")
		os.Exit(0)
	}
	ctx := context.Background()
	dbName = "fair_it_" + randHex(4)
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		fmt.Println("connect admin:", err)
		os.Exit(1)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		fmt.Println("create db:", err)
		os.Exit(1)
	}
	for _, r := range []string{"app_migrator", "app_rw", "app_engine"} {
		pw[r] = randHex(24)
	}
	cmd := exec.Command("psql", adminDBURL(), "-q", "-v", "ON_ERROR_STOP=1",
		"-v", "migrator_password="+pw["app_migrator"],
		"-v", "app_rw_password="+pw["app_rw"],
		"-v", "app_engine_password="+pw["app_engine"],
		"-f", "../../db/bootstrap/roles.sql")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("bootstrap: %v\n%s\n", err, out)
		os.Exit(1)
	}
	// Bootstrap must be idempotent.
	if out, err := exec.Command(cmd.Path, cmd.Args[1:]...).CombinedOutput(); err != nil {
		fmt.Printf("bootstrap re-run: %v\n%s\n", err, out)
		os.Exit(1)
	}
	code := m.Run()
	if os.Getenv("FAIR_TEST_KEEP_DB") == "" {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
	}
	admin.Close(ctx)
	os.Exit(code)
}

func connect(t *testing.T, role string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(context.Background(), urlFor(role))
	if err != nil {
		t.Fatalf("connect %s: %v", role, err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func migrateUp(t *testing.T) {
	t.Helper()
	migs, err := migrate.Load(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Up(context.Background(), connect(t, "app_migrator"), migs, discard); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// relExists checks the catalog directly, so the answer does not depend on
// the caller's schema privileges.
const relExists = `SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                                   WHERE n.nspname = $1 AND c.relname = $2)`

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// expectDenied runs stmt and requires a privilege/ownership error.
func expectDenied(t *testing.T, c *pgx.Conn, stmt string) {
	t.Helper()
	_, err := c.Exec(context.Background(), stmt)
	switch sqlState(err) {
	case "42501": // insufficient_privilege (includes "must be owner")
	default:
		t.Errorf("%q: want insufficient_privilege, got %v", stmt, err)
	}
}

func TestMigrationsApplyAndAreIdempotent(t *testing.T) {
	migrateUp(t)
	migrateUp(t) // second run applies nothing
	applied, err := migrate.ListApplied(context.Background(), connect(t, "app_migrator"))
	if err != nil || len(applied) == 0 {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
}

func TestRoleAttributes(t *testing.T) {
	migrateUp(t)
	c := connect(t, "app_migrator")
	rows, err := c.Query(context.Background(),
		`SELECT rolname, rolcanlogin, rolbypassrls, rolsuper, rolcreaterole, rolcreatedb
		   FROM pg_roles WHERE rolname IN ('fair_owner','authz_definer','app_migrator','app_rw','app_engine')`)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for rows.Next() {
		var name string
		var login, bypass, super, createrole, createdb bool
		if err := rows.Scan(&name, &login, &bypass, &super, &createrole, &createdb); err != nil {
			t.Fatal(err)
		}
		seen++
		if bypass || super || createrole || createdb {
			t.Errorf("%s has elevated attributes (bypassrls=%v super=%v createrole=%v createdb=%v)", name, bypass, super, createrole, createdb)
		}
		ownerRole := name == "fair_owner" || name == "authz_definer"
		if ownerRole == login {
			t.Errorf("%s: canlogin=%v", name, login)
		}
	}
	if seen != 5 {
		t.Fatalf("found %d roles", seen)
	}
}

func TestOwnerRolesCannotLogIn(t *testing.T) {
	// Give the owner roles a known password so a failure can only be NOLOGIN.
	admin, err := pgx.Connect(context.Background(), adminDBURL())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	for _, r := range []string{"fair_owner", "authz_definer"} {
		pw[r] = randHex(16)
		if _, err := admin.Exec(context.Background(), "ALTER ROLE "+r+" PASSWORD '"+pw[r]+"'"); err != nil {
			t.Fatal(err)
		}
		c, err := pgx.Connect(context.Background(), urlFor(r))
		if err == nil {
			c.Close(context.Background())
			t.Errorf("%s was able to log in", r)
			continue
		}
		if !strings.Contains(err.Error(), "not permitted to log in") {
			t.Errorf("%s: want NOLOGIN refusal, got %v", r, err)
		}
		_, _ = admin.Exec(context.Background(), "ALTER ROLE "+r+" PASSWORD NULL")
	}
}

func TestObjectsOwnedByNonLoginRoles(t *testing.T) {
	migrateUp(t)
	c := connect(t, "app_migrator")
	var bad []string
	rows, err := c.Query(context.Background(), `
		SELECT n.nspname || '.' || cl.relname || ' owned by ' || r.rolname
		  FROM pg_class cl JOIN pg_namespace n ON n.oid = cl.relnamespace JOIN pg_roles r ON r.oid = cl.relowner
		 WHERE n.nspname IN ('iam','authz','fair_meta') AND r.rolcanlogin
		UNION ALL
		SELECT n.nspname || ' owned by ' || r.rolname
		  FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
		 WHERE n.nspname IN ('iam','authz','fair_meta') AND r.rolcanlogin`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		bad = append(bad, s)
	}
	if len(bad) > 0 {
		t.Fatalf("objects owned by login roles: %v", bad)
	}
}

// setupRLSTable creates a forced-RLS table as fair_owner, standing in for the
// BU-owned tables Phase 1 creates via authz.apply_bu_rls.
func setupRLSTable(t *testing.T) string {
	t.Helper()
	migrateUp(t)
	table := "iam.t02_probe_" + randHex(3)
	c := connect(t, "app_migrator")
	ctx := context.Background()
	stmts := []string{
		"SET ROLE fair_owner",
		"CREATE TABLE " + table + " (id int PRIMARY KEY, bu_id text NOT NULL)",
		"INSERT INTO " + table + " VALUES (1,'bu-a'),(2,'bu-b'),(3,'bu-b')",
		"ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY",
		// Stand-in policy keyed on the context setting; T-09 replaces it with
		// the HMAC-verifying authz.visible_bus().
		"CREATE POLICY p ON " + table + " USING (bu_id = current_setting('authz.ctx', true))",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON " + table + " TO app_rw",
		"RESET ROLE",
	}
	for _, s := range stmts {
		if _, err := c.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	return table
}

func TestAppRWCannotBypassRLS(t *testing.T) {
	table := setupRLSTable(t)
	c := connect(t, "app_rw")
	ctx := context.Background()

	var n int
	if err := c.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 0 {
		t.Fatalf("without context app_rw saw %d rows (err %v); want 0 (fail closed)", n, err)
	}

	// Turning row security off does not bypass it: PostgreSQL raises an error.
	if _, err := c.Exec(ctx, "SET row_security = off"); err != nil {
		t.Fatal(err)
	}
	_, err := c.Exec(ctx, "SELECT * FROM "+table)
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("row_security=off should error for a NOBYPASSRLS role, got %v", err)
	}
	_, _ = c.Exec(ctx, "RESET row_security")

	expectDenied(t, c, "ALTER TABLE "+table+" DISABLE ROW LEVEL SECURITY")
	expectDenied(t, c, "ALTER TABLE "+table+" NO FORCE ROW LEVEL SECURITY")
	expectDenied(t, c, "DROP POLICY p ON "+table)
	expectDenied(t, c, "ALTER ROLE app_rw BYPASSRLS")

	// Scoped transaction sees only its BU.
	tx, err := authz.BeginScoped(ctx, c, "bu-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 2 {
		t.Fatalf("scoped count = %d, %v; want 2", n, err)
	}
	_ = tx.Rollback(ctx)
}

func TestAppRWCannotReadKeysOrAlterSchema(t *testing.T) {
	table := setupRLSTable(t)
	c := connect(t, "app_rw")
	expectDenied(t, c, "SELECT * FROM authz.ctx_key")
	expectDenied(t, c, "INSERT INTO authz.ctx_key VALUES ('k', '\\x00')")
	expectDenied(t, c, "ALTER TABLE "+table+" ADD COLUMN x int")
	expectDenied(t, c, "DROP TABLE "+table)
	expectDenied(t, c, "CREATE TABLE iam.sneaky (id int)")
	expectDenied(t, c, "CREATE SCHEMA sneaky")
	expectDenied(t, c, "CREATE TABLE public.sneaky (id int)")
	expectDenied(t, c, "SET ROLE fair_owner")
	expectDenied(t, c, "SET ROLE authz_definer")
	expectDenied(t, c, "SELECT * FROM fair_meta.schema_migrations")

	// app_engine has no table access at all yet.
	e := connect(t, "app_engine")
	expectDenied(t, e, "SELECT * FROM "+table)
	expectDenied(t, e, "SELECT * FROM authz.ctx_key")

	// Even the table-owner role cannot read the HMAC key: it belongs to authz_definer.
	m := connect(t, "app_migrator")
	if _, err := m.Exec(context.Background(), "SET ROLE fair_owner"); err != nil {
		t.Fatal(err)
	}
	expectDenied(t, m, "SELECT * FROM authz.ctx_key")
	// And the migrator inherits nothing without an explicit SET ROLE.
	m2 := connect(t, "app_migrator")
	expectDenied(t, m2, "SELECT * FROM authz.ctx_key")
	expectDenied(t, m2, "CREATE TABLE iam.unowned (id int)")
}

func TestBeginScopedIsTransactionLocalAndInjectionSafe(t *testing.T) {
	migrateUp(t)
	c := connect(t, "app_rw")
	ctx := context.Background()
	evil := `x'; DROP TABLE authz.ctx_key; --`
	tx, err := authz.BeginScoped(ctx, c, evil)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	if err := tx.QueryRow(ctx, "SELECT current_setting('authz.ctx')").Scan(&got); err != nil || got != evil {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, "SELECT coalesce(current_setting('authz.ctx', true), '')").Scan(&got); err != nil || got != "" {
		t.Fatalf("context leaked past commit: %q, %v", got, err)
	}
	// ctx_key still exists (check as its owner).
	m := connect(t, "app_migrator")
	var exists bool
	_ = m.QueryRow(ctx, relExists, "authz", "ctx_key").Scan(&exists)
	if !exists {
		t.Fatal("injection succeeded")
	}
}

func TestMigrationTamperAndDowngradeRefused(t *testing.T) {
	migrateUp(t)
	c := connect(t, "app_migrator")
	ctx := context.Background()
	migs, _ := migrate.Load(migrations.FS)

	tampered := append([]migrate.Migration(nil), migs...)
	tampered[0].Checksum = "deadbeef"
	if _, err := migrate.Up(ctx, c, tampered, discard); !errors.Is(err, migrate.ErrChecksumMismatch) {
		t.Fatalf("tamper: got %v", err)
	}
	if _, err := migrate.Up(ctx, c, nil, discard); !errors.Is(err, migrate.ErrDatabaseNewer) {
		t.Fatalf("downgrade: got %v", err)
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	migrateUp(t)
	c := connect(t, "app_migrator")
	ctx := context.Background()
	migs, _ := migrate.Load(migrations.FS)
	next := len(migs) + 1
	fs := fstest.MapFS{}
	for _, m := range migs {
		fs[fmt.Sprintf("%04d_%s.sql", m.Version, m.Name)] = &fstest.MapFile{Data: []byte(m.SQL)}
	}
	fs[fmt.Sprintf("%04d_broken.sql", next)] = &fstest.MapFile{Data: []byte("CREATE TABLE iam.half_done (id int); SELECT 1/0;")}
	all, err := migrate.Load(fs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Up(ctx, c, all, discard); err == nil {
		t.Fatal("expected failure")
	}
	var exists bool
	_ = c.QueryRow(ctx, relExists, "iam", "half_done").Scan(&exists)
	if exists {
		t.Fatal("partial migration was not rolled back")
	}
	applied, _ := migrate.ListApplied(ctx, c)
	if len(applied) != len(migs) {
		t.Fatalf("broken migration recorded: %v", applied)
	}
}
