// Package tests verifies the database role model (F-001 T-02, AC-27, ADR-007).
//
// These tests need a PostgreSQL 16+ server and the psql client. They run when
// the admin connection is provided through standard libpq variables:
//
//	FAIR_TEST_PG=1 PGHOST=... PGPORT=... PGUSER=<superuser> PGPASSWORD=... go test ./db/tests/
//
// Each run creates and drops its own database. Roles are cluster-wide and are
// re-asserted idempotently by the bootstrap script.
package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	fairdb "github.com/rformer/fair-app/db"
	"github.com/rformer/fair-app/internal/access/catalog"
	"github.com/rformer/fair-app/internal/migrate"
)

type env struct {
	t        *testing.T
	root     string
	db       string
	secrets  map[string]string // role -> password file
	adminEnv []string
	install  migrate.Result // result of the first migration run
}

func setup(t *testing.T) *env {
	t.Helper()
	if os.Getenv("FAIR_TEST_PG") != "1" {
		t.Skip("set FAIR_TEST_PG=1 and libpq admin variables to run database tests")
	}
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skip("psql not installed")
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))

	e := &env{t: t, root: root, db: "fairtest_" + randHex(6), secrets: map[string]string{}, adminEnv: os.Environ()}
	dir := t.TempDir()
	for _, r := range []string{"app_migrator", "app_rw", "app_engine", "app_posture"} {
		p := filepath.Join(dir, r)
		if err := os.WriteFile(p, []byte(randHex(24)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		e.secrets[r] = p
	}

	e.admin("postgres", "CREATE DATABASE "+e.db)
	t.Cleanup(func() {
		_ = e.psqlAs(nil, "postgres", fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", e.db))
	})

	e.script("db-bootstrap.sh", map[string]string{
		"PGDATABASE":                  e.db,
		"FAIR_MIGRATOR_PASSWORD_FILE": e.secrets["app_migrator"],
		"FAIR_RW_PASSWORD_FILE":       e.secrets["app_rw"],
		"FAIR_ENGINE_PASSWORD_FILE":   e.secrets["app_engine"],
		"FAIR_POSTURE_PASSWORD_FILE":  e.secrets["app_posture"],
	})
	res, err := e.migrate("")
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	e.install = res
	return e
}

// migrate runs the embedded migration runner (T-02b) as app_migrator. dir,
// when set, replaces the embedded migrations with the files in it.
func (e *env) migrate(dir string) (migrate.Result, error) {
	cfg, err := migrate.ConnConfig("development", e.secrets["app_migrator"])
	if err != nil {
		return migrate.Result{}, err
	}
	cfg.Database = e.db
	ctx := context.Background()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return migrate.Result{}, err
	}
	defer func() { _ = conn.Close(ctx) }()

	var migrations fs.FS
	if dir != "" {
		migrations = os.DirFS(dir)
	} else if migrations, err = fs.Sub(fairdb.Migrations, "migrations"); err != nil {
		return migrate.Result{}, err
	}
	c, roles, err := catalog.Release()
	if err != nil {
		return migrate.Result{}, err
	}
	payload, err := catalog.SyncPayload(c, roles)
	if err != nil {
		return migrate.Result{}, err
	}
	return migrate.Run(ctx, conn, migrations, payload)
}

func (e *env) script(name string, vars map[string]string) {
	e.t.Helper()
	if out, err := e.scriptErr(name, vars); err != nil {
		e.t.Fatalf("%s failed: %v\n%s", name, err, out)
	}
}

func (e *env) scriptErr(name string, vars map[string]string) (string, error) {
	cmd := exec.Command("bash", filepath.Join(e.root, "scripts", name))
	cmd.Env = withVars(e.adminEnv, vars)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// admin runs SQL as the admin connection against database db.
func (e *env) admin(db, sql string) {
	e.t.Helper()
	if err := e.psqlAs(nil, db, sql); err != nil {
		e.t.Fatalf("admin SQL failed: %v", err)
	}
}

func (e *env) psqlAs(vars map[string]string, db, sql string) error {
	cmd := exec.Command("psql", "--no-psqlrc", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql)
	cmd.Env = withVars(e.adminEnv, vars)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(buf.String()))
	}
	return nil
}

// as runs SQL as an application role and returns (output, error).
func (e *env) as(role, sql string) (string, error) {
	pw, _ := os.ReadFile(e.secrets[role])
	cmd := exec.Command("psql", "--no-psqlrc", "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1", "-d", e.db, "-c", sql)
	cmd.Env = withVars(e.adminEnv, map[string]string{"PGUSER": role, "PGPASSWORD": strings.TrimSpace(string(pw))})
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (e *env) mustFail(role, sql, wantSubstr string) {
	e.t.Helper()
	out, err := e.as(role, sql)
	if err == nil {
		e.t.Fatalf("%s: expected failure for %q, got success: %s", role, sql, out)
	}
	if wantSubstr != "" && !strings.Contains(out, wantSubstr) {
		e.t.Fatalf("%s: expected %q in error, got: %s", role, wantSubstr, out)
	}
}

func TestRoleAttributes(t *testing.T) {
	e := setup(t)
	out, err := e.as("app_rw", `SELECT string_agg(rolname||':'||rolcanlogin||':'||rolbypassrls||':'||rolsuper||':'||rolinherit, ',' ORDER BY rolname)
		FROM pg_roles WHERE rolname IN ('fair_owner','authz_definer','posture_definer','app_migrator','app_rw','app_engine','app_posture')`)
	if err != nil {
		t.Fatal(err, out)
	}
	want := "app_engine:true:false:false:false,app_migrator:true:false:false:false,app_posture:true:false:false:false,app_rw:true:false:false:false," +
		"authz_definer:false:false:false:false,fair_owner:false:false:false:false,posture_definer:false:false:false:false"
	if out != want {
		t.Fatalf("role attributes\n got: %s\nwant: %s", out, want)
	}
}

func TestAppRoleCannotReadContextKeys(t *testing.T) {
	e := setup(t)
	e.mustFail("app_rw", "SELECT * FROM authz.ctx_key", "permission denied")
	e.mustFail("app_engine", "SELECT * FROM authz.ctx_key", "permission denied")
	// The migrator, without SET ROLE, inherits nothing.
	e.mustFail("app_migrator", "SELECT * FROM authz.ctx_key", "permission denied")
}

func TestAppRoleCannotCreateOrAlter(t *testing.T) {
	e := setup(t)
	e.mustFail("app_rw", "CREATE TABLE iam.evil(id int)", "permission denied")
	e.mustFail("app_rw", "CREATE TABLE public.evil(id int)", "permission denied")
	e.mustFail("app_rw", "CREATE SCHEMA evil", "permission denied")
	e.mustFail("app_rw", "ALTER TABLE authz.ctx_key DISABLE ROW LEVEL SECURITY", "must be owner")
	e.mustFail("app_rw", "SET ROLE fair_owner", "permission denied")
	e.mustFail("app_rw", "SELECT * FROM fair_meta.schema_migrations", "permission denied")
}

func TestAppRoleCannotBypassRLS(t *testing.T) {
	e := setup(t)
	dir := t.TempDir()
	copyMigrations(t, e.root, dir)
	probe := `CREATE TABLE iam.rls_probe (id int PRIMARY KEY, secret text);
INSERT INTO iam.rls_probe VALUES (1, 'top secret');
ALTER TABLE iam.rls_probe ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.rls_probe FORCE ROW LEVEL SECURITY;
CREATE POLICY deny_all ON iam.rls_probe USING (false);
GRANT SELECT, INSERT, UPDATE, DELETE ON iam.rls_probe TO app_rw;
`
	if err := os.WriteFile(filepath.Join(dir, "9000_rls_probe.sql"), []byte(probe), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.migrate(dir); err != nil {
		t.Fatalf("migrate probe: %v", err)
	}

	out, err := e.as("app_rw", "SELECT count(*) FROM iam.rls_probe")
	if err != nil || out != "0" {
		t.Fatalf("app_rw must see 0 rows under RLS, got %q err=%v", out, err)
	}
	e.mustFail("app_rw", "SET row_security = off; SELECT * FROM iam.rls_probe", "row-level security")
	e.mustFail("app_rw", "ALTER TABLE iam.rls_probe DISABLE ROW LEVEL SECURITY", "must be owner")
	e.mustFail("app_rw", "DROP POLICY deny_all ON iam.rls_probe", "must be owner")
	e.mustFail("app_rw", "INSERT INTO iam.rls_probe VALUES (2, 'x')", "row-level security")
}

func TestOwnerRolesCannotLogIn(t *testing.T) {
	e := setup(t)
	for _, r := range []string{"fair_owner", "authz_definer", "posture_definer"} {
		cmd := exec.Command("psql", "--no-psqlrc", "-X", "-d", e.db, "-c", "SELECT 1")
		cmd.Env = withVars(e.adminEnv, map[string]string{"PGUSER": r, "PGPASSWORD": "irrelevant"})
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("%s must not be able to log in: %s", r, out)
		}
	}
}

func TestMigrationsIdempotentAndTamperEvident(t *testing.T) {
	e := setup(t)
	if res, err := e.migrate(""); err != nil || len(res.Applied) != 0 || len(res.Sync.AddedPermissions) != 0 {
		t.Fatalf("second run must apply nothing: err=%v result=%+v", err, res)
	}

	dir := t.TempDir()
	copyMigrations(t, e.root, dir)
	f := filepath.Join(dir, "0001_schemas.sql")
	b, _ := os.ReadFile(f)
	if err := os.WriteFile(f, append(b, []byte("\n-- tampered\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.migrate(dir); !errors.Is(err, migrate.ErrChecksum) {
		t.Fatalf("modified applied migration must be refused: err=%v", err)
	}
}

func TestBootstrapRepairsRoleDrift(t *testing.T) {
	e := setup(t)
	e.admin(e.db, "ALTER ROLE app_rw BYPASSRLS")
	e.script("db-bootstrap.sh", map[string]string{
		"PGDATABASE":                  e.db,
		"FAIR_MIGRATOR_PASSWORD_FILE": e.secrets["app_migrator"],
		"FAIR_RW_PASSWORD_FILE":       e.secrets["app_rw"],
		"FAIR_ENGINE_PASSWORD_FILE":   e.secrets["app_engine"],
		"FAIR_POSTURE_PASSWORD_FILE":  e.secrets["app_posture"],
	})
	out, err := e.as("app_rw", "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'app_rw'")
	if err != nil || out != "f" {
		t.Fatalf("bootstrap must remove BYPASSRLS drift, got %q err=%v", out, err)
	}
}

func copyMigrations(t *testing.T, root, dst string) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(root, "db", "migrations", "*.sql"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, filepath.Base(f)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func withVars(base []string, vars map[string]string) []string {
	out := make([]string, 0, len(base)+len(vars))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if _, override := vars[k]; !override {
			out = append(out, kv)
		}
	}
	for k, v := range vars {
		out = append(out, k+"="+v)
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
