package tests

// F-001 T-02b: embedded migration runner (`iam migrate`).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeMigration(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A fresh install gets the release catalog and built-in roles (T-06).
func TestMigrateSeedsReleaseCatalog(t *testing.T) {
	e := setup(t)
	c, br := release(t)
	out := e.mustOwner("SELECT (SELECT version FROM iam.permission_catalog) || '/' || (SELECT count(*) FROM iam.permission) || '/' || (SELECT count(*) FROM iam.role WHERE builtin)")
	if want := fmt.Sprintf("1/%d/%d", len(c.Permissions), len(br.Roles)); out != want {
		t.Fatalf("catalog/permissions/built-in roles = %s, want %s", out, want)
	}
	if out := e.mustOwner("SELECT string_agg(version, ',' ORDER BY version) FROM fair_meta.schema_migrations"); !strings.HasPrefix(out, "0001_schemas,0002_bu,0003_bu_restrict,0004_roles") {
		t.Fatalf("recorded migrations = %s", out)
	}
}

// A failing migration leaves no trace: no objects, no record, and a fixed
// file applies cleanly afterwards.
func TestMigrateFailureRollsBack(t *testing.T) {
	e := setup(t)
	dir := t.TempDir()
	copyMigrations(t, e.root, dir)
	writeMigration(t, dir, "9001_half.sql", "CREATE TABLE iam.half (id int);\nSELECT * FROM no_such_table;\n")
	if _, err := e.migrate(dir); err == nil || !strings.Contains(err.Error(), "9001_half") {
		t.Fatalf("broken migration: err = %v", err)
	}
	if out := e.mustOwner("SELECT to_regclass('iam.half') IS NULL AND NOT EXISTS (SELECT 1 FROM fair_meta.schema_migrations WHERE version = '9001_half')"); out != "t" {
		t.Fatal("failed migration left objects or a record behind")
	}
	writeMigration(t, dir, "9001_half.sql", "CREATE TABLE iam.half (id int);\n")
	res, err := e.migrate(dir)
	if err != nil || len(res.Applied) != 1 || res.Applied[0] != "9001_half" {
		t.Fatalf("fixed migration: applied %v err %v", res.Applied, err)
	}
}

func TestMigrateRejectsBadNames(t *testing.T) {
	e := setup(t)
	for _, name := range []string{"5_short.sql", "0005_Upper.sql", "0005-dash.sql"} {
		dir := t.TempDir()
		copyMigrations(t, e.root, dir)
		writeMigration(t, dir, name, "SELECT 1;")
		if _, err := e.migrate(dir); err == nil || !strings.Contains(err.Error(), "bad migration file name") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// Concurrent runners (e.g. two Jobs during an upgrade) apply each migration once.
func TestMigrateConcurrentRunners(t *testing.T) {
	e := setup(t)
	dir := t.TempDir()
	copyMigrations(t, e.root, dir)
	writeMigration(t, dir, "9002_slow.sql", "SELECT pg_sleep(0.5);\nCREATE TABLE iam.once (id int);\n")

	var wg sync.WaitGroup
	applied := make([][]string, 4)
	errs := make([]error, 4)
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := e.migrate(dir)
			applied[i], errs[i] = res.Applied, err
		}()
	}
	wg.Wait()
	total := 0
	for i := range 4 {
		if errs[i] != nil {
			t.Fatalf("runner %d: %v", i, errs[i])
		}
		total += len(applied[i])
	}
	if total != 1 {
		t.Fatalf("9002_slow applied %d times across runners, want 1 (%v)", total, applied)
	}
}
