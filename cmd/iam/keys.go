package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/keys"
	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/pkg/audit"
)

const keysUsage = `usage:
  iam keys init -dir DIR                      create every key (never overwrites)
  iam keys upgrade -dir DIR                   add the keys of services newer than DIR (F-002: audit/; F-003: risk/; F-005: the engine channel)
  iam keys rotate -dir DIR -kind KIND         add a key: jwt, login-ticket, db-context, checkpoint or engine
  iam keys check -dir DIR                     check a key directory as a whole
  iam keys register -dir DIR                  add the gateway's DB-context key to the database
  iam keys retire-db-context -id ID           retire a DB-context key the gateway no longer uses`

// runKeys implements `iam keys` (F-001 T-41, design §10; docs/install/keys.md).
// init, rotate and check work on files only; register and retire-db-context
// connect as app_migrator (FAIR_MIGRATOR_PASSWORD_FILE and the libpq
// variables), acting as fair_owner, and record the change in the install log
// (stdout).
func runKeys(args []string) int {
	if err := keysCommand(args, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "iam keys:", err)
		return 1
	}
	return 0
}

func keysCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(keysUsage)
	}
	fs := flag.NewFlagSet("keys "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", "", "the key directory (one subdirectory per service)")
	kind := fs.String("kind", "", "rotate: jwt, login-ticket, db-context, checkpoint or engine")
	id := fs.String("id", "", "retire-db-context: the key id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	env := os.Getenv("FAIR_ENV")
	if env == "" {
		env = "production"
	}
	if (os.Getenv("FAIR_REQUIRE_FIPS") != "false" || env == "production") && !fips140.Enabled() {
		return errors.New("FIPS 140 mode is required but not enabled")
	}
	needDir := func() error {
		if *dir == "" {
			return errors.New("-dir is required")
		}
		return nil
	}
	now := time.Now()
	switch args[0] {
	case "init":
		if err := needDir(); err != nil {
			return err
		}
		s, err := keys.Init(*dir, now)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "created in %s: internal-JWT key %s, login-ticket key %s, DB-context key %s, audit checkpoint key %s\n"+
			"load gateway/, iam/, posture/ and audit/ into your secret store, register the DB-context key (iam keys register), then delete this directory\n",
			*dir, s.JWT, s.Ticket, s.DBContext, s.Checkpoint)
		return err
	case "upgrade":
		if err := needDir(); err != nil {
			return err
		}
		added, err := keys.Upgrade(*dir, now)
		if err != nil {
			return err
		}
		if len(added) == 0 {
			_, err = fmt.Fprintln(out, "nothing to add: the directory has every service's keys")
			return err
		}
		_, err = fmt.Fprintf(out, "added %s/ to %s; load it into your secret store\n", strings.Join(added, "/, "), *dir)
		return err
	case "rotate":
		if err := needDir(); err != nil {
			return err
		}
		k, err := keys.Rotate(*dir, *kind, now)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "added %s key %s; see docs/install/keys.md for the rollout order\n", *kind, k)
		return err
	case "check":
		if err := needDir(); err != nil {
			return err
		}
		if err := keys.Check(*dir); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "ok")
		return err
	case "register", "retire-db-context":
		if args[0] == "register" {
			if err := needDir(); err != nil {
				return err
			}
		} else if *id == "" {
			return errors.New("-id is required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cfg, err := migrate.ConnConfig(env, os.Getenv("FAIR_MIGRATOR_PASSWORD_FILE"))
		if err != nil {
			return err
		}
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return fmt.Errorf("connect: %w", err)
		}
		defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
		c, err := audit.DefaultCatalog()
		if err != nil {
			return err
		}
		// The install log, and the audit trail as fair_owner (F-002 T-06).
		emit := audit.WithTrail(audit.Validating{Next: audit.NewJSONLines(out), Catalog: c}, audit.Trail{DB: conn, Role: "fair_owner"})
		if args[0] == "retire-db-context" {
			return keys.RetireDBContext(ctx, conn, emit, *id)
		}
		k, added, err := keys.RegisterDBContext(ctx, conn, emit, *dir)
		if err == nil && !added {
			_, err = fmt.Fprintf(out, "DB-context key %s is already registered\n", k)
		}
		return err
	}
	return errors.New(keysUsage)
}
