package main

import (
	"context"
	"crypto/fips140"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/authn/breakglass"
	"github.com/rformer/fair-app/internal/migrate"
)

// runBreakglass implements `iam breakglass` (F-001 T-34; AC-40, AC-45), the
// installer's path:
//
//	iam breakglass enable -reason TEXT -holder "email=Name" [-holder "email=Name"]
//	iam breakglass enable -emergency -operator NAME -reason TEXT -holder "email=Name" [...]
//	iam breakglass disable -reason TEXT
//
// -emergency is the IdP-outage recovery (T-35, AC-46;
// docs/operations/idp-outage-recovery.md): at any time while break-glass is
// off, by an operator with cluster-level access who names themselves;
// audited critical, every channel notified, and on for at most 24 hours.
//
// enable works only on an installation nobody has signed in to yet (after
// that: POST /api/v1/breakglass/enable and a second approval, AC-41). It
// prints each holder's one-time enrollment code (24 hours) once, for the
// installer to hand over out of band, and records the enablement in the
// install log (stdout) and the audit trail. disable works at any time.
// It connects as app_migrator (FAIR_MIGRATOR_PASSWORD_FILE and the libpq
// variables), acting as fair_owner.
func runBreakglass(args []string) int {
	env := os.Getenv("FAIR_ENV")
	if env == "" {
		env = "production"
	}
	if (os.Getenv("FAIR_REQUIRE_FIPS") != "false" || env == "production") && !fips140.Enabled() {
		fmt.Fprintln(os.Stderr, "iam breakglass: FIPS 140 mode is required but not enabled")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg, err := migrate.ConnConfig(env, os.Getenv("FAIR_MIGRATOR_PASSWORD_FILE"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "iam breakglass:", err)
		return 1
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iam breakglass: connect:", err)
		return 1
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if err := breakglass.Command(ctx, conn, args, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "iam breakglass:", err)
		return 1
	}
	return 0
}
