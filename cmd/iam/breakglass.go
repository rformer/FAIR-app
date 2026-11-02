package main

import (
	"context"
	"crypto/fips140"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/iamapi"
	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/pkg/audit"
)

// runBreakglass implements `iam breakglass` (F-001 T-34; AC-40, AC-45), the
// installer's path:
//
//	iam breakglass enable -reason TEXT -holder "email=Name" [-holder "email=Name"]
//	iam breakglass disable -reason TEXT
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
	if err := breakglassCommand(ctx, conn, args, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "iam breakglass:", err)
		return 1
	}
	return 0
}

type holderFlags []string

func (h *holderFlags) String() string     { return strings.Join(*h, ",") }
func (h *holderFlags) Set(v string) error { *h = append(*h, v); return nil }

// breakglassCommand runs the command on conn (a connection as app_migrator).
func breakglassCommand(ctx context.Context, conn *pgx.Conn, args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "enable" && args[0] != "disable") {
		return errors.New("usage: iam breakglass enable -reason TEXT -holder email=Name [-holder email=Name] | disable -reason TEXT")
	}
	fs := flag.NewFlagSet("breakglass "+args[0], flag.ContinueOnError)
	reason := fs.String("reason", "", "why (required; recorded in the install log and the audit trail)")
	var holders holderFlags
	if args[0] == "enable" {
		fs.Var(&holders, "holder", "a holder as email=Name (one or two)")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*reason) == "" {
		return errors.New("-reason is required")
	}
	emitter := audit.NewJSONLines(out) // the install log
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE fair_owner"); err != nil {
		return err
	}
	if args[0] == "disable" {
		var n int
		if err := tx.QueryRow(ctx, "SELECT iam.breakglass_install_disable($1)", *reason).Scan(&n); err != nil {
			return err
		}
		if err := emitter.Emit(ctx, audit.Event{Type: "breakglass.disabled", Severity: audit.SeverityHigh, Actor: "system:installer",
			Attributes: map[string]string{"reason": *reason, "accounts_disabled": fmt.Sprint(n)}}); err != nil {
			return err // audit failures fail closed
		}
		return tx.Commit(ctx)
	}
	type h struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	var list []h
	for _, v := range holders {
		email, name, ok := strings.Cut(v, "=")
		if !ok {
			return fmt.Errorf("-holder %q: want email=Name", v)
		}
		list = append(list, h{strings.TrimSpace(email), strings.TrimSpace(name)})
	}
	doc, _ := json.Marshal(list)
	var plain []string
	var hashes [][]byte
	for range list {
		c, sum, err := iamapi.NewEnrollmentCode()
		if err != nil {
			return err
		}
		plain, hashes = append(plain, c), append(hashes, sum)
	}
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT iam.breakglass_install_enable($1, $2, $3)", doc, hashes, *reason).Scan(&raw); err != nil {
		return err
	}
	var created []struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		return err
	}
	emails := make([]string, 0, len(created))
	for _, c := range created {
		emails = append(emails, c.Email)
	}
	if err := emitter.Emit(ctx, audit.Event{Type: "breakglass.enabled", Severity: audit.SeverityHigh, Actor: "system:installer",
		Attributes: map[string]string{"reason": *reason, "holders": strings.Join(emails, ","), "at_install": "true"}}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// The codes appear in this output only, never in the audit record.
	for i, c := range created {
		if _, err := fmt.Fprintf(out, "enrollment code for %s (user %s), valid 24 hours, shown once: %s\n", c.Email, c.UserID, plain[i]); err != nil {
			return err
		}
	}
	return nil
}
