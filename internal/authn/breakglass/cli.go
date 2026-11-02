package breakglass

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/pkg/audit"
)

// EnrollmentCodePrefix starts every enrollment code (for secret scanners).
const EnrollmentCodePrefix = "fbg_"

// NewEnrollmentCode returns a code and its SHA-256 (what the database keeps).
func NewEnrollmentCode() (string, []byte, error) {
	code, err := authn.NewToken(EnrollmentCodePrefix)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256([]byte(code))
	return code, sum[:], nil
}

type holderFlags []string

func (h *holderFlags) String() string     { return strings.Join(*h, ",") }
func (h *holderFlags) Set(v string) error { *h = append(*h, v); return nil }

// Command runs `iam breakglass` on conn (a connection as app_migrator):
// enable, enable -emergency, disable. Output is the install log (JSON
// lines) and, after it, the enrollment codes.
func Command(ctx context.Context, conn *pgx.Conn, args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "enable" && args[0] != "disable") {
		return errors.New("usage: iam breakglass enable -reason TEXT -holder email=Name [-holder email=Name] | disable -reason TEXT")
	}
	fs := flag.NewFlagSet("breakglass "+args[0], flag.ContinueOnError)
	reason := fs.String("reason", "", "why (required; recorded in the install log and the audit trail)")
	var holders holderFlags
	emergency := fs.Bool("emergency", false, "IdP-outage recovery: enable although the installation is in use (audited critical, 24 hours)")
	operator := fs.String("operator", "", "with -emergency: who is running the recovery (recorded)")
	if args[0] == "enable" {
		fs.Var(&holders, "holder", "a holder as email=Name (one or two)")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*reason) == "" {
		return errors.New("-reason is required")
	}
	c, err := audit.DefaultCatalog()
	if err != nil {
		return err
	}
	emitter := audit.Validating{Next: audit.NewJSONLines(out), Catalog: c} // the install log
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
		if err := emitter.Emit(ctx, audit.Event{Type: "breakglass.disabled", Severity: audit.SeverityHigh, Actor: "system:installer", Target: "breakglass",
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
		c, sum, err := NewEnrollmentCode()
		if err != nil {
			return err
		}
		plain, hashes = append(plain, c), append(hashes, sum)
	}
	var raw []byte
	var until *time.Time
	if *emergency {
		if strings.TrimSpace(*operator) == "" {
			return errors.New("-emergency needs -operator (who is running the recovery)")
		}
		if err := tx.QueryRow(ctx, "SELECT accounts, expires_at FROM iam.breakglass_emergency_enable($1, $2, $3, $4)",
			doc, hashes, *reason, *operator).Scan(&raw, &until); err != nil {
			return err
		}
	} else if err := tx.QueryRow(ctx, "SELECT iam.breakglass_install_enable($1, $2, $3)", doc, hashes, *reason).Scan(&raw); err != nil {
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
	ev := audit.Event{Type: "breakglass.enabled", Severity: audit.SeverityHigh, Actor: "system:installer", Target: "breakglass",
		Attributes: map[string]string{"reason": *reason, "holders": strings.Join(emails, ","), "at_install": "true"}}
	if *emergency {
		ev = audit.Event{Type: "breakglass.emergency_enabled", Severity: audit.SeverityCritical, Actor: "operator:" + strings.TrimSpace(*operator), Target: "breakglass",
			Attributes: map[string]string{"reason": *reason, "holders": strings.Join(emails, ","), "expires_at": until.UTC().Format(time.RFC3339)}}
	}
	if err := emitter.Emit(ctx, ev); err != nil {
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
