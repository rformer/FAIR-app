// Package risk is the risk service (F-003): the Open FAIR data model's
// documents (canon, model), their storage in the risk schema, and the
// service's install-time and runtime pieces.
package risk

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/audit"
)

// InstallCheck is what the risk service checks at startup (design §7; the
// mode matrix, TestDeploymentModeMatrix).
type InstallCheck struct {
	Env    string // FAIR_ENV
	Mode   string // FAIR_DEPLOYMENT_MODE
	Getenv func(string) string
}

// CheckInstall refuses an install that lacks what its environment needs. In
// production, in every mode, the risk API verifies the gateway's internal
// JWTs, so FAIR_JWT_KEYS_DIR is required. The service makes no outbound
// connections in any mode (design §7).
func CheckInstall(c InstallCheck) error {
	var errs []error
	if c.Env == "production" && c.Getenv("FAIR_JWT_KEYS_DIR") == "" {
		errs = append(errs, errors.New("FAIR_JWT_KEYS_DIR is required in production"))
	}
	return errors.Join(errs...)
}

// SetCurrency records the installation currency (design §3.4; AC-07) and
// the risk.currency_set event in one transaction, as fair_owner on a
// migrator connection. It returns the previous code ("" if none). The
// database refuses a change once a stored version holds a magnitude
// (PF019).
func SetCurrency(ctx context.Context, conn *pgx.Conn, emit audit.Emitter, code, operator string) (string, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE fair_owner"); err != nil {
		return "", err
	}
	var prev string
	if err := tx.QueryRow(ctx, "SELECT risk.set_currency($1, $2)", code, operator).Scan(&prev); err != nil {
		return "", fmt.Errorf("risk: currency: %w", err)
	}
	if prev != code {
		if err := emit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: "risk.currency_set", Severity: audit.SeverityHigh,
			Actor: "operator:" + strings.TrimSpace(operator), Target: "risk:currency",
			Attributes: map[string]string{"currency": code, "previous": prev}}); err != nil {
			return "", err // audit failures fail closed
		}
	}
	return prev, tx.Commit(ctx)
}

// Currency returns the installation currency, or "" if it is not set.
func Currency(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (string, error) {
	var c string
	err := q.QueryRow(ctx, "SELECT coalesce((SELECT currency FROM risk.instance), '')").Scan(&c)
	return c, err
}
