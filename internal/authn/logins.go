package authn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/authz"
)

// Logins is what every login flow of the iam service shares (SAML, T-15;
// OIDC, T-16): the IdP's subject looked up as a user, a login ticket for
// the gateway, and the audit trail. Users see a generic failure; the audit
// trail has the reason.
type Logins struct {
	DB      *pgxpool.Pool     // app_rw
	Origin  string            // the platform's public origin, e.g. https://fair.example.com
	Tickets authz.KeyProvider // signs login tickets
	Logger  *slog.Logger
	Now     func() time.Time
}

func (h *Logins) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// errUnknownIDP: no enabled IdP of that kind with that id.
var errUnknownIDP = errors.New("authn: unknown identity provider")

// complete finishes a verified login: the user the IdP's subject (external
// id) identifies must exist and be active (JIT provisioning is T-23); then
// the login is audited and answered with a ticket. t carries the method,
// MFA evidence, authentication time and return path.
func (h *Logins) complete(w http.ResponseWriter, r *http.Request, idpID, externalID string, t Ticket, attrs map[string]any) {
	var userID, status string
	err := h.DB.QueryRow(r.Context(), "SELECT user_id::text, status FROM iam.login_user($1, $2)", idpID, externalID).Scan(&userID, &status)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		h.deny(w, r, idpID, attrs, "unknown user")
		return
	case err != nil:
		h.fail(w, r, idpID, err)
		return
	case status != "active":
		attrs["user_id"] = userID
		h.deny(w, r, idpID, attrs, "user "+status)
		return
	}
	t.UserID, t.IDPID = userID, idpID
	tok, err := IssueTicket(h.Tickets, t, h.now())
	if err != nil {
		h.fail(w, r, idpID, err)
		return
	}
	attrs["user_id"] = userID
	if err := h.event(r.Context(), "authn.login.success", "info", userID, idpID, attrs, ""); err != nil {
		h.fail(w, r, idpID, err) // audit failures fail closed (ADR-006)
		return
	}
	w.Header().Set(TicketHeader, tok)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" { // set by the gateway
		return strings.TrimSpace(strings.Split(f, ",")[0])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (h *Logins) event(ctx context.Context, typ, severity, actor, idp string, attrs map[string]any, reason string) error {
	b, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	var idpArg any
	if idp != "" {
		idpArg = idp
	}
	_, err = h.DB.Exec(ctx, "SELECT iam.authn_event($1, $2, $3, $4, $5, $6)", typ, severity, actor, idpArg, b, reason)
	return err
}

// deny refuses a login: audited with the reason, generic to the user.
func (h *Logins) deny(w http.ResponseWriter, r *http.Request, idp string, attrs map[string]any, reason string) {
	if attrs == nil {
		attrs = map[string]any{"idp": idp, "client": clientIP(r)}
	}
	if err := h.event(r.Context(), "authn.login.denied", "low", "anonymous", idp, attrs, reason); err != nil && h.Logger != nil {
		h.Logger.Error("auditing a denied login", "error", err.Error())
	}
	writeFailure(w, http.StatusUnauthorized)
}

func (h *Logins) fail(w http.ResponseWriter, r *http.Request, idp string, err error) {
	if errors.Is(err, errUnknownIDP) {
		writeFailure(w, http.StatusNotFound)
		return
	}
	if h.Logger != nil {
		h.Logger.Error("SAML login", "idp", idp, "path", r.URL.Path, "error", err.Error())
	}
	writeFailure(w, http.StatusServiceUnavailable)
}

func writeFailure(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"sign_in_failed","detail":"Sign-in did not succeed. Try again, or contact your administrator."}`+"\n")
}
