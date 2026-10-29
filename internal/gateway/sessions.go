// Package gateway is the platform's gateway (F-001 design §2, §5.1, §5.2):
// browser sessions in the __Host-sid cookie, CSRF protection, the session
// APIs, and an authenticated reverse proxy that mints each request's
// internal JWT and DB context token for the service it reaches.
//
// Sessions (T-13; AC-31, AC-33, AC-35): the cookie holds 256 random bits;
// the database stores only HMAC-SHA-256(pepper, token), with a pepper the
// database never sees (migration 0037). The gateway connects as
// app_gateway and reaches sessions only through iam's session functions.
package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CookieName is the session cookie. The __Host- prefix makes browsers
// require Secure and Path=/ and refuse a Domain attribute.
const CookieName = "__Host-sid"

// MinPepperLen is the shortest session pepper accepted.
const MinPepperLen = 32

// Session is a live session as a request sees it.
type Session struct {
	Handle       string // the public id (never the HMAC)
	UserID       string
	ScopeVersion int64
	AuthMethod   string
	CreatedAt    time.Time
	LastSeenAt   time.Time
	ExpiresAt    time.Time  // the earlier of the idle and absolute deadlines
	BannerAckAt  *time.Time // when the system-use banner was acknowledged (T-19)
	token        string
}

// Timeouts returns the idle and absolute session timeouts in force
// (session.idle_timeout, session.absolute_timeout).
type Timeouts func() (idle, absolute time.Duration, err error)

// Sessions creates and looks up sessions. Connect as app_gateway.
type Sessions struct {
	DB       *pgxpool.Pool
	Pepper   []byte
	Timeouts Timeouts
}

// Login is an authenticated user handed over by the login flows (SAML and
// OIDC, T-15/T-16; break-glass, T-31).
type Login struct {
	UserID     string
	AuthMethod string // saml, oidc, breakglass
	MFA        map[string]any
	IP         net.IP
	UserAgent  string
}

// Errors.
var (
	// ErrNoSession: no cookie, an unknown or malformed token, or a session
	// that has ended; Status says why.
	ErrNoSession = errors.New("gateway: no valid session")
	// ErrUserInactive: the user may not sign in.
	ErrUserInactive = errors.New("gateway: user is not active")
)

// SessionError is ErrNoSession with the reason.
type SessionError struct{ Status string }

func (e *SessionError) Error() string { return "gateway: no valid session (" + e.Status + ")" }
func (e *SessionError) Unwrap() error { return ErrNoSession }

func (s Sessions) idHMAC(token string) []byte {
	m := hmac.New(sha256.New, s.Pepper)
	m.Write([]byte("sid\x00" + token))
	return m.Sum(nil)
}

// CSRFToken is the session's CSRF token: HMAC(pepper, token), so it is
// bound to the session and needs no storage.
func (s Sessions) CSRFToken(sess Session) string {
	m := hmac.New(sha256.New, s.Pepper)
	m.Write([]byte("csrf\x00" + sess.token))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s Sessions) validCSRF(sess Session, got string) bool {
	return got != "" && hmac.Equal([]byte(got), []byte(s.CSRFToken(sess)))
}

// Create starts a session for l and returns it with the cookie value.
func (s Sessions) Create(ctx context.Context, l Login) (Session, string, error) {
	if len(s.Pepper) < MinPepperLen {
		return Session{}, "", fmt.Errorf("gateway: the session pepper must be at least %d bytes", MinPepperLen)
	}
	_, absolute, err := s.Timeouts()
	if err != nil {
		return Session{}, "", fmt.Errorf("gateway: session timeouts: %w", err)
	}
	raw := make([]byte, 32) // 256 bits
	if _, err := rand.Read(raw); err != nil {
		return Session{}, "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	mfa, err := json.Marshal(l.MFA)
	if err != nil {
		return Session{}, "", err
	}
	if l.MFA == nil {
		mfa = []byte("{}")
	}
	var ip any
	if l.IP != nil {
		ip = l.IP.String()
	}
	sess := Session{UserID: l.UserID, AuthMethod: l.AuthMethod, token: token}
	var expiry time.Time
	err = s.DB.QueryRow(ctx, "SELECT handle::text, created_at, absolute_expiry_at FROM iam.session_create($1, $2, $3, $4, $5, $6, $7)",
		s.idHMAC(token), l.UserID, l.AuthMethod, mfa, ip, l.UserAgent, absolute).Scan(&sess.Handle, &sess.CreatedAt, &expiry)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "28000" {
		return Session{}, "", ErrUserInactive
	}
	if err != nil {
		return Session{}, "", err
	}
	sess.LastSeenAt, sess.ExpiresAt = sess.CreatedAt, expiry
	return sess, token, nil
}

// Lookup returns the live session of a cookie value, applying the timeouts
// in force; an ended session is a *SessionError.
func (s Sessions) Lookup(ctx context.Context, token string) (Session, error) {
	if len(token) != 43 { // 32 bytes, base64url without padding
		return Session{}, &SessionError{Status: "unknown"}
	}
	idle, absolute, err := s.Timeouts()
	if err != nil {
		return Session{}, fmt.Errorf("gateway: session timeouts: %w", err) // fail closed: no request without them
	}
	var status string
	var handle, user, method *string
	var version *int64
	var created, seen, expires, ack *time.Time
	err = s.DB.QueryRow(ctx, `SELECT status, handle::text, user_id::text, scope_version, auth_method, created_at, last_seen_at, expires_at,
		banner_ack_at FROM iam.session_lookup($1, $2, $3)`, s.idHMAC(token), idle, absolute).
		Scan(&status, &handle, &user, &version, &method, &created, &seen, &expires, &ack)
	if err != nil {
		return Session{}, err
	}
	if status != "active" {
		return Session{}, &SessionError{Status: status}
	}
	return Session{Handle: *handle, UserID: *user, ScopeVersion: *version, AuthMethod: *method,
		CreatedAt: *created, LastSeenAt: *seen, ExpiresAt: *expires, BannerAckAt: ack, token: token}, nil
}

// Banner is the system-use banner in force (T-19).
type Banner struct {
	Version int    `json:"version"`
	Text    string `json:"text"`
}

// CurrentBanner reads the banner in force.
func (s Sessions) CurrentBanner(ctx context.Context) (Banner, error) {
	var b Banner
	err := s.DB.QueryRow(ctx, "SELECT version, text FROM iam.banner_current()").Scan(&b.Version, &b.Text)
	return b, err
}

// AckBanner records that the session acknowledged banner version v:
// "ok", "stale" (not the current version) or "inactive".
func (s Sessions) AckBanner(ctx context.Context, sess Session, v int) (string, error) {
	var out string
	err := s.DB.QueryRow(ctx, "SELECT iam.session_banner_ack($1, $2)", s.idHMAC(sess.token), v).Scan(&out)
	return out, err
}

// Logout ends the session of a cookie value.
func (s Sessions) Logout(ctx context.Context, token string) error {
	_, err := s.DB.Exec(ctx, "SELECT iam.session_logout($1)", s.idHMAC(token))
	return err
}

// SetCookie sets the session cookie: Secure, HttpOnly, SameSite=Strict,
// Path=/, no Domain, and no expiry (the server enforces the timeouts; the
// browser drops it when it closes).
func SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// ClearCookie removes the session cookie.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}
