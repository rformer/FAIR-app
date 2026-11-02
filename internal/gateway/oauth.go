package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/authn"
)

// Service accounts (F-001 T-33; AC-37, AC-38; design §5.2). A service
// account exchanges a client secret, or an mTLS client certificate, for an
// access token at TokenPath (OAuth 2.0 client credentials, RFC 6749 §4.4;
// RFC 8705 for mTLS), then calls the services with "Authorization: Bearer
// <access token>". The gateway checks the token in the database on every
// request (iam.sa_access_lookup), so disabling the account or revoking the
// credential ends it at once, and mints the internal JWT and DB context as
// for a session. Bearer requests need no CSRF token (the token is not sent
// by browsers on their own) and see no system-use banner (no person reads
// it). Tokens issued over mTLS are bound to the certificate (RFC 8705 §3).

// TokenPath is the token endpoint.
const TokenPath = "/api/v1/oauth/token" // #nosec G101 -- a path, not a credential

// AccessTTL is an access token's lifetime.
const AccessTTL = 10 * time.Minute

// ServiceAccounts authenticates service accounts. Connect as app_gateway.
type ServiceAccounts struct {
	DB     *pgxpool.Pool
	Pepper []byte // FAIR_TOKEN_PEPPER_FILE (iam's too: client secrets are stored under it)
	// CertHeader names the header in which a TLS-terminating ingress passes
	// the client's certificate (URL-encoded PEM, as ingress-nginx's
	// ssl-client-cert). It is believed only from Sessions.Network's trusted
	// proxies. Empty: certificates come only from the gateway's own TLS
	// connections.
	CertHeader string
	// PerMinute limits token requests per client address (default 60).
	PerMinute int

	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (s *ServiceAccounts) allow(client string, now time.Time) bool {
	rate := float64(s.PerMinute)
	if rate <= 0 {
		rate = 60
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buckets == nil || len(s.buckets) > 100_000 {
		s.buckets = map[string]*tokenBucket{}
	}
	b := s.buckets[client]
	if b == nil {
		b = &tokenBucket{tokens: rate, last: now}
		s.buckets[client] = b
	}
	b.tokens = min(rate, b.tokens+now.Sub(b.last).Minutes()*rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

var clientIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// clientCert is the certificate the client proved it holds: from the
// gateway's own TLS handshake, or from the ingress's header when the
// request came through a trusted proxy.
func (g *Gateway) clientCert(r *http.Request) *x509.Certificate {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0]
	}
	sa := g.ServiceAccounts
	if sa == nil || sa.CertHeader == "" {
		return nil
	}
	v := r.Header.Get(sa.CertHeader)
	if v == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil || !g.Sessions.Network.trusted(remote) {
		return nil // anyone can send the header; only the ingress is believed
	}
	text, err := url.QueryUnescape(v)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return c
}

func thumbprint(c *x509.Certificate) []byte {
	sum := sha256.Sum256(c.Raw)
	return sum[:]
}

// oauthError answers an RFC 6749 §5.2 error.
func oauthError(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": detail})
}

// token is the token endpoint (client credentials).
func (g *Gateway) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	sa := g.ServiceAccounts
	ip := g.Sessions.Network.ClientIP(r)
	if !sa.allow(ip.String(), g.now()) {
		w.Header().Set("Retry-After", "60")
		oauthError(w, http.StatusTooManyRequests, "rate_limited", "too many token requests from this address")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body must be application/x-www-form-urlencoded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body does not parse")
		return
	}
	f := r.PostForm
	for k, v := range f {
		if len(v) > 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request", "parameter "+k+" is repeated")
			return
		}
	}
	if r.URL.Query().Has("client_secret") {
		oauthError(w, http.StatusBadRequest, "invalid_request", "client_secret never goes in the URL")
		return
	}
	if f.Get("grant_type") != "client_credentials" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only client_credentials is supported")
		return
	}
	// Client authentication (RFC 6749 §2.3.1): HTTP Basic or the body, not
	// both; or the TLS client certificate (RFC 8705 §2).
	id, secret, basic := r.BasicAuth()
	if basic {
		var e1, e2 error
		id, e1 = url.QueryUnescape(id)
		secret, e2 = url.QueryUnescape(secret)
		if e1 != nil || e2 != nil || f.Has("client_secret") || (f.Has("client_id") && f.Get("client_id") != id) {
			oauthError(w, http.StatusBadRequest, "invalid_request", "authenticate the client one way")
			return
		}
	} else {
		id, secret = f.Get("client_id"), f.Get("client_secret")
	}
	invalidClient := func() {
		if basic {
			w.Header().Set("WWW-Authenticate", `Basic realm="fair"`)
		}
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
	}
	var secretHMAC, thumb []byte
	if secret != "" {
		h, err := authn.TokenHMAC(sa.Pepper, secret)
		if err != nil {
			g.log(r, "token pepper", err)
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
		secretHMAC = h
	} else if c := g.clientCert(r); c != nil {
		thumb = thumbprint(c)
	}
	if !clientIDRE.MatchString(id) || (secretHMAC == nil && thumb == nil) {
		invalidClient()
		return
	}
	var requested []string
	if f.Has("scope") {
		requested = strings.Fields(f.Get("scope"))
	}
	access, err := authn.NewToken(authn.AccessPrefix)
	if err != nil {
		g.log(r, "access token", err)
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
		return
	}
	accessHMAC, _ := authn.TokenHMAC(sa.Pepper, access)
	var status string
	var scopes []string
	var expires *time.Time
	err = sa.DB.QueryRow(r.Context(), "SELECT status, scopes, expires_at FROM iam.sa_token_issue($1, $2, $3, $4, $5, $6, $7)",
		id, secretHMAC, thumb, requested, accessHMAC, AccessTTL, ip.String()).Scan(&status, &scopes, &expires)
	if err != nil {
		g.log(r, "token issue", err)
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
		return
	}
	switch status {
	case "ok":
	case "invalid_scope":
		oauthError(w, http.StatusBadRequest, "invalid_scope", "the requested scope exceeds the service account's scopes")
		return
	default:
		invalidClient()
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer",
		"expires_in": int(AccessTTL.Seconds()), "scope": strings.Join(scopes, " ")})
}

// errInvalidToken: the bearer token is unknown, expired, revoked or
// presented without its certificate.
var errInvalidToken = errors.New("gateway: invalid access token")

// bearer looks up a service account's access token.
func (g *Gateway) bearer(ctx context.Context, r *http.Request, token string) (Session, error) {
	sa := g.ServiceAccounts
	if !strings.HasPrefix(token, authn.AccessPrefix) {
		return Session{}, errInvalidToken
	}
	h, err := authn.TokenHMAC(sa.Pepper, token)
	if err != nil {
		return Session{}, err
	}
	var s Session
	var bound []byte
	err = sa.DB.QueryRow(ctx, `SELECT user_id::text, scope_version, issued_at, expires_at, thumbprint, auth_method
		FROM iam.sa_access_lookup($1)`, h).Scan(&s.UserID, &s.ScopeVersion, &s.CreatedAt, &s.ExpiresAt, &bound, &s.AuthMethod)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, errInvalidToken
	}
	if err != nil {
		return Session{}, err
	}
	if bound != nil {
		c := g.clientCert(r)
		if c == nil || !hmac.Equal(thumbprint(c), bound) {
			return Session{}, errInvalidToken // RFC 8705 §3: the certificate the token was issued to
		}
	}
	s.ServiceAccount = true
	s.LastSeenAt = g.now()
	return s, nil
}

// sessionOrBearer authenticates a proxied request with a session, or with
// a service account's access token when service accounts are enabled.
func (g *Gateway) sessionOrBearer(next http.HandlerFunc) http.HandlerFunc {
	session := g.authenticated(next)
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || g.ServiceAccounts == nil {
			session(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if _, err := r.Cookie(CookieName); err == nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "send a session cookie or a bearer token, not both")
			return
		}
		sess, err := g.bearer(r.Context(), r, strings.TrimSpace(tok))
		if errors.Is(err, errInvalidToken) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "")
			return
		}
		if err != nil {
			g.log(r, "access token lookup", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	}
}
