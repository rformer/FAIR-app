package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// TokenTTL is the lifetime of the internal JWT and DB context token minted
// for each request.
const TokenTTL = 2 * time.Minute

// CSRFHeader carries the session's CSRF token on state-changing requests.
const CSRFHeader = "X-CSRF-Token"

// Gateway serves the session APIs and proxies /api/v1/<service>/ to the
// services, authenticated.
type Gateway struct {
	Sessions   Sessions
	ContextKey authz.ContextKey    // signs DB context tokens (authz.ctx_key)
	JWT        authz.KeyProvider   // signs internal JWTs
	Tickets    authz.KeyProvider   // verifies iam's login tickets (T-15)
	Origin     string              // the platform's public origin, e.g. https://fair.example.com
	Upstreams  map[string]*url.URL // service name -> base URL (/api/v1/<name>/ is routed there)
	Transport  http.RoundTripper   // to the services (mTLS); default http.DefaultTransport
	UI         http.Handler        // optional: the web UI at /
	// BannerEnabled reports banner.enabled (T-19, AC-34). Nil, or an error,
	// means the banner is required (the secure default; fail closed).
	BannerEnabled func() (bool, error)
	// NetworkBinding reports session.network_binding at the instance level
	// (T-20, design §5.8): off, flag or reauthenticate. Nil means off; an
	// error means reauthenticate (fail closed).
	NetworkBinding func() (string, error)
	Logger         *slog.Logger
	Now            func() time.Time
}

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// The gateway's own API (design §6: /auth/logout, /me, /me/sessions,
// /sessions), all behind a session.
var routes = []struct {
	pattern string
	h       func(*Gateway) http.HandlerFunc
}{
	{"GET /api/v1/me", func(g *Gateway) http.HandlerFunc { return g.me }},
	{"POST /api/v1/auth/logout", func(g *Gateway) http.HandlerFunc { return g.logout }},
	{"POST /api/v1/auth/banner/ack", func(g *Gateway) http.HandlerFunc { return g.ackBanner }},
	{"GET /api/v1/me/sessions", func(g *Gateway) http.HandlerFunc { return g.listSessions(true) }},
	{"DELETE /api/v1/me/sessions", func(g *Gateway) http.HandlerFunc { return g.revokeAll(true) }},
	{"DELETE /api/v1/me/sessions/{handle}", func(g *Gateway) http.HandlerFunc { return g.revoke }},
	{"GET /api/v1/sessions", func(g *Gateway) http.HandlerFunc { return g.listSessions(false) }},
	{"DELETE /api/v1/sessions", func(g *Gateway) http.HandlerFunc { return g.revokeAll(false) }},
	{"DELETE /api/v1/sessions/{handle}", func(g *Gateway) http.HandlerFunc { return g.revoke }},
}

// Routes lists "METHOD /path" of the gateway's own API (for the OpenAPI
// document).
func Routes() []string {
	out := make([]string, 0, len(routes))
	for _, rt := range routes {
		out = append(out, rt.pattern)
	}
	return out
}

// Segments routes the first path segment of the design §6 resources to the
// service that owns them (T-17): /api/v1/idps/... goes to iam with an "iam"
// token. A service also gets /api/v1/<name>/ (Upstreams).
var Segments = map[string]string{
	"idps": "iam", "users": "iam", "groups": "iam", "service-accounts": "iam", "bus": "iam",
	"roles": "iam", "permissions": "iam", "assignments": "iam", "group-mappings": "iam",
	"sod-rules": "iam", "sod-exceptions": "iam", "approvals": "iam", "access-reviews": "iam",
	"entitlements": "iam", "banner": "iam",
}

type ctxKey struct{}

type tokensKey struct{}

type tokens struct{ db, jwt string }

func sessionFrom(ctx context.Context) Session { s, _ := ctx.Value(ctxKey{}).(Session); return s }

// Handler is the gateway.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routes {
		mux.Handle(rt.pattern, server.SecurityHeaders(g.authenticated(rt.h(g))))
	}
	for name, base := range g.Upstreams {
		mux.Handle("/api/v1/"+name+"/", g.authenticated(g.forward(name, g.proxy(base))))
	}
	for seg, name := range Segments {
		if base, ok := g.Upstreams[name]; ok && g.Upstreams[seg] == nil {
			h := g.authenticated(g.forward(name, g.proxy(base)))
			mux.Handle("/api/v1/"+seg, h)
			mux.Handle("/api/v1/"+seg+"/", h)
		}
	}
	if iam, ok := g.Upstreams["iam"]; ok {
		login := g.loginRoutes(iam) // no session yet (SAML T-15, OIDC T-16, discovery T-17)
		mux.Handle("/api/v1/auth/saml/", login)
		mux.Handle("/api/v1/auth/oidc/", login)
		mux.Handle(authn.DiscoverPath, login)
		mux.Handle(SCIMPrefix, g.scimRoute(iam)) // the SCIM token is the credential (T-21)
	}
	mux.Handle("/api/", server.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "")
	})))
	if g.UI != nil {
		mux.Handle("/", server.UISecurityHeaders(g.UI))
	}
	return mux
}

// authenticated requires a live session and, for state-changing methods,
// the session's CSRF token and a same-origin request (AC-35).
func (g *Gateway) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		c, err := r.Cookie(CookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "")
			return
		}
		sess, err := g.Sessions.Lookup(r.Context(), c.Value)
		var se *SessionError
		if errors.As(err, &se) {
			g.ended(w, se)
			return
		}
		if err != nil {
			g.log(r, "session lookup", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "")
			return
		}
		if sess, err = g.checkNetwork(r, sess); errors.As(err, &se) {
			g.ended(w, se)
			return
		} else if err != nil {
			g.log(r, "session network", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "")
			return
		}
		if !safeMethod(r.Method) {
			if !g.sameOrigin(r) {
				writeError(w, http.StatusForbidden, "csrf", "the request did not come from this site")
				return
			}
			if !g.Sessions.validCSRF(sess, r.Header.Get(CSRFHeader)) {
				writeError(w, http.StatusForbidden, "csrf", "the "+CSRFHeader+" header is missing or wrong")
				return
			}
		}
		if sess.BannerAckAt == nil && !bannerExempt(r) && g.bannerRequired() {
			writeError(w, http.StatusForbidden, "banner_required", "acknowledge the system-use notification first")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	}
}

// ended answers a request whose session has ended, with the way back in
// when the network binding ended it (design §5.8: sign in again at the
// IdP; the UI adds the return path).
func (g *Gateway) ended(w http.ResponseWriter, se *SessionError) {
	ClearCookie(w)
	if se.Status == "network_change" {
		body := map[string]any{"error": "unauthenticated", "detail": sessionEnded(se.Status)}
		if se.IDPID != "" && (se.AuthMethod == "saml" || se.AuthMethod == "oidc") {
			body["login_url"] = "/api/v1/auth/" + se.AuthMethod + "/" + se.IDPID + "/login"
		}
		writeJSON(w, http.StatusUnauthorized, body)
		return
	}
	writeError(w, http.StatusUnauthorized, "unauthenticated", sessionEnded(se.Status))
}

// networkMode is session.network_binding in force at the instance level.
func (g *Gateway) networkMode() string {
	if g.NetworkBinding == nil {
		return "off"
	}
	m, err := g.NetworkBinding()
	if err != nil || (m != "off" && m != "flag") {
		return "reauthenticate"
	}
	return m
}

// checkNetwork applies the network binding (design §5.8) to a live
// session: a client outside the network recorded at login revokes the
// session (reauthenticate) or marks it (flag, audited; off, silently, so a
// BU that requires re-authentication can still refuse it).
func (g *Gateway) checkNetwork(r *http.Request, sess Session) (Session, error) {
	if !sess.IP.IsValid() {
		return sess, nil
	}
	client := g.Sessions.Network.ClientIP(r)
	if !client.IsValid() || g.Sessions.Network.SameNetwork(sess.IP, client) {
		return sess, nil
	}
	mode := g.networkMode()
	if sess.NetworkChangedAt != nil && mode != "reauthenticate" {
		return sess, nil // marked already
	}
	out, err := g.Sessions.NetworkChanged(r.Context(), sess, client, mode)
	switch {
	case err != nil:
		return sess, err
	case out == "revoked":
		return sess, &SessionError{Status: "network_change", AuthMethod: sess.AuthMethod, IDPID: sess.IDPID}
	case out != "marked":
		return sess, &SessionError{Status: "revoked"}
	}
	now := g.now()
	sess.NetworkChangedAt = &now
	return sess, nil
}

// bannerRequired: banner.enabled, or unknown (fail closed).
func (g *Gateway) bannerRequired() bool {
	if g.BannerEnabled == nil {
		return true
	}
	on, err := g.BannerEnabled()
	return err != nil || on
}

// bannerExempt: what a session may do before acknowledging the banner
// (AC-34): read /me (which carries the banner), acknowledge, sign out.
func bannerExempt(r *http.Request) bool {
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/me", "POST /api/v1/auth/banner/ack", "POST /api/v1/auth/logout":
		return true
	}
	return false
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// sameOrigin: Origin must be the platform's; without Origin, Fetch
// Metadata must say same-origin. A request with neither is refused.
func (g *Gateway) sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return o == g.Origin
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

func sessionEnded(status string) string {
	switch status {
	case "idle_timeout":
		return "the session timed out after a period of inactivity"
	case "absolute_timeout":
		return "the session reached its maximum duration"
	case "revoked":
		return "the session was signed out or revoked"
	case "user_disabled":
		return "the account is disabled"
	case "network_change":
		return "the session's network changed; sign in again"
	}
	return ""
}

// mint returns the DB context token and internal JWT for the session.
func (g *Gateway) mint(sess Session, audience string) (dbToken, jwt string, err error) {
	now := g.now()
	if dbToken, err = authz.MintDBContext(g.ContextKey, sess.UserID, sess.ScopeVersion, TokenTTL, now); err != nil {
		return "", "", err
	}
	// auth_time is the session's start until the login flows record the
	// IdP's authentication time (F-015 T-24b).
	jwt, err = authz.MintJWT(g.JWT, authz.Claims{Subject: sess.UserID, ScopeVersion: sess.ScopeVersion, AuthTime: sess.CreatedAt.Unix(),
		DBContext: authz.DBContextHash(dbToken), NetworkChanged: sess.NetworkChangedAt != nil}, audience, TokenTTL, now)
	return dbToken, jwt, err
}

// withContext runs f in a transaction carrying the session user's signed
// DB context (the iam session functions take the actor from it).
func (g *Gateway) withContext(ctx context.Context, sess Session, f func(tx pgx.Tx) error) error {
	dbToken, err := authz.MintDBContext(g.ContextKey, sess.UserID, sess.ScopeVersion, TokenTTL, g.now())
	if err != nil {
		return err
	}
	return authz.WithDBContext(ctx, g.Sessions.DB, dbToken, f)
}

// forward mints the request's tokens for the service and proxies it.
func (g *Gateway) forward(service string, p *httputil.ReverseProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbToken, jwt, err := g.mint(sessionFrom(r.Context()), service)
		if err != nil {
			g.log(r, "minting tokens", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "")
			return
		}
		p.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokensKey{}, tokens{dbToken, jwt})))
	}
}

func (g *Gateway) proxy(base *url.URL) *httputil.ReverseProxy {
	p := &httputil.ReverseProxy{
		Transport: g.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(base)
			pr.Out.URL.Path, pr.Out.URL.RawPath = pr.In.URL.Path, pr.In.URL.RawPath // services serve /api/v1/<name>/...
			pr.SetXForwarded()
			g.forwardedFor(pr)
			// The browser's credentials never reach a service: only the
			// gateway's own short-lived tokens do.
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del(server.DBContextHeader)
			pr.Out.Header.Del(CSRFHeader)
			t, _ := pr.In.Context().Value(tokensKey{}).(tokens)
			pr.Out.Header.Set("Authorization", "Bearer "+t.jwt)
			pr.Out.Header.Set(server.DBContextHeader, t.db)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.log(r, "proxy", err)
			writeError(w, http.StatusBadGateway, "unavailable", "")
		},
	}
	return p
}

// --- the session APIs (AC-33) ---------------------------------------------

func (g *Gateway) me(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	banner := map[string]any{"required": false, "acknowledged_at": sess.BannerAckAt}
	if sess.BannerAckAt == nil && g.bannerRequired() {
		b, err := g.Sessions.CurrentBanner(r.Context())
		if err != nil {
			g.log(r, "banner", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "")
			return
		}
		banner = map[string]any{"required": true, "version": b.Version, "text": b.Text}
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": sess.UserID, "session": sess.Handle, "auth_method": sess.AuthMethod,
		"created_at": sess.CreatedAt, "expires_at": sess.ExpiresAt, "csrf_token": g.Sessions.CSRFToken(sess), "banner": banner})
}

// ackBanner records the session's acknowledgment of the banner version it
// was shown; a version that is no longer current is refused (409) so the
// user reads the current text.
func (g *Gateway) ackBanner(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version int `json:"version"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.Version <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "the body is {\"version\": n}")
		return
	}
	out, err := g.Sessions.AckBanner(r.Context(), sessionFrom(r.Context()), body.Version)
	switch {
	case err != nil:
		g.log(r, "banner acknowledgment", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "")
	case out == "stale":
		writeError(w, http.StatusConflict, "banner_changed", "the notification changed; read it again")
	case out != "ok":
		writeError(w, http.StatusUnauthorized, "unauthenticated", "")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (g *Gateway) logout(w http.ResponseWriter, r *http.Request) {
	if err := g.Sessions.Logout(r.Context(), sessionFrom(r.Context()).token); err != nil {
		g.log(r, "logout", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// target is the user a /sessions call is about: ?user= (required), or the
// caller for /me/sessions.
func target(w http.ResponseWriter, r *http.Request, own bool) (any, bool) {
	if own {
		return nil, true
	}
	u := r.URL.Query().Get("user")
	if !uuidRE.MatchString(u) {
		writeError(w, http.StatusBadRequest, "invalid_request", "user must be a user id")
		return nil, false
	}
	return u, true
}

func (g *Gateway) listSessions(own bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r.Context())
		t, ok := target(w, r, own)
		if !ok {
			return
		}
		type item struct {
			Handle     string     `json:"session"`
			UserID     string     `json:"user_id"`
			AuthMethod string     `json:"auth_method"`
			CreatedAt  time.Time  `json:"created_at"`
			LastSeenAt time.Time  `json:"last_seen_at"`
			Absolute   time.Time  `json:"absolute_expiry_at"`
			IP         *string    `json:"ip,omitempty"`
			UserAgent  *string    `json:"user_agent,omitempty"`
			NetChanged *time.Time `json:"network_changed_at,omitempty"` // flagged (T-20)
			Current    bool       `json:"current"`
		}
		out := []item{}
		err := g.withContext(r.Context(), sess, func(tx pgx.Tx) error {
			rows, err := tx.Query(r.Context(), `SELECT handle::text, user_id::text, auth_method, created_at, last_seen_at, absolute_expiry_at, ip, user_agent,
				network_changed_at FROM iam.session_list($1)`, t)
			if err != nil {
				return err
			}
			out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (item, error) {
				var i item
				err := row.Scan(&i.Handle, &i.UserID, &i.AuthMethod, &i.CreatedAt, &i.LastSeenAt, &i.Absolute, &i.IP, &i.UserAgent, &i.NetChanged)
				i.Current = i.Handle == sess.Handle
				return i, err
			})
			return err
		})
		if g.dbFail(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
	}
}

func reason(r *http.Request) string {
	var body struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 {
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	}
	return body.Reason
}

func (g *Gateway) revoke(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	h := r.PathValue("handle")
	if !uuidRE.MatchString(h) {
		writeError(w, http.StatusNotFound, "not_found", "")
		return
	}
	var revoked bool
	err := g.withContext(r.Context(), sess, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.session_revoke($1, $2)", h, reason(r)).Scan(&revoked)
	})
	if g.dbFail(w, r, err) {
		return
	}
	if !revoked {
		writeError(w, http.StatusNotFound, "not_found", "no active session with that id")
		return
	}
	if h == sess.Handle {
		ClearCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeAll: /me/sessions revokes the caller's other sessions;
// /sessions?user= revokes every session of that user (session.revoke).
func (g *Gateway) revokeAll(own bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r.Context())
		t, ok := target(w, r, own)
		if !ok {
			return
		}
		var keep any
		if own {
			keep = sess.Handle
		}
		var n int
		err := g.withContext(r.Context(), sess, func(tx pgx.Tx) error {
			return tx.QueryRow(r.Context(), "SELECT iam.session_revoke_all($1, $2, $3)", t, keep, reason(r)).Scan(&n)
		})
		if g.dbFail(w, r, err) {
			return
		}
		if !own && t == sess.UserID {
			ClearCookie(w)
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
	}
}

// dbFail answers a database error; false when there is none.
func (g *Gateway) dbFail(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	var pg *pgconn.PgError
	switch {
	case errors.As(err, &pg) && pg.Code == "PF008":
		writeError(w, http.StatusForbidden, "forbidden", "the action needs a permission you do not hold")
	case errors.As(err, &pg) && pg.Code == "PF002":
		writeError(w, http.StatusUnprocessableEntity, "reason_required", "a reason is required")
	case errors.As(err, &pg) && pg.Code == "PF007", errors.Is(err, authz.ErrNoDBContext):
		writeError(w, http.StatusUnauthorized, "unauthenticated", "")
	default:
		g.log(r, "session API", err)
		writeError(w, http.StatusInternalServerError, "internal", "")
	}
	return true
}

func (g *Gateway) log(r *http.Request, what string, err error) {
	if g.Logger != nil {
		g.Logger.Error(what, "path", r.URL.Path, "error", err.Error())
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, detail string) {
	body := map[string]string{"error": code}
	if detail != "" {
		body["detail"] = detail
	}
	writeJSON(w, status, body)
}
