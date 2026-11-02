// Package breakglass is the break-glass sign-in (F-001 T-34; AC-40, AC-42,
// AC-43, AC-47; design §5.7; ADR-010): WebAuthn only, through
// github.com/go-webauthn/webauthn, for the at most two local break-glass
// accounts. The routes exist only while breakglass.enabled is on (404
// otherwise):
//
//	POST /api/v1/auth/breakglass/enroll/begin   {code}                       registration options
//	POST /api/v1/auth/breakglass/enroll/finish  {ceremony, code, credential}  the key is registered; the code is spent
//	POST /api/v1/auth/breakglass/login/begin    {}                           assertion options (discoverable)
//	POST /api/v1/auth/breakglass/login/finish   {ceremony, credential, return}
//
// A holder enrolls with the one-time code given when break-glass was
// enabled (no password ever exists, AC-40). Credentials must be
// discoverable and user-verified, with ES256, ES384, RS256 or PS256 keys.
// A successful login answers with a login ticket the gateway turns into a
// session (authn.TicketHeader); the database audits it high and announces
// it (AC-43). Failures of a known account count towards the lockout
// (AC-47). The gateway forwards these routes without a session.
package breakglass

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/pkg/authz"
)

// Prefix is where the routes live.
const Prefix = "/api/v1/auth/breakglass/"

// Algorithms are the credential algorithms accepted (FIPS 186 signatures).
var Algorithms = []webauthncose.COSEAlgorithmIdentifier{webauthncose.AlgES256, webauthncose.AlgES384, webauthncose.AlgRS256, webauthncose.AlgPS256}

// Server serves the break-glass ceremonies.
type Server struct {
	DB        *pgxpool.Pool     // app_rw
	Tickets   authz.KeyProvider // signs login tickets for the gateway
	WebAuthn  *webauthn.WebAuthn
	Logger    *slog.Logger
	Now       func() time.Time
	PerMinute int // requests per client address (default 30)

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a Server for the platform's public origin (the relying party
// is its host).
func New(db *pgxpool.Pool, tickets authz.KeyProvider, origin string, logger *slog.Logger) (*Server, error) {
	host := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: host, RPDisplayName: "FAIR break-glass", RPOrigins: []string{origin}})
	if err != nil {
		return nil, err
	}
	return &Server{DB: db, Tickets: tickets, WebAuthn: wa, Logger: logger}, nil
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) allow(client string) bool {
	rate := float64(s.PerMinute)
	if rate <= 0 {
		rate = 30
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buckets == nil || len(s.buckets) > 10000 {
		s.buckets = map[string]*bucket{}
	}
	b := s.buckets[client]
	if b == nil {
		b = &bucket{tokens: rate, last: now}
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

// account is a break-glass account as WebAuthn sees it. The user handle is
// the account's id.
type account struct {
	id          uuid.UUID
	email, name string
	status      string
	creds       []webauthn.Credential
	counts      map[string]uint32 // the stored counters, by credential id
}

func (a *account) WebAuthnID() []byte                         { return a.id[:] }
func (a *account) WebAuthnName() string                       { return a.email }
func (a *account) WebAuthnDisplayName() string                { return a.name }
func (a *account) WebAuthnCredentials() []webauthn.Credential { return a.creds }

func (s *Server) loadAccount(ctx context.Context, id uuid.UUID) (*account, error) {
	var raw []byte
	a := &account{id: id, counts: map[string]uint32{}}
	err := s.DB.QueryRow(ctx, "SELECT email, display_name, status, credentials FROM iam.breakglass_login_account($1)", id).
		Scan(&a.email, &a.name, &a.status, &raw)
	if err != nil {
		return nil, err
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	for _, item := range list {
		var c webauthn.Credential
		var extra struct {
			Count uint32 `json:"fair_sign_count"`
		}
		if err := json.Unmarshal(item, &c); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(item, &extra)
		c.Authenticator.SignCount = extra.Count // the database's counter, not the one stored at enrollment
		a.creds = append(a.creds, c)
		a.counts[string(c.ID)] = extra.Count
	}
	return a, nil
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// failed answers every refusal alike; the audit trail has the reason.
func failed(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]string{"error": "sign_in_failed", "detail": "Break-glass sign-in did not succeed."})
}

func (s *Server) log(r *http.Request, what string, err error) {
	if s.Logger != nil {
		s.Logger.Error("break-glass "+what, "path", r.URL.Path, "error", err.Error())
	}
}

// ServeHTTP routes the ceremonies.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var on bool
	if err := s.DB.QueryRow(r.Context(), "SELECT iam.breakglass_enabled()").Scan(&on); err != nil {
		s.log(r, "setting", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	if !on { // AC-39: the routes do not exist while break-glass is off
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	if !s.allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	var body struct {
		Code       string          `json:"code"`
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
		Return     string          `json:"return"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	switch strings.TrimPrefix(r.URL.Path, Prefix) {
	case "enroll/begin":
		s.enrollBegin(w, r, body.Code)
	case "enroll/finish":
		s.enrollFinish(w, r, body.Code, body.Ceremony, body.Credential)
	case "login/begin":
		s.loginBegin(w, r)
	case "login/finish":
		s.loginFinish(w, r, body.Ceremony, body.Credential, body.Return)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}

func codeHash(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}

func (s *Server) enrollee(ctx context.Context, code string) (*account, error) {
	var id uuid.UUID
	a := &account{}
	err := s.DB.QueryRow(ctx, "SELECT user_id, email, display_name FROM iam.breakglass_enrollee($1)", codeHash(code)).Scan(&id, &a.email, &a.name)
	a.id = id
	return a, err
}

func credParams() []protocol.CredentialParameter {
	out := make([]protocol.CredentialParameter, 0, len(Algorithms))
	for _, alg := range Algorithms {
		out = append(out, protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: alg})
	}
	return out
}

func (s *Server) enrollBegin(w http.ResponseWriter, r *http.Request, code string) {
	a, err := s.enrollee(r.Context(), code)
	if errors.Is(err, pgx.ErrNoRows) {
		failed(w, http.StatusUnauthorized)
		return
	}
	if err != nil {
		s.log(r, "enrollment", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	creation, session, err := s.WebAuthn.BeginRegistration(a,
		webauthn.WithCredentialParameters(credParams()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		s.log(r, "registration options", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	id, err := s.putCeremony(r.Context(), "enroll", &a.id, session)
	if err != nil {
		s.log(r, "ceremony", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": creation})
}

func (s *Server) putCeremony(ctx context.Context, kind string, user *uuid.UUID, session *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	var id string
	err = s.DB.QueryRow(ctx, "SELECT iam.webauthn_ceremony_put($1, $2, $3)::text", kind, user, data).Scan(&id)
	return id, err
}

// takeCeremony returns the ceremony's session once.
func (s *Server) takeCeremony(ctx context.Context, id, kind string) (*uuid.UUID, *webauthn.SessionData, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, nil, pgx.ErrNoRows
	}
	var user *uuid.UUID
	var data []byte
	if err := s.DB.QueryRow(ctx, "SELECT user_id, session FROM iam.webauthn_ceremony_take($1, $2)", id, kind).Scan(&user, &data); err != nil {
		return nil, nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, nil, err
	}
	return user, &session, nil
}

func (s *Server) enrollFinish(w http.ResponseWriter, r *http.Request, code, ceremony string, cred json.RawMessage) {
	user, session, err := s.takeCeremony(r.Context(), ceremony, "enroll")
	if errors.Is(err, pgx.ErrNoRows) {
		failed(w, http.StatusUnauthorized)
		return
	}
	if err != nil {
		s.log(r, "ceremony", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	a, err := s.enrollee(r.Context(), code)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (user == nil || *user != a.id)) {
		failed(w, http.StatusUnauthorized) // the code is spent, expired, or not this ceremony's
		return
	}
	if err != nil {
		s.log(r, "enrollment", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(cred)
	if err != nil {
		s.deny(r, "enrollment", a.id.String(), "unparsable registration: "+err.Error())
		failed(w, http.StatusBadRequest)
		return
	}
	c, err := s.WebAuthn.CreateCredential(a, *session, parsed)
	if err != nil {
		s.deny(r, "enrollment", a.id.String(), "registration refused: "+err.Error())
		failed(w, http.StatusBadRequest)
		return
	}
	if !c.Flags.UserVerified {
		s.deny(r, "enrollment", a.id.String(), "registration without user verification")
		failed(w, http.StatusBadRequest)
		return
	}
	raw, err := json.Marshal(c)
	if err != nil {
		failed(w, http.StatusInternalServerError)
		return
	}
	if _, err := s.DB.Exec(r.Context(), "SELECT iam.breakglass_enroll($1, $2, $3, $4, $5)",
		codeHash(code), c.ID, raw, int64(c.Authenticator.SignCount), clientIP(r)); err != nil {
		s.log(r, "enrolling", err)
		failed(w, http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"enrolled": true})
}

func (s *Server) loginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, session, err := s.WebAuthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.log(r, "assertion options", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	id, err := s.putCeremony(r.Context(), "login", nil, session)
	if err != nil {
		s.log(r, "ceremony", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": assertion})
}

// deny audits a refusal (the database counts failures of known accounts).
func (s *Server) deny(r *http.Request, what, user, reason string) {
	attrs, _ := json.Marshal(map[string]any{"client": clientIP(r), "user_id": user, "stage": what})
	if _, err := s.DB.Exec(r.Context(), "SELECT iam.authn_event($1, $2, $3, $4, $5, $6)",
		"authn.login.denied", "high", "anonymous", nil, attrs, "break-glass: "+reason); err != nil {
		s.log(r, "auditing a refusal", err)
	}
}

func (s *Server) loginFinish(w http.ResponseWriter, r *http.Request, ceremony string, cred json.RawMessage, returnTo string) {
	_, session, err := s.takeCeremony(r.Context(), ceremony, "login")
	if errors.Is(err, pgx.ErrNoRows) {
		failed(w, http.StatusUnauthorized)
		return
	}
	if err != nil {
		s.log(r, "ceremony", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(cred)
	if err != nil {
		s.deny(r, "login", "", "unparsable assertion")
		failed(w, http.StatusUnauthorized)
		return
	}
	// The account the credential names (its user handle); a failure of a
	// known account counts towards its lockout.
	var known *account
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		id, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, err
		}
		a, err := s.loadAccount(r.Context(), id)
		if err != nil {
			return nil, err
		}
		known = a
		return a, nil
	}
	c, err := s.WebAuthn.ValidateDiscoverableLogin(handler, *session, parsed)
	if err == nil && !c.Flags.UserVerified {
		err = errors.New("no user verification")
	}
	if err != nil {
		if known != nil {
			if _, e := s.DB.Exec(r.Context(), "SELECT iam.breakglass_login_failed($1, $2, $3)", known.id, "assertion refused: "+err.Error(), clientIP(r)); e != nil {
				s.log(r, "recording a failure", e)
			}
		} else {
			s.deny(r, "login", "", "unknown credential or account")
		}
		failed(w, http.StatusUnauthorized)
		return
	}
	var refused *string
	if err := s.DB.QueryRow(r.Context(), "SELECT iam.breakglass_login_succeeded($1, $2, $3, $4, $5)",
		known.id, c.ID, int64(c.Authenticator.SignCount), clientIP(r), r.Header.Get("User-Agent")).Scan(&refused); err != nil {
		s.log(r, "recording the login", err)
		failed(w, http.StatusServiceUnavailable) // audit failures fail closed (ADR-006)
		return
	}
	if refused != nil {
		s.deny(r, "login", known.id.String(), *refused)
		failed(w, http.StatusUnauthorized)
		return
	}
	now := s.now()
	tok, err := authn.IssueTicket(s.Tickets, authn.Ticket{UserID: known.id.String(), AuthMethod: "breakglass",
		MFA: map[string]any{"satisfied": true, "webauthn": true, "user_verified": true}, AuthTime: now.Unix(), ReturnTo: returnTo}, now)
	if err != nil {
		s.log(r, "ticket", err)
		failed(w, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set(authn.TicketHeader, tok)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
