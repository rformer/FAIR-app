package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
)

// API request conventions (F-001 design §5.2, §6; F-015 T-31; reused by
// F-001 T-42): authentication from the gateway's internal JWT and DB context
// token, and Idempotency-Key on every mutation.

// DBContextHeader carries the DB context token the gateway minted with the
// internal JWT.
const DBContextHeader = "X-Fair-DB-Context"

type principalKey struct{}

// PrincipalFrom returns the authenticated principal of a request.
func PrincipalFrom(ctx context.Context) (authz.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(authz.Principal)
	return p, ok
}

// WithPrincipal returns ctx carrying p (tests and internal callers).
func WithPrincipal(ctx context.Context, p authz.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// Authenticate requires a valid internal JWT for audience (Authorization:
// Bearer) and the DB context token it was minted with (DBContextHeader), and
// puts the principal in the request context. Anything else is 401.
func Authenticate(kp authz.KeyProvider, audience string, now func() time.Time) func(http.Handler) http.Handler {
	if now == nil {
		now = time.Now
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			dbc := r.Header.Get(DBContextHeader)
			c, err := authz.VerifyJWT(kp, strings.TrimSpace(tok), audience, now())
			if !ok || err != nil || dbc == "" || authz.DBContextHash(dbc) != c.DBContext {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			p := authz.Principal{UserID: c.Subject, ScopeVersion: c.ScopeVersion, DBToken: dbc, NetworkChanged: c.NetworkChanged}
			if c.AuthTime > 0 {
				p.AuthTime = time.Unix(c.AuthTime, 0)
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// IdempotencyStore keeps mutation outcomes per user and key.
type IdempotencyStore interface {
	// Begin reserves (user, key) for a request with the given hash. It
	// returns the stored response of a completed identical request,
	// ErrIdempotencyMismatch if the key was used for a different request, or
	// ErrIdempotencyInProgress while another request holds it.
	Begin(ctx context.Context, user, key, requestHash string) (*StoredResponse, error)
	Complete(ctx context.Context, user, key string, resp StoredResponse) error
	// Abandon frees a reservation (the request failed with a server error).
	Abandon(ctx context.Context, user, key string) error
}

// StoredResponse is a completed mutation's response.
type StoredResponse struct {
	Status      int
	ContentType string
	Body        []byte
}

// Idempotency errors.
var (
	ErrIdempotencyMismatch   = errors.New("server: idempotency key reused for a different request")
	ErrIdempotencyInProgress = errors.New("server: a request with this idempotency key is in progress")
)

// IdempotencyHeader is the request header.
const IdempotencyHeader = "Idempotency-Key"

var idemKeyRE = regexp.MustCompile(`^[\x21-\x7e]{8,128}$`)

const maxMutationBody = 4 << 20

type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (r *recorder) WriteHeader(s int) { r.status = s; r.ResponseWriter.WriteHeader(s) }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.buf.Write(b)
	return r.ResponseWriter.Write(b)
}

// Idempotent requires an Idempotency-Key on POST, PUT, PATCH and DELETE and
// replays the stored response of a repeated identical request instead of
// running it again. It needs the principal (Authenticate before it).
func Idempotent(store IdempotencyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			default:
				next.ServeHTTP(w, r)
				return
			}
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			key := r.Header.Get(IdempotencyHeader)
			if !idemKeyRE.MatchString(key) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "idempotency_key_required",
					"detail": "mutations need an Idempotency-Key header of 8-128 printable characters"})
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, maxMutationBody+1))
			if err != nil || len(body) > maxMutationBody {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request_too_large"})
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			h := sha256.New()
			h.Write([]byte(r.Method + " " + r.URL.RequestURI() + "\n"))
			h.Write(body)
			hash := hex.EncodeToString(h.Sum(nil))

			stored, err := store.Begin(r.Context(), p.UserID, key, hash)
			switch {
			case errors.Is(err, ErrIdempotencyMismatch):
				writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "idempotency_key_reused"})
				return
			case errors.Is(err, ErrIdempotencyInProgress):
				writeJSON(w, http.StatusConflict, map[string]string{"error": "request_in_progress"})
				return
			case err != nil:
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
				return
			case stored != nil:
				w.Header().Set("Content-Type", stored.ContentType)
				w.Header().Set("Idempotent-Replayed", "true")
				w.WriteHeader(stored.Status)
				_, _ = w.Write(stored.Body) // #nosec G705 -- the stored response of this handler, replayed with its content type
				return
			}
			rec := &recorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			if rec.status >= 500 {
				_ = store.Abandon(context.WithoutCancel(r.Context()), p.UserID, key)
				return
			}
			_ = store.Complete(context.WithoutCancel(r.Context()), p.UserID, key,
				StoredResponse{Status: rec.status, ContentType: w.Header().Get("Content-Type"), Body: rec.buf.Bytes()})
		})
	}
}
