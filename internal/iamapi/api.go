// Package iamapi is the iam service's administration API (F-001 design §6),
// behind the gateway: every request carries an internal JWT and DB context
// (server.Authenticate) and every mutation an Idempotency-Key
// (server.Idempotent). T-17 adds the IdP routes:
//
//	GET    /api/v1/idps                        list            idp.view
//	POST   /api/v1/idps                        create          idp.manage
//	GET    /api/v1/idps/{id}                   read            idp.view
//	PATCH  /api/v1/idps/{id}                   name, domains, enabled, settings
//	PUT    /api/v1/idps/{id}/metadata          upload SAML metadata, OIDC discovery or JWKS
//	POST   /api/v1/idps/{id}/metadata/fetch    fetch metadata from a URL (not air-gapped)
//
// Without idp.view the routes do not exist for the caller (404, AC-25);
// changes need idp.manage, checked by the database from the signed context
// (403). A change of trust anchors (signing certificates, keys, issuer) is
// applied only with ?confirm= naming exactly the new fingerprints (409
// otherwise, listing them).
package iamapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// API serves iam's administration routes.
type API struct {
	DB             *pgxpool.Pool // app_rw
	Authz          authz.Checker
	DeploymentMode string // air-gapped refuses metadata URLs (design §10)
	Dev            bool   // development: http endpoints accepted

	rootOnce sync.Once
	root     string
	rootErr  error
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/api/v1/idps", (*API).listIDPs},
	{"POST", "/api/v1/idps", (*API).createIDP},
	{"GET", "/api/v1/idps/{id}", (*API).getIDP},
	{"PATCH", "/api/v1/idps/{id}", (*API).updateIDP},
	{"PUT", "/api/v1/idps/{id}/metadata", (*API).uploadMetadata},
	{"POST", "/api/v1/idps/{id}/metadata/fetch", (*API).fetchMetadata},
}

// Routes lists "METHOD /path" of every route (for the OpenAPI document).
func Routes() []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.method+" "+r.path)
	}
	sort.Strings(out)
	return out
}

// Prefixes are the path prefixes the API owns (for the service's mux).
var Prefixes = []string{"/api/v1/idps"}

// Handler returns the API with authentication and idempotency in front.
func (a *API) Handler(kp authz.KeyProvider, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routes {
		h := rt.h
		mux.HandleFunc(rt.method+" "+rt.path, func(w http.ResponseWriter, r *http.Request) {
			p, _ := server.PrincipalFrom(r.Context())
			h(a, w, r, p)
		})
	}
	return server.Authenticate(kp, "iam", now)(server.Idempotent(IdempotencyStore{DB: a.DB})(mux))
}

func (a *API) airGapped() bool { return a.DeploymentMode == config.ModeAirGapped }

func (a *API) rootBU(ctx context.Context) (string, error) {
	a.rootOnce.Do(func() { a.rootErr = a.DB.QueryRow(ctx, "SELECT iam.root_bu()::text").Scan(&a.root) })
	return a.root, a.rootErr
}

// view requires idp.view at the root; it answers and returns false
// otherwise (404 without it: the API does not exist for the caller).
func (a *API) view(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	root, err := a.rootBU(r.Context())
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "", nil)
		return false
	}
	if err := a.Authz.Check(r.Context(), p, "idp.view", root); err != nil {
		server.WriteAuthzError(w, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, code, detail string, extra map[string]any) {
	body := map[string]any{"error": code}
	if detail != "" {
		body["detail"] = detail
	}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object with the documented fields", nil)
		return false
	}
	return true
}

// fail answers a database or validation error.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, authn.ErrMetadata):
		problem(w, http.StatusUnprocessableEntity, "invalid_metadata", err.Error(), nil)
	case errors.As(err, &pg) && pg.Code == "PF008":
		problem(w, http.StatusForbidden, "forbidden", "the action needs a permission you do not hold", nil)
	case errors.As(err, &pg) && pg.Code == "PF007", errors.Is(err, authz.ErrNoDBContext):
		problem(w, http.StatusUnauthorized, "unauthenticated", "", nil)
	case errors.As(err, &pg) && pg.Code == "PF003":
		problem(w, http.StatusConflict, "not_applicable", pg.Message, nil)
	case errors.As(err, &pg) && (pg.Code == "PF004" || pg.Code == "23514" || pg.Code == "22023"):
		problem(w, http.StatusBadRequest, "invalid_value", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "23505":
		problem(w, http.StatusConflict, "duplicate", "an IdP with that name exists", nil)
	case errors.Is(err, errNotFound):
		problem(w, http.StatusNotFound, "not_found", "", nil)
	default:
		problem(w, http.StatusInternalServerError, "internal", "", nil)
	}
}
