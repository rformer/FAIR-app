// Package importapi serves F-011's imports API in the risk service (design
// §6.2; contract api/openapi/import.yaml), behind the gateway like the
// register API: an internal JWT (audience "risk") and its DB context on
// every request, an Idempotency-Key on every mutation. Customer automation
// pushes batches as service accounts holding integration.push;
// administrators upload them with integration.manage; the integrate
// service's connectors push as the integration's service account.
//
// T-08 serves batches and runs:
//
//	POST /api/v1/imports/{integration}/batches[?dry_run=true]   JSON or CSV   integration.push or manage at its BU
//	GET  /api/v1/imports/runs/{id}                              a run         integration.view or manage, or its actor
//
// A batch is processed in its request, in one transaction: checked record
// by record (internal/integration), its records' business units resolved
// inside the integration's subtree, matched by external ID, staged, and
// the run recorded with its counts. A dry run does all of it but write.
package importapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// API serves the imports API.
type API struct {
	DB    *pgxpool.Pool // app_rw
	Authz riskapi.Authorizer
	// Now is the clock (tests).
	Now func() time.Time
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"POST", "/api/v1/imports/{integration}/batches", (*API).pushBatch},
	{"GET", "/api/v1/imports/runs/{id}", (*API).getRun},
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
var Prefixes = []string{"/api/v1/imports"}

// Handler returns the API with authentication and idempotency.
func (a *API) Handler(kp authz.KeyProvider, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routes {
		h := rt.h
		mux.HandleFunc(rt.method+" "+rt.path, func(w http.ResponseWriter, r *http.Request) {
			p, _ := server.PrincipalFrom(r.Context())
			h(a, w, r, p)
		})
	}
	return server.Authenticate(kp, "risk", now)(server.Idempotent(riskapi.IdempotencyStore{DB: a.DB})(mux))
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// anywhere answers 404 and returns false unless the caller holds an
// integration permission at some BU.
func (a *API) anywhere(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	for _, perm := range []authz.Permission{"integration.push", "integration.manage", "integration.view"} {
		bus, err := a.Authz.BUsWith(r.Context(), p, perm)
		if err != nil {
			server.WriteAuthzError(w, err)
			return false
		}
		if len(bus) > 0 {
			return true
		}
	}
	notFound(w)
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
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

func notFound(w http.ResponseWriter) { problem(w, http.StatusNotFound, "not_found", "", nil) }

// readBody reads at most max bytes; false (after answering 413) when the
// body is larger.
func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body could not be read", nil)
		return nil, false
	}
	if int64(len(b)) > max {
		problem(w, http.StatusRequestEntityTooLarge, "limit_exceeded", "the body is larger than the limit", map[string]any{"limit": max})
		return nil, false
	}
	return b, true
}

// fail answers a database error.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.As(err, &pg) && pg.Code == "P0002":
		notFound(w)
	case errors.Is(err, authz.ErrNoDBContext), errors.As(err, &pg) && pg.Code == "PF031" && pg.Hint == "no_context":
		problem(w, http.StatusUnauthorized, "unauthenticated", "", nil)
	case errors.As(err, &pg) && pg.Code == "42501":
		problem(w, http.StatusForbidden, "forbidden", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF032" && pg.Hint == "too_many_runs":
		problem(w, http.StatusTooManyRequests, "too_many_runs", pg.Message, map[string]any{"limit": 12})
	case errors.As(err, &pg) && pg.Code == "PF031" && (pg.Hint == "invalid_state" || pg.Hint == "integration_deleted" || pg.Hint == "run_in_progress"):
		problem(w, http.StatusConflict, pg.Hint, pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF031":
		problem(w, http.StatusUnprocessableEntity, "invalid_value", pg.Message, nil)
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "", nil) // includes an event that could not be recorded
	}
}
