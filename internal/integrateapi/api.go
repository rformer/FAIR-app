// Package integrateapi serves F-011's integrations API in the integrate
// service (design §6.1; contract api/openapi/integrate.yaml), behind the
// gateway: an internal JWT (audience "integrate") and its DB context on
// every request (server.Authenticate), an Idempotency-Key on every
// mutation (server.Idempotent).
//
//	GET    /api/v1/integrations                          integrations the caller views or manages
//	POST   /api/v1/integrations                          create one (integration.manage at its BU)
//	GET    /api/v1/integrations/{id}                     one, with which credentials are set
//	PUT    /api/v1/integrations/{id}                     change it (expected_version)
//	DELETE /api/v1/integrations/{id}                     delete it, with a reason; runs and provenance stay
//	POST   /api/v1/integrations/{id}/pause|resume        pause or resume it
//	POST   /api/v1/integrations/{id}/run                 queue a connector run now
//	POST   /api/v1/integrations/{id}/test                fetch the first page, submit nothing
//	PUT    /api/v1/integrations/{id}/credentials/{purpose}  set a credential, write-only
//	DELETE /api/v1/integrations/{id}/credentials/{purpose}  remove it
//	GET    /api/v1/integrations/{id}/runs[/{run}]        its runs
//	GET    /api/v1/integrations/options                  what the form offers (T-18)
//
// The database decides who may do what (integration.view or manage at the
// integration's BU, iam.holds_permission; grants above a restricted BU do
// not reach it, AC-02): an integration the caller may not see is 404, one
// they may see but not change is 403. Credentials are sealed here, under
// integrate/secrets, and never answered (AC-03). A connector's source host
// passes the guard on every save, and a refusal is recorded (AC-04).
package integrateapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/egress"
	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// Tester fetches a connector's first page without submitting it
// (integration.Fetcher, T-17). An error wrapping egress.ErrRefused is a
// refused destination (recorded, AC-04).
type Tester interface {
	Test(ctx context.Context, req integration.TestRequest) (integration.TestResult, error)
}

// API serves the integrations API.
type API struct {
	DB     *pgxpool.Pool        // app_integrate
	Keys   *integration.Keyring // integrate/secrets; nil: credentials cannot be set (503)
	Guard  egress.Guard         // integration.allowed_hosts as in force
	Tester Tester               // nil: tests answer 503
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/api/v1/integrations", (*API).listIntegrations},
	{"GET", "/api/v1/integrations/options", (*API).integrationOptions},
	{"POST", "/api/v1/integrations", (*API).createIntegration},
	{"GET", "/api/v1/integrations/{id}", (*API).getIntegration},
	{"PUT", "/api/v1/integrations/{id}", (*API).updateIntegration},
	{"DELETE", "/api/v1/integrations/{id}", (*API).deleteIntegration},
	{"POST", "/api/v1/integrations/{id}/pause", (*API).pauseIntegration},
	{"POST", "/api/v1/integrations/{id}/resume", (*API).resumeIntegration},
	{"POST", "/api/v1/integrations/{id}/run", (*API).runIntegration},
	{"POST", "/api/v1/integrations/{id}/test", (*API).testIntegration},
	{"PUT", "/api/v1/integrations/{id}/credentials/{purpose}", (*API).putCredential},
	{"DELETE", "/api/v1/integrations/{id}/credentials/{purpose}", (*API).deleteCredential},
	{"GET", "/api/v1/integrations/{id}/runs", (*API).listRuns},
	{"GET", "/api/v1/integrations/{id}/runs/{run}", (*API).getRun},
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
var Prefixes = []string{"/api/v1/integrations"}

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
	return server.Authenticate(kp, "integrate", now)(server.Idempotent(riskapi.IdempotencyStore{DB: a.DB})(mux))
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, code, detail string) {
	body := map[string]any{"error": code}
	if detail != "" {
		body["detail"] = detail
	}
	writeJSON(w, status, body)
}

// fail answers a database refusal.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	if errors.Is(err, authz.ErrNoDBContext) {
		problem(w, http.StatusUnauthorized, "unauthenticated", "")
		return
	}
	if !errors.As(err, &pg) {
		problem(w, http.StatusServiceUnavailable, "unavailable", "") // includes an event that could not be recorded
		return
	}
	switch pg.Code {
	case "P0002":
		problem(w, http.StatusNotFound, "not_found", "")
	case "42501":
		problem(w, http.StatusForbidden, "forbidden", "integration.manage at the integration's business unit is needed")
	case "23505":
		problem(w, http.StatusConflict, "name_taken", "another integration of the business unit has this name")
	case "23514", "22001":
		problem(w, http.StatusUnprocessableEntity, "invalid_integration", "a value is out of range (names are 1 to 100 characters)")
	case "PF032":
		problem(w, http.StatusConflict, "limit_exceeded", pg.Message)
	case "PF031":
		switch pg.Hint {
		case "no_context":
			problem(w, http.StatusUnauthorized, "unauthenticated", "")
		case "stale_version", "integration_deleted", "invalid_state":
			problem(w, http.StatusConflict, pg.Hint, pg.Message)
		case "reason_required", "invalid_value":
			problem(w, http.StatusBadRequest, pg.Hint, pg.Message)
		case "invalid_integration", "integration_fixed":
			problem(w, http.StatusUnprocessableEntity, pg.Hint, pg.Message)
		default:
			problem(w, http.StatusUnprocessableEntity, "refused", pg.Message)
		}
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "")
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 128<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object with the documented fields")
		return false
	}
	return true
}

// tx runs fn under the caller's DB context.
func (a *API) tx(r *http.Request, p authz.Principal, fn func(tx pgx.Tx) error) error {
	return authz.WithDBContext(r.Context(), a.DB, p.DBToken, fn)
}

// one runs sql under the caller's context and answers its one JSON value.
func (a *API) one(r *http.Request, p authz.Principal, sql string, args ...any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := a.tx(r, p, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), sql, args...).Scan(&raw)
	})
	return raw, err
}

// id is the path's integration id; an id that is not one is 404.
func id(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := r.PathValue(name)
	if !uuidRE.MatchString(v) {
		problem(w, http.StatusNotFound, "not_found", "")
		return "", false
	}
	return v, true
}
