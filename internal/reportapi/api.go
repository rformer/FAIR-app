// Package reportapi serves F-010's reports API in the risk service (design
// §6; contract api/openapi/report.yaml), behind the gateway like the
// register API: an internal JWT (audience "risk") and its DB context on
// every request (server.Authenticate), an Idempotency-Key on every mutation
// (server.Idempotent). Service accounts use the same routes (AC-22).
//
// T-09 serves runs:
//
//	GET  /api/v1/reports/kinds                   the report kinds and their parameters   report.view or report.export anywhere
//	POST /api/v1/reports                         request a report (202)                  report.export at the BU
//	GET  /api/v1/reports                         the caller's own runs                   the requester
//	GET  /api/v1/reports/{id}                    one, with its files' sizes and digests  the requester
//	GET  /api/v1/reports/{id}/files/{format}     a file, recorded first                  the requester, report.export re-checked
//
// T-14 serves the dashboard:
//
//	GET  /api/v1/reports/dashboard?bu=           a BU subtree's portfolio                report.view at the BU
//
// T-15 serves the trend:
//
//	GET  /api/v1/reports/dashboard/trend?bu=&from=&to=   the snapshots the caller may see   report.view at the BU
//
// T-16 serves schedules (the owner's own; report.export at the BU):
//
//	GET, POST          /api/v1/reports/schedules
//	GET, PUT, DELETE   /api/v1/reports/schedules/{id}       PUT with expected_version, DELETE with a reason
//	POST               /api/v1/reports/schedules/{id}/resume
//
// Without report.view or report.export anywhere the routes do not exist for
// the caller (404, F-001 AC-25); another user's run is 404 like a missing
// one. The database records every event (design §8) in the change's
// transaction.
package reportapi

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

	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

const (
	permView   authz.Permission = "report.view"
	permExport authz.Permission = "report.export"
)

// API serves the reports API.
type API struct {
	DB    *pgxpool.Pool // app_rw
	Authz riskapi.Authorizer
	// Kinds are the report kinds with readers; a request for another kind
	// is refused.
	Kinds map[string]reports.Kind
	// Enqueue queues a run's job in the request's transaction; nil when
	// reports are not configured (requests answer 503).
	Enqueue func(context.Context, pgx.Tx, reports.GenerateArgs) error
	// Store serves downloads; nil answers them 503.
	Store reports.Store
	// Settings gives export.reason_required (the reason rule).
	Settings reports.ReasonSettings
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/api/v1/reports/kinds", (*API).listKinds},
	{"GET", "/api/v1/reports/dashboard", (*API).getDashboard},
	{"GET", "/api/v1/reports/dashboard/trend", (*API).getTrend},
	{"POST", "/api/v1/reports", (*API).requestReport},
	{"GET", "/api/v1/reports", (*API).listReports},
	{"GET", "/api/v1/reports/{id}", (*API).getReport},
	{"GET", "/api/v1/reports/{id}/files/{format}", (*API).downloadFile},
	{"GET", "/api/v1/reports/schedules", (*API).listSchedules},
	{"POST", "/api/v1/reports/schedules", (*API).createSchedule},
	{"GET", "/api/v1/reports/schedules/{id}", (*API).getSchedule},
	{"PUT", "/api/v1/reports/schedules/{id}", (*API).updateSchedule},
	{"DELETE", "/api/v1/reports/schedules/{id}", (*API).deleteSchedule},
	{"POST", "/api/v1/reports/schedules/{id}/resume", (*API).resumeSchedule},
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
var Prefixes = []string{"/api/v1/reports"}

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

// anywhere answers 404 and returns false unless the caller holds
// report.view or report.export at some BU.
func (a *API) anywhere(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	for _, perm := range []authz.Permission{permView, permExport} {
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

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object with the documented fields", nil)
		return false
	}
	return true
}

// errAudit: a download whose event could not be recorded, or whose file
// the store could not open.
var errAudit = errors.New("reportapi: the download could not be recorded")

// fail answers a database error.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.As(err, &pg) && pg.Code == "P0002":
		notFound(w)
	case errors.Is(err, authz.ErrNoDBContext), errors.As(err, &pg) && pg.Code == "PF029" && pg.Hint == "no_context":
		problem(w, http.StatusUnauthorized, "unauthenticated", "", nil)
	case errors.As(err, &pg) && pg.Code == "PF029" && pg.Hint == "limit_exceeded":
		problem(w, http.StatusUnprocessableEntity, "limit_exceeded", pg.Message, map[string]any{"limit": reports.MaxRisks})
	case errors.As(err, &pg) && pg.Code == "PF029" && pg.Hint == "too_many_running":
		problem(w, http.StatusConflict, "too_many_running", pg.Message, map[string]any{"limit": reports.MaxRunning})
	case errors.As(err, &pg) && pg.Code == "PF029" && pg.Hint == "not_succeeded":
		problem(w, http.StatusConflict, "not_succeeded", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF029" && pg.Hint == "purged":
		problem(w, http.StatusGone, "purged", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF029" && pg.Hint == "invalid_schedule":
		problem(w, http.StatusUnprocessableEntity, "invalid_value", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF029" && (pg.Hint == "stale_version" || pg.Hint == "not_suspended"):
		problem(w, http.StatusConflict, pg.Hint, pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF029" && pg.Hint == "reason_required":
		problem(w, http.StatusBadRequest, "reason_required", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF030":
		problem(w, http.StatusConflict, "too_many_schedules", pg.Message, map[string]any{"limit": 20})
	case errors.As(err, &pg) && pg.Code == "42501":
		problem(w, http.StatusForbidden, "forbidden", pg.Message, nil)
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "", nil) // includes an event that could not be recorded
	}
}
