// Package analysisapi serves F-005's analysis API in the risk service
// (design §5; contract api/openapi/analysis.yaml), behind the gateway like
// the risk API: an internal JWT (audience "risk") and its DB context on
// every request (server.Authenticate), an Idempotency-Key on every mutation
// (server.Idempotent).
//
// T-11 serves runs:
//
//	POST /api/v1/analyses/runs                     request a run        analysis.run at the scenario's BU
//	GET  /api/v1/analyses/runs?scenario=           a scenario's runs    analysis.view (RLS)
//	GET  /api/v1/analyses/runs/{id}                a run, with its results once it succeeded
//	GET  /api/v1/analyses/runs/{id}/series/{set}   a set's per-year annual losses (float64 little-endian)
//	POST /api/v1/analyses/runs/{id}/cancel         the requester, or analysis.run at the run's BU
//
// T-12 serves reproductions and aggregates:
//
//	POST /api/v1/analyses/runs/{id}/reproduce      a run with the recorded inputs     analysis.run at the run's BU
//	POST /api/v1/analyses/aggregates               an aggregate of runs' control sets analysis.run at the chosen BU
//	GET  /api/v1/analyses/aggregates[?bu=]         the aggregates whose members the caller all sees
//	GET  /api/v1/analyses/aggregates/{id}          one, with members and summary
//
// F-006 T-01 serves histograms of the stored series (F-006 design §3.1):
//
//	GET  /api/v1/analyses/runs/{id}/histogram?set=&scale=&relative_to=   a set's annual loss, or its per-year difference from the current set
//	GET  /api/v1/analyses/aggregates/{id}/histogram?scale=               an aggregate's annual loss
//
// Without analysis.view or analysis.run anywhere the routes do not exist
// for the caller (404, F-001 AC-25); a run or scenario the caller cannot
// see is 404 like a missing one. The database records every event (design
// §9) in the change's transaction.
package analysisapi

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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

const (
	permView authz.Permission = "analysis.view"
	permRun  authz.Permission = "analysis.run"
)

// Settings gives F-005's limits (design §7) at request time.
type Settings interface {
	Limits(ctx context.Context) (analysis.Limits, error)
}

// API serves the analysis API.
type API struct {
	DB    *pgxpool.Pool // app_rw
	Authz riskapi.Authorizer
	// Enqueue queues a run's job in the request's transaction; nil when no
	// engine is configured (requests answer 503 engine_unavailable).
	Enqueue func(context.Context, pgx.Tx, analysis.SimulateArgs) error
	// EnqueueAggregate queues an aggregate's job (nil: no engine).
	EnqueueAggregate func(context.Context, pgx.Tx, analysis.AggregateArgs) error
	Settings         Settings
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"POST", "/api/v1/analyses/runs", (*API).createRun},
	{"GET", "/api/v1/analyses/runs", (*API).listRuns},
	{"GET", "/api/v1/analyses/runs/{id}", (*API).getRun},
	{"GET", "/api/v1/analyses/runs/{id}/series/{set}", (*API).getRunSeries},
	{"POST", "/api/v1/analyses/runs/{id}/cancel", (*API).cancelRun},
	{"POST", "/api/v1/analyses/runs/{id}/reproduce", (*API).reproduceRun},
	{"POST", "/api/v1/analyses/aggregates", (*API).createAggregate},
	{"GET", "/api/v1/analyses/aggregates", (*API).listAggregates},
	{"GET", "/api/v1/analyses/aggregates/{id}", (*API).getAggregate},
	{"GET", "/api/v1/analyses/runs/{id}/histogram", (*API).getRunHistogram},
	{"GET", "/api/v1/analyses/aggregates/{id}/histogram", (*API).getAggregateHistogram},
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
var Prefixes = []string{"/api/v1/analyses"}

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
// analysis.view or analysis.run at some BU.
func (a *API) anywhere(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	for _, perm := range []authz.Permission{permView, permRun} {
		bus, err := a.Authz.BUsWith(r.Context(), p, perm)
		if err != nil {
			server.WriteAuthzError(w, err)
			return false
		}
		if len(bus) > 0 {
			return true
		}
	}
	problem(w, http.StatusNotFound, "not_found", "", nil)
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

const maxBody = 64 << 10

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object with the documented fields", nil)
		return false
	}
	return true
}

var errNotFound = errors.New("analysisapi: not found")

// Ints reads integer settings (settings.Client).
type Ints interface {
	Int(key, bu string) (int, error)
}

// ClientSettings gives the limits from the service's settings client.
type ClientSettings struct{ C Ints }

// Limits implements Settings.
func (s ClientSettings) Limits(context.Context) (analysis.Limits, error) {
	var l analysis.Limits
	for _, x := range []struct {
		key string
		v   *int
	}{
		{settings.KeySimulationIterationsDefault, &l.IterationsDefault}, {settings.KeySimulationIterationsMin, &l.IterationsMin},
		{settings.KeySimulationIterationsMax, &l.IterationsMax}, {settings.KeySimulationMaxActiveRuns, &l.MaxActive},
	} {
		n, err := s.C.Int(x.key, "")
		if err != nil {
			return l, err
		}
		*x.v = n
	}
	return l, nil
}
