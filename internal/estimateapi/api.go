// Package estimateapi serves F-004's estimate API in the risk service
// (design §5; contract api/openapi/estimate.yaml), behind the gateway like
// the risk API: an internal JWT (audience "risk") and its DB context on
// every request (server.Authenticate), an Idempotency-Key on every mutation
// (server.Idempotent) but those declared exempt.
//
// T-05 serves the estimating aids:
//
//	POST /api/v1/estimates/warnings   warnings, the equivalent bet and a preview for an estimate
//
// Without a permission that enters estimates anywhere (estimate.submit,
// scenario.edit, library.edit or control.edit) the routes do not exist for
// the caller (404, F-001 AC-25).
package estimateapi

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/estimate"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// API serves the estimate API.
type API struct {
	DB    *pgxpool.Pool // app_rw
	Authz riskapi.Authorizer
	Audit audit.Emitter
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
	// exempt routes change nothing, so they need no Idempotency-Key
	// (x-idempotency-exempt in the contract).
	exempt bool
}

var routes = []route{
	{"POST", "/api/v1/estimates/warnings", (*API).checkEstimate, true},
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
var Prefixes = []string{"/api/v1/estimates"}

// Handler returns the API with authentication, and idempotency in front of
// every route that is not exempt.
func (a *API) Handler(kp authz.KeyProvider, now func() time.Time) http.Handler {
	exempt, checked := http.NewServeMux(), http.NewServeMux()
	for _, rt := range routes {
		h := rt.h
		mux := checked
		if rt.exempt {
			mux = exempt
		}
		mux.HandleFunc(rt.method+" "+rt.path, func(w http.ResponseWriter, r *http.Request) {
			p, _ := server.PrincipalFrom(r.Context())
			h(a, w, r, p)
		})
	}
	idem := server.Idempotent(riskapi.IdempotencyStore{DB: a.DB})(checked)
	both := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := exempt.Handler(r); pattern != "" {
			exempt.ServeHTTP(w, r)
			return
		}
		idem.ServeHTTP(w, r)
	})
	return server.Authenticate(kp, "risk", now)(both)
}

// entersEstimates are the permissions of people who enter estimates.
var entersEstimates = []authz.Permission{"estimate.submit", "scenario.edit", "library.edit", "control.edit"}

// anywhere answers 404 and returns false unless the caller holds one of
// perms at some BU.
func (a *API) anywhere(w http.ResponseWriter, r *http.Request, p authz.Principal, perms []authz.Permission) bool {
	for _, perm := range perms {
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

var units = []string{model.UnitEventsPerYear, model.UnitProbability, model.UnitCurrency, model.UnitPercentile, model.UnitFraction}

// checkEstimate gives the estimating aids for an estimate being entered
// (F-004 AC-11, AC-12; design §3.7): warnings, the equivalent bet and an
// illustrative preview. It changes nothing and records nothing.
func (a *API) checkEstimate(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, entersEstimates) {
		return
	}
	var body struct {
		Unit                string         `json:"unit"`
		Estimate            estimate.Range `json:"estimate"`
		RequestedConfidence string         `json:"requested_confidence"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !slices.Contains(units, body.Unit) {
		problem(w, http.StatusBadRequest, "invalid_value", "unit is one of events_per_year, probability, currency, percentile, fraction", nil)
		return
	}
	warnings, err := estimate.Warnings(body.Unit, body.Estimate, body.RequestedConfidence)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_estimate", err.Error(), nil)
		return
	}
	preview, _ := estimate.PreviewOf(body.Estimate, 100)
	if warnings == nil {
		warnings = []estimate.Warning{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"warnings": warnings, "bet": estimate.Bet(body.Estimate), "preview": preview})
}
