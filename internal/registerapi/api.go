// Package registerapi serves F-007's register API in the risk service
// (design §6; contract api/openapi/register.yaml), behind the gateway like
// the risk API: an internal JWT (audience "risk") and its DB context on
// every request (server.Authenticate), an Idempotency-Key on every mutation
// (server.Idempotent).
//
// T-04 serves risks and categories; T-05 pins, exposure and coverage:
//
//	GET   /api/v1/register/risks                   the risks the caller sees          register.view (RLS)
//	POST  /api/v1/register/risks                   create a risk                       register.edit at the BU
//	GET   /api/v1/register/risks/{id}              a risk with its links
//	PUT   /api/v1/register/risks/{id}              save a version                      register.edit at its BU
//	POST  /api/v1/register/risks/{id}/close        close, with a reason
//	POST  /api/v1/register/risks/{id}/reopen       reopen, with a reason
//	POST  /api/v1/register/risks/{id}/move         move, with a reason                 register.edit at both BUs
//	GET   /api/v1/register/risks/{id}/versions     its versions
//	GET   /api/v1/register/risks/{id}/diff         two versions' differences
//	POST  /api/v1/register/risks/{id}/adopt        adopt newer runs (T-05)            register.edit at its BU
//	GET   /api/v1/register/coverage                open risks by exposure status (T-05)
//	GET   /api/v1/register/categories              the categories                      register.view
//	POST  /api/v1/register/categories              add one                             register.edit at the root
//	PATCH /api/v1/register/categories/{id}         rename, archive or restore one
//
// Without register.view or register.edit anywhere the routes do not exist
// for the caller (404, F-001 AC-25); a risk the caller cannot see is 404
// like a missing one, and one they see but may not change is 403. Every
// change records its events in its transaction (design §8).
package registerapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

const (
	permView authz.Permission = "register.view"
	permEdit authz.Permission = "register.edit"
)

// API serves the register API.
type API struct {
	DB    *pgxpool.Pool // app_rw
	Authz riskapi.Authorizer
	Audit audit.Emitter
	// EnqueueAggregate queues an exposure aggregate's job in the request's
	// transaction (analysis.AggregateEnqueuer); required once pins exist.
	EnqueueAggregate func(context.Context, pgx.Tx, analysis.AggregateArgs) error
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/api/v1/register/risks", (*API).listRisks},
	{"POST", "/api/v1/register/risks", (*API).createRisk},
	{"GET", "/api/v1/register/risks/{id}", (*API).getRisk},
	{"PUT", "/api/v1/register/risks/{id}", (*API).saveRisk},
	{"POST", "/api/v1/register/risks/{id}/close", (*API).closeRisk},
	{"POST", "/api/v1/register/risks/{id}/reopen", (*API).reopenRisk},
	{"POST", "/api/v1/register/risks/{id}/move", (*API).moveRisk},
	{"GET", "/api/v1/register/risks/{id}/versions", (*API).listRiskVersions},
	{"GET", "/api/v1/register/risks/{id}/diff", (*API).diffRisk},
	{"POST", "/api/v1/register/risks/{id}/adopt", (*API).adoptRisk},
	{"GET", "/api/v1/register/coverage", (*API).coverage},
	{"GET", "/api/v1/register/categories", (*API).listCategories},
	{"POST", "/api/v1/register/categories", (*API).createCategory},
	{"PATCH", "/api/v1/register/categories/{id}", (*API).changeCategory},
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
var Prefixes = []string{"/api/v1/register"}

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

var errNotFound = errors.New("registerapi: not found")

// anywhere answers 404 and returns false unless the caller holds
// register.view or register.edit at some BU.
func (a *API) anywhere(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	for _, perm := range []authz.Permission{permView, permEdit} {
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

// mayEdit answers and returns false unless the caller holds register.edit
// at bu (403 for someone who sees the register there, 404 otherwise).
func (a *API) mayEdit(w http.ResponseWriter, r *http.Request, p authz.Principal, bu string) bool {
	err := a.Authz.Check(r.Context(), p, permEdit, bu)
	if err == nil {
		return true
	}
	var su *authz.StepUpError
	if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
		server.WriteAuthzError(w, err)
		return false
	}
	if a.Authz.Check(r.Context(), p, permView, bu) == nil {
		problem(w, http.StatusForbidden, "forbidden", "changing the register needs register.edit at this business unit", nil)
		return false
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

const maxBody = register.MaxDocumentBytes + 64<<10

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object with the documented fields", nil)
		return false
	}
	return true
}

// invalid answers 422 with every problem found in a document.
func invalid(w http.ResponseWriter, problems model.Problems) {
	problem(w, http.StatusUnprocessableEntity, "invalid_document", "", map[string]any{"problems": problems})
}

// problemsOf reads the database's problems ("pointer: message" lines).
func problemsOf(pg *pgconn.PgError) model.Problems {
	var out model.Problems
	for _, line := range strings.Split(pg.Detail, "\n") {
		if ptr, msg, ok := strings.Cut(line, ": "); ok {
			out = append(out, model.Problem{Pointer: ptr, Message: msg})
		}
	}
	if len(out) == 0 {
		out = model.Problems{{Pointer: "/", Message: pg.Message}}
	}
	return out
}

// fail answers a database or audit error.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, errNotFound), errors.As(err, &pg) && pg.Code == "P0002":
		notFound(w)
	case errors.Is(err, authz.ErrNoDBContext):
		problem(w, http.StatusUnauthorized, "unauthenticated", "", nil)
	case errors.As(err, &pg) && pg.Code == "PF026":
		switch pg.Hint {
		case "stale_version":
			problem(w, http.StatusConflict, "stale_version", pg.Message, nil)
		case "scenario_linked":
			// Naming nothing the caller may not see: the scenario is theirs.
			problem(w, http.StatusConflict, "scenario_linked", "a scenario is linked to another open risk", map[string]any{"problems": problemsOf(pg)})
		case "scenario_outside":
			problem(w, http.StatusConflict, "scenario_outside", "a linked scenario would be outside the business unit's subtree", map[string]any{"problems": problemsOf(pg)})
		case "same_bu":
			problem(w, http.StatusConflict, "same_bu", "the risk is in that business unit already", nil)
		case "closed":
			problem(w, http.StatusConflict, "closed", "the risk is closed; reopen it to change it", nil)
		case "duplicate":
			problem(w, http.StatusConflict, "duplicate", "a category of that name is in use", nil)
		default:
			invalid(w, problemsOf(pg))
		}
	case errors.As(err, &pg) && pg.Code == "PF020":
		problem(w, http.StatusConflict, "restricted_move", "the risk is inside a restricted business unit and cannot leave its subtree", nil)
	case errors.As(err, &pg) && pg.Code == "42501":
		problem(w, http.StatusForbidden, "forbidden", "", nil)
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "", nil) // includes an event that could not be recorded
	}
}

// reasonOf checks a reason: 1 to 1,000 characters, nothing secret-looking.
func reasonOf(w http.ResponseWriter, s string) (string, bool) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || len([]rune(s)) > 1000:
		problem(w, http.StatusBadRequest, "invalid_value", "reason is required, at most 1,000 characters", nil)
	case audit.LooksSecret(s):
		problem(w, http.StatusBadRequest, "invalid_value", "reason looks like a secret", nil)
	default:
		return s, true
	}
	return "", false
}

func (a *API) emit(ctx context.Context, e audit.Event) error {
	return a.Audit.Emit(ctx, e)
}
