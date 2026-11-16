// Package acceptanceapi serves F-008's acceptance API in the risk service
// (design §6; contract api/openapi/acceptance.yaml), behind the gateway like
// the register API: an internal JWT (audience "risk") and its DB context on
// every request (server.Authenticate), an Idempotency-Key on every mutation
// (server.Idempotent).
//
//	GET  /api/v1/acceptances                  the acceptances the caller sees     acceptance.view (RLS)
//	POST /api/v1/acceptances                  request (or renew)                   acceptance.request at the risk's BU
//	GET  /api/v1/acceptances/inbox            those the caller may decide          acceptance.approve
//	GET  /api/v1/acceptances/tiers            the tiers in force
//	GET  /api/v1/acceptances/{id}             one, with its history and evidence
//	POST /api/v1/acceptances/{id}/decisions   approve or reject                    acceptance.approve at the tier's BU
//	POST /api/v1/acceptances/{id}/withdraw    the requester, while pending
//	POST /api/v1/acceptances/{id}/revoke      an approver, while active or suspended
//
// Without an acceptance permission anywhere the routes do not exist for the
// caller (404, F-001 AC-25). The database's functions check every change
// and record its events in the change's transaction (design §5, §8).
package acceptanceapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/acceptance"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

const (
	permView    authz.Permission = "acceptance.view"
	permRequest authz.Permission = "acceptance.request"
	permApprove authz.Permission = "acceptance.approve"
)

// Limits reads the acceptance settings in force.
type Limits interface {
	Limits() (acceptance.Limits, error)
}

// API serves the acceptance API.
type API struct {
	DB       *pgxpool.Pool // app_rw
	Authz    riskapi.Authorizer
	Settings Limits
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/api/v1/acceptances", (*API).listAcceptances},
	{"POST", "/api/v1/acceptances", (*API).requestAcceptance},
	{"GET", "/api/v1/acceptances/inbox", (*API).inbox},
	{"GET", "/api/v1/acceptances/tiers", (*API).tiers},
	{"GET", "/api/v1/acceptances/{id}", (*API).getAcceptance},
	{"POST", "/api/v1/acceptances/{id}/decisions", (*API).decideAcceptance},
	{"POST", "/api/v1/acceptances/{id}/withdraw", (*API).withdrawAcceptance},
	{"POST", "/api/v1/acceptances/{id}/revoke", (*API).revokeAcceptance},
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
var Prefixes = []string{"/api/v1/acceptances"}

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

var errNotFound = errors.New("acceptanceapi: not found")

// anywhere answers 404 and returns false unless the caller holds an
// acceptance permission at some BU.
func (a *API) anywhere(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	for _, perm := range []authz.Permission{permView, permRequest, permApprove} {
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

// conflicts are the refusals (PF027 hints) answered 409.
var conflicts = map[string]bool{"exposure_not_current": true, "not_accept": true, "pending_exists": true, "already_accepted": true,
	"already_decided": true, "not_pending": true, "not_active": true, "not_renewable": true, "risk_closed": true}

// fail answers a database error.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, errNotFound), errors.As(err, &pg) && pg.Code == "P0002":
		notFound(w)
	case errors.Is(err, authz.ErrNoDBContext), errors.As(err, &pg) && pg.Code == "PF027" && pg.Hint == "no_context":
		problem(w, http.StatusUnauthorized, "unauthenticated", "", nil)
	case errors.As(err, &pg) && pg.Code == "PF027" && conflicts[pg.Hint]:
		problem(w, http.StatusConflict, pg.Hint, pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF027" && (pg.Hint == "invalid_request" || pg.Hint == "invalid_expiry"):
		var problems []map[string]string
		for _, line := range strings.Split(pg.Detail, "\n") {
			if ptr, msg, ok := strings.Cut(line, ": "); ok {
				problems = append(problems, map[string]string{"pointer": ptr, "message": msg})
			}
		}
		problem(w, http.StatusUnprocessableEntity, pg.Hint, pg.Message, map[string]any{"problems": problems})
	case errors.As(err, &pg) && pg.Code == "42501":
		code := pg.Hint
		if code == "" {
			code = "forbidden"
		}
		problem(w, http.StatusForbidden, code, pg.Message, nil)
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "", nil) // includes an event that could not be recorded
	}
}

// reasonOf checks a reason: 1 to 1,000 characters.
func reasonOf(w http.ResponseWriter, s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > 1000 {
		problem(w, http.StatusBadRequest, "invalid_value", "reason is required, at most 1,000 characters", nil)
		return "", false
	}
	return s, true
}
