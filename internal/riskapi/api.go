// Package riskapi serves the risk API (F-003 design §5; contract
// api/openapi/risk.yaml) in the risk service, behind the gateway: every
// request carries an internal JWT (audience "risk") and the DB context it
// was minted with (server.Authenticate), and every mutation an
// Idempotency-Key (server.Idempotent).
//
// T-05 serves scenarios:
//
//	GET  /api/v1/scenarios                          list            scenario.view (BU-scoped)
//	POST /api/v1/scenarios                          create          scenario.edit at the BU
//	GET  /api/v1/scenarios/{id}                     read, with the taxonomy view (AC-28)
//	PUT  /api/v1/scenarios/{id}                     save a version  scenario.edit at its BU
//	GET  /api/v1/scenarios/{id}/versions[/{v}]      history
//	GET  /api/v1/risk/settings                      the installation currency
//
// T-07 adds GET .../{id}/diff?from=&to= (all three; AC-17) and POST
// /api/v1/scenarios/{id}/adopt (re-pin to newer library and control
// versions; AC-10). Pins report the pinned entry's current version and
// whether it is newer.
//
// T-08 adds GET /api/v1/scenarios/{id}/versions/{v}/bundle: the frozen,
// self-contained input of a simulation, with its digest (AC-16).
//
// T-09 adds POST /api/v1/scenarios/{id}/move (scenario.edit at both BUs,
// never out of a restricted subtree; AC-19) and .../{id}/archive and
// /restore for the three kinds (AC-22); scenario pins say whether the
// scenario's BU still reads them (reachable; AC-20).
//
// T-10 adds the starter library: GET /api/v1/library/starter (library.view
// somewhere) and POST /api/v1/library/starter/{key}/copy (library.edit at
// the BU): a copy is an ordinary entry recording its origin (AC-11).
//
// T-11 adds GET /api/v1/risk/export (a fair.risk.v1 file of what the
// requester sees, recorded) and POST /api/v1/risk/imports[?dry_run=true]
// (all or nothing into one BU; AC-24, AC-25).
//
// T-06 serves the library (assets, asset groups, threat communities, loss
// profiles; library.view and library.edit) and controls (control.view and
// control.edit) in the same shape under /api/v1/library and
// /api/v1/controls. Both are shared down the BU tree: a caller also reads,
// marked inherited, the entries of the BUs above theirs (ADR-007 amendment
// 2), and may not change them (403).
//
// Without the view permission anywhere a route does not exist for the
// caller (404, F-001 AC-25); a scenario the caller cannot see is 404 like a
// missing one. A change needs the edit permission at the scenario's BU
// (403 for someone who can see it, 404 otherwise). The database decides
// what is visible (RLS) and re-checks every document (design §4.2).
// Every change is recorded in the audit trail in its own transaction.
package riskapi

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

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Authorizer checks grants (authz.Cache).
type Authorizer interface {
	authz.Checker
	BUsWith(ctx context.Context, p authz.Principal, perm authz.Permission) (map[string]struct{}, error)
}

// API serves the risk API.
type API struct {
	DB    *pgxpool.Pool // app_rw
	Authz Authorizer
	Audit audit.Emitter
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/api/v1/scenarios", (*API).listScenarios},
	{"POST", "/api/v1/scenarios", (*API).createScenario},
	{"GET", "/api/v1/scenarios/{id}", (*API).getScenario},
	{"PUT", "/api/v1/scenarios/{id}", (*API).saveScenario},
	{"GET", "/api/v1/scenarios/{id}/versions", (*API).listScenarioVersions},
	{"GET", "/api/v1/scenarios/{id}/versions/{version}", (*API).getScenarioVersion},
	{"GET", "/api/v1/scenarios/{id}/diff", (*API).diffScenario},
	{"GET", "/api/v1/scenarios/{id}/versions/{version}/bundle", (*API).getScenarioBundle},
	{"POST", "/api/v1/scenarios/{id}/adopt", (*API).adoptScenarioPins},
	{"POST", "/api/v1/scenarios/{id}/move", (*API).moveScenario},
	{"POST", "/api/v1/scenarios/{id}/archive", (*API).archiveScenario},
	{"POST", "/api/v1/scenarios/{id}/restore", (*API).restoreScenario},
	{"GET", "/api/v1/library", (*API).listLibrary},
	{"GET", "/api/v1/library/starter", (*API).listStarterEntries},
	{"POST", "/api/v1/library/starter/{key}/copy", (*API).copyStarterEntry},
	{"POST", "/api/v1/library", (*API).createLibraryEntry},
	{"GET", "/api/v1/library/{id}", (*API).getLibraryEntry},
	{"PUT", "/api/v1/library/{id}", (*API).saveLibraryEntry},
	{"GET", "/api/v1/library/{id}/versions", (*API).listLibraryVersions},
	{"GET", "/api/v1/library/{id}/versions/{version}", (*API).getLibraryVersion},
	{"GET", "/api/v1/library/{id}/diff", (*API).diffLibraryEntry},
	{"POST", "/api/v1/library/{id}/archive", (*API).archiveLibraryEntry},
	{"POST", "/api/v1/library/{id}/restore", (*API).restoreLibraryEntry},
	{"GET", "/api/v1/controls", (*API).listControls},
	{"POST", "/api/v1/controls", (*API).createControl},
	{"GET", "/api/v1/controls/{id}", (*API).getControl},
	{"PUT", "/api/v1/controls/{id}", (*API).saveControl},
	{"GET", "/api/v1/controls/{id}/versions", (*API).listControlVersions},
	{"GET", "/api/v1/controls/{id}/versions/{version}", (*API).getControlVersion},
	{"GET", "/api/v1/controls/{id}/diff", (*API).diffControl},
	{"POST", "/api/v1/controls/{id}/archive", (*API).archiveControl},
	{"POST", "/api/v1/controls/{id}/restore", (*API).restoreControl},
	{"GET", "/api/v1/risk/settings", (*API).getSettings},
	{"GET", "/api/v1/risk/export", (*API).exportRisk},
	{"POST", "/api/v1/risk/imports", (*API).importRisk},
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
var Prefixes = []string{"/api/v1/scenarios", "/api/v1/library", "/api/v1/controls", "/api/v1/risk"}

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
	return server.Authenticate(kp, "risk", now)(server.Idempotent(IdempotencyStore{DB: a.DB})(mux))
}

// --- permissions -------------------------------------------------------------

// viewAnywhere answers 404 and returns false unless the caller holds perm
// at some BU: without it the API does not exist for them (F-001 AC-25).
func (a *API) viewAnywhere(w http.ResponseWriter, r *http.Request, p authz.Principal, perms ...authz.Permission) bool {
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
	notFound(w)
	return false
}

// editAt answers and returns false unless the caller holds edit at bu: 403
// for someone who sees what they would change (seen), 404 for anyone else.
func (a *API) editAt(w http.ResponseWriter, r *http.Request, p authz.Principal, edit authz.Permission, bu string, seen bool) bool {
	err := a.Authz.Check(r.Context(), p, edit, bu)
	if err == nil {
		return true
	}
	var su *authz.StepUpError
	if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
		server.WriteAuthzError(w, err)
		return false
	}
	if seen {
		problem(w, http.StatusForbidden, "forbidden", "the change needs "+string(edit)+" at this business unit", nil)
		return false
	}
	notFound(w)
	return false
}

// --- helpers -------------------------------------------------------------------

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var errNotFound = errors.New("riskapi: not found")

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

// maxBody bounds a request body: a document (1 MiB) and its envelope.
const maxBody = model.MaxDocumentBytes + 64<<10

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

// fail answers a database or audit error.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, errNotFound), errors.As(err, &pg) && pg.Code == "P0002":
		notFound(w)
	case errors.Is(err, authz.ErrNoDBContext):
		problem(w, http.StatusUnauthorized, "unauthenticated", "", nil)
	case errors.As(err, &pg) && pg.Code == "PF016":
		// The database refused the document or a pin (design §4.2).
		var problems model.Problems
		for _, line := range strings.Split(pg.Detail, "\n") {
			if ptr, msg, ok := strings.Cut(line, ": "); ok {
				problems = append(problems, model.Problem{Pointer: ptr, Message: msg})
			}
		}
		if len(problems) == 0 {
			problems = model.Problems{{Pointer: "", Message: pg.Message}}
		}
		invalid(w, problems)
	case errors.As(err, &pg) && pg.Code == "PF020":
		problem(w, http.StatusConflict, "restricted_move", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF017":
		problem(w, http.StatusConflict, "stale_version", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "42501":
		problem(w, http.StatusForbidden, "forbidden", "", nil)
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "", nil) // includes an event that could not be recorded
	}
}
