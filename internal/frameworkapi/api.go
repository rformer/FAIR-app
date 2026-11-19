// Package frameworkapi serves F-013's framework API in the risk service
// (design §6; contract api/openapi/framework.yaml), behind the gateway: an
// internal JWT (audience "risk") and its DB context on every request, an
// Idempotency-Key on every mutation.
//
//	GET  /api/v1/frameworks                               families and their versions
//	GET  /api/v1/frameworks/versions/{id}                 a version, its baselines and what changed
//	GET  /api/v1/frameworks/versions/{id}/requirements    its requirements (?q=, ?parent=, paged)
//	GET  /api/v1/frameworks/versions/{id}/diff            what changed since the family's previous version
//	POST /api/v1/frameworks/versions/{id}/retire          retire it (a reason)
//	GET  /api/v1/frameworks/requirements/{id}             a requirement, its children and baselines
//	GET  /api/v1/frameworks/baselines[/{id}]              baselines
//	POST /api/v1/frameworks/baselines/{id}/retire         retire one (a reason)
//	POST /api/v1/frameworks/imports                       upload a catalog, profile or simple framework (?dry_run=true)
//	GET  /api/v1/frameworks/imports/{id}                  an import's outcome
//
// The database decides who may: readers hold framework.view, control.view
// or control.edit somewhere (404 otherwise); imports and retirements need
// framework.manage at the top business unit (403 for readers).
package frameworkapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/framework"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// API serves the framework API.
type API struct {
	DB *pgxpool.Pool // app_rw
	// Enqueue queues an import's job in the request's transaction; nil
	// answers imports 503.
	Enqueue func(context.Context, pgx.Tx, ImportArgs) error
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/api/v1/frameworks", (*API).listFrameworks},
	{"GET", "/api/v1/frameworks/versions/{id}", (*API).getVersion},
	{"GET", "/api/v1/frameworks/versions/{id}/requirements", (*API).listRequirements},
	{"GET", "/api/v1/frameworks/versions/{id}/diff", (*API).getVersionDiff},
	{"POST", "/api/v1/frameworks/versions/{id}/retire", (*API).retireVersion},
	{"GET", "/api/v1/frameworks/requirements/{id}", (*API).getRequirement},
	{"GET", "/api/v1/frameworks/baselines", (*API).listBaselines},
	{"GET", "/api/v1/frameworks/baselines/{id}", (*API).getBaseline},
	{"POST", "/api/v1/frameworks/baselines/{id}/retire", (*API).retireBaseline},
	{"POST", "/api/v1/frameworks/imports", (*API).requestImport},
	{"GET", "/api/v1/frameworks/imports/{id}", (*API).getImport},
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
var Prefixes = []string{"/api/v1/frameworks"}

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
	// Imports take files up to framework.MaxFile (the rest of the request
	// is small).
	return server.Authenticate(kp, "risk", now)(server.IdempotentLimit(riskapi.IdempotencyStore{DB: a.DB}, framework.MaxFile+64<<10)(mux))
}

var (
	uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

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

func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, authz.ErrNoDBContext):
		problem(w, http.StatusUnauthorized, "unauthenticated", "")
	case !errors.As(err, &pg):
		problem(w, http.StatusServiceUnavailable, "unavailable", "")
	case pg.Code == "P0002":
		problem(w, http.StatusNotFound, "not_found", "")
	case pg.Code == "42501":
		problem(w, http.StatusForbidden, "forbidden", "framework.manage at the top business unit is needed")
	case pg.Code == "PF034":
		problem(w, http.StatusConflict, "limit_exceeded", pg.Message)
	case pg.Code == "PF033" && pg.Hint == "no_context":
		problem(w, http.StatusUnauthorized, "unauthenticated", "")
	case pg.Code == "PF033" && (pg.Hint == "reason_required" || pg.Hint == "invalid_value"):
		problem(w, http.StatusBadRequest, pg.Hint, pg.Message)
	case pg.Code == "PF033" && pg.Hint == "retired":
		problem(w, http.StatusConflict, "retired", pg.Message)
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "")
	}
}

func (a *API) one(r *http.Request, p authz.Principal, sql string, args ...any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), sql, args...).Scan(&raw)
	})
	return raw, err
}

func id(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := r.PathValue("id")
	if !uuidRE.MatchString(v) {
		problem(w, http.StatusNotFound, "not_found", "")
		return "", false
	}
	return v, true
}

func boolParam(w http.ResponseWriter, r *http.Request, name string) (bool, bool) {
	switch v := r.URL.Query().Get(name); v {
	case "", "false":
		return false, true
	case "true":
		return true, true
	default:
		problem(w, http.StatusBadRequest, "invalid_value", name+" is true or false")
		return false, false
	}
}

func (a *API) listFrameworks(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	retired, ok := boolParam(w, r, "retired")
	if !ok {
		return
	}
	raw, err := a.one(r, p, "SELECT framework.families($1)", retired)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"frameworks": raw})
}

func (a *API) getVersion(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if v, ok := id(w, r); ok {
		a.answer(w, r, p, "SELECT framework.version_get($1)", v)
	}
}

func (a *API) getVersionDiff(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if v, ok := id(w, r); ok {
		a.answer(w, r, p, "SELECT framework.version_diff($1)", v)
	}
}

func (a *API) getRequirement(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if v, ok := id(w, r); ok {
		a.answer(w, r, p, "SELECT framework.requirement_get($1)", v)
	}
}

func (a *API) getBaseline(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if v, ok := id(w, r); ok {
		a.answer(w, r, p, "SELECT framework.baseline_get($1)", v)
	}
}

func (a *API) getImport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if v, ok := id(w, r); ok {
		a.answer(w, r, p, "SELECT framework.import_get($1)", v)
	}
}

func (a *API) answer(w http.ResponseWriter, r *http.Request, p authz.Principal, sql string, args ...any) {
	raw, err := a.one(r, p, sql, args...)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

// listRequirements answers ?q= (identifier, label, title or statement),
// ?parent= (an identifier; empty for top-level), ?limit= 1 to 500 (100),
// ?offset=; more says whether more remain.
func (a *API) listRequirements(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	v, ok := id(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, offset := 100, 0
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 500 {
			problem(w, http.StatusBadRequest, "invalid_value", "limit is 1 to 500")
			return
		}
		limit = n
	}
	if s := q.Get("offset"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			problem(w, http.StatusBadRequest, "invalid_value", "offset is 0 or more")
			return
		}
		offset = n
	}
	var parent any
	if q.Has("parent") {
		parent = q.Get("parent")
	}
	var search any
	if s := strings.TrimSpace(q.Get("q")); s != "" {
		if len(s) > 200 {
			problem(w, http.StatusBadRequest, "invalid_value", "q is at most 200 characters")
			return
		}
		search = s
	}
	raw, err := a.one(r, p, "SELECT framework.requirements($1, $2, $3, $4, $5)", v, search, parent, limit+1, offset)
	if err != nil {
		fail(w, err)
		return
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		fail(w, err)
		return
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"requirements": items, "more": more})
}

func (a *API) listBaselines(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	retired, ok := boolParam(w, r, "retired")
	if !ok {
		return
	}
	var version any
	if v := r.URL.Query().Get("version"); v != "" {
		if !uuidRE.MatchString(v) {
			problem(w, http.StatusBadRequest, "invalid_value", "version is a framework version's id")
			return
		}
		version = v
	}
	raw, err := a.one(r, p, "SELECT framework.baselines($1::uuid, $2)", version, retired)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"baselines": raw})
}

type reasonBody struct {
	Reason string `json:"reason"`
}

func decodeReason(w http.ResponseWriter, r *http.Request) (string, bool) {
	var b reasonBody
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body is {\"reason\": ...}")
		return "", false
	}
	return b.Reason, true
}

func (a *API) retireVersion(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	v, ok := id(w, r)
	if !ok {
		return
	}
	if reason, ok := decodeReason(w, r); ok {
		a.answer(w, r, p, "SELECT framework.retire_version($1, $2)", v, reason)
	}
}

func (a *API) retireBaseline(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	v, ok := id(w, r)
	if !ok {
		return
	}
	if reason, ok := decodeReason(w, r); ok {
		a.answer(w, r, p, "SELECT framework.retire_baseline($1, $2)", v, reason)
	}
}

// requestImport takes the file as the body (an OSCAL catalog or profile,
// fair.framework.v1 JSON, or CSV), with ?kind=catalog|profile|simple and
// what the file cannot say: ?family=, ?family_title=, ?publisher= (a
// catalog, a CSV file), ?label=, ?title=, ?published= (a CSV file),
// ?catalog_family= and ?catalog_version= and ?key= (a profile), and
// ?dry_run=true. 202 with the import; GET it for the outcome.
func (a *API) requestImport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if a.Enqueue == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "framework imports are not configured")
		return
	}
	q := r.URL.Query()
	dry, ok := boolParam(w, r, "dry_run")
	if !ok {
		return
	}
	kind := q.Get("kind")
	meta := Meta{}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	switch ct {
	case "application/json", "application/oscal+json":
		meta.Format = "json"
	case "text/csv":
		meta.Format = "csv"
	default:
		problem(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "an import is application/json or text/csv")
		return
	}
	switch kind {
	case "catalog", "simple":
		if kind == "catalog" && meta.Format != "json" {
			problem(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "an OSCAL catalog is JSON")
			return
		}
		if kind == "catalog" || meta.Format == "csv" {
			fam := framework.Family{Key: q.Get("family"), Title: q.Get("family_title"), Publisher: q.Get("publisher")}
			if !keyRE.MatchString(fam.Key) || strings.TrimSpace(fam.Title) == "" {
				problem(w, http.StatusBadRequest, "invalid_value", "family (lower-case letters, digits and hyphens) and family_title name the framework")
				return
			}
			meta.Family = &fam
		}
		if meta.Format == "csv" {
			meta.Label, meta.Title, meta.Published = q.Get("label"), q.Get("title"), q.Get("published")
		}
	case "profile":
		if meta.Format != "json" {
			problem(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "an OSCAL profile is JSON")
			return
		}
		meta.Catalog = &framework.Ref{Family: q.Get("catalog_family"), Version: q.Get("catalog_version")}
		meta.Key = q.Get("key")
		if !keyRE.MatchString(meta.Catalog.Family) || meta.Catalog.Version == "" || !keyRE.MatchString(meta.Key) {
			problem(w, http.StatusBadRequest, "invalid_value", "catalog_family, catalog_version and key (lower-case letters, digits and hyphens) are required")
			return
		}
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "kind is catalog, profile or simple (crosswalks: kind crosswalk)")
		return
	}
	file, err := io.ReadAll(io.LimitReader(r.Body, framework.MaxFile+1))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the file could not be read")
		return
	}
	if len(file) > framework.MaxFile {
		problem(w, http.StatusRequestEntityTooLarge, "too_large", "a file is at most 50 MiB")
		return
	}
	if len(file) == 0 {
		problem(w, http.StatusBadRequest, "invalid_request", "the body is the file to import")
		return
	}
	sum := sha256.Sum256(file)
	mj, _ := json.Marshal(meta)
	var raw json.RawMessage
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var iid string
		if err := tx.QueryRow(r.Context(), "SELECT framework.request_import($1, $2, $3, $4::jsonb, $5)::text", kind, hex.EncodeToString(sum[:]), file,
			string(mj), dry).Scan(&iid); err != nil {
			return err
		}
		if err := a.Enqueue(r.Context(), tx, ImportArgs{ImportID: iid}); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), "SELECT framework.import_get($1)", iid).Scan(&raw)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, raw)
}
