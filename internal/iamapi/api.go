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
// otherwise, listing them). T-19 adds the system-use banner:
//
//	GET    /api/v1/banner                      read            any session
//	PUT    /api/v1/banner                      change          banner.manage
//
// T-23b adds user administration:
//
//	GET    /api/v1/users, /api/v1/users/{id}   read            user.view (BU-scoped)
//	POST   /api/v1/users/{id}/{action}         disable, enable, unlock   user.manage
//	GET    /api/v1/groups, /api/v1/groups/{id} read            user.view (BU-scoped)
//
// T-24 adds group-to-role mappings:
//
//	GET    /api/v1/group-mappings[/{id}]       read            access.view (BU-scoped)
//	POST   /api/v1/group-mappings              create          access.map_groups at the BU
//	DELETE /api/v1/group-mappings/{id}         remove          access.map_groups at the BU
//
// T-27 adds separation of duties and the approvals engine over HTTP:
//
//	GET    /api/v1/sod-rules, sod-exceptions   read            role.view
//	POST   /api/v1/sod-rules, PATCH .../{id}   add, enable, disable   sod.manage
//	POST   /api/v1/sod-exceptions              request (202)   role.manage
//	POST   /api/v1/sod-exceptions/apply        apply approved  role.manage
//	DELETE /api/v1/sod-exceptions/{id}         revoke          sod.manage
//	GET    /api/v1/approvals[/{id}]            requests made or decidable
//	POST   /api/v1/approvals/{id}/decision     approve, reject (T-26 rules)
//
// T-28 adds custom roles:
//
//	GET    /api/v1/permissions, /roles[/{id}], /roles/{id}/versions, /roles/{id}/diff   role.view
//	POST   /api/v1/roles, /roles/{id}/clone, /roles/{id}/retire; PUT /roles/{id}         role.manage
//
// T-29 adds catalog notices and role export/import:
//
//	GET    /api/v1/permissions/notices, /api/v1/roles/export                            role.view
//	POST   /api/v1/permissions/notices/acknowledge, /api/v1/roles/import[?dry_run]      role.manage
//
// T-30 adds restricted BU administration:
//
//	GET    /api/v1/bus[/{id}]                                          bu.view
//	POST   /api/v1/bus/{id}/restriction, PUT /api/v1/bus/{id}/rollup-mode, POST /api/v1/bus/apply
//	GET    /api/v1/bus/export[?format=csv], POST /api/v1/bus/import[?dry_run=true]  bu.manage
//	                                                                   bu.restrict at the parent
//
// T-33 adds service accounts (service_account.manage at the account's BU):
//
//	GET    /api/v1/service-accounts[/{id}]                             list, read
//	POST   /api/v1/service-accounts, PATCH /api/v1/service-accounts/{id}   create, rename, scopes (202 when approval is needed)
//	POST   /api/v1/service-accounts/apply                              apply an approved scope request
//	POST   /api/v1/service-accounts/{id}/{disable|enable}
//	GET|POST /api/v1/service-accounts/{id}/tokens, DELETE .../tokens/{id}              client secrets (shown once)
//	GET|POST /api/v1/service-accounts/{id}/certificates, DELETE .../certificates/{id}  mTLS certificates
//
// T-34 adds break-glass administration (breakglass.manage at the root):
//
//	GET    /api/v1/breakglass                                status and accounts
//	POST   /api/v1/breakglass/enable                         ask to enable (202, a breakglass.enable approval)
//	POST   /api/v1/breakglass/apply                          enable once approved; enrollment codes, shown once
//	POST   /api/v1/breakglass/disable                        at once, no approval; sessions end
//	POST   /api/v1/breakglass/accounts/{id}/enrollment       a new enrollment code (the old keys stop working)
//
// T-38 adds the entitlement report and the restricted-BU access listing:
//
//	GET    /api/v1/entitlements/report[?format=csv|pdf]     entitlement.view (+ entitlement.export for files)
//	GET    /api/v1/entitlements/restricted[?format=csv|pdf]
//
// T-39 adds access review campaigns (access_review.manage to open and close,
// access_review.decide to certify or revoke):
//
//	GET|POST /api/v1/access-reviews, GET /api/v1/access-reviews/{id}, POST .../{id}/close
//	POST   /api/v1/access-reviews/{id}/items/{item}/decision
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
	// TokenPepper keys the HMAC of service-account client secrets (T-33;
	// FAIR_TOKEN_PEPPER_FILE, shared with the gateway).
	TokenPepper []byte
	Dev         bool // development: http endpoints accepted

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
	{"GET", "/api/v1/banner", (*API).getBanner},
	{"PUT", "/api/v1/banner", (*API).setBanner},
	{"GET", "/api/v1/idps/{id}/scim-tokens", (*API).listSCIMTokens},
	{"POST", "/api/v1/idps/{id}/scim-tokens", (*API).createSCIMToken},
	{"DELETE", "/api/v1/idps/{id}/scim-tokens/{token}", (*API).revokeSCIMToken},
	{"GET", "/api/v1/users", (*API).listUsers},
	{"GET", "/api/v1/users/{id}", (*API).getUser},
	{"POST", "/api/v1/users/{id}/{action}", (*API).userAction},
	{"GET", "/api/v1/groups", (*API).listGroups},
	{"GET", "/api/v1/groups/{id}", (*API).getGroup},
	{"GET", "/api/v1/group-mappings", (*API).listMappings},
	{"POST", "/api/v1/group-mappings", (*API).createMapping},
	{"GET", "/api/v1/group-mappings/{id}", (*API).getMapping},
	{"DELETE", "/api/v1/group-mappings/{id}", (*API).removeMapping},
	{"GET", "/api/v1/sod-rules", (*API).listSoDRules},
	{"POST", "/api/v1/sod-rules", (*API).createSoDRule},
	{"PATCH", "/api/v1/sod-rules/{id}", (*API).updateSoDRule},
	{"GET", "/api/v1/sod-exceptions", (*API).listSoDExceptions},
	{"POST", "/api/v1/sod-exceptions", (*API).requestSoDException},
	{"POST", "/api/v1/sod-exceptions/apply", (*API).applySoDException},
	{"DELETE", "/api/v1/sod-exceptions/{id}", (*API).revokeSoDException},
	{"GET", "/api/v1/approvals", (*API).listApprovals},
	{"GET", "/api/v1/approvals/{id}", (*API).getApproval},
	{"POST", "/api/v1/approvals/{id}/decision", (*API).decideApproval},
	{"GET", "/api/v1/permissions", (*API).listPermissions},
	{"GET", "/api/v1/roles", (*API).listRoles},
	{"POST", "/api/v1/roles", (*API).createRole},
	{"GET", "/api/v1/roles/{id}", (*API).getRole},
	{"PUT", "/api/v1/roles/{id}", (*API).updateRole},
	{"GET", "/api/v1/roles/{id}/versions", (*API).roleVersions},
	{"GET", "/api/v1/roles/{id}/diff", (*API).roleDiff},
	{"POST", "/api/v1/roles/{id}/clone", (*API).cloneRole},
	{"POST", "/api/v1/roles/{id}/retire", (*API).retireRole},
	{"GET", "/api/v1/permissions/notices", (*API).listCatalogNotices},
	{"POST", "/api/v1/permissions/notices/acknowledge", (*API).acknowledgeCatalogNotices},
	{"GET", "/api/v1/roles/export", (*API).exportRoles},
	{"POST", "/api/v1/roles/import", (*API).importRoles},
	{"GET", "/api/v1/bus", (*API).listBUs},
	{"GET", "/api/v1/bus/{id}", (*API).getBU},
	{"POST", "/api/v1/bus/{id}/restriction", (*API).setRestriction},
	{"PUT", "/api/v1/bus/{id}/rollup-mode", (*API).setRollupMode},
	{"POST", "/api/v1/bus/apply", (*API).applyBUApproval},
	{"GET", "/api/v1/bus/export", (*API).exportBUs},
	{"POST", "/api/v1/bus/import", (*API).importBUs},
	{"GET", "/api/v1/service-accounts", (*API).listServiceAccounts},
	{"POST", "/api/v1/service-accounts", (*API).createServiceAccount},
	{"POST", "/api/v1/service-accounts/apply", (*API).applyServiceAccount},
	{"GET", "/api/v1/service-accounts/{id}", (*API).getServiceAccount},
	{"PATCH", "/api/v1/service-accounts/{id}", (*API).updateServiceAccount},
	{"POST", "/api/v1/service-accounts/{id}/{action}", (*API).serviceAccountAction},
	{"GET", "/api/v1/service-accounts/{id}/tokens", (*API).listSASecrets},
	{"POST", "/api/v1/service-accounts/{id}/tokens", (*API).createSASecret},
	{"DELETE", "/api/v1/service-accounts/{id}/tokens/{credential}", (*API).revokeSACredential},
	{"GET", "/api/v1/service-accounts/{id}/certificates", (*API).listSACertificates},
	{"POST", "/api/v1/service-accounts/{id}/certificates", (*API).addSACertificate},
	{"DELETE", "/api/v1/service-accounts/{id}/certificates/{credential}", (*API).revokeSACredential},
	{"GET", "/api/v1/breakglass", (*API).getBreakglass},
	{"POST", "/api/v1/breakglass/enable", (*API).enableBreakglass},
	{"POST", "/api/v1/breakglass/apply", (*API).applyBreakglass},
	{"POST", "/api/v1/breakglass/disable", (*API).disableBreakglass},
	{"POST", "/api/v1/breakglass/accounts/{id}/enrollment", (*API).newBreakglassCode},
	{"GET", "/api/v1/entitlements/report", (*API).entitlementReport},
	{"GET", "/api/v1/entitlements/restricted", (*API).restrictedListing},
	{"GET", "/api/v1/access-reviews", (*API).listReviews},
	{"POST", "/api/v1/access-reviews", (*API).openReview},
	{"GET", "/api/v1/access-reviews/{id}", (*API).getReview},
	{"POST", "/api/v1/access-reviews/{id}/close", (*API).closeReview},
	{"POST", "/api/v1/access-reviews/{id}/items/{item}/decision", (*API).decideReviewItem},
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
var Prefixes = []string{"/api/v1/idps", "/api/v1/banner", "/api/v1/users", "/api/v1/groups", "/api/v1/group-mappings", "/api/v1/sod-rules", "/api/v1/sod-exceptions", "/api/v1/approvals", "/api/v1/permissions", "/api/v1/roles", "/api/v1/bus", "/api/v1/service-accounts", "/api/v1/breakglass", "/api/v1/entitlements", "/api/v1/access-reviews"}

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
	case errors.As(err, &pg) && pg.Code == "23503":
		problem(w, http.StatusBadRequest, "invalid_value", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "PF010":
		problem(w, http.StatusConflict, "stale_version", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "23505":
		problem(w, http.StatusConflict, "duplicate", "it exists already", nil)
	case errors.As(err, &pg) && (pg.Code == "AP002" || pg.Code == "AP003"):
		problem(w, http.StatusForbidden, "forbidden", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "AP004":
		problem(w, http.StatusConflict, "not_applicable", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "AP005":
		problem(w, http.StatusBadRequest, "invalid_value", pg.Message, nil)
	case errors.As(err, &pg) && pg.Code == "P0002", errors.Is(err, errNotFound):
		problem(w, http.StatusNotFound, "not_found", "", nil)
	default:
		problem(w, http.StatusInternalServerError, "internal", "", nil)
	}
}
