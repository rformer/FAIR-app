// Package notifyapi serves F-009's notifications API in the notify service
// (design §6; contract api/openapi/notify.yaml), behind the gateway: an
// internal JWT (audience "notify") and its DB context on every request
// (server.Authenticate), an Idempotency-Key on every mutation
// (server.Idempotent).
//
//	GET  /api/v1/notifications              the caller's notifications, newest first
//	GET  /api/v1/notifications/count        their unread count
//	POST /api/v1/notifications/read         mark some, or all, read
//	GET  /api/v1/notifications/preferences  their mutes and digest
//	PUT  /api/v1/notifications/preferences  change them
//
// Every route is the caller's own: the database's functions take the user
// from the signed context and touch only their rows (design §5). The
// channel routes (T-11) need notification.manage or notification.view.
package notifyapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/telemetry"
)

// API serves the notifications API.
type API struct {
	DB *pgxpool.Pool // app_notify
	// The channel routes (T-11): permissions, the webhook-secrets keys,
	// the guard and the senders (for test messages), the composer.
	Authz    riskapi.Authorizer
	Keys     *notify.Keyring
	Guard    notify.Guard
	Mail     notify.Mailer
	Post     notify.Poster
	Composer func() notify.Composer
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/api/v1/notifications", (*API).listNotifications},
	{"GET", "/api/v1/notifications/count", (*API).unreadCount},
	{"POST", "/api/v1/notifications/read", (*API).markRead},
	{"GET", "/api/v1/notifications/preferences", (*API).getPreferences},
	{"PUT", "/api/v1/notifications/preferences", (*API).setPreferences},
	{"GET", "/api/v1/notifications/channels", (*API).listChannels},
	{"PUT", "/api/v1/notifications/channels/smtp", (*API).putSMTP},
	{"POST", "/api/v1/notifications/channels/webhooks", (*API).createWebhook},
	{"PUT", "/api/v1/notifications/channels/webhooks/{id}", (*API).updateWebhook},
	{"POST", "/api/v1/notifications/channels/webhooks/{id}/rotate-secret", (*API).rotateSecret},
	{"POST", "/api/v1/notifications/channels/{id}/disable", (*API).disableChannel},
	{"POST", "/api/v1/notifications/channels/{id}/enable", (*API).enableChannel},
	{"POST", "/api/v1/notifications/channels/{id}/remove", (*API).removeChannel},
	{"POST", "/api/v1/notifications/channels/{id}/test", (*API).testChannel},
	{"GET", "/api/v1/notifications/deliveries", (*API).listDeliveries},
	{"GET", "/api/v1/notifications/bus", (*API).listBUs},
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
var Prefixes = []string{"/api/v1/notifications"}

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
	return server.Authenticate(kp, "notify", now)(server.Idempotent(riskapi.IdempotencyStore{DB: a.DB})(telemetry.Routed(mux)))
}

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

func pgHint(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "PF028" {
		return pg.Hint
	}
	return ""
}

func errMessage(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Message
	}
	return ""
}

// fail answers a database refusal: PF028 by its hint, else 503.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, authz.ErrNoDBContext), errors.As(err, &pg) && pg.Code == "PF028" && pg.Hint == "no_context":
		problem(w, http.StatusUnauthorized, "unauthenticated", "")
	case errors.As(err, &pg) && pg.Code == "PF028" && pg.Hint == "mandatory":
		problem(w, http.StatusConflict, "mandatory", pg.Message)
	case errors.As(err, &pg) && pg.Code == "PF028" && pg.Hint == "invalid_request":
		problem(w, http.StatusBadRequest, "invalid_request", pg.Message)
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "") // includes an event that could not be recorded
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object with the documented fields")
		return false
	}
	return true
}

// query runs sql under the caller's DB context and scans one value.
func (a *API) query(r *http.Request, p authz.Principal, out any, sql string, args ...any) error {
	return authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), sql, args...).Scan(out)
	})
}

// listNotifications answers ?unread=true, ?before=<id> (older than),
// ?limit= 1 to 200 (50); more says whether older ones remain (AC-02).
func (a *API) listNotifications(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	q := r.URL.Query()
	unread := q.Get("unread") == "true"
	if v := q.Get("unread"); v != "" && v != "true" && v != "false" {
		problem(w, http.StatusBadRequest, "invalid_value", "unread is true or false")
		return
	}
	var before *int64
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			problem(w, http.StatusBadRequest, "invalid_value", "before is a notification id")
			return
		}
		before = &n
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			problem(w, http.StatusBadRequest, "invalid_value", "limit is 1 to 200")
			return
		}
		limit = n
	}
	var raw []byte
	if err := a.query(r, p, &raw, "SELECT notify.my_notifications($1, $2, $3)", unread, before, limit+1); err != nil {
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
	if items == nil {
		items = []json.RawMessage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"notifications": items, "more": more})
}

func (a *API) unreadCount(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var n int
	if err := a.query(r, p, &n, "SELECT notify.unread_count()"); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"unread": n})
}

type readBody struct {
	IDs []int64 `json:"ids"`
	All bool    `json:"all"`
}

func (a *API) markRead(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body readBody
	if !decode(w, r, &body) {
		return
	}
	if body.All == (len(body.IDs) > 0) {
		problem(w, http.StatusBadRequest, "invalid_request", "name ids, or all: true")
		return
	}
	var n int
	if err := a.query(r, p, &n, "SELECT notify.mark_read($1, $2)", body.IDs, body.All); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"marked": n})
}

func (a *API) getPreferences(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var raw json.RawMessage
	if err := a.query(r, p, &raw, "SELECT notify.my_preferences()"); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

type preferencesBody struct {
	Mutes      map[string]bool `json:"mutes"`
	Digest     *bool           `json:"digest"`
	DigestHour *int            `json:"digest_hour"`
}

// setPreferences replaces the caller's mutes (kinds absent are left as
// they are), digest and digest hour (AC-18, AC-19).
func (a *API) setPreferences(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body preferencesBody
	if !decode(w, r, &body) {
		return
	}
	if body.Digest == nil || body.DigestHour == nil {
		problem(w, http.StatusBadRequest, "invalid_request", "digest and digest_hour are required")
		return
	}
	if body.Mutes == nil {
		body.Mutes = map[string]bool{}
	}
	mutes, _ := json.Marshal(body.Mutes)
	var raw json.RawMessage
	if err := a.query(r, p, &raw, "SELECT notify.set_preferences($1::jsonb, $2, $3)", string(mutes), *body.Digest, *body.DigestHour); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}
