package notifyapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-009 T-11 (F-009-AC-08 to AC-12, AC-17; design §3.4, §6): the channel
// routes. notification.manage changes, notification.view reads (both at the
// root, checked by the database); without either anywhere the routes do not
// exist (404). Destinations are checked by the guard, as far as they can be
// without sending: the host must be allowed and must not resolve to a
// refused address.

const (
	permManage authz.Permission = "notification.manage"
	permView   authz.Permission = "notification.view"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// admin answers 404 and false unless the caller holds a notification
// permission somewhere.
func (a *API) admin(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	if a.Authz == nil {
		problem(w, http.StatusNotFound, "not_found", "")
		return false
	}
	for _, perm := range []authz.Permission{permManage, permView} {
		bus, err := a.Authz.BUsWith(r.Context(), p, perm)
		if err != nil {
			server.WriteAuthzError(w, err)
			return false
		}
		if len(bus) > 0 {
			return true
		}
	}
	problem(w, http.StatusNotFound, "not_found", "")
	return false
}

// failChannel answers a channel function's refusal.
func failChannel(w http.ResponseWriter, err error) {
	var pg interface{ SQLState() string }
	if errors.As(err, &pg) {
		switch pg.SQLState() {
		case "42501":
			problem(w, http.StatusForbidden, "forbidden", "notification.manage (or .view) at the top business unit is needed")
			return
		case "P0002":
			problem(w, http.StatusNotFound, "not_found", "")
			return
		}
	}
	if hint := pgHint(err); hint != "" {
		switch hint {
		case "stale_version", "name_taken", "unchanged":
			problem(w, http.StatusConflict, hint, errMessage(err))
			return
		}
	}
	fail(w, err)
}

// channelTx runs sql under the caller's context and scans one JSON value.
func (a *API) channelJSON(r *http.Request, p authz.Principal, sql string, args ...any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), sql, args...).Scan(&raw)
	})
	return raw, err
}

// listChannels answers the relay and webhooks with their state: last
// success and failure, backlog, failures in 24 hours (AC-17).
func (a *API) listChannels(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.admin(w, r, p) {
		return
	}
	raw, err := a.channelJSON(r, p, "SELECT notify.channels()")
	if err != nil {
		failChannel(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": raw})
}

// checkHost runs the guard over host as far as it can without sending.
func (a *API) checkHost(ctx context.Context, w http.ResponseWriter, host string) bool {
	if _, err := a.Guard.Resolve(ctx, host); err != nil {
		code := "destination_unresolved"
		if errors.Is(err, notify.ErrRefused) {
			code = "destination_refused"
		}
		problem(w, http.StatusUnprocessableEntity, code, err.Error())
		return false
	}
	return true
}

type smtpBody struct {
	Config          notify.SMTPConfig `json:"config"`
	ExpectedVersion int               `json:"expected_version"`
	Reason          string            `json:"reason"`
}

// putSMTP configures the relay (AC-08): TLS always, credentials only as a
// password file's name.
func (a *API) putSMTP(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.admin(w, r, p) {
		return
	}
	var body smtpBody
	if !decode(w, r, &body) {
		return
	}
	if err := body.Config.Check(); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_config", err.Error())
		return
	}
	if !a.checkHost(r.Context(), w, body.Config.Host) {
		return
	}
	cfg, _ := json.Marshal(body.Config)
	raw, err := a.channelJSON(r, p, "SELECT notify.put_smtp($1::jsonb, $2, $3)", string(cfg), body.ExpectedVersion, body.Reason)
	if err != nil {
		failChannel(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

type webhookBody struct {
	Name            string   `json:"name"`
	URL             string   `json:"url"`
	BUID            string   `json:"bu_id"`
	Kinds           []string `json:"kinds"`
	ExpectedVersion int      `json:"expected_version"`
	Reason          string   `json:"reason"`
}

// webhookConfig checks a webhook's URL (https, no credentials, no
// fragment) and its host.
func (a *API) webhookConfig(w http.ResponseWriter, r *http.Request, b webhookBody) (string, bool) {
	u, err := url.Parse(b.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(b.URL) > 2000 {
		problem(w, http.StatusUnprocessableEntity, "invalid_config", "url is an https URL without credentials or fragment")
		return "", false
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			problem(w, http.StatusUnprocessableEntity, "invalid_config", "the URL's port is 1 to 65535")
			return "", false
		}
	}
	if !uuidRE.MatchString(b.BUID) {
		problem(w, http.StatusBadRequest, "invalid_request", "bu_id is a business unit id")
		return "", false
	}
	if !a.checkHost(r.Context(), w, u.Hostname()) {
		return "", false
	}
	cfg, _ := json.Marshal(map[string]string{"url": u.String(), "host": strings.ToLower(u.Hostname())})
	return string(cfg), true
}

// createWebhook adds a webhook (AC-09) and answers its secret, this once.
func (a *API) createWebhook(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.admin(w, r, p) {
		return
	}
	if a.Keys == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "webhooks need the webhook-secrets keys (FAIR_NOTIFY_SECRETS_DIR)")
		return
	}
	var body webhookBody
	if !decode(w, r, &body) {
		return
	}
	cfg, ok := a.webhookConfig(w, r, body)
	if !ok {
		return
	}
	secret, err := notify.NewWebhookSecret()
	if err != nil {
		fail(w, err)
		return
	}
	raw, err := a.channelJSON(r, p, "SELECT notify.create_webhook($1, $2::jsonb, $3::uuid, $4, $5, $6)", body.Name, cfg, body.BUID, body.Kinds,
		a.Keys.Seal(secret), body.Reason)
	if err != nil {
		failChannel(w, err)
		return
	}
	a.answerSecret(w, http.StatusCreated, raw, secret)
}

// answerSecret answers the channel with its new secret, once: a replayed
// request is told it was issued and gets no secret (as SCIM tokens).
func (a *API) answerSecret(w http.ResponseWriter, status int, channel json.RawMessage, secret string) {
	var id struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(channel, &id)
	server.SecretResponse(w, http.StatusConflict, map[string]any{"error": "secret_not_replayed", "id": id.ID,
		"detail": "the secret was returned to the first request and is not shown again; rotate it if it was lost"})
	writeJSON(w, status, map[string]any{"channel": channel, "secret": secret})
}

func (a *API) updateWebhook(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.admin(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "")
		return
	}
	var body webhookBody
	if !decode(w, r, &body) {
		return
	}
	cfg, ok := a.webhookConfig(w, r, body)
	if !ok {
		return
	}
	raw, err := a.channelJSON(r, p, "SELECT notify.update_webhook($1, $2, $3::jsonb, $4::uuid, $5, $6, $7)", id, body.Name, cfg, body.BUID, body.Kinds,
		body.ExpectedVersion, body.Reason)
	if err != nil {
		failChannel(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

type reasonBody struct {
	Reason string `json:"reason"`
}

func (a *API) disableChannel(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setChannel(w, r, p, "disable")
}

func (a *API) enableChannel(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setChannel(w, r, p, "enable")
}

func (a *API) removeChannel(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setChannel(w, r, p, "remove")
}

func (a *API) setChannel(w http.ResponseWriter, r *http.Request, p authz.Principal, action string) {
	if !a.admin(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "")
		return
	}
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	raw, err := a.channelJSON(r, p, "SELECT notify.set_channel($1, $2, $3)", id, action, body.Reason)
	if err != nil {
		failChannel(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

// rotateSecret gives a webhook a new secret (answered once); the previous
// one still signs for 24 hours (OQ1).
func (a *API) rotateSecret(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.admin(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "")
		return
	}
	if a.Keys == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "webhooks need the webhook-secrets keys (FAIR_NOTIFY_SECRETS_DIR)")
		return
	}
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	secret, err := notify.NewWebhookSecret()
	if err != nil {
		fail(w, err)
		return
	}
	raw, err := a.channelJSON(r, p, "SELECT notify.rotate_secret($1, $2, $3)", id, a.Keys.Seal(secret), body.Reason)
	if err != nil {
		failChannel(w, err)
		return
	}
	a.answerSecret(w, http.StatusOK, raw, secret)
}

// testChannel sends a fixed test notice through a channel (AC-11): to the
// caller's own address by email, or to the webhook; never queued, never
// retried; the outcome is answered and recorded.
func (a *API) testChannel(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.admin(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "")
		return
	}
	raw, err := a.channelJSON(r, p, "SELECT notify.test_target($1)", id)
	if err != nil {
		failChannel(w, err)
		return
	}
	var t struct {
		Kind   string          `json:"kind"`
		Config json.RawMessage `json:"config"`
		Secret *string         `json:"secret"`
		Email  string          `json:"email"`
		BUName string          `json:"bu_name"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		fail(w, err)
		return
	}
	env := notify.Envelope{ID: "test", Kind: "notify.test", At: time.Now().UTC()}
	env.BU.Name, env.Item.Type, env.Item.Link = t.BUName, "test", "/notifications"
	k, _ := notify.KindOf("notify.test")
	var sent notify.Sent
	deliveryID := "test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	ctx, cancel := context.WithTimeout(r.Context(), 3*notify.Timeout)
	defer cancel()
	switch t.Kind {
	case "smtp":
		var cfg notify.SMTPConfig
		if err = json.Unmarshal(t.Config, &cfg); err == nil {
			var msg notify.Message
			if msg, err = a.composer().Email(env, k.Label); err == nil {
				sent, err = a.Mail.Send(ctx, cfg, t.Email, msg, deliveryID)
			}
		}
	case "webhook":
		var cfg notify.WebhookConfig
		var secret string
		if err = json.Unmarshal(t.Config, &cfg); err == nil && t.Secret != nil && a.Keys != nil {
			ct, _ := base64.StdEncoding.DecodeString(*t.Secret)
			if secret, err = a.Keys.Open(ct); err == nil {
				var b []byte
				if b, err = a.composer().WebhookBody(env, deliveryID); err == nil {
					sent, err = a.Post.Send(ctx, cfg.URL, secret, "", deliveryID, b)
				}
			}
		} else if err == nil {
			err = errors.New("notify: the webhook's secret cannot be opened (FAIR_NOTIFY_SECRETS_DIR)")
		}
	}
	detail := sent.TLSVersion
	if err != nil {
		detail = err.Error()
	}
	if rerr := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT notify.record_test($1, $2, $3)", id, err == nil, detail)
		return err
	}); rerr != nil {
		failChannel(w, rerr)
		return
	}
	out := map[string]any{"sent": err == nil, "tls_version": sent.TLSVersion, "detail": detail, "refused": errors.Is(err, notify.ErrRefused)}
	if sent.Status != 0 {
		out["status"] = sent.Status
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) composer() notify.Composer {
	if a.Composer == nil {
		return notify.Composer{}
	}
	return a.Composer()
}

// listDeliveries answers the delivery log (AC-17): ?channel=, ?state=,
// ?kind=, ?before= (an RFC 3339 time), ?limit= 1 to 200 (50).
func (a *API) listDeliveries(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.admin(w, r, p) {
		return
	}
	q := r.URL.Query()
	var channel, state, kind *string
	var before *time.Time
	if v := q.Get("channel"); v != "" {
		if !uuidRE.MatchString(v) {
			problem(w, http.StatusBadRequest, "invalid_value", "channel is a channel id")
			return
		}
		channel = &v
	}
	if v := q.Get("state"); v != "" {
		switch v {
		case "pending", "sending", "sent", "failed", "dropped":
			state = &v
		default:
			problem(w, http.StatusBadRequest, "invalid_value", "state is pending, sending, sent, failed or dropped")
			return
		}
	}
	if v := q.Get("kind"); v != "" {
		if _, ok := notify.KindOf(v); !ok {
			problem(w, http.StatusBadRequest, "invalid_value", "kind is a notice kind")
			return
		}
		kind = &v
	}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_value", "before is an RFC 3339 time")
			return
		}
		before = &t
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
	raw, err := a.channelJSON(r, p, "SELECT notify.deliveries($1::uuid, $2, $3, $4, $5)", channel, state, kind, before, limit+1)
	if err != nil {
		failChannel(w, err)
		return
	}
	var items []json.RawMessage
	_ = json.Unmarshal(raw, &items)
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": items, "more": more})
}

// listBUs answers the business units a webhook may take notices of (names
// only), for the channels page.
func (a *API) listBUs(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.admin(w, r, p) {
		return
	}
	raw, err := a.channelJSON(r, p, "SELECT notify.bus()")
	if err != nil {
		failChannel(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bus": raw})
}
