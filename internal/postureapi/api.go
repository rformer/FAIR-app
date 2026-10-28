// Package postureapi is the Posture REST API (F-015 T-31, design §7):
// /api/v1/posture, behind the gateway's internal JWT (server.Authenticate)
// and Idempotency-Key on every mutation (server.Idempotent). Every route
// requires posture.view (at the root, or at the BU asked about); without it
// the answer is 404 (F-001 AC-25). Mutations call the posture services,
// which take the actor from the signed DB context and check their own
// permissions. Exports (POST /exports, GET /exports/{id}) arrive with
// T-33 to T-35.
package postureapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// Prefix is the API's base path.
const Prefix = "/api/v1/posture"

// Authorizer answers permission questions from the caller's grant snapshot
// (authz.Cache).
type Authorizer interface {
	authz.Checker
	BUsWith(ctx context.Context, p authz.Principal, perm authz.Permission) (map[string]struct{}, error)
}

// API serves the Posture API.
type API struct {
	DB      *pgxpool.Pool // app_posture
	Authz   Authorizer
	Audit   audit.Emitter
	Publish posture.Publisher // optional

	rootOnce sync.Once
	root     string
	rootErr  error
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/registry", (*API).registry},
	{"GET", "/settings", (*API).settingsView},
	{"POST", "/settings/{key}", (*API).changeSetting},
	{"GET", "/changes", (*API).changes},
	{"GET", "/exceptions", (*API).exceptions},
	{"POST", "/exceptions/{id}/renew", (*API).renew},
	{"GET", "/profiles", (*API).profiles},
	{"POST", "/profiles", (*API).createProfile},
	{"PATCH", "/profiles/{id}", (*API).editProfile},
	{"POST", "/profiles/{id}/submit", (*API).submitProfile},
	{"GET", "/profiles/{id}/diff", (*API).diffProfile},
	{"POST", "/profiles/import", (*API).importProfile},
	{"GET", "/profiles/{id}/export", (*API).exportProfile},
	{"GET", "/switches", (*API).pendingSwitch},
	{"POST", "/switches", (*API).requestSwitch},
	{"GET", "/switches/{id}", (*API).getSwitch},
	{"POST", "/switches/{id}/conflicts/{cid}/resolve", (*API).resolveConflict},
	{"POST", "/switches/{id}/activate", (*API).activateSwitch},
	{"POST", "/switches/{id}/cancel", (*API).cancelSwitch},
	{"GET", "/overlay", (*API).overlay},
	{"PATCH", "/overlay", (*API).changeOverlay},
	{"GET", "/drift", (*API).drift},
	{"POST", "/drift/{id}/acknowledge", (*API).acknowledgeDrift},
	{"GET", "/k8s-access", (*API).k8sAccess},
	{"POST", "/k8s-access/acknowledge-grant", (*API).acknowledgeGrant},
}

// Routes lists "METHOD /path" of every route (for the OpenAPI document).
func Routes() []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.method+" "+Prefix+r.path)
	}
	sort.Strings(out)
	return out
}

// Handler returns the API with authentication and idempotency in front.
func (a *API) Handler(kp authz.KeyProvider, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routes {
		h := rt.h
		mux.HandleFunc(rt.method+" "+Prefix+rt.path, func(w http.ResponseWriter, r *http.Request) {
			p, _ := server.PrincipalFrom(r.Context())
			h(a, w, r, p)
		})
	}
	return server.Authenticate(kp, "posture", now)(server.Idempotent(posture.IdempotencyStore{DB: a.DB})(mux))
}

// --- helpers --------------------------------------------------------------

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

func (a *API) rootBU(ctx context.Context) (string, error) {
	a.rootOnce.Do(func() { a.rootErr = a.DB.QueryRow(ctx, "SELECT posture.root_bu()::text").Scan(&a.root) })
	return a.root, a.rootErr
}

// view requires posture.view at bu (the root when ""); it answers and
// returns false otherwise.
func (a *API) view(w http.ResponseWriter, r *http.Request, p authz.Principal, bu string) bool {
	if bu == "" {
		root, err := a.rootBU(r.Context())
		if err != nil {
			problem(w, http.StatusServiceUnavailable, "unavailable", "", nil)
			return false
		}
		bu = root
	}
	if err := a.Authz.Check(r.Context(), p, "posture.view", bu); err != nil {
		server.WriteAuthzError(w, err)
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object with the documented fields", nil)
		return false
	}
	return true
}

func duration(w http.ResponseWriter, s string) (time.Duration, bool) {
	if s == "" {
		return 0, true
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		problem(w, http.StatusBadRequest, "invalid_duration", "a positive Go duration such as 720h", nil)
		return 0, false
	}
	return d, true
}

// fail maps the posture services' errors to responses; anything unexpected
// is a 500 without detail (it is logged by the service).
func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, posture.ErrNotPermitted):
		problem(w, http.StatusForbidden, "forbidden", "the action needs a permission you do not hold here", nil)
	case errors.Is(err, posture.ErrHardFloor):
		problem(w, http.StatusUnprocessableEntity, "hard_floor", "the value is below the hard floor; no approval can allow it", nil)
	case errors.Is(err, posture.ErrExplanationRequired):
		problem(w, http.StatusUnprocessableEntity, "explanation_required", "a written explanation is required", nil)
	case errors.Is(err, posture.ErrInvalidValue), errors.Is(err, posture.ErrExpiryOutOfRange):
		problem(w, http.StatusBadRequest, "invalid_value", trimSentinel(err), nil)
	case errors.Is(err, posture.ErrNotApplicable), errors.Is(err, posture.ErrNotApproved):
		problem(w, http.StatusConflict, "not_applicable", trimSentinel(err), nil)
	case errors.Is(err, posture.ErrNoContext):
		problem(w, http.StatusUnauthorized, "unauthenticated", "", nil)
	case errors.Is(err, posture.ErrConfiguration):
		problem(w, http.StatusServiceUnavailable, "not_configured", trimSentinel(err), nil)
	case errors.Is(err, pgx.ErrNoRows):
		problem(w, http.StatusNotFound, "not_found", "", nil)
	default:
		problem(w, http.StatusInternalServerError, "internal", "", nil)
	}
}

// trimSentinel keeps the database's explanation of a domain error.
func trimSentinel(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

func (a *API) evaluator() posture.Evaluator {
	return posture.Evaluator{DB: a.DB, Audit: a.Audit, Publish: a.Publish}
}

// --- registry and settings (AC-03) ---------------------------------------

func (a *API) registry(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	rows, err := a.DB.Query(r.Context(), `SELECT key, type, direction, enum_order, bu_scopable, owner_feature, params, hard_floor,
		value, source, profile_default, bound, deviation, exception_id::text, exception_expires FROM posture.registry_view()`)
	if err != nil {
		fail(w, err)
		return
	}
	type entry struct {
		Key              string          `json:"key"`
		Type             string          `json:"type"`
		Direction        string          `json:"direction"`
		Order            []string        `json:"order,omitempty"`
		BUScopable       bool            `json:"bu_scopable"`
		Owner            string          `json:"owner_feature"`
		Params           []string        `json:"params"`
		Controls         []string        `json:"controls"`
		HardFloor        json.RawMessage `json:"hard_floor,omitempty"`
		Value            json.RawMessage `json:"value"`
		Source           string          `json:"source"`
		Default          json.RawMessage `json:"profile_default"`
		Bound            json.RawMessage `json:"bound"`
		Deviation        string          `json:"deviation"`
		ExceptionID      *string         `json:"exception_id,omitempty"`
		ExceptionExpires *time.Time      `json:"exception_expires,omitempty"`
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (entry, error) {
		var e entry
		err := row.Scan(&e.Key, &e.Type, &e.Direction, &e.Order, &e.BUScopable, &e.Owner, &e.Params, &e.HardFloor,
			&e.Value, &e.Source, &e.Default, &e.Bound, &e.Deviation, &e.ExceptionID, &e.ExceptionExpires)
		e.Controls = posture.ControlsForParams(e.Params)
		if e.Controls == nil {
			e.Controls = []string{} // an empty list, never null
		}
		return e, err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": out})
}

// settingsView: the values in force for the instance, or for ?bu=, and the
// BU overrides the caller may see (restricted BUs only for those assigned
// there).
func (a *API) settingsView(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	bu := r.URL.Query().Get("bu")
	if !a.view(w, r, p, bu) {
		return
	}
	snap, err := settings.DBSource{DB: a.DB}.Snapshot(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	effective := map[string]json.RawMessage{}
	for k, v := range snap.Instance {
		effective[k] = v
	}
	for k, v := range snap.BU[bu] {
		effective[k] = v
	}
	visible, err := a.Authz.BUsWith(r.Context(), p, "posture.view")
	if err != nil {
		server.WriteAuthzError(w, err)
		return
	}
	rows, err := a.DB.Query(r.Context(), "SELECT key, bu_id::text, value, source, exception_id::text, updated_at FROM posture.bu_overrides()")
	if err != nil {
		fail(w, err)
		return
	}
	type override struct {
		Key         string          `json:"key"`
		BUID        string          `json:"bu_id"`
		Value       json.RawMessage `json:"value"`
		Source      string          `json:"source"`
		ExceptionID *string         `json:"exception_id,omitempty"`
		UpdatedAt   time.Time       `json:"updated_at"`
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (override, error) {
		var o override
		err := row.Scan(&o.Key, &o.BUID, &o.Value, &o.Source, &o.ExceptionID, &o.UpdatedAt)
		return o, err
	})
	if err != nil {
		fail(w, err)
		return
	}
	overrides := []override{}
	for _, o := range all {
		if _, ok := visible[o.BUID]; ok {
			overrides = append(overrides, o)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": snap.Version, "profile": snap.Profile, "profile_version": snap.ProfileVersion,
		"bu_id": bu, "effective": effective, "overrides": overrides})
}

func (a *API) changeSetting(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Value             json.RawMessage `json:"value"`
		BUID              string          `json:"bu_id"`
		Explanation       string          `json:"explanation"`
		ExceptionDuration string          `json:"exception_duration"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	if body.BUID != "" && !a.view(w, r, p, body.BUID) {
		return
	}
	d, ok := duration(w, body.ExceptionDuration)
	if !ok {
		return
	}
	key := r.PathValue("key")
	// Design §7: every loosening call carries an explanation, in bounds or not.
	var direction string
	var buArg any
	if body.BUID != "" {
		buArg = body.BUID
	}
	if err := a.DB.QueryRow(r.Context(), "SELECT direction FROM posture.preview_change($1, $2, $3)", key, buArg, []byte(body.Value)).Scan(&direction); err != nil {
		fail(w, mapPreview(err))
		return
	}
	if direction == "loosen" && strings.TrimSpace(body.Explanation) == "" {
		problem(w, http.StatusUnprocessableEntity, "explanation_required", "loosening a setting needs a written explanation", nil)
		return
	}
	res, err := a.evaluator().Change(r.Context(), p, posture.ChangeRequest{Key: key, BUID: body.BUID, Value: body.Value,
		Explanation: body.Explanation, ExceptionDuration: d})
	if err != nil {
		if errors.Is(err, posture.ErrExplanationRequired) && res.Warning != nil {
			problem(w, http.StatusUnprocessableEntity, "explanation_required", res.Warning.Message, map[string]any{"warning": res.Warning})
			return
		}
		fail(w, err)
		return
	}
	writeChange(w, res)
}

// mapPreview turns a preview's database error into the services' errors.
func mapPreview(err error) error {
	return posture.MapError(err)
}

func writeChange(w http.ResponseWriter, res posture.ChangeResult) {
	body := map[string]any{"outcome": res.Outcome, "change_id": res.ChangeID, "direction": res.Direction}
	status := http.StatusOK
	if res.Outcome == posture.PendingApproval {
		status = http.StatusAccepted
		body["approval_id"] = res.ApprovalID
		body["warning"] = res.Warning
	}
	writeJSON(w, status, body)
}

func (a *API) changes(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	rows, err := a.DB.Query(r.Context(), `SELECT change_id::text, key, bu_id::text, old_value, new_value, direction, explanation,
		requested_by::text, approval_request_id::text, state, created_at, applied_at FROM posture.changes_view($1)`, limit)
	if err != nil {
		fail(w, err)
		return
	}
	type change struct {
		ID          string          `json:"change_id"`
		Key         string          `json:"key"`
		BUID        *string         `json:"bu_id,omitempty"`
		Old         json.RawMessage `json:"old_value"`
		New         json.RawMessage `json:"new_value"`
		Direction   string          `json:"direction"`
		Explanation *string         `json:"explanation,omitempty"`
		RequestedBy string          `json:"requested_by"`
		ApprovalID  *string         `json:"approval_id,omitempty"`
		State       string          `json:"state"`
		CreatedAt   time.Time       `json:"created_at"`
		AppliedAt   *time.Time      `json:"applied_at,omitempty"`
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (change, error) {
		var c change
		err := row.Scan(&c.ID, &c.Key, &c.BUID, &c.Old, &c.New, &c.Direction, &c.Explanation, &c.RequestedBy, &c.ApprovalID,
			&c.State, &c.CreatedAt, &c.AppliedAt)
		return c, err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": out})
}

func (a *API) exceptions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	rows, err := a.DB.Query(r.Context(), `SELECT exception_id::text, key, bu_id::text, is_overlay, value, bound_at_creation, justification,
		owner_id::text, approved_by::text, created_at, expires_at, renewed_from::text, state FROM posture.exceptions_view()`)
	if err != nil {
		fail(w, err)
		return
	}
	type exc struct {
		ID          string          `json:"exception_id"`
		Key         string          `json:"key"`
		BUID        *string         `json:"bu_id,omitempty"`
		Overlay     bool            `json:"overlay"`
		Value       json.RawMessage `json:"value"`
		Bound       json.RawMessage `json:"bound_at_creation"`
		Reason      string          `json:"justification"`
		Owner       string          `json:"owner_id"`
		ApprovedBy  string          `json:"approved_by"`
		CreatedAt   time.Time       `json:"created_at"`
		ExpiresAt   time.Time       `json:"expires_at"`
		RenewedFrom *string         `json:"renewed_from,omitempty"`
		State       string          `json:"state"`
	}
	visible, err := a.Authz.BUsWith(r.Context(), p, "posture.view")
	if err != nil {
		server.WriteAuthzError(w, err)
		return
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (exc, error) {
		var e exc
		err := row.Scan(&e.ID, &e.Key, &e.BUID, &e.Overlay, &e.Value, &e.Bound, &e.Reason, &e.Owner, &e.ApprovedBy,
			&e.CreatedAt, &e.ExpiresAt, &e.RenewedFrom, &e.State)
		return e, err
	})
	if err != nil {
		fail(w, err)
		return
	}
	out := []exc{}
	for _, e := range all {
		if e.BUID != nil {
			if _, ok := visible[*e.BUID]; !ok {
				continue // a BU exception the caller may not see
			}
		}
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"exceptions": out})
}

func (a *API) renew(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Justification string `json:"justification"`
		Duration      string `json:"duration"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	d, ok := duration(w, body.Duration)
	if !ok {
		return
	}
	rn, err := a.evaluator().RequestRenewal(r.Context(), p, r.PathValue("id"), body.Justification, d)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"renewal_id": rn.ID, "approval_id": rn.ApprovalID})
}

// --- profiles ---------------------------------------------------------------

func (a *API) profilesSvc() posture.Profiles { return posture.Profiles{DB: a.DB, Audit: a.Audit} }

func (a *API) profiles(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	rows, err := a.DB.Query(r.Context(), `SELECT profile_id, version, name, family, kind, base_profile_id, base_version, status,
		label_deviates, active, created_at FROM posture.profiles_view()`)
	if err != nil {
		fail(w, err)
		return
	}
	type prof struct {
		ID            string    `json:"id"`
		Version       string    `json:"version"`
		Name          string    `json:"name"`
		Family        string    `json:"family"`
		Kind          string    `json:"kind"`
		BaseID        *string   `json:"base_profile_id,omitempty"`
		BaseVersion   *string   `json:"base_version,omitempty"`
		Status        string    `json:"status"`
		LabelDeviates bool      `json:"label_deviates"`
		Active        bool      `json:"active"`
		CreatedAt     time.Time `json:"created_at"`
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (prof, error) {
		var x prof
		err := row.Scan(&x.ID, &x.Version, &x.Name, &x.Family, &x.Kind, &x.BaseID, &x.BaseVersion, &x.Status, &x.LabelDeviates, &x.Active, &x.CreatedAt)
		return x, err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

func (a *API) createProfile(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		BaseID      string `json:"base_id"`
		BaseVersion string `json:"base_version"`
		ID          string `json:"id"`
		Name        string `json:"name"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	v, err := a.profilesSvc().Create(r.Context(), p, body.BaseID, body.BaseVersion, body.ID, body.Name)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": body.ID, "version": v})
}

func (a *API) editProfile(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Version       string          `json:"version"`
		Key           string          `json:"key"`
		Default       json.RawMessage `json:"default"`
		Bound         json.RawMessage `json:"bound"`
		Justification string          `json:"justification"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	loosened, err := a.profilesSvc().Edit(r.Context(), p, r.PathValue("id"), body.Version, body.Key, body.Default, body.Bound, body.Justification)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"loosened": loosened})
}

func (a *API) submitProfile(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Version string `json:"version"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	approval, err := a.profilesSvc().Submit(r.Context(), p, r.PathValue("id"), body.Version)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"approval_id": approval})
}

func (a *API) diffProfile(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	q := r.URL.Query()
	otherID, otherVersion, ok := strings.Cut(q.Get("against"), "@")
	if !ok || q.Get("version") == "" {
		problem(w, http.StatusBadRequest, "invalid_request", "version=V&against=ID@VERSION", nil)
		return
	}
	rows, err := a.profilesSvc().Diff(r.Context(), p, r.PathValue("id"), q.Get("version"), otherID, otherVersion)
	if err != nil {
		fail(w, err)
		return
	}
	type row struct {
		Key      string          `json:"key"`
		ADefault json.RawMessage `json:"default"`
		ABound   json.RawMessage `json:"bound"`
		BDefault json.RawMessage `json:"against_default"`
		BBound   json.RawMessage `json:"against_bound"`
		Change   string          `json:"change"`
	}
	out := make([]row, 0, len(rows))
	for _, d := range rows {
		out = append(out, row{d.Key, d.ADefault, d.ABound, d.BDefault, d.BBound, d.Change})
	}
	writeJSON(w, http.StatusOK, map[string]any{"diff": out})
}

func (a *API) importProfile(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		ID       string          `json:"id"`
		Format   string          `json:"format"`
		Document json.RawMessage `json:"document"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	var v string
	var err error
	switch body.Format {
	case "json":
		v, err = a.profilesSvc().ImportJSON(r.Context(), p, body.ID, body.Document)
	case "oscal":
		v, err = a.profilesSvc().ImportOSCAL(r.Context(), p, body.ID, body.Document)
	default:
		problem(w, http.StatusBadRequest, "invalid_request", "format is json or oscal", nil)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": body.ID, "version": v})
}

func (a *API) exportProfile(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	q := r.URL.Query()
	var b []byte
	var err error
	switch q.Get("format") {
	case "", "json":
		b, err = a.profilesSvc().ExportJSON(r.Context(), p, r.PathValue("id"), q.Get("version"))
	case "oscal":
		b, err = a.profilesSvc().ExportOSCAL(r.Context(), p, r.PathValue("id"), q.Get("version"))
	default:
		problem(w, http.StatusBadRequest, "invalid_request", "format is json or oscal", nil)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.json"`, r.PathValue("id"), q.Get("version")))
	_, _ = w.Write(b) // #nosec G705 -- a JSON document served as application/json, as an attachment, with nosniff
}

// --- switches ------------------------------------------------------------

func (a *API) switches() posture.Switches {
	return posture.Switches{DB: a.DB, Audit: a.Audit, Publish: a.Publish}
}

func (a *API) requestSwitch(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		TargetID      string `json:"target_id"`
		TargetVersion string `json:"target_version"`
		Justification string `json:"justification"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	req, err := a.switches().Request(r.Context(), p, body.TargetID, body.TargetVersion, body.Justification)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"switch_id": req.ID, "loosening": req.Loosening, "conflicts": req.Conflicts,
		"approval_id": req.ApprovalID})
}

// pendingSwitch: the pending switch, if any (the Posture page finds it here;
// T-32).
func (a *API) pendingSwitch(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	ps, err := a.switches().Pending(r.Context(), p)
	if err != nil {
		fail(w, err)
		return
	}
	if ps == nil {
		writeJSON(w, http.StatusOK, map[string]any{"pending": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": switchJSON(ps)})
}

func (a *API) getSwitch(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	ps, err := a.switches().Pending(r.Context(), p)
	if err != nil {
		fail(w, err)
		return
	}
	if ps == nil || ps.ID != r.PathValue("id") {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	writeJSON(w, http.StatusOK, switchJSON(ps))
}

func switchJSON(ps *posture.PendingSwitch) map[string]any {
	type conflict struct {
		ID         string          `json:"conflict_id"`
		Key        string          `json:"key"`
		BUID       string          `json:"bu_id,omitempty"`
		Current    json.RawMessage `json:"current"`
		NewBound   json.RawMessage `json:"new_bound"`
		BelowFloor bool            `json:"below_floor"`
		Resolution string          `json:"resolution"`
	}
	cs := []conflict{}
	for _, c := range ps.Conflicts {
		id := c.Key
		if c.BUID != "" {
			id += "@" + c.BUID
		}
		cs = append(cs, conflict{id, c.Key, c.BUID, c.Current, c.NewBound, c.BelowFloor, c.Resolution})
	}
	return map[string]any{"switch_id": ps.ID, "from": ps.From, "target": ps.Target, "loosening": ps.Loosening,
		"approval_id": ps.ApprovalID, "unresolved": ps.Unresolved(), "conflicts": cs}
}

func (a *API) resolveConflict(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Resolution string `json:"resolution"`
		Reason     string `json:"reason"`
		Duration   string `json:"duration"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	d, ok := duration(w, body.Duration)
	if !ok {
		return
	}
	key, bu, _ := strings.Cut(r.PathValue("cid"), "@")
	approval, err := a.switches().Resolve(r.Context(), p, r.PathValue("id"), key, bu, body.Resolution, body.Reason, d)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approval_id": approval})
}

func (a *API) activateSwitch(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	n, err := a.switches().Activate(r.Context(), p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changed": n})
}

func (a *API) cancelSwitch(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	if err := a.switches().Cancel(r.Context(), p, r.PathValue("id")); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": true})
}

// --- overlay, drift, Kubernetes access -------------------------------------

func (a *API) overlaySvc() posture.Overlay {
	return posture.Overlay{DB: a.DB, Audit: a.Audit, Publish: a.Publish}
}

func (a *API) overlay(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	es, err := a.overlaySvc().View(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"overlay": es})
}

func (a *API) changeOverlay(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Key               string          `json:"key"`
		Value             json.RawMessage `json:"value"`
		Explanation       string          `json:"explanation"`
		ExceptionDuration string          `json:"exception_duration"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	d, ok := duration(w, body.ExceptionDuration)
	if !ok {
		return
	}
	res, err := a.overlaySvc().Change(r.Context(), p, body.Key, body.Value, body.Explanation, d)
	if err != nil {
		if errors.Is(err, posture.ErrExplanationRequired) && res.Warning != nil {
			problem(w, http.StatusUnprocessableEntity, "explanation_required", res.Warning.Message, map[string]any{"warning": res.Warning})
			return
		}
		fail(w, err)
		return
	}
	writeChange(w, res)
}

func (a *API) drift(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	var since time.Time
	if s := r.URL.Query().Get("resolved_since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_request", "resolved_since is an RFC 3339 time", nil)
			return
		}
		since = t
	}
	fs, err := posture.Findings(r.Context(), a.DB, since)
	if err != nil {
		fail(w, err)
		return
	}
	type finding struct {
		ID                string          `json:"finding_id"`
		Kind              string          `json:"kind"`
		CheckID           string          `json:"check_id"`
		Severity          string          `json:"severity"`
		Controls          []string        `json:"controls"`
		Subject           string          `json:"subject"`
		Detail            json.RawMessage `json:"detail"`
		Remediation       string          `json:"remediation"`
		Status            string          `json:"status"`
		FirstSeen         time.Time       `json:"first_seen"`
		LastSeen          time.Time       `json:"last_seen"`
		AcknowledgedBy    string          `json:"acknowledged_by,omitempty"`
		AcknowledgedAt    *time.Time      `json:"acknowledged_at,omitempty"`
		AcknowledgeReason string          `json:"acknowledge_reason,omitempty"`
		ResolvedAt        *time.Time      `json:"resolved_at,omitempty"`
	}
	out := make([]finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, finding{f.ID, f.Kind, f.CheckID, f.Severity, f.Controls, f.Subject, f.Detail, f.Remediation, f.Status,
			f.FirstSeen, f.LastSeen, f.AcknowledgedBy, f.AcknowledgedAt, f.AcknowledgeReason, f.ResolvedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out})
}

func (a *API) acknowledgeDrift(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	f, err := posture.Drift{DB: a.DB, Audit: a.Audit}.Acknowledge(r.Context(), p, r.PathValue("id"), body.Reason)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"finding_id": f.ID, "status": f.Status, "acknowledged_by": f.AcknowledgedBy})
}

func (a *API) k8sAccess(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	k := posture.K8sAccess{DB: a.DB, Audit: a.Audit}
	st, err := k.Status(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	as, err := k.Assessment(r.Context(), 0)
	if err != nil {
		fail(w, err)
		return
	}
	type check struct {
		ID       string   `json:"check_id"`
		Title    string   `json:"title"`
		Controls []string `json:"controls"`
		Assessed bool     `json:"assessed"`
		Reason   string   `json:"reason,omitempty"`
	}
	checks := make([]check, 0, len(as))
	for _, c := range as {
		checks = append(checks, check{c.CheckID, c.Title, c.Controls, c.Assessed, c.Reason})
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": st.State, "permissions_digest": st.Digest, "current_permissions_digest": st.CurrentDigest,
		"decided_by": st.DecidedActor, "decided_at": st.DecidedAt, "reason": st.Reason, "deployment_mode": st.DeploymentMode,
		"last_report": st.LastReport, "warning": st.Warning, "checks": checks})
}

func (a *API) acknowledgeGrant(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		PermissionsDigest string `json:"permissions_digest"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	if err := (posture.K8sAccess{DB: a.DB, Audit: a.Audit}).Acknowledge(r.Context(), p, body.PermissionsDigest); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": posture.AccessGranted})
}
