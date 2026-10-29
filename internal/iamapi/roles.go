package iamapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// Custom roles (T-28; AC-51, AC-52, AC-54 to AC-56; design §5.6, §6
// /roles, /permissions). Reading needs role.view somewhere (404
// otherwise); creating, cloning, editing and retiring need role.manage at
// the root, checked by the database (403). An edit names the version it
// was reviewed against (409 if another landed since); GET .../diff shows
// what it would change and whom it affects before it is saved.

type permissionItem struct {
	Key          string `json:"key"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Privileged   bool   `json:"privileged"`
	RiskData     bool   `json:"risk_data"`
	Retired      bool   `json:"retired"` // D-OQ5: grants nothing, cannot be added to roles
}

type roleItem struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Builtin        bool      `json:"builtin"`
	Status         string    `json:"status"`
	CurrentVersion int       `json:"current_version"`
	Permissions    []string  `json:"permissions"`
	Privileged     []string  `json:"privileged"` // AC-54: flagged
	CreatedAt      time.Time `json:"created_at"`
	Assignments    int       `json:"assignments"`
	Users          int       `json:"users"`
	Mappings       int       `json:"group_mappings"`
}

func (a *API) listPermissions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	out := []permissionItem{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT key, resource_type, action, privileged, risk_data, retired FROM iam.permission_list()")
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[permissionItem])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": out})
}

func (a *API) roles(r *http.Request, p authz.Principal, id string) ([]roleItem, error) {
	var out []roleItem
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, name, builtin, status, current_version, permissions, privileged, created_at,
			assignments, users, mappings FROM iam.role_list($1)`, nilIfEmpty(id))
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[roleItem])
		return err
	})
	return out, err
}

func (a *API) listRoles(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	out, err := a.roles(r, p, "")
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []roleItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": out})
}

func (a *API) getRole(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	out, err := a.roles(r, p, id)
	if err != nil {
		fail(w, err)
		return
	}
	if len(out) == 0 {
		fail(w, errNotFound)
		return
	}
	writeJSON(w, http.StatusOK, out[0])
}

func (a *API) roleVersions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	type version struct {
		Version     int       `json:"version"`
		Permissions []string  `json:"permissions"`
		ChangedBy   *string   `json:"changed_by"`
		Reason      string    `json:"change_reason"`
		CreatedAt   time.Time `json:"created_at"`
	}
	out := []version{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT version, permissions, changed_by::text, change_reason, created_at FROM iam.role_versions($1)", id)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[version])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if len(out) == 0 {
		fail(w, errNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out})
}

// roleDiff previews saving ?permissions=a,b,c as the role's next version.
func (a *API) roleDiff(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	var perms []string
	for _, k := range strings.Split(r.URL.Query().Get("permissions"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			perms = append(perms, k)
		}
	}
	var d json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.role_diff($1, $2)", id, perms).Scan(&d)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *API) createRole(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
		Reason      string   `json:"reason"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.role_create($1, $2, $3)::text", body.Name, body.Permissions, body.Reason).Scan(&id)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "version": 1})
}

func (a *API) cloneRole(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	src := r.PathValue("id")
	if !uuidRE.MatchString(src) {
		fail(w, errNotFound)
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.role_clone($1, $2, $3)::text", src, body.Name, body.Reason).Scan(&id)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "version": 1})
}

func (a *API) updateRole(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Permissions     []string `json:"permissions"`
		ExpectedVersion *int     `json:"expected_version"`
		Reason          string   `json:"reason"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	if body.ExpectedVersion == nil {
		problem(w, http.StatusBadRequest, "invalid_value", "expected_version (the version the change was reviewed against) is required", nil)
		return
	}
	var version int
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.role_update($1, $2, $3, $4)", id, body.Permissions, *body.ExpectedVersion, body.Reason).Scan(&version)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "version": version})
}

func (a *API) retireRole(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT iam.role_retire($1, $2)", id, body.Reason)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "retired"})
}
