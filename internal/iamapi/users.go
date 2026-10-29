package iamapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// User administration (T-23b; design §6 /users, /groups). user.view
// somewhere is needed to see the API at all (404 otherwise, AC-25); the
// database shows the users and groups the caller may see (every one with
// user.view at the root; those assigned in its BUs' subtrees otherwise).
// disable, enable and unlock need user.manage at the root (403), a reason,
// and are audited.

// userView requires user.view in some BU; it answers and returns false
// otherwise.
func (a *API) userView(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	if bw, ok := a.Authz.(interface {
		BUsWith(context.Context, authz.Principal, authz.Permission) (map[string]struct{}, error)
	}); ok {
		bus, err := bw.BUsWith(r.Context(), p, "user.view")
		if err != nil || len(bus) == 0 {
			problem(w, http.StatusNotFound, "not_found", "", nil)
			return false
		}
		return true
	}
	root, err := a.rootBU(r.Context())
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "", nil)
		return false
	}
	if err := a.Authz.Check(r.Context(), p, "user.view", root); err != nil {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return false
	}
	return true
}

type userItem struct {
	ID             string          `json:"id"`
	Email          string          `json:"email"`
	DisplayName    string          `json:"display_name"`
	Status         string          `json:"status"`
	DisabledReason *string         `json:"disabled_reason"`
	Source         string          `json:"source"`
	IDPID          *string         `json:"idp_id"`
	ExternalID     *string         `json:"external_id"`
	UserName       *string         `json:"user_name"`
	LastLoginAt    *time.Time      `json:"last_login_at"`
	CreatedAt      time.Time       `json:"created_at"`
	ReactivatedAt  *time.Time      `json:"reactivated_at"`
	LiveSessions   int             `json:"live_sessions"`
	Groups         json.RawMessage `json:"groups"`
	Assignments    json.RawMessage `json:"assignments"`
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// users queries iam.user_admin_list through the caller's signed context.
func (a *API) users(r *http.Request, p authz.Principal, id, status, source, idp, q string, limit, offset int) ([]userItem, int, error) {
	var out []userItem
	total := 0
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, email, display_name, status, disabled_reason, source, idp_id::text, external_id,
			user_name, last_login_at, created_at, reactivated_at, live_sessions, groups, assignments, total
			FROM iam.user_admin_list($1, $2, $3, $4, $5, $6, $7)`,
			nilIfEmpty(id), nilIfEmpty(status), nilIfEmpty(source), nilIfEmpty(idp), nilIfEmpty(q), limit, offset)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (userItem, error) {
			var u userItem
			var t int64
			err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Status, &u.DisabledReason, &u.Source, &u.IDPID, &u.ExternalID,
				&u.UserName, &u.LastLoginAt, &u.CreatedAt, &u.ReactivatedAt, &u.LiveSessions, &u.Groups, &u.Assignments, &t)
			total = int(t)
			return u, err
		})
		return err
	})
	return out, total, err
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.userView(w, r, p) {
		return
	}
	q := r.URL.Query()
	limit, offset := 100, 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			problem(w, http.StatusBadRequest, "invalid_value", "limit is 1 to 1000", nil)
			return
		}
		limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problem(w, http.StatusBadRequest, "invalid_value", "offset is 0 or more", nil)
			return
		}
		offset = n
	}
	status, source, idp := q.Get("status"), q.Get("source"), q.Get("idp")
	switch status {
	case "", "active", "disabled", "locked":
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "status is active, disabled or locked", nil)
		return
	}
	switch source {
	case "", "scim", "jit", "breakglass":
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "source is scim, jit or breakglass", nil)
		return
	}
	if idp != "" && !uuidRE.MatchString(idp) {
		problem(w, http.StatusBadRequest, "invalid_value", "idp is an IdP id", nil)
		return
	}
	out, total, err := a.users(r, p, "", status, source, idp, q.Get("q"), limit, offset)
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []userItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "total": total, "limit": limit, "offset": offset})
}

func (a *API) getUser(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.userView(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	out, _, err := a.users(r, p, id, "", "", "", "", 1, 0)
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

// userAction disables, enables or unlocks a user.
func (a *API) userAction(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !a.userView(w, r, p) || !decode(w, r, &body) {
		return
	}
	id, action := r.PathValue("id"), r.PathValue("action")
	if !uuidRE.MatchString(id) || (action != "disable" && action != "enable" && action != "unlock") {
		fail(w, errNotFound)
		return
	}
	var status string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.user_admin_action($1, $2, $3)", id, action, body.Reason).Scan(&status)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": status})
}

type groupItem struct {
	ID          string          `json:"id"`
	DisplayName string          `json:"display_name"`
	ExternalID  *string         `json:"external_id"`
	IDPID       *string         `json:"idp_id"`
	CreatedAt   time.Time       `json:"created_at"`
	Members     int             `json:"members"`
	Assignments json.RawMessage `json:"assignments"`
}

func (a *API) groups(r *http.Request, p authz.Principal, id string) ([]groupItem, error) {
	var out []groupItem
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, display_name, external_id, idp_id::text, created_at, members, assignments
			FROM iam.group_admin_list($1)`, nilIfEmpty(id))
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (groupItem, error) {
			var g groupItem
			err := row.Scan(&g.ID, &g.DisplayName, &g.ExternalID, &g.IDPID, &g.CreatedAt, &g.Members, &g.Assignments)
			return g, err
		})
		return err
	})
	return out, err
}

func (a *API) listGroups(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.userView(w, r, p) {
		return
	}
	out, err := a.groups(r, p, "")
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []groupItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (a *API) getGroup(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.userView(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	out, err := a.groups(r, p, id)
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
