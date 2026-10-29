package iamapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// Group-to-role mappings (T-24; AC-12 to AC-14; design §6
// /group-mappings): a SCIM group mapped to a role at a BU gives each active
// member a mapped assignment, kept in line with membership by the database.
// access.view somewhere is needed to see the API (404 otherwise, AC-25);
// mappings are listed where the caller holds access.view. Creating and
// removing need access.map_groups at the BU (and at the root for roles with
// admin permissions, AC-22), checked by the database (403), with a reason.

type mapping struct {
	ID        string          `json:"id"`
	GroupID   string          `json:"group_id"`
	GroupName string          `json:"group_name"`
	RoleID    string          `json:"role_id"`
	RoleName  string          `json:"role_name"`
	BUID      string          `json:"bu_id"`
	BUCode    string          `json:"bu_code"`
	Reason    string          `json:"reason"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	Assigned  int             `json:"assigned"`
	Skipped   json.RawMessage `json:"skipped"`
}

func (a *API) accessView(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	return a.somewhere(w, r, p, "access.view")
}

func (a *API) mappings(r *http.Request, p authz.Principal, id string) ([]mapping, error) {
	var out []mapping
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, group_id::text, group_name, role_id::text, role_name, bu_id::text, bu_code,
			reason, created_by::text, created_at, assigned, skipped FROM iam.group_mapping_list($1)`, nilIfEmpty(id))
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (mapping, error) {
			var m mapping
			err := row.Scan(&m.ID, &m.GroupID, &m.GroupName, &m.RoleID, &m.RoleName, &m.BUID, &m.BUCode, &m.Reason, &m.CreatedBy,
				&m.CreatedAt, &m.Assigned, &m.Skipped)
			return m, err
		})
		return err
	})
	return out, err
}

func (a *API) listMappings(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.accessView(w, r, p) {
		return
	}
	out, err := a.mappings(r, p, "")
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []mapping{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mappings": out})
}

func (a *API) getMapping(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.accessView(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	out, err := a.mappings(r, p, id)
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

func (a *API) createMapping(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		GroupID string `json:"group_id"`
		RoleID  string `json:"role_id"`
		BUID    string `json:"bu_id"`
		Reason  string `json:"reason"`
	}
	if !a.accessView(w, r, p) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.GroupID) || !uuidRE.MatchString(body.RoleID) || !uuidRE.MatchString(body.BUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "group_id, role_id and bu_id are ids", nil)
		return
	}
	var id string
	var assigned, skipped int
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT id::text, assigned, skipped FROM iam.group_mapping_create($1, $2, $3, $4)",
			body.GroupID, body.RoleID, body.BUID, body.Reason).Scan(&id, &assigned, &skipped)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "assigned": assigned, "skipped": skipped})
}

func (a *API) removeMapping(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.accessView(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	var revoked int
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.group_mapping_remove($1, $2)", id, r.URL.Query().Get("reason")).Scan(&revoked)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "revoked": revoked})
}
