package registerapi

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// F-007 T-08 (F-007-AC-01, AC-19): what the register pages choose from.

// listBUs answers the BUs where the caller holds a register or treatment
// permission (?permission=register.view, register.edit, treatment.view,
// treatment.edit), with code and name.
func (a *API) listBUs(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	perm := r.URL.Query().Get("permission")
	if !slices.Contains([]string{"register.view", "register.edit", "treatment.view", "treatment.edit"}, perm) {
		problem(w, http.StatusBadRequest, "invalid_value", "permission is register.view, register.edit, treatment.view or treatment.edit", nil)
		return
	}
	rt, mode := "register", "read"
	switch perm {
	case "register.edit":
		mode = "write"
	case "treatment.view":
		rt = "treatment"
	case "treatment.edit":
		rt, mode = "treatment", "write"
	}
	type bu struct {
		ID   string `json:"id"`
		Code string `json:"code"`
		Name string `json:"name"`
	}
	out := []bu{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT id::text, code, name FROM register.scope_bus($1, $2)", rt, mode)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b bu
			if err := rows.Scan(&b.ID, &b.Code, &b.Name); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bus": out})
}

// listOwners answers who may own a risk at ?bu= (register.view there),
// names only, for a holder of register.edit at bu (AC-01).
func (a *API) listOwners(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	bu := r.URL.Query().Get("bu")
	if !uuidRE.MatchString(bu) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu is a business unit id", nil)
		return
	}
	if !a.mayEdit(w, r, p, bu) {
		return
	}
	var raw []byte
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT register.owners($1)", bu).Scan(&raw)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"owners": json.RawMessage(raw)})
}
