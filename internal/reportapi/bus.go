package reportapi

import (
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// F-010 T-17 (design §6): what the report pages choose a business unit
// from.

// listBUs answers the live BUs where the caller holds ?permission=
// (report.view or report.export), with code and name (report.scope_bus).
func (a *API) listBUs(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	perm := r.URL.Query().Get("permission")
	if perm != string(permView) && perm != string(permExport) {
		problem(w, http.StatusBadRequest, "invalid_value", "permission is report.view or report.export", nil)
		return
	}
	type bu struct {
		ID   string `json:"id"`
		Code string `json:"code"`
		Name string `json:"name"`
	}
	out := []bu{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT id::text, code, name FROM report.scope_bus($1)", perm)
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
