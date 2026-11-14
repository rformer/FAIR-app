package registerapi

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-007 T-04 (OQ3; design §3.5): categories. Every register reader sees
// them; register.edit at the root changes them (the database checks it:
// register.root_writer).

// listCategories lists the categories, in use first, then by name.
func (a *API) listCategories(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	out := []map[string]any{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT id::text, name, archived_at FROM register.category ORDER BY archived_at IS NOT NULL, lower(name)")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, name string
			var archived *time.Time
			if err := rows.Scan(&id, &name, &archived); err != nil {
				return err
			}
			out = append(out, map[string]any{"id": id, "name": name, "archived_at": archived})
		}
		return rows.Err()
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"categories": out})
}

// categoryEvent records a category change under the root BU.
func (a *API) categoryEvent(r *http.Request, tx pgx.Tx, p authz.Principal, id, name, change string) error {
	var root string
	if err := tx.QueryRow(r.Context(), "SELECT register.root_writer()::text").Scan(&root); err != nil {
		return err
	}
	return a.emit(audit.WithTx(r.Context(), tx), audit.Event{Type: "register.category_changed", Severity: audit.SeverityLow, Actor: p.UserID,
		Target: "register_category:" + id, BUID: root, Attributes: map[string]string{"category": id, "name": name, "change": change}})
}

// createCategory adds a category.
func (a *API) createCategory(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), "SELECT register.category_add($1)::text", body.Name).Scan(&id); err != nil {
			return err
		}
		return a.categoryEvent(r, tx, p, id, body.Name, "added")
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// changeCategory renames, archives or restores a category.
func (a *API) changeCategory(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var body struct {
		Name     *string `json:"name"`
		Archived *bool   `json:"archived"`
	}
	if !decode(w, r, &body) {
		return
	}
	if (body.Name == nil) == (body.Archived == nil) {
		problem(w, http.StatusBadRequest, "invalid_value", "give either name or archived", nil)
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		if body.Name != nil {
			if _, err := tx.Exec(r.Context(), "SELECT register.category_rename($1, $2)", id, *body.Name); err != nil {
				return err
			}
			return a.categoryEvent(r, tx, p, id, *body.Name, "renamed")
		}
		if _, err := tx.Exec(r.Context(), "SELECT register.category_archive($1, $2)", id, *body.Archived); err != nil {
			return err
		}
		var name string
		if err := tx.QueryRow(r.Context(), "SELECT name FROM register.category WHERE id = $1", id).Scan(&name); err != nil {
			return err
		}
		change := "archived"
		if !*body.Archived {
			change = "restored"
		}
		return a.categoryEvent(r, tx, p, id, name, change)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}
