package iamapi

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// The system-use banner (T-19, AC-34): any signed-in user reads it; a
// banner.manage holder changes it (the database checks, 403 otherwise),
// audited. The gateway shows it and records acknowledgments.

func (a *API) getBanner(w http.ResponseWriter, r *http.Request, _ authz.Principal) {
	var out struct {
		Version   int       `json:"version"`
		Text      string    `json:"text"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := a.DB.QueryRow(r.Context(), "SELECT version, text, updated_at FROM iam.banner_current()").Scan(&out.Version, &out.Text, &out.UpdatedAt); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) setBanner(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Text   string `json:"text"`
		Reason string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return
	}
	var version int
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.banner_admin_set($1, $2)", body.Text, body.Reason).Scan(&version)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": version})
}
