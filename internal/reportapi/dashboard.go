package reportapi

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-010 T-14 (F-010-AC-01 to AC-05; design §3.1): the dashboard of a BU's
// subtree, read in one snapshot under the caller's context.
func (a *API) getDashboard(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	bu := r.URL.Query().Get("bu")
	if !uuidRE.MatchString(bu) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu is a business unit id", nil)
		return
	}
	if err := a.Authz.Check(r.Context(), p, permView, bu); err != nil {
		var su *authz.StepUpError
		if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
			server.WriteAuthzError(w, err)
			return
		}
		notFound(w)
		return
	}
	var d *reports.Dashboard
	err := authz.WithDBSnapshot(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		d, err = reports.ReadDashboard(r.Context(), tx, bu)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}
