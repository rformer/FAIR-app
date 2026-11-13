package analysisapi

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-006 T-02 (F-006-AC-10, AC-11, AC-13, AC-20; design §3.2, §5):
// comparisons. One read-only snapshot under the caller's context; any item
// the caller cannot see, or that does not exist, answers the same 404
// whichever item it is (AC-13); then a set that is not the run's is 422,
// then an item without results 409.

// getComparison answers ?item=…&item=… (2 to 6, in order; the first is
// the base).
func (a *API) getComparison(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	items, err := analysis.ParseItems(r.URL.Query()["item"])
	if msg, ok := analysis.IsCompareItems(err); ok {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", msg, nil)
		return
	}
	var out map[string]any
	err = authz.WithDBSnapshot(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		out, err = analysis.Compare(r.Context(), tx, items)
		return err
	})
	if msg, ok := analysis.IsCompareItems(err); ok {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", msg, nil)
		return
	}
	switch {
	case errors.Is(err, analysis.ErrHidden):
		problem(w, http.StatusNotFound, "not_found", "", nil)
	case errors.Is(err, analysis.ErrNotSucceeded):
		notSucceeded(w)
	case err != nil:
		fail(w, err)
	default:
		writeJSON(w, http.StatusOK, out)
	}
}
