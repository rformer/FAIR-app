package reportapi

import (
	"errors"
	"net/http"
	"time"

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

// getTrend answers a BU subtree's snapshots in a period (F-010 T-15;
// AC-07; design §3.2): from and to are RFC 3339 times or dates (default
// the last 365 days); report.trend gives only what the caller may see.
func (a *API) getTrend(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	q := r.URL.Query()
	bu := q.Get("bu")
	if !uuidRE.MatchString(bu) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu is a business unit id", nil)
		return
	}
	to, from := time.Now().UTC(), time.Time{}
	for _, x := range []struct {
		name string
		t    *time.Time
	}{{"to", &to}, {"from", &from}} {
		v := q.Get(x.name)
		if v == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			if t, err = time.Parse(time.DateOnly, v); err != nil {
				problem(w, http.StatusBadRequest, "invalid_value", x.name+" is an RFC 3339 time or a date", nil)
				return
			}
			if x.name == "to" {
				t = t.AddDate(0, 0, 1).Add(-time.Nanosecond)
			}
		}
		*x.t = t
	}
	if from.IsZero() {
		from = to.AddDate(-1, 0, 0)
	}
	if from.After(to) || to.Sub(from) > 3651*24*time.Hour {
		problem(w, http.StatusBadRequest, "invalid_value", "from is before to, at most 10 years apart", nil)
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
	var points []reports.TrendPoint
	err := authz.WithDBSnapshot(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		points, err = reports.ReadTrend(r.Context(), tx, bu, from, to)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bu_id": bu, "from": from, "to": to, "snapshots": points})
}
