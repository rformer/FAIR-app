package analysisapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-006 T-01 (F-006-AC-02, AC-07, AC-09, AC-20; design §3.1, §5):
// histograms of a succeeded run's or aggregate's per-year series, computed
// on request under the caller's RLS. Markers (mean and percentiles) are
// the stored summary's: the set's `ale`, or for a difference its
// `comparison.difference` (null when the summary has none).

var errNotSucceeded = errors.New("analysisapi: not succeeded")

// notSucceeded answers 409 for a result the caller sees that has none yet.
func notSucceeded(w http.ResponseWriter) {
	problem(w, http.StatusConflict, "not_succeeded", "it has no results: it has not succeeded", nil)
}

// histogramScale reads ?scale= (log by default); false after answering 422.
func histogramScale(w http.ResponseWriter, r *http.Request) (string, bool) {
	switch s := r.URL.Query().Get("scale"); s {
	case "", analysis.ScaleLog:
		return analysis.ScaleLog, true
	case analysis.ScaleLinear:
		return s, true
	default:
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "scale is log or linear", nil)
		return "", false
	}
}

// markers picks the mean and percentiles of a stored summary at path.
func markers(summary []byte, path ...string) any {
	var v any
	if json.Unmarshal(summary, &v) != nil {
		return nil
	}
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return map[string]any{"mean": m["mean"], "percentiles": m["percentiles"]}
}

// getRunHistogram answers ?set='s annual loss in bins (?scale=log|linear),
// or with ?relative_to=<the current set> its per-year difference from the
// current set (linear only; AC-09 compares each set with the current one).
func (a *API) getRunHistogram(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	q := r.URL.Query()
	set, rel := q.Get("set"), q.Get("relative_to")
	if set == "" {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "set (a control set of the run) is required", nil)
		return
	}
	scale, ok := histogramScale(w, r)
	if !ok {
		return
	}
	if rel != "" && q.Get("scale") == analysis.ScaleLog {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "a difference is binned on a linear scale", nil)
		return
	}
	var out map[string]any
	var bad string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		var state string
		var sets []string
		var n int
		err := tx.QueryRow(ctx, "SELECT state, control_sets, iterations FROM analysis.run WHERE id = $1", id).Scan(&state, &sets, &n)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case state != "succeeded":
			return errNotSucceeded
		case !slices.Contains(sets, set):
			bad = "set is not a control set of the run"
			return nil
		case rel != "" && rel != sets[0]:
			bad = "relative_to is the run's current control set (" + sets[0] + ")"
			return nil
		case rel == set:
			bad = "relative_to is another control set than set"
			return nil
		}
		series := func(s string) ([]float64, error) {
			var b []byte
			if err := tx.QueryRow(ctx, "SELECT ale FROM analysis.series WHERE run_id = $1 AND control_set = $2", id, s).Scan(&b); err != nil {
				return nil, err
			}
			return analysis.Floats(b, n)
		}
		var summary []byte
		if err := tx.QueryRow(ctx, "SELECT summary FROM analysis.result WHERE run_id = $1 AND control_set = $2", id, set).Scan(&summary); err != nil {
			return err
		}
		v, err := series(set)
		if err != nil {
			return err
		}
		var h analysis.Histogram
		var mk any
		if rel != "" {
			base, err := series(rel)
			if err != nil {
				return err
			}
			h, mk = analysis.DifferenceHistogram(v, base), markers(summary, "comparison", "difference")
		} else {
			h, mk = analysis.LossHistogram(v, scale), markers(summary, "ale")
		}
		out = histogramBody(h, mk)
		out["run_id"], out["control_set"] = id, set
		out["relative_to"] = nil
		if rel != "" {
			out["relative_to"] = rel
		}
		return nil
	})
	switch {
	case errors.Is(err, errNotSucceeded):
		notSucceeded(w)
	case err != nil:
		fail(w, err)
	case bad != "":
		problem(w, http.StatusUnprocessableEntity, "invalid_value", bad, nil)
	default:
		writeJSON(w, http.StatusOK, out)
	}
}

// getAggregateHistogram answers an aggregate's annual loss in bins (AC-07);
// the aggregate is visible only with every member (F-005-AC-19).
func (a *API) getAggregateHistogram(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	if r.URL.Query().Get("relative_to") != "" || r.URL.Query().Get("set") != "" {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "an aggregate has one series: set and relative_to do not apply", nil)
		return
	}
	scale, ok := histogramScale(w, r)
	if !ok {
		return
	}
	var out map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var state string
		var n int
		var ale, summary []byte
		err := tx.QueryRow(r.Context(), "SELECT state, iterations, ale, summary FROM analysis.aggregate WHERE id = $1", id).Scan(&state, &n, &ale, &summary)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		if state != "succeeded" {
			return errNotSucceeded
		}
		v, err := analysis.Floats(ale, n)
		if err != nil {
			return err
		}
		out = histogramBody(analysis.LossHistogram(v, scale), markers(summary, "ale"))
		out["aggregate_id"] = id
		return nil
	})
	switch {
	case errors.Is(err, errNotSucceeded):
		notSucceeded(w)
	case err != nil:
		fail(w, err)
	default:
		writeJSON(w, http.StatusOK, out)
	}
}

func histogramBody(h analysis.Histogram, mk any) map[string]any {
	out := map[string]any{"scale": h.Scale, "n": h.N, "zero": h.Zero, "zero_share": h.ZeroShare, "edges": h.Edges, "counts": h.Counts, "markers": mk}
	if h.BothNone != nil {
		out["both_none"] = *h.BothNone
	}
	return out
}
