package analysisapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/risk"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-006 T-03 (F-006-AC-17 to AC-20; design §3.3, §6.2, §6.3, §8):
// downloads. A CSV is built and its analysis.downloaded events recorded in
// one transaction under the caller's context, and sent only once that
// commits (503 otherwise: audit fails closed). An image is drawn by the
// browser, which first records it here (POST /downloads) and draws nothing
// unless that succeeds. One event per business unit of the downloaded
// results, naming only that unit's results.

// Download views per subject (design §3.3).
var (
	runViews        = []string{"summary", "curve", "histogram", "breakdown", "sensitivity", "comparison"}
	aggregateViews  = []string{"summary", "curve", "histogram", "contributions"}
	comparisonViews = []string{"summary", "curve"}
)

var errAudit = errors.New("analysisapi: the download could not be recorded")

// newDownloadID is a random UUID (version 4) naming a download in its
// events and in the file.
func newDownloadID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// downloaded records the download in tx: one event per business unit,
// naming that unit's results (ids, sorted).
func (a *API) downloaded(ctx context.Context, tx pgx.Tx, p authz.Principal, id, subject, view, format string, byBU map[string][]string) error {
	if a.Audit == nil {
		return errAudit
	}
	bus := make([]string, 0, len(byBU))
	for bu := range byBU {
		bus = append(bus, bu)
	}
	slices.Sort(bus)
	for _, bu := range bus {
		ids := slices.Clone(byBU[bu])
		slices.Sort(ids)
		ids = slices.Compact(ids)
		target := "analysis_" + subject + ":" + ids[0]
		if subject == "comparison" {
			target = "analysis_comparison:" + id
		}
		if err := a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: "analysis.downloaded", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: target, BUID: bu, Attributes: map[string]string{"download_id": id, "subject": subject, "ids": strings.Join(ids, " "),
				"view": view, "format": format}}); err != nil {
			return fmt.Errorf("%w: %v", errAudit, err)
		}
	}
	return nil
}

// answerDownload answers a download's error.
func answerDownload(w http.ResponseWriter, err error) {
	var bad badRequest
	switch {
	case errors.As(err, &bad):
		problem(w, http.StatusUnprocessableEntity, "invalid_value", string(bad), nil)
	case errors.Is(err, errNotSucceeded), errors.Is(err, analysis.ErrNotSucceeded):
		notSucceeded(w)
	case errors.Is(err, analysis.ErrHidden):
		problem(w, http.StatusNotFound, "not_found", "", nil)
	case errors.Is(err, errAudit):
		problem(w, http.StatusServiceUnavailable, "unavailable", "the download could not be recorded in the audit trail", nil)
	default:
		if msg, ok := analysis.IsCompareItems(err); ok {
			problem(w, http.StatusUnprocessableEntity, "invalid_value", msg, nil)
			return
		}
		fail(w, err)
	}
}

type badRequest string

func (b badRequest) Error() string { return string(b) }

// sendCSV writes a recorded CSV.
func sendCSV(w http.ResponseWriter, name string, body []byte) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// runRecord is a run as a download reads it.
type runRecord struct {
	bu, state, scenario, bundle, seed string
	version                           int64
	sets                              []string
	engine, result, name              *string
	iterations                        int
}

func readRunRecord(ctx context.Context, tx pgx.Tx, id string) (runRecord, error) {
	var r runRecord
	err := tx.QueryRow(ctx, `SELECT r.bu_id::text, r.state, r.scenario_id::text, r.bundle_digest, r.seed::text, r.scenario_version, r.control_sets,
		r.engine_version, r.result_digest, s.name, r.iterations FROM analysis.run r LEFT JOIN risk.scenario s ON s.id = r.scenario_id WHERE r.id = $1`, id).
		Scan(&r.bu, &r.state, &r.scenario, &r.bundle, &r.seed, &r.version, &r.sets, &r.engine, &r.result, &r.name, &r.iterations)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, errNotFound
	}
	if err == nil && r.state != "succeeded" {
		err = errNotSucceeded
	}
	return r, err
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// getRunData answers a run's view as CSV (AC-18).
func (a *API) getRunData(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	q := r.URL.Query()
	view, set, rel := q.Get("view"), q.Get("set"), q.Get("relative_to")
	if !slices.Contains(runViews, view) {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "view is one of "+strings.Join(runViews, ", "), nil)
		return
	}
	scale, ok := histogramScale(w, r)
	if !ok {
		return
	}
	dl := newDownloadID()
	var body bytes.Buffer
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		run, err := readRunRecord(ctx, tx, id)
		if err != nil {
			return err
		}
		needSet := view == "histogram" || view == "sensitivity"
		switch {
		case needSet && !slices.Contains(run.sets, set):
			return badRequest("set (a control set of the run) is required for this view")
		case !needSet && set != "":
			return badRequest("set applies to the histogram and sensitivity views")
		case rel != "" && view != "histogram":
			return badRequest("relative_to applies to the histogram view")
		case rel != "" && (rel != run.sets[0] || rel == set):
			return badRequest("relative_to is the run's current control set, and set another one")
		case rel != "" && q.Get("scale") == analysis.ScaleLog:
			return badRequest("a difference is binned on a linear scale")
		}
		sets := []analysis.Set{}
		rows, err := tx.Query(ctx, `SELECT x.control_set, x.summary FROM analysis.result x WHERE x.run_id = $1 ORDER BY array_position($2::text[], x.control_set)`, id, run.sets)
		if err != nil {
			return err
		}
		for rows.Next() {
			var s analysis.Set
			var raw []byte
			if err := rows.Scan(&s.Name, &raw); err != nil {
				rows.Close()
				return err
			}
			if err := json.Unmarshal(raw, &s.Summary); err != nil {
				rows.Close()
				return err
			}
			sets = append(sets, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		of := func(name string) analysis.Set {
			for _, s := range sets {
				if s.Name == name {
					return s
				}
			}
			return analysis.Set{Name: name}
		}
		t := analysis.Table{}
		switch view {
		case "summary":
			t.Header, t.Rows = analysis.SummaryTable(sets)
		case "curve":
			t.Header, t.Rows = analysis.CurveTable(sets)
		case "breakdown":
			t.Header, t.Rows = analysis.BreakdownTable(sets)
		case "comparison":
			t.Header, t.Rows = analysis.ComparisonTable(sets)
		case "sensitivity":
			t.Header, t.Rows = analysis.SensitivityTable(of(set))
		case "histogram":
			series := func(s string) ([]float64, error) {
				var b []byte
				if err := tx.QueryRow(ctx, "SELECT ale FROM analysis.series WHERE run_id = $1 AND control_set = $2", id, s).Scan(&b); err != nil {
					return nil, err
				}
				return analysis.Floats(b, run.iterations)
			}
			v, err := series(set)
			if err != nil {
				return err
			}
			h := analysis.LossHistogram(v, scale)
			if rel != "" {
				base, err := series(rel)
				if err != nil {
					return err
				}
				h = analysis.DifferenceHistogram(v, base)
			}
			t.Header, t.Rows = analysis.HistogramTable(set, rel, h)
		}
		cur, err := risk.Currency(ctx, tx)
		if err != nil {
			return err
		}
		controlSets := strings.Join(run.sets, "; ")
		if set != "" {
			controlSets = set
		}
		t.Meta = [][2]string{{"download", dl}, {"subject", "run"}, {"id", id}, {"view", view}, {"scenario", str(run.name)},
			{"scenario_id", run.scenario}, {"scenario_version", fmt.Sprint(run.version)}, {"control_sets", controlSets},
			{"iterations", fmt.Sprint(run.iterations)}, {"seed", run.seed}, {"bundle_digest", run.bundle}, {"result_digest", str(run.result)},
			{"engine_version", str(run.engine)}, {"currency", cur}, {"independence", independence(sets)}}
		if view == "histogram" {
			t.Meta = append(t.Meta, [2]string{"scale", map[bool]string{true: analysis.ScaleLinear, false: scale}[rel != ""]})
			if rel != "" {
				t.Meta = append(t.Meta, [2]string{"relative_to", rel})
			}
		}
		if err := t.Write(&body); err != nil {
			return err
		}
		return a.downloaded(ctx, tx, p, dl, "run", view, "csv", map[string][]string{run.bu: {id}})
	})
	if err != nil {
		answerDownload(w, err)
		return
	}
	sendCSV(w, analysis.FileName("run", id, view, "csv"), body.Bytes())
}

// independence is the stored statement that inputs are sampled
// independently (F-005-AC-10), from the first summary that has one.
func independence(sets []analysis.Set) string {
	for _, s := range sets {
		if v, ok := s.Summary["independence"].(string); ok {
			return v
		}
	}
	return ""
}

// getAggregateData answers an aggregate's view as CSV (AC-18).
func (a *API) getAggregateData(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	view := r.URL.Query().Get("view")
	if !slices.Contains(aggregateViews, view) {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "view is one of "+strings.Join(aggregateViews, ", "), nil)
		return
	}
	scale, ok := histogramScale(w, r)
	if !ok {
		return
	}
	dl := newDownloadID()
	var body bytes.Buffer
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		var bu, state, name, seed string
		var n int
		var engine, result *string
		var raw, ale []byte
		err := tx.QueryRow(ctx, `SELECT bu_id::text, state, name, seed::text, iterations, engine_version, result_digest, summary, ale
			FROM analysis.aggregate WHERE id = $1`, id).Scan(&bu, &state, &name, &seed, &n, &engine, &result, &raw, &ale)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		if state != "succeeded" {
			return errNotSucceeded
		}
		var s analysis.Summary
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		set := []analysis.Set{{Name: name, Summary: s}}
		t := analysis.Table{}
		switch view {
		case "summary":
			t.Header, t.Rows = analysis.SummaryTable(set)
		case "curve":
			t.Header, t.Rows = analysis.CurveTable(set)
		case "contributions":
			t.Header, t.Rows = analysis.ContributionsTable(s)
		case "histogram":
			v, err := analysis.Floats(ale, n)
			if err != nil {
				return err
			}
			t.Header, t.Rows = analysis.HistogramTable(name, "", analysis.LossHistogram(v, scale))
		}
		cur, err := risk.Currency(ctx, tx)
		if err != nil {
			return err
		}
		t.Meta = [][2]string{{"download", dl}, {"subject", "aggregate"}, {"id", id}, {"view", view}, {"aggregate", name},
			{"iterations", fmt.Sprint(n)}, {"seed", seed}, {"result_digest", str(result)}, {"engine_version", str(engine)}, {"currency", cur},
			{"independence", independence(set)}}
		if view == "histogram" {
			t.Meta = append(t.Meta, [2]string{"scale", scale})
		}
		if err := t.Write(&body); err != nil {
			return err
		}
		return a.downloaded(ctx, tx, p, dl, "aggregate", view, "csv", map[string][]string{bu: {id}})
	})
	if err != nil {
		answerDownload(w, err)
		return
	}
	sendCSV(w, analysis.FileName("aggregate", id, view, "csv"), body.Bytes())
}

// comparisonBUs groups a comparison's results by business unit.
func comparisonBUs(c map[string]any) map[string][]string {
	out := map[string][]string{}
	items, _ := c["items"].([]map[string]any)
	for _, it := range items {
		bu, _ := it["bu_id"].(string)
		id, _ := it["id"].(string)
		out[bu] = append(out[bu], id)
	}
	return out
}

// getComparisonData answers a comparison as CSV (AC-18): all visible or
// one 404, as the comparison itself.
func (a *API) getComparisonData(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	view := r.URL.Query().Get("view")
	if !slices.Contains(comparisonViews, view) {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "view is one of "+strings.Join(comparisonViews, ", "), nil)
		return
	}
	items, err := analysis.ParseItems(r.URL.Query()["item"])
	if err != nil {
		answerDownload(w, err)
		return
	}
	dl := newDownloadID()
	var body bytes.Buffer
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		c, err := analysis.Compare(ctx, tx, items)
		if err != nil {
			return err
		}
		t := analysis.Table{}
		if view == "summary" {
			t.Header, t.Rows = analysis.ComparisonSummaryTable(c)
		} else {
			t.Header, t.Rows = analysis.ComparisonCurveTable(c)
		}
		cur, err := risk.Currency(ctx, tx)
		if err != nil {
			return err
		}
		names := make([]string, len(items))
		for i, it := range items {
			names[i] = it.String()
		}
		statement, _ := c["statement"].(string)
		t.Meta = [][2]string{{"download", dl}, {"subject", "comparison"}, {"items", strings.Join(names, " ")}, {"view", view},
			{"unlike", strings.Join(c["unlike"].([]string), " ")}, {"sampling_noise", statement}, {"currency", cur}}
		for i, it := range c["items"].([]map[string]any) {
			digest, _ := it["result_digest"].(*string)
			t.Meta = append(t.Meta, [2]string{fmt.Sprintf("item_%d_result_digest", i+1), str(digest)})
		}
		if err := t.Write(&body); err != nil {
			return err
		}
		return a.downloaded(ctx, tx, p, dl, "comparison", view, "csv", comparisonBUs(c))
	})
	if err != nil {
		answerDownload(w, err)
		return
	}
	sendCSV(w, analysis.FileName("comparison", dl, view, "csv"), body.Bytes())
}

type downloadBody struct {
	Subject string   `json:"subject"`
	ID      string   `json:"id"`
	Items   []string `json:"items"`
	View    string   `json:"view"`
	Format  string   `json:"format"`
}

// createDownload records an image download before the browser draws it
// (AC-17, AC-19; design §6.3): the same visibility as the views; 201 with
// the download's id, which the image carries.
func (a *API) createDownload(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var body downloadBody
	if !decode(w, r, &body) {
		return
	}
	views := map[string][]string{"run": runViews, "aggregate": aggregateViews, "comparison": comparisonViews}[body.Subject]
	switch {
	case views == nil:
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "subject is run, aggregate or comparison", nil)
		return
	case body.Format != "svg" && body.Format != "png":
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "format is svg or png", nil)
		return
	case !slices.Contains(views, body.View):
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "view is one of "+strings.Join(views, ", "), nil)
		return
	case body.Subject == "comparison" && body.ID != "", body.Subject != "comparison" && len(body.Items) > 0:
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "a comparison names items; a run or aggregate its id", nil)
		return
	case body.Subject != "comparison" && !uuidRE.MatchString(body.ID):
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	var items []analysis.Item
	if body.Subject == "comparison" {
		var err error
		if items, err = analysis.ParseItems(body.Items); err != nil {
			answerDownload(w, err)
			return
		}
	}
	dl := newDownloadID()
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		byBU := map[string][]string{}
		switch body.Subject {
		case "run":
			run, err := readRunRecord(ctx, tx, body.ID)
			if err != nil {
				return err
			}
			byBU[run.bu] = []string{body.ID}
		case "aggregate":
			var bu, state string
			err := tx.QueryRow(ctx, "SELECT bu_id::text, state FROM analysis.aggregate WHERE id = $1", body.ID).Scan(&bu, &state)
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			if err != nil {
				return err
			}
			if state != "succeeded" {
				return errNotSucceeded
			}
			byBU[bu] = []string{body.ID}
		default:
			c, err := analysis.Compare(ctx, tx, items)
			if err != nil {
				return err
			}
			byBU = comparisonBUs(c)
		}
		return a.downloaded(ctx, tx, p, dl, body.Subject, body.View, body.Format, byBU)
	})
	if err != nil {
		answerDownload(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"download_id": dl})
}
