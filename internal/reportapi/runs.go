package reportapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/objstore"
	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-010 T-09 (F-010-AC-14 to AC-18, AC-22; design §3.6): requests, the
// requester's runs and downloads.

// listKinds answers the report kinds this installation generates.
func (a *API) listKinds(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	out := []map[string]any{}
	for _, k := range a.Kinds {
		out = append(out, map[string]any{"kind": k.Name, "title": k.Title, "formats": reports.Formats})
	}
	slices.SortFunc(out, func(x, y map[string]any) int { return strings.Compare(x["kind"].(string), y["kind"].(string)) })
	writeJSON(w, http.StatusOK, map[string]any{"kinds": out, "limits": map[string]any{"risks": reports.MaxRisks, "running": reports.MaxRunning,
		"file_bytes": reports.MaxFile}})
}

type requestBody struct {
	Kind    string          `json:"kind"`
	BUID    string          `json:"bu_id"`
	Params  json.RawMessage `json:"params"`
	Formats []string        `json:"formats"`
	Reason  string          `json:"reason"`
}

// mayExport: report.export at bu; else 403 with report.view there, 404
// without.
func (a *API) mayExport(w http.ResponseWriter, r *http.Request, p authz.Principal, bu string) bool {
	err := a.Authz.Check(r.Context(), p, permExport, bu)
	if err == nil {
		return true
	}
	var su *authz.StepUpError
	if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
		server.WriteAuthzError(w, err)
		return false
	}
	if a.Authz.Check(r.Context(), p, permView, bu) == nil {
		problem(w, http.StatusForbidden, "forbidden", "generating a report needs report.export at this business unit", nil)
		return false
	}
	notFound(w)
	return false
}

var errReasonRequired = errors.New("reportapi: a reason is required")

// requestReport queues a report (AC-15, AC-16, AC-18, AC-22): 202 with the
// run.
func (a *API) requestReport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var body requestBody
	if !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.BUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id is a business unit id", nil)
		return
	}
	k, ok := a.Kinds[body.Kind]
	if !ok {
		var names []string
		for n := range a.Kinds {
			names = append(names, n)
		}
		slices.Sort(names)
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "kind is one of: "+strings.Join(names, ", "), nil)
		return
	}
	formats, err := reports.CheckFormats(body.Formats)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", strings.TrimPrefix(err.Error(), "reports: "), nil)
		return
	}
	params, err := k.CheckParams(body.Params)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", strings.TrimPrefix(err.Error(), "reports: "), nil)
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if len([]rune(reason)) > 500 {
		problem(w, http.StatusBadRequest, "invalid_value", "reason is at most 500 characters", nil)
		return
	}
	if !a.mayExport(w, r, p, body.BUID) {
		return
	}
	if a.Enqueue == nil || a.Settings == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "report generation is not configured", nil)
		return
	}
	var run json.RawMessage
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		need, err := reports.ReasonRequired(ctx, tx, a.Settings, body.BUID)
		if err != nil {
			return err
		}
		if need && reason == "" {
			return errReasonRequired
		}
		id, err := reports.RequestRun(ctx, tx, a.Enqueue, reports.Request{Kind: k.Name, BU: body.BUID, Params: params, Formats: formats, Reason: reason})
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT report.get_run($1)", id).Scan(&run)
	})
	if errors.Is(err, errReasonRequired) {
		problem(w, http.StatusBadRequest, "reason_required", "export.reason_required is in force in this report's scope: give a reason", nil)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/reports/"+runID(run))
	writeJSON(w, http.StatusAccepted, run)
}

func runID(run json.RawMessage) string {
	var v struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(run, &v)
	return v.ID
}

// listReports answers the caller's own runs, newest first (AC-15).
func (a *API) listReports(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	limit, offset := 50, 0
	q := r.URL.Query()
	for _, x := range []struct {
		name     string
		v        *int
		min, max int
	}{{"limit", &limit, 1, 200}, {"offset", &offset, 0, 1_000_000}} {
		if s := q.Get(x.name); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < x.min || n > x.max {
				problem(w, http.StatusBadRequest, "invalid_value", x.name+" is out of range", nil)
				return
			}
			*x.v = n
		}
	}
	out := []json.RawMessage{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT report.my_runs($1, $2)", limit+1, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var j json.RawMessage
			if err := rows.Scan(&j); err != nil {
				return err
			}
			out = append(out, j)
		}
		return rows.Err()
	})
	if err != nil {
		fail(w, err)
		return
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": out, "more": more})
}

// getReport answers one of the caller's runs with its progress and files.
func (a *API) getReport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var run json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT report.get_run($1)", id).Scan(&run)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// downloadFile sends a file to its requester (AC-14, AC-17): report.export
// re-checked (the cache here, the database in report.download), the
// download recorded and the object opened before the transaction commits;
// nothing is sent unless both succeed.
func (a *API) downloadFile(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id, format := r.PathValue("id"), r.PathValue("format")
	if !uuidRE.MatchString(id) || !slices.Contains(reports.Formats, format) {
		notFound(w)
		return
	}
	if a.Store == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "the report store is not configured", nil)
		return
	}
	var f struct {
		Key     string `json:"object_key"`
		Version string `json:"version_id"`
		Size    int64  `json:"size"`
		SHA256  string `json:"sha256"`
	}
	var body io.ReadCloser
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		var bu string
		if err := tx.QueryRow(ctx, "SELECT (report.get_run($1)) ->> 'bu_id'", id).Scan(&bu); err != nil {
			return err
		}
		if err := a.Authz.Check(ctx, p, permExport, bu); err != nil {
			return errForbidden{err}
		}
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT report.download($1, $2)", id, format).Scan(&raw); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return err
		}
		rc, err := a.Store.Open(ctx, objstore.Version{Key: f.Key, VersionID: f.Version})
		if err != nil {
			return errors.Join(errAudit, err)
		}
		body = rc
		return nil
	})
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		var fb errForbidden
		switch {
		case errors.As(err, &fb):
			var su *authz.StepUpError
			if errors.As(fb.err, &su) || errors.Is(fb.err, authz.ErrStepUpRequired) {
				server.WriteAuthzError(w, fb.err)
				return
			}
			problem(w, http.StatusForbidden, "forbidden", "downloading needs report.export at the report's business unit", nil)
		case errors.Is(err, errAudit):
			problem(w, http.StatusServiceUnavailable, "unavailable", "the file could not be opened", nil)
		default:
			fail(w, err)
		}
		return
	}
	defer func() { _ = body.Close() }()
	w.Header().Set("Content-Type", reports.MediaType(format))
	w.Header().Set("Content-Disposition", `attachment; filename="`+reports.FileName(format)+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	w.Header().Set("X-Fair-Digest", "sha256="+f.SHA256)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, body)
}

type errForbidden struct{ err error }

func (e errForbidden) Error() string { return "reportapi: forbidden: " + e.err.Error() }
