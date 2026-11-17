package reportapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/reports"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-010 T-16 (F-010-AC-19 to AC-21; design §3.7): a person's schedules.
// Created, changed, deleted and resumed by their owner only, with
// report.export at the BU; the reason rule applies as to requests.

type scheduleBody struct {
	Kind            string          `json:"kind"`
	BUID            string          `json:"bu_id"`
	Params          json.RawMessage `json:"params"`
	Formats         []string        `json:"formats"`
	Cadence         string          `json:"cadence"`
	Weekday         *int            `json:"weekday"`
	Monthday        *int            `json:"monthday"`
	Hour            *int            `json:"hour"`
	Reason          string          `json:"reason"`
	ExpectedVersion *int            `json:"expected_version"`
}

// checked validates the parts a create and an update share; false after
// answering.
func (a *API) checked(w http.ResponseWriter, body *scheduleBody) (reports.Kind, json.RawMessage, []string, string, bool) {
	k, ok := a.Kinds[body.Kind]
	if !ok {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "kind is not a report kind this installation generates", nil)
		return k, nil, nil, "", false
	}
	formats, err := reports.CheckFormats(body.Formats)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", strings.TrimPrefix(err.Error(), "reports: "), nil)
		return k, nil, nil, "", false
	}
	params, err := k.CheckParams(body.Params)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", strings.TrimPrefix(err.Error(), "reports: "), nil)
		return k, nil, nil, "", false
	}
	if body.Hour == nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "hour (0 to 23, UTC) is required", nil)
		return k, nil, nil, "", false
	}
	reason := strings.TrimSpace(body.Reason)
	if len([]rune(reason)) > 500 {
		problem(w, http.StatusBadRequest, "invalid_value", "reason is at most 500 characters", nil)
		return k, nil, nil, "", false
	}
	return k, params, formats, reason, true
}

func (a *API) listSchedules(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	out := []json.RawMessage{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT report.my_schedules()")
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
	writeJSON(w, http.StatusOK, map[string]any{"schedules": out})
}

func (a *API) createSchedule(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var body scheduleBody
	if !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.BUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id is a business unit id", nil)
		return
	}
	k, params, formats, reason, ok := a.checked(w, &body)
	if !ok || !a.mayExport(w, r, p, body.BUID) {
		return
	}
	if a.Settings == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "report generation is not configured", nil)
		return
	}
	var out json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		need, err := reports.ReasonRequired(ctx, tx, a.Settings, body.BUID)
		if err != nil {
			return err
		}
		if need && reason == "" {
			return errReasonRequired
		}
		var id string
		if err := tx.QueryRow(ctx, "SELECT report.create_schedule($1, $2, $3, $4, $5, $6, $7, $8, $9)::text", k.Name, body.BUID, []byte(params), formats,
			body.Cadence, body.Weekday, body.Monthday, *body.Hour, nullable(reason)).Scan(&id); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT report.get_schedule($1)", id).Scan(&out)
	})
	if a.answered(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// answered answers err (a schedule route's); false when there is none.
func (a *API) answered(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, errReasonRequired):
		problem(w, http.StatusBadRequest, "reason_required", "export.reason_required is in force in this schedule's scope: give a reason", nil)
	default:
		fail(w, err)
	}
	return true
}

func (a *API) getSchedule(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var out json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT report.get_schedule($1)", id).Scan(&out)
	})
	if a.answered(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) updateSchedule(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var body scheduleBody
	if !decode(w, r, &body) {
		return
	}
	if body.ExpectedVersion == nil {
		problem(w, http.StatusBadRequest, "invalid_value", "expected_version is required", nil)
		return
	}
	var out json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		var cur struct {
			Kind string `json:"kind"`
			BU   string `json:"bu_id"`
		}
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT report.get_schedule($1)", id).Scan(&raw); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &cur); err != nil {
			return err
		}
		if body.Kind != "" && body.Kind != cur.Kind || body.BUID != "" && body.BUID != cur.BU {
			return errFixed
		}
		body.Kind = cur.Kind
		_, params, formats, reason, ok := a.checked(w, &body)
		if !ok {
			return errAnswered
		}
		need, err := reports.ReasonRequired(ctx, tx, a.Settings, cur.BU)
		if err != nil {
			return err
		}
		if need && reason == "" {
			return errReasonRequired
		}
		if _, err := tx.Exec(ctx, "SELECT report.update_schedule($1, $2, $3, $4, $5, $6, $7, $8, $9)", id, *body.ExpectedVersion, []byte(params), formats,
			body.Cadence, body.Weekday, body.Monthday, *body.Hour, nullable(reason)); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT report.get_schedule($1)", id).Scan(&out)
	})
	switch {
	case errors.Is(err, errAnswered):
		return
	case errors.Is(err, errFixed):
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "a schedule keeps its kind and business unit; delete it and create another", nil)
		return
	}
	if a.answered(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

var (
	errAnswered = errors.New("reportapi: answered")
	errFixed    = errors.New("reportapi: kind and business unit are fixed")
)

func (a *API) deleteSchedule(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT report.delete_schedule($1, $2)", id, body.Reason)
		return err
	})
	if a.answered(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) resumeSchedule(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var out json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), "SELECT report.resume_schedule($1)", id); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), "SELECT report.get_schedule($1)", id).Scan(&out)
	})
	if a.answered(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}
