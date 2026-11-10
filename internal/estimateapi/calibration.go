package estimateapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-004 T-10 (AC-20 to AC-23, AC-27 to AC-29; design §4.2, §6.5):
// calibration exercises and records, through estimate_definer's functions,
// which score and decide what the caller may see.

const (
	permCalibrationTake  authz.Permission = "calibration.take"
	permCalibrationAudit authz.Permission = "calibration.audit"
)

// Settings reads F-004's settings (settings.Client).
type Settings interface {
	Duration(key, buID string) (time.Duration, error)
	Int(key, buID string) (int, error)
}

// calibrationSettings are the values the functions take, with every
// built-in profile's defaults when a setting cannot be read.
func (a *API) calibrationSettings() (size int, reuse, window time.Duration, minAnswers int) {
	size, reuse, window, minAnswers = 20, 180*24*time.Hour, 365*24*time.Hour, 20
	if a.Settings == nil {
		return
	}
	if v, err := a.Settings.Int(settings.KeyCalibrationExerciseSize, ""); err == nil {
		size = v
	}
	if v, err := a.Settings.Duration(settings.KeyCalibrationReusePeriod, ""); err == nil {
		reuse = v
	}
	if v, err := a.Settings.Duration(settings.KeyCalibrationWindow, ""); err == nil {
		window = v
	}
	if v, err := a.Settings.Int(settings.KeyCalibrationMinAnswers, ""); err == nil {
		minAnswers = v
	}
	return
}

// interval writes a duration as PostgreSQL reads it.
func interval(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d/time.Second)) }

// callJSON runs one function returning jsonb in the caller's context.
func (a *API) callJSON(w http.ResponseWriter, r *http.Request, p authz.Principal, status int, sql string, args ...any) {
	var out json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), sql, args...).Scan(&out)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, status, out)
}

// startExercise starts an exercise, or resumes the unsubmitted one (AC-20,
// AC-21): questions only, no truths.
func (a *API) startExercise(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permCalibrationTake}) {
		return
	}
	size, reuse, _, _ := a.calibrationSettings()
	if size > 50 {
		size = 50 // the service's cap (design §4.4)
	}
	a.callJSON(w, r, p, http.StatusOK, "SELECT estimate.start_exercise($1, $2::interval)", size, interval(reuse))
}

// getExercise reads one of the caller's exercises; truths only once
// submitted (AC-21, AC-22).
func (a *API) getExercise(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permCalibrationTake}) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	a.callJSON(w, r, p, http.StatusOK, "SELECT estimate.exercise($1)", id)
}

// submitExercise submits every answer of an exercise; the database scores
// it and gives back the truths with their sources (AC-22, AC-23).
func (a *API) submitExercise(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Answers []map[string]json.RawMessage `json:"answers"`
	}
	if !a.anywhere(w, r, p, []authz.Permission{permCalibrationTake}) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	if len(body.Answers) == 0 || len(body.Answers) > 50 {
		problem(w, http.StatusBadRequest, "invalid_value", "answers lists every question of the exercise", nil)
		return
	}
	answers, _ := json.Marshal(body.Answers)
	_, _, window, minAnswers := a.calibrationSettings()
	a.callJSON(w, r, p, http.StatusOK, "SELECT estimate.submit_exercise($1, $2::jsonb, $3::interval, $4)", id, string(answers), interval(window), minAnswers)
}

// getMyCalibration is the caller's own record (AC-27).
func (a *API) getMyCalibration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permCalibrationTake}) {
		return
	}
	a.callJSON(w, r, p, http.StatusOK, "SELECT estimate.my_calibration()")
}

// getPersonCalibration is another person's record as far as the caller may
// see it (AC-28, AC-29); each view is recorded.
func (a *API) getPersonCalibration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permEstimateRequest, permCalibrationAudit}) {
		return
	}
	id := r.PathValue("user")
	bu := r.URL.Query().Get("bu")
	if !uuidRE.MatchString(id) || (bu != "" && !uuidRE.MatchString(bu)) {
		problem(w, http.StatusBadRequest, "invalid_value", "the person and bu are UUIDs", nil)
		return
	}
	var buArg any
	if bu != "" {
		buArg = bu
	}
	a.callJSON(w, r, p, http.StatusOK, "SELECT estimate.calibration_of($1, $2)", id, buArg)
}
