package analysisapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/risk"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-005 T-11 (F-005-AC-01 to AC-06, AC-11 to AC-15, AC-21 to AC-23;
// design §5, §6.1): runs.

// fail answers a database or context error.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, errNotFound), errors.As(err, &pg) && pg.Code == "P0002":
		problem(w, http.StatusNotFound, "not_found", "", nil)
	case errors.Is(err, authz.ErrNoDBContext):
		problem(w, http.StatusUnauthorized, "unauthenticated", "", nil)
	case errors.Is(err, risk.ErrNoVersion):
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "the scenario has no such version", nil)
	case errors.Is(err, analysis.ErrControlSet):
		problem(w, http.StatusUnprocessableEntity, "invalid_value", strings.TrimPrefix(err.Error(), "analysis: control sets: "), nil)
	case errors.As(err, &pg) && pg.Code == "42501":
		problem(w, http.StatusForbidden, "forbidden", "", nil)
	case errors.As(err, &pg) && pg.Code == "PF024":
		msg := strings.TrimPrefix(strings.TrimPrefix(pg.Message, "analysis.run: "), "analysis: ")
		switch pg.Hint {
		case "archived":
			problem(w, http.StatusConflict, "archived", "the scenario is archived; restore it to run it", nil)
		case "too_many_runs":
			problem(w, http.StatusConflict, "too_many_runs", msg, nil)
		case "iterations":
			problem(w, http.StatusUnprocessableEntity, "invalid_value", msg, nil)
		case "finished":
			problem(w, http.StatusConflict, "finished", msg, nil)
		case "bundle_changed":
			problem(w, http.StatusConflict, "bundle_changed", msg, nil)
		default:
			problem(w, http.StatusConflict, "refused", msg, nil)
		}
	case errors.As(err, &pg) && pg.Code == "23514":
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "the run is too large (iterations × control sets at most 20,000,000)", nil)
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "", nil)
	}
}

type createBody struct {
	ScenarioID  string   `json:"scenario_id"`
	Version     int64    `json:"version"`
	ControlSets []string `json:"control_sets"`
	Iterations  int      `json:"iterations"`
	Seed        *string  `json:"seed"` // decimal, 0 to 2^64 - 1 (a string: JSON numbers lose precision past 2^53)
}

// createRun requests a run (AC-01, AC-05; design §6.1).
func (a *API) createRun(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var body createBody
	if !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.ScenarioID) || body.Version < 1 || body.Iterations < 0 {
		problem(w, http.StatusBadRequest, "invalid_value", "scenario_id (a uuid) and version (1 or more) are required; iterations is positive", nil)
		return
	}
	req := analysis.RunRequest{ScenarioID: body.ScenarioID, Version: body.Version, ControlSets: body.ControlSets, Iterations: body.Iterations}
	if body.Seed != nil {
		s, err := strconv.ParseUint(*body.Seed, 10, 64)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_value", "seed is a decimal integer from 0 to 18446744073709551615", nil)
			return
		}
		req.Seed = &s
	}
	if a.Enqueue == nil {
		problem(w, http.StatusServiceUnavailable, "engine_unavailable", "no simulation engine is configured", nil)
		return
	}
	bu, err := a.scenarioBU(r.Context(), p, body.ScenarioID)
	if err != nil {
		fail(w, err)
		return
	}
	if !a.mayRun(w, r, p, bu) {
		return
	}
	lim, err := a.Settings.Limits(r.Context())
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "the simulation settings are not available", nil)
		return
	}
	var run map[string]any
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		got, err := analysis.Request(r.Context(), tx, a.Enqueue, req, lim)
		if err != nil {
			return err
		}
		run, err = readRun(r.Context(), tx, got.ID)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

// scenarioBU is the scenario's BU as the caller sees it (404 otherwise).
func (a *API) scenarioBU(ctx context.Context, p authz.Principal, id string) (string, error) {
	var bu string
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT bu_id::text FROM risk.scenario WHERE id = $1", id).Scan(&bu)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		return err
	})
	return bu, err
}

// mayRun answers and returns false unless the caller holds analysis.run at
// bu (403 for someone who can see analyses there, 404 otherwise).
func (a *API) mayRun(w http.ResponseWriter, r *http.Request, p authz.Principal, bu string) bool {
	err := a.Authz.Check(r.Context(), p, permRun, bu)
	if err == nil {
		return true
	}
	var su *authz.StepUpError
	if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
		server.WriteAuthzError(w, err)
		return false
	}
	if a.Authz.Check(r.Context(), p, permView, bu) == nil {
		problem(w, http.StatusForbidden, "forbidden", "running a simulation needs analysis.run at this business unit", nil)
		return false
	}
	problem(w, http.StatusNotFound, "not_found", "", nil)
	return false
}

const runColumns = `r.id::text, r.bu_id::text, r.scenario_id::text, r.scenario_version, r.bundle_digest, r.seed::text, r.iterations, r.control_sets,
	r.requested_by::text, r.requested_at, r.state, r.progress::float8, r.started_at, r.finished_at, r.cancel_reason, r.failure, r.failure_detail,
	r.engine_version, r.architecture, r.image_digest, r.validation, r.warnings, r.result_digest, r.reproduces::text, r.reproduction, r.seq`

func scanRun(row pgx.Row) (map[string]any, error) {
	var (
		id, bu, scenario, digest, seed, by, state string
		version, iterations                       int64
		sets                                      []string
		requestedAt                               time.Time
		progress                                  float64
		startedAt, finishedAt                     *time.Time
		cancelReason, failure, failureDetail      *string
		engineVersion, architecture, imageDigest  *string
		resultDigest, reproduces, reproduction    *string
		validation, warnings                      []byte
		seq                                       int64
	)
	if err := row.Scan(&id, &bu, &scenario, &version, &digest, &seed, &iterations, &sets, &by, &requestedAt, &state, &progress,
		&startedAt, &finishedAt, &cancelReason, &failure, &failureDetail, &engineVersion, &architecture, &imageDigest, &validation,
		&warnings, &resultDigest, &reproduces, &reproduction, &seq); err != nil {
		return nil, err
	}
	out := map[string]any{
		"id": id, "bu_id": bu, "scenario_id": scenario, "scenario_version": version, "bundle_digest": digest, "seed": seed,
		"iterations": iterations, "control_sets": sets, "requested_by": by, "requested_at": requestedAt, "state": state, "progress": progress,
		"started_at": startedAt, "finished_at": finishedAt, "cancel_reason": cancelReason, "failure": failure, "failure_detail": failureDetail,
		"result_digest": resultDigest, "reproduces": reproduces, "reproduction": reproduction, "warnings": json.RawMessage(warnings), "seq": seq,
	}
	if engineVersion != nil {
		eng := map[string]any{"version": *engineVersion, "architecture": architecture, "image_digest": imageDigest}
		if validation != nil {
			eng["validation"] = json.RawMessage(validation)
		}
		out["engine"] = eng
	} else {
		out["engine"] = nil
	}
	return out, nil
}

func readRun(ctx context.Context, tx pgx.Tx, id string) (map[string]any, error) {
	run, err := scanRun(tx.QueryRow(ctx, "SELECT "+runColumns+" FROM analysis.run r WHERE r.id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	return run, err
}

// listRuns lists a scenario's runs, newest first (AC-02): ?scenario= is
// required, ?before= (a run's seq) pages, ?limit= is 1 to 200 (50).
func (a *API) listRuns(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	q := r.URL.Query()
	scenario := q.Get("scenario")
	if !uuidRE.MatchString(scenario) {
		problem(w, http.StatusBadRequest, "invalid_value", "scenario (a uuid) is required", nil)
		return
	}
	limit := 50
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 200 {
			problem(w, http.StatusBadRequest, "invalid_value", "limit is 1 to 200", nil)
			return
		}
		limit = n
	}
	var before any
	if s := q.Get("before"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 1 {
			problem(w, http.StatusBadRequest, "invalid_value", "before is a run's seq", nil)
			return
		}
		before = n
	}
	var runs []map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT "+runColumns+" FROM analysis.run r WHERE r.scenario_id = $1 AND ($2::bigint IS NULL OR r.seq < $2)"+
			" ORDER BY r.seq DESC LIMIT $3", scenario, before, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			run, err := scanRun(rows)
			if err != nil {
				return err
			}
			runs = append(runs, run)
		}
		return rows.Err()
	})
	if err != nil {
		fail(w, err)
		return
	}
	if runs == nil {
		runs = []map[string]any{}
	}
	out := map[string]any{"runs": runs, "next_before": nil}
	if len(runs) == limit {
		out["next_before"] = runs[len(runs)-1]["seq"]
	}
	writeJSON(w, http.StatusOK, out)
}

// getRun answers a run: state, progress, inputs, engine record, warnings,
// and once it succeeded every set's summary (AC-02, AC-11 to AC-15).
func (a *API) getRun(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	var run map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		if run, err = readRun(r.Context(), tx, id); err != nil {
			return err
		}
		results := []map[string]any{}
		if run["state"] == "succeeded" {
			rows, err := tx.Query(r.Context(), `SELECT x.control_set, x.summary FROM analysis.result x JOIN analysis.run r ON r.id = x.run_id
				WHERE x.run_id = $1 ORDER BY array_position(r.control_sets, x.control_set)`, id)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var set string
				var summary []byte
				if err := rows.Scan(&set, &summary); err != nil {
					return err
				}
				results = append(results, map[string]any{"control_set": set, "summary": json.RawMessage(summary)})
			}
			if err := rows.Err(); err != nil {
				return err
			}
		}
		run["results"] = results
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// getRunSeries answers a succeeded run's per-year annual losses for one
// control set (float64 little-endian), for F-006's charts.
func (a *API) getRunSeries(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	var ale []byte
	var iterations int
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		err := tx.QueryRow(r.Context(), `SELECT s.ale, r.iterations FROM analysis.series s JOIN analysis.run r ON r.id = s.run_id
			WHERE s.run_id = $1 AND s.control_set = $2 AND r.state = 'succeeded'`, id, r.PathValue("set")).Scan(&ale, &iterations)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Fair-Iterations", strconv.Itoa(iterations))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(ale)
}

// cancelRun cancels a queued or running run with a reason (AC-03): the
// requester, or analysis.run at its BU (the database decides; others see
// 404). The worker stops at its next progress report.
func (a *API) cancelRun(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return
	}
	reason := strings.TrimSpace(body.Reason)
	switch {
	case reason == "" || len([]rune(reason)) > 1000:
		problem(w, http.StatusBadRequest, "invalid_value", "reason is required, at most 1000 characters", nil)
		return
	case audit.LooksSecret(reason):
		problem(w, http.StatusBadRequest, "invalid_value", "reason looks like a secret", nil)
		return
	}
	var run map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), "SELECT analysis.cancel_run($1, $2)", id, reason); err != nil {
			return err
		}
		var err error
		run, err = readRun(r.Context(), tx, id)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}
