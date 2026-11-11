package analysisapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-005 T-12 (F-005-AC-16, AC-18, AC-19, AC-23; design §5, §6.2, §6.4):
// reproductions and aggregates.

// reproduceRun requests a run with a succeeded run's recorded inputs; it is
// compared with the original when it succeeds (match, mismatch,
// other_version, other_architecture). The bundle is rebuilt and must have
// the recorded digest (409 bundle_changed).
func (a *API) reproduceRun(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	var orig map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		orig, err = readRun(r.Context(), tx, id)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if !a.mayRun(w, r, p, orig["bu_id"].(string)) {
		return
	}
	if orig["state"] != "succeeded" {
		problem(w, http.StatusConflict, "refused", "only a succeeded run is reproduced", nil)
		return
	}
	if a.Enqueue == nil {
		problem(w, http.StatusServiceUnavailable, "engine_unavailable", "no simulation engine is configured", nil)
		return
	}
	seed, _ := strconv.ParseUint(orig["seed"].(string), 10, 64)
	req := analysis.RunRequest{ScenarioID: orig["scenario_id"].(string), Version: orig["scenario_version"].(int64), ControlSets: orig["control_sets"].([]string),
		Iterations: int(orig["iterations"].(int64)), Seed: &seed, Reproduces: id}
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

type aggregateBody struct {
	BUID    string               `json:"bu_id"`
	Name    string               `json:"name"`
	Seed    *string              `json:"seed"`
	Members []analysis.MemberRef `json:"members"`
}

// createAggregate requests an aggregate of runs' control sets (AC-18):
// analysis.run at the chosen BU; every member a succeeded run the caller
// sees, in the BU's subtree, of the same iterations (the database checks).
func (a *API) createAggregate(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var body aggregateBody
	if !decode(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	switch {
	case !uuidRE.MatchString(body.BUID):
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id (a uuid) is required", nil)
		return
	case name == "" || len([]rune(name)) > 200 || strings.ContainsAny(name, "\r\n"):
		problem(w, http.StatusBadRequest, "invalid_value", "name is required: one line, at most 200 characters", nil)
		return
	case audit.LooksSecret(name):
		problem(w, http.StatusBadRequest, "invalid_value", "name looks like a secret", nil)
		return
	case len(body.Members) < 2 || len(body.Members) > 200:
		problem(w, http.StatusBadRequest, "invalid_value", "an aggregate has 2 to 200 members", nil)
		return
	}
	for _, m := range body.Members {
		if !uuidRE.MatchString(m.RunID) || m.ControlSet == "" {
			problem(w, http.StatusBadRequest, "invalid_value", "each member names a run (uuid) and one of its control sets", nil)
			return
		}
	}
	req := analysis.AggregateRequest{BU: body.BUID, Name: name, Members: body.Members}
	if body.Seed != nil {
		s, err := strconv.ParseUint(*body.Seed, 10, 64)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_value", "seed is a decimal integer from 0 to 18446744073709551615", nil)
			return
		}
		req.Seed = &s
	}
	if !a.mayRun(w, r, p, body.BUID) {
		return
	}
	if a.EnqueueAggregate == nil {
		problem(w, http.StatusServiceUnavailable, "engine_unavailable", "no simulation engine is configured", nil)
		return
	}
	var agg map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		id, err := analysis.RequestAggregate(r.Context(), tx, a.EnqueueAggregate, req)
		if err != nil {
			return err
		}
		agg, err = readAggregate(r, tx, id)
		return err
	})
	var pg *pgconn.PgError
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, agg)
	case errors.As(err, &pg) && pg.Code == "P0002":
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "a member run does not exist or is not visible to you", nil)
	case errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23503"):
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "each member is a control set of its run, named once", nil)
	default:
		fail(w, err)
	}
}

const aggregateColumns = `a.id::text, a.bu_id::text, a.name, a.seed::text, a.iterations, a.requested_by::text, a.requested_at, a.state, a.started_at,
	a.finished_at, a.failure, a.failure_detail, a.engine_version, a.architecture, a.result_digest, a.seq`

func scanAggregate(row pgx.Row) (map[string]any, error) {
	var (
		id, bu, name, seed, by, state             string
		iterations, seq                           int64
		requestedAt                               time.Time
		startedAt, finishedAt                     *time.Time
		failure, failureDetail, version, arch, rd *string
	)
	if err := row.Scan(&id, &bu, &name, &seed, &iterations, &by, &requestedAt, &state, &startedAt, &finishedAt, &failure, &failureDetail,
		&version, &arch, &rd, &seq); err != nil {
		return nil, err
	}
	out := map[string]any{"id": id, "bu_id": bu, "name": name, "seed": seed, "iterations": iterations, "requested_by": by, "requested_at": requestedAt,
		"state": state, "started_at": startedAt, "finished_at": finishedAt, "failure": failure, "failure_detail": failureDetail,
		"result_digest": rd, "seq": seq, "engine": nil}
	if version != nil {
		out["engine"] = map[string]any{"version": *version, "architecture": arch}
	}
	return out, nil
}

// readAggregate reads an aggregate with its members (each with its run's
// scenario and its engine version) and, once it succeeded, its summary.
func readAggregate(r *http.Request, tx pgx.Tx, id string) (map[string]any, error) {
	ctx := r.Context()
	agg, err := scanAggregate(tx.QueryRow(ctx, "SELECT "+aggregateColumns+" FROM analysis.aggregate a WHERE a.id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT m.position, m.run_id::text, m.control_set, m.engine_version, r.scenario_id::text, r.scenario_version, coalesce(s.name, '')
		FROM analysis.aggregate_member m JOIN analysis.run r ON r.id = m.run_id LEFT JOIN risk.scenario s ON s.id = r.scenario_id
		WHERE m.aggregate_id = $1 ORDER BY m.position`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := []map[string]any{}
	versions := map[string]bool{}
	for rows.Next() {
		var pos int
		var run, set, scenario, sname string
		var ev *string
		var sv int64
		if err := rows.Scan(&pos, &run, &set, &ev, &scenario, &sv, &sname); err != nil {
			return nil, err
		}
		if ev != nil {
			versions[*ev] = true
		}
		members = append(members, map[string]any{"position": pos, "run_id": run, "control_set": set, "engine_version": ev,
			"scenario_id": scenario, "scenario_version": sv, "scenario_name": sname})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	agg["members"] = members
	// Members computed by different engine versions are listed (design §3.5).
	vs := make([]string, 0, len(versions))
	for v := range versions {
		vs = append(vs, v)
	}
	agg["member_engine_versions"] = vs
	agg["mixed_engine_versions"] = len(vs) > 1
	agg["summary"] = nil
	if agg["state"] == "succeeded" {
		var summary []byte
		if err := tx.QueryRow(ctx, "SELECT summary FROM analysis.aggregate WHERE id = $1", id).Scan(&summary); err != nil {
			return nil, err
		}
		agg["summary"] = json.RawMessage(summary)
	}
	return agg, nil
}

// listAggregates lists the aggregates the caller sees (every member
// visible), newest first; ?bu= narrows to one BU.
func (a *API) listAggregates(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var bu any
	if s := r.URL.Query().Get("bu"); s != "" {
		if !uuidRE.MatchString(s) {
			problem(w, http.StatusBadRequest, "invalid_value", "bu is a uuid", nil)
			return
		}
		bu = s
	}
	var out []map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT "+aggregateColumns+" FROM analysis.aggregate a WHERE ($1::uuid IS NULL OR a.bu_id = $1) ORDER BY a.seq DESC LIMIT 200", bu)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			agg, err := scanAggregate(rows)
			if err != nil {
				return err
			}
			out = append(out, agg)
		}
		return rows.Err()
	})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"aggregates": out})
}

// getAggregate answers an aggregate the caller sees (every member visible:
// 404 otherwise, AC-19).
func (a *API) getAggregate(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return
	}
	var agg map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		agg, err = readAggregate(r, tx, id)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agg)
}
