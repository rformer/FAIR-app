package registerapi

import (
	"cmp"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-007 T-07 (F-007-AC-11 to AC-14; design §3.4, §6): business unit
// roll-ups. The database plans and requests a roll-up in the requester's
// transaction (register.request_rollup); the service queues its nodes'
// jobs there too. A roll-up is its requester's alone (RLS).

// requestRollup requests a roll-up of a BU (AC-11): register.view there.
func (a *API) requestRollup(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var body struct {
		BUID string `json:"bu_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.BUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id is a business unit id", nil)
		return
	}
	if err := a.Authz.Check(r.Context(), p, permView, body.BUID); err != nil {
		var su *authz.StepUpError
		if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
			server.WriteAuthzError(w, err)
			return
		}
		notFound(w)
		return
	}
	var out struct {
		ID    string   `json:"id"`
		State string   `json:"state"`
		Queue []string `json:"queue"`
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(r.Context(), "SELECT register.request_rollup($1)", body.BUID).Scan(&raw); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return err
		}
		if len(out.Queue) > 0 && a.EnqueueAggregate == nil {
			return errNoQueue
		}
		for _, id := range out.Queue {
			if err := a.EnqueueAggregate(r.Context(), tx, analysis.AggregateArgs{AggregateID: id}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": out.ID, "state": out.State, "nodes": len(out.Queue)})
}

// listRollups lists the caller's roll-ups, newest first (?bu=).
func (a *API) listRollups(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	where, args := "true", []any{}
	if bu := r.URL.Query().Get("bu"); bu != "" {
		if !uuidRE.MatchString(bu) {
			problem(w, http.StatusBadRequest, "invalid_value", "bu is a business unit id", nil)
			return
		}
		where, args = "bu_id = $1", append(args, bu)
	}
	out := []map[string]any{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, bu_id::text, state, requested_at, finished_at, jsonb_array_length(included), left_out, excluded_bus
			FROM register.rollup WHERE `+where+` ORDER BY requested_at DESC, seq DESC LIMIT 100`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, bu, state string
			var at time.Time
			var done *time.Time
			var n, excluded int
			var left json.RawMessage
			if err := rows.Scan(&id, &bu, &state, &at, &done, &n, &left, &excluded); err != nil {
				return err
			}
			out = append(out, map[string]any{"id": id, "bu_id": bu, "state": state, "requested_at": at, "finished_at": done, "risks": n,
				"left_out": left, "excluded_bus": excluded})
		}
		return rows.Err()
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rollups": out})
}

type included struct {
	RiskID string          `json:"risk_id"`
	BUID   string          `json:"bu_id"`
	Ref    json.RawMessage `json:"ref"`
	Mean   *float64        `json:"mean"`
	P90    *float64        `json:"p90"`
}

// getRollup answers a roll-up (AC-11 to AC-14): its summary, what it
// includes (each risk's mean, 90th percentile and share of the mean, by
// ?sort=mean|p90), what it leaves out and why, the aggregate-only total,
// and whether it is stale.
func (a *API) getRollup(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	sortBy := r.URL.Query().Get("sort")
	if sortBy == "" {
		sortBy = "mean"
	}
	if sortBy != "mean" && sortBy != "p90" {
		problem(w, http.StatusBadRequest, "invalid_value", "sort is mean or p90", nil)
		return
	}
	var out map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		var (
			bu, state, digest                 string
			at                                time.Time
			done                              *time.Time
			failure, rootAgg, rootRun, rootCS *string
			summary, incl, left, aggOnly      []byte
			excluded, nodes                   int
		)
		err := tx.QueryRow(ctx, `SELECT bu_id::text, state, requested_at, finished_at, failure, root_aggregate_id::text, root_run_id::text, root_control_set,
			summary, digest, included, left_out, excluded_bus, aggregate_only, nodes FROM register.rollup WHERE id = $1`, id).
			Scan(&bu, &state, &at, &done, &failure, &rootAgg, &rootRun, &rootCS, &summary, &digest, &incl, &left, &excluded, &aggOnly, &nodes)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		var items []included
		if err := json.Unmarshal(incl, &items); err != nil {
			return err
		}
		// Staleness (AC-12): what a roll-up would include now differs.
		var now string
		if err := tx.QueryRow(ctx, "SELECT register.rollup_plan($1) ->> 'digest'", bu).Scan(&now); err != nil {
			return err
		}
		titles := map[string]string{}
		ids := make([]string, 0, len(items))
		for _, x := range items {
			ids = append(ids, x.RiskID)
		}
		rows, err := tx.Query(ctx, "SELECT id::text, title FROM register.risk WHERE id = ANY ($1::uuid[])", ids)
		if err != nil {
			return err
		}
		for rows.Next() {
			var rid string
			var title *string
			if err := rows.Scan(&rid, &title); err != nil {
				rows.Close()
				return err
			}
			if title != nil {
				titles[rid] = *title
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// Means add: the roll-up's mean is the sum of its risks' (AC-14).
		var sumMeans float64
		for _, x := range items {
			if x.Mean != nil {
				sumMeans += *x.Mean
			}
		}
		key := func(x included) float64 {
			v := x.Mean
			if sortBy == "p90" {
				v = x.P90
			}
			if v == nil {
				return -1
			}
			return *v
		}
		slices.SortStableFunc(items, func(x, y included) int { return cmp.Compare(key(y), key(x)) })
		risks := make([]map[string]any, 0, len(items))
		for _, x := range items {
			e := map[string]any{"risk_id": x.RiskID, "bu_id": x.BUID, "title": nil, "mean": x.Mean, "p90": x.P90, "share": nil, "exposure": x.Ref}
			if t, ok := titles[x.RiskID]; ok {
				e["title"] = t
			}
			if sumMeans > 0 && x.Mean != nil {
				e["share"] = *x.Mean / sumMeans
			}
			risks = append(risks, e)
		}
		var leftOut map[string]int
		if err := json.Unmarshal(left, &leftOut); err != nil {
			return err
		}
		sum := 0
		for _, n := range leftOut {
			sum += n
		}
		root := map[string]any{"aggregate_id": rootAgg, "run_id": rootRun, "control_set": rootCS}
		out = map[string]any{"id": id, "bu_id": bu, "state": state, "requested_at": at, "finished_at": done, "failure": failure, "root": root,
			"summary": nil, "aggregate_only": nil, "risks": risks, "covers": len(items), "left_out": leftOut, "left_out_total": sum,
			"excluded_bus": excluded, "nodes": nodes, "stale": now != digest,
			"independence": "risks are combined as independent; correlations between them are not modelled"}
		if summary != nil {
			out["summary"] = json.RawMessage(summary)
		}
		if aggOnly != nil {
			var ao map[string]any
			if err := json.Unmarshal(aggOnly, &ao); err != nil {
				return err
			}
			out["aggregate_only"] = ao
			// Added to the mean, never to the distribution (AC-13, OQ6).
			if m, ok := ao["mean_total"].(float64); ok {
				base := sumMeans
				if m := meanOf(summary); m != nil {
					base = *m // the distribution's own mean
				}
				out["mean_with_aggregate_only"] = base + m
			}
		}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
