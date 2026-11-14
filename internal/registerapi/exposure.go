package registerapi

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/analysis"
	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-007 T-05 (F-007-AC-06 to AC-10; design §3.3, §6, §8): pins, the
// exposure they make, its status, newer runs and adoption, coverage.

var errNoQueue = errors.New("registerapi: no aggregate queue")

// requestExposure asks the database for the risk's exposure aggregate
// (register.request_exposure: two or more pins, changed) and queues its
// job in tx.
func (a *API) requestExposure(ctx context.Context, tx pgx.Tx, id string) error {
	var buf [8]byte
	_, _ = rand.Read(buf[:]) // crypto/rand.Read never fails
	var agg *string
	if err := tx.QueryRow(ctx, "SELECT register.request_exposure($1, $2::numeric)::text", id, strconv.FormatUint(binary.BigEndian.Uint64(buf[:]), 10)).
		Scan(&agg); err != nil {
		return err
	}
	if agg == nil {
		return nil
	}
	if a.EnqueueAggregate == nil {
		return errNoQueue
	}
	return a.EnqueueAggregate(ctx, tx, analysis.AggregateArgs{AggregateID: *agg})
}

// afterVersion records the pins set, changed or cleared between two
// documents (register.pin_set) and requests the exposure they make.
func (a *API) afterVersion(ctx context.Context, tx pgx.Tx, p authz.Principal, id, bu string, version int, from, to []byte, adopted bool) error {
	changes, err := register.PinChanges(from, to)
	if err != nil {
		return err
	}
	for _, c := range changes {
		attrs := map[string]string{"scenario": c.ScenarioID, "version": strconv.Itoa(version), "adopted": strconv.FormatBool(adopted), "run": "none"}
		if c.Pin != nil {
			attrs["run"], attrs["control_set"] = c.Pin.RunID, c.Pin.ControlSet
			if c.Pin.Reason != "" {
				attrs["reason"] = c.Pin.Reason
			}
		}
		if err := a.emit(ctx, audit.Event{Type: "register.pin_set", Severity: audit.SeverityLow, Actor: p.UserID, Target: target + id, BUID: bu,
			Attributes: attrs}); err != nil {
			return err
		}
	}
	return a.requestExposure(ctx, tx, id)
}

type adoptPin struct {
	ScenarioID string `json:"scenario_id"`
	RunID      string `json:"run_id"`
	ControlSet string `json:"control_set"`
	Reason     string `json:"reason"`
}

type adoptBody struct {
	ExpectedVersion *int       `json:"expected_version"`
	ChangeNote      string     `json:"change_note"`
	Pins            []adoptPin `json:"pins"`
}

// adoptRisk adopts newer runs (AC-10): the pins named, or, without any,
// the newest run of every pinned scenario that has a newer one.
func (a *API) adoptRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	h, ok := a.riskTo(w, r, p)
	if !ok {
		return
	}
	var body adoptBody
	if !decode(w, r, &body) {
		return
	}
	if body.ExpectedVersion == nil || *body.ExpectedVersion < 1 {
		problem(w, http.StatusBadRequest, "invalid_value", "expected_version (the version the change was made from) is required", nil)
		return
	}
	note, ok := checkNote(w, body.ChangeNote)
	if !ok {
		return
	}
	if len(body.Pins) > register.MaxScenarios {
		problem(w, http.StatusBadRequest, "invalid_value", "pins has at most 200 entries", nil)
		return
	}
	for _, x := range body.Pins {
		if !uuidRE.MatchString(x.ScenarioID) || !uuidRE.MatchString(x.RunID) {
			problem(w, http.StatusBadRequest, "invalid_value", "each pin names a scenario_id and a run_id", nil)
			return
		}
	}
	if h.State == "closed" {
		problem(w, http.StatusConflict, "closed", "the risk is closed; reopen it to change it", nil)
		return
	}
	var out map[string]any
	var problems model.Problems
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := audit.WithTx(r.Context(), tx)
		cur, err := readHead(ctx, tx, h.ID)
		if err != nil {
			return err
		}
		if cur.Version != *body.ExpectedVersion {
			return errStale
		}
		prev, err := currentDoc(ctx, tx, cur)
		if err != nil {
			return err
		}
		d, err := register.Decode(prev)
		if err != nil {
			return err
		}
		pins := map[string]register.Pin{}
		if len(body.Pins) > 0 {
			linked := map[string]bool{}
			for _, l := range d.Scenarios {
				linked[l.ScenarioID] = true
			}
			for i, x := range body.Pins {
				if !linked[x.ScenarioID] {
					problems = append(problems, model.Problem{Pointer: fmt.Sprintf("/pins/%d/scenario_id", i), Message: "is not a scenario of the risk"})
					continue
				}
				if _, dup := pins[x.ScenarioID]; dup {
					problems = append(problems, model.Problem{Pointer: fmt.Sprintf("/pins/%d/scenario_id", i), Message: "is given twice"})
					continue
				}
				set := x.ControlSet
				if set == "" {
					// The run's current set, as the caller sees the run.
					var sets []string
					if err := tx.QueryRow(ctx, "SELECT control_sets FROM analysis.run WHERE id = $1", x.RunID).Scan(&sets); err != nil && !errors.Is(err, pgx.ErrNoRows) {
						return err
					}
					if len(sets) > 0 {
						set = sets[0]
					}
				}
				pins[x.ScenarioID] = register.Pin{RunID: x.RunID, ControlSet: set, Reason: strings.TrimSpace(x.Reason)}
			}
			if problems != nil {
				return errInvalid
			}
		} else {
			rows, err := tx.Query(ctx, "SELECT scenario_id::text, run_id::text, control_sets FROM register.newer_runs($1)", h.ID)
			if err != nil {
				return err
			}
			var newer []register.NewerRun
			for rows.Next() {
				var n register.NewerRun
				if err := rows.Scan(&n.ScenarioID, &n.RunID, &n.ControlSets); err != nil {
					rows.Close()
					return err
				}
				newer = append(newer, n)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			pins = register.Adoptions(d, newer)
			if len(pins) == 0 {
				return errNothingNewer
			}
		}
		doc, digest, err := register.WithPins(prev, pins)
		if err != nil {
			return err
		}
		version := cur.Version + 1
		if err := insertVersion(ctx, tx, h.ID, version, doc, digest, note); err != nil {
			return err
		}
		if err := a.emit(ctx, audit.Event{Type: "register.risk_changed", Severity: audit.SeverityLow, Actor: p.UserID, Target: target + h.ID, BUID: cur.BU,
			Attributes: map[string]string{"version": strconv.Itoa(version), "digest": digest, "change_note": note}}); err != nil {
			return err
		}
		adopted := make([]string, 0, len(pins))
		for _, l := range d.Scenarios {
			if _, ok := pins[l.ScenarioID]; ok {
				adopted = append(adopted, l.ScenarioID)
			}
		}
		out = map[string]any{"id": h.ID, "version": version, "digest": digest, "adopted": adopted}
		return a.afterVersion(ctx, tx, p, h.ID, cur.BU, version, prev, doc, true)
	})
	switch {
	case errors.Is(err, errInvalid):
		invalid(w, problems)
	case errors.Is(err, errStale):
		problem(w, http.StatusConflict, "stale_version", "the risk has changed since that version", nil)
	case errors.Is(err, errNothingNewer):
		problem(w, http.StatusConflict, "nothing_newer", "no pinned scenario has a newer run to adopt", nil)
	case err != nil:
		fail(w, err)
	default:
		writeJSON(w, http.StatusOK, out)
	}
}

var (
	errInvalid      = errors.New("registerapi: invalid")
	errStale        = errors.New("registerapi: stale version")
	errNothingNewer = errors.New("registerapi: nothing newer")
)

// statuses are the exposure statuses (register.exposure_status).
var statuses = []string{"current", "stale", "unquantified", "computing"}

// coverage counts the open risks the caller sees, in ?bu='s subtree if
// given, by exposure status (AC-09). The list (?status=) names them.
func (a *API) coverage(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	where, args := "r.state = 'open'", []any{}
	bu := r.URL.Query().Get("bu")
	if bu != "" {
		if !uuidRE.MatchString(bu) {
			problem(w, http.StatusBadRequest, "invalid_value", "bu is a business unit id", nil)
			return
		}
		where += " AND r.bu_id IN (SELECT register.subtree($1::uuid))"
		args = append(args, bu)
	}
	counts := map[string]int64{}
	for _, s := range statuses {
		counts[s] = 0
	}
	var open int64
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT register.exposure_status(r.id) ->> 'status', count(*) FROM register.risk r WHERE "+where+" GROUP BY 1", args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s *string
			var n int64
			if err := rows.Scan(&s, &n); err != nil {
				return err
			}
			if s != nil {
				counts[*s] += n
				open += n
			}
		}
		return rows.Err()
	})
	if err != nil {
		fail(w, err)
		return
	}
	var share any
	if open > 0 {
		share = float64(counts["current"]) / float64(open)
	}
	out := map[string]any{"open": open, "current_share": share}
	if bu != "" {
		out["bu_id"] = bu
	}
	for s, n := range counts {
		out[s] = n
	}
	writeJSON(w, http.StatusOK, out)
}

// links reads a risk's links with their pins, what makes them stale, and
// the newer runs the caller sees (AC-06, AC-08, AC-10).
func links(ctx context.Context, tx pgx.Tx, id string, doc []byte) ([]map[string]any, error) {
	reasons := map[string]string{}
	if d, err := register.Decode(doc); err == nil {
		for _, l := range d.Scenarios {
			if l.Pin != nil && l.Pin.Reason != "" {
				reasons[l.ScenarioID] = l.Pin.Reason
			}
		}
	}
	rows, err := tx.Query(ctx, `SELECT l.scenario_id::text, s.name, l.open, l.run_id::text, l.control_set, l.pinned_version, v.author::text, v.created_at,
		l.run_scenario_version, l.run_finished_at, l.scenario_version, l.scenario_archived
		FROM register.risk_scenario l LEFT JOIN risk.scenario s ON s.id = l.scenario_id
		LEFT JOIN register.risk_version v ON v.risk_id = l.risk_id AND v.version = l.pinned_version
		WHERE l.risk_id = $1 ORDER BY s.name, l.scenario_id`, id)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	index := map[string]map[string]any{}
	for rows.Next() {
		var (
			sid                  string
			name, run, set, by   *string
			open, archived       bool
			pinned, runV, scenV  *int
			pinnedAt, finishedAt *time.Time
		)
		if err := rows.Scan(&sid, &name, &open, &run, &set, &pinned, &by, &pinnedAt, &runV, &finishedAt, &scenV, &archived); err != nil {
			rows.Close()
			return nil, err
		}
		l := map[string]any{"scenario_id": sid, "scenario_name": name, "open": open, "scenario_version": scenV, "scenario_archived": archived,
			"pin": nil, "newer_runs": []map[string]any{}}
		if run != nil {
			pin := map[string]any{"run_id": *run, "control_set": set, "pinned_version": pinned, "pinned_by": by, "pinned_at": pinnedAt,
				"run_scenario_version": runV, "run_finished_at": finishedAt}
			if reason, ok := reasons[sid]; ok {
				pin["reason"] = reason
			}
			l["pin"] = pin
		}
		out = append(out, l)
		index[sid] = l
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	nrows, err := tx.Query(ctx, "SELECT scenario_id::text, run_id::text, scenario_version, finished_at, control_sets FROM register.newer_runs($1)", id)
	if err != nil {
		return nil, err
	}
	defer nrows.Close()
	for nrows.Next() {
		var sid, run string
		var v int
		var at time.Time
		var sets []string
		if err := nrows.Scan(&sid, &run, &v, &at, &sets); err != nil {
			return nil, err
		}
		if l, ok := index[sid]; ok {
			l["newer_runs"] = append(l["newer_runs"].([]map[string]any), map[string]any{"run_id": run, "scenario_version": v, "finished_at": at, "control_sets": sets})
		}
	}
	return out, nrows.Err()
}

// exposure is a risk's exposure as the caller sees it (AC-07): its one
// pinned result, or the aggregate of its pinned results.
func exposure(ctx context.Context, tx pgx.Tx, aggregate *string, ls []map[string]any) (map[string]any, error) {
	var pins []map[string]any
	for _, l := range ls {
		if pin, ok := l["pin"].(map[string]any); ok {
			pins = append(pins, pin)
		}
	}
	var summary []byte
	switch {
	case len(pins) == 0:
		return map[string]any{"kind": "none"}, nil
	case len(pins) == 1:
		out := map[string]any{"kind": "run", "run_id": pins[0]["run_id"], "control_set": pins[0]["control_set"], "visible": false}
		err := tx.QueryRow(ctx, "SELECT summary FROM analysis.result WHERE run_id = $1 AND control_set = $2", pins[0]["run_id"], pins[0]["control_set"]).Scan(&summary)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if summary != nil {
			out["visible"], out["summary"] = true, json.RawMessage(summary)
		}
		return out, nil
	default:
		out := map[string]any{"kind": "aggregate", "aggregate_id": aggregate, "visible": false, "assumption": "the scenarios' losses are independent"}
		if aggregate == nil {
			return out, nil
		}
		var state string
		err := tx.QueryRow(ctx, "SELECT state, summary FROM analysis.aggregate WHERE id = $1", *aggregate).Scan(&state, &summary)
		if errors.Is(err, pgx.ErrNoRows) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out["visible"], out["state"] = true, state
		if summary != nil {
			out["summary"] = json.RawMessage(summary)
		}
		return out, nil
	}
}
