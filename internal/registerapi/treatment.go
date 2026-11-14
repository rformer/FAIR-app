package registerapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-007 T-06 (F-007-AC-15 to AC-18, AC-21; design §3.2, §6): a risk's
// treatment plan. Treatment is its own resource type, read under RLS with
// treatment.view and changed with treatment.edit; a reader of the risk
// without them is answered 403 here and the risk's other answers carry no
// treatment.

const (
	permTView authz.Permission = "treatment.view"
	permTEdit authz.Permission = "treatment.edit"
)

// treatmentAccess resolves the path's risk and checks perm at its BU: 404
// for a risk the caller does not see, 403 for one they see without perm.
func (a *API) treatmentAccess(w http.ResponseWriter, r *http.Request, p authz.Principal, perm authz.Permission) (head, bool) {
	if !a.anywhere(w, r, p) {
		return head{}, false
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return head{}, false
	}
	h, err := a.headOf(r.Context(), p, id)
	if err != nil {
		fail(w, err)
		return head{}, false
	}
	err = a.Authz.Check(r.Context(), p, perm, h.BU)
	if err == nil {
		return h, true
	}
	var su *authz.StepUpError
	if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
		server.WriteAuthzError(w, err)
		return head{}, false
	}
	problem(w, http.StatusForbidden, "forbidden", "the treatment needs "+string(perm)+" at this business unit", nil)
	return head{}, false
}

// readTreatment reads a risk's current plan as the caller sees it: its
// version (0 without one) and document.
func readTreatment(ctx context.Context, tx pgx.Tx, id string) (int, []byte, error) {
	var v int
	var doc []byte
	err := tx.QueryRow(ctx, `SELECT t.current_version, v.document FROM register.treatment t
		JOIN register.treatment_version v ON v.risk_id = t.risk_id AND v.version = t.current_version WHERE t.risk_id = $1`, id).Scan(&v, &doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, register.EmptyTreatment, nil
	}
	return v, doc, err
}

func today() time.Time { return time.Now().UTC() }

// getTreatment answers a risk's plan (AC-15 to AC-18): its document, its
// actions with the overdue ones flagged, whether an acceptance is needed,
// and the expected exposure after treatment (AC-16).
func (a *API) getTreatment(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	h, ok := a.treatmentAccess(w, r, p, permTView)
	if !ok {
		return
	}
	var out map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		version, doc, err := readTreatment(ctx, tx, h.ID)
		if err != nil {
			return err
		}
		t, err := register.DecodeTreatment(doc)
		if err != nil {
			return err
		}
		now := today()
		actions := []map[string]any{}
		overdue := 0
		for _, x := range t.Actions {
			o := x.Overdue(now)
			if o {
				overdue++
			}
			actions = append(actions, map[string]any{"id": x.ID, "title": x.Title, "owner": x.Owner, "due": x.Due, "state": x.State,
				"cancel_reason": x.CancelReason, "overdue": o})
		}
		decision := ""
		if t.Decision != nil {
			decision = *t.Decision
		}
		expected, err := expectedExposure(ctx, tx, h.ID, t)
		if err != nil {
			return err
		}
		out = map[string]any{"risk_id": h.ID, "version": version, "document": json.RawMessage(doc), "actions": actions, "overdue_actions": overdue,
			// F-007 records that an acceptance is needed; F-008 decides it (AC-18).
			"acceptance": map[string]any{"needed": decision == "accept", "state": nil},
			"expected":   expected}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// expectedExposure compares, scenario by scenario, the pinned control set
// with the plan's target set of the same pinned run (AC-16; F-006
// comparisons): each one's mean annualized loss and the totals' (means
// add whatever the scenarios' dependence). Available only for a
// mitigation with targets, every linked scenario pinned, and every target
// a set of its pinned run the caller sees.
func expectedExposure(ctx context.Context, tx pgx.Tx, id string, t register.Treatment) (map[string]any, error) {
	if t.Decision == nil || *t.Decision != "mitigate" || len(t.Targets) == 0 {
		return map[string]any{"available": false, "reason": "no_targets"}, nil
	}
	targets := map[string]string{}
	for _, x := range t.Targets {
		targets[x.ScenarioID] = x.ControlSet
	}
	rows, err := tx.Query(ctx, `SELECT l.scenario_id::text, l.run_id::text, l.control_set, r.control_sets,
		(SELECT s.summary FROM analysis.result s WHERE s.run_id = l.run_id AND s.control_set = l.control_set)
		FROM register.risk_scenario l LEFT JOIN analysis.run r ON r.id = l.run_id WHERE l.risk_id = $1 ORDER BY l.scenario_id`, id)
	if err != nil {
		return nil, err
	}
	type item struct {
		scenario, set, target, status string
		run                           *string
		sets                          []string
		current                       []byte
	}
	var items []item
	for rows.Next() {
		var x item
		var set *string
		if err := rows.Scan(&x.scenario, &x.run, &set, &x.sets, &x.current); err != nil {
			rows.Close()
			return nil, err
		}
		if set != nil {
			x.set = *set
		}
		items = append(items, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	available := len(items) > 0
	var curTotal, tgtTotal float64
	scenarios := []map[string]any{}
	compare := []string{}
	for _, x := range items {
		x.target = x.set
		if s, ok := targets[x.scenario]; ok {
			x.target = s
		}
		e := map[string]any{"scenario_id": x.scenario, "run_id": x.run, "current_set": nil, "target_set": x.target}
		var cur, tgt *float64
		switch {
		case x.run == nil:
			x.status = "no_pin"
		case x.sets == nil || x.current == nil:
			x.status = "not_visible"
		case !slices.Contains(x.sets, x.target):
			x.status = "target_not_in_pinned_run"
		default:
			x.status = "ok"
			cur = meanOf(x.current)
			var summary []byte
			if err := tx.QueryRow(ctx, "SELECT summary FROM analysis.result WHERE run_id = $1 AND control_set = $2", *x.run, x.target).Scan(&summary); err != nil &&
				!errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			tgt = meanOf(summary)
			if cur == nil || tgt == nil {
				x.status = "not_visible"
			}
		}
		if x.run != nil {
			e["current_set"] = x.set
		}
		e["status"] = x.status
		if x.status == "ok" {
			e["current_mean"], e["target_mean"], e["reduction"] = *cur, *tgt, *cur-*tgt
			curTotal += *cur
			tgtTotal += *tgt
			compare = append(compare, "run:"+*x.run+":"+x.set)
			if x.target != x.set {
				compare = append(compare, "run:"+*x.run+":"+x.target)
			}
		} else {
			available = false
		}
		scenarios = append(scenarios, e)
	}
	out := map[string]any{"available": available, "scenarios": scenarios,
		"assumption": "totals are sums of the scenarios' mean annualized losses; percentiles are compared per scenario"}
	if !available {
		out["reason"] = "incomplete"
		return out, nil
	}
	out["current_mean_total"], out["target_mean_total"], out["reduction"] = curTotal, tgtTotal, curTotal-tgtTotal
	if len(compare) >= 2 && len(compare) <= 6 {
		out["compare_items"] = compare // for the F-006 comparison (2 to 6 items)
	}
	return out, nil
}

// meanOf reads a result summary's mean annualized loss.
func meanOf(summary []byte) *float64 {
	var s struct {
		ALE struct {
			Mean *float64 `json:"mean"`
		} `json:"ale"`
	}
	if summary == nil || json.Unmarshal(summary, &s) != nil {
		return nil
	}
	return s.ALE.Mean
}

type treatmentBody struct {
	Document        json.RawMessage `json:"document"`
	ExpectedVersion *int            `json:"expected_version"`
	ChangeNote      string          `json:"change_note"`
}

// saveTreatment saves a new version of a risk's plan (AC-15, AC-17):
// expected_version 0 makes its first.
func (a *API) saveTreatment(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	h, ok := a.treatmentAccess(w, r, p, permTEdit)
	if !ok {
		return
	}
	var body treatmentBody
	if !decode(w, r, &body) {
		return
	}
	if body.ExpectedVersion == nil || *body.ExpectedVersion < 0 {
		problem(w, http.StatusBadRequest, "invalid_value", "expected_version (the version the change was made from; 0 for the first) is required", nil)
		return
	}
	note, ok := checkNote(w, body.ChangeNote)
	if !ok {
		return
	}
	if h.State == "closed" {
		problem(w, http.StatusConflict, "closed", "the risk is closed; reopen it to change its treatment", nil)
		return
	}
	doc, digest, problems := register.CanonicalTreatment(body.Document)
	if problems != nil {
		invalid(w, problems)
		return
	}
	version := *body.ExpectedVersion + 1
	var decision string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := audit.WithTx(r.Context(), tx)
		cur, prev, err := readTreatment(ctx, tx, h.ID)
		if err != nil {
			return err
		}
		if cur != *body.ExpectedVersion {
			return errStale
		}
		if cur == 0 {
			if _, err := tx.Exec(ctx, "INSERT INTO register.treatment (risk_id, bu_id) VALUES ($1, $2)", h.ID, h.BU); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "INSERT INTO register.treatment_version (risk_id, version, document, digest, change_note) VALUES ($1, $2, $3, $4, $5)",
			h.ID, version, doc, digest, note); err != nil {
			return err
		}
		before, err := register.DecodeTreatment(prev)
		if err != nil {
			return err
		}
		after, err := register.DecodeTreatment(doc)
		if err != nil {
			return err
		}
		decision = "none"
		if after.Decision != nil {
			decision = *after.Decision
		}
		return a.emit(ctx, audit.Event{Type: "register.treatment_changed", Severity: audit.SeverityLow, Actor: p.UserID, Target: target + h.ID, BUID: h.BU,
			Attributes: map[string]string{"version": strconv.Itoa(version), "decision": decision, "actions_changed": strconv.Itoa(register.ActionsChanged(before, after)),
				"change_note": note}})
	})
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, errStale), errors.As(err, &pg) && pg.Code == "23505": // a first plan saved meanwhile
		problem(w, http.StatusConflict, "stale_version", "the treatment has changed since that version", nil)
	case err != nil:
		fail(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"id": h.ID, "version": version, "digest": digest, "acceptance_needed": decision == "accept"})
	}
}
