package estimateapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/estimate"
	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-004 T-08 (AC-15 to AC-19; design §3.4, §3.5, §6.3): reviewing answers
// and accepting them into the scenario.

// storedAnswer is one submitted revision, as estimate.request_answers gives it.
type storedAnswer struct {
	Estimator   string          `json:"estimator"`
	Pointer     string          `json:"pointer"`
	Revision    int64           `json:"revision"`
	Estimate    json.RawMessage `json:"estimate"`
	Declined    *string         `json:"declined"`
	Calibration json.RawMessage `json:"calibration"`
	CreatedAt   time.Time       `json:"created_at"`
}

type answersView struct {
	Estimators []struct {
		UserID     string     `json:"user_id"`
		Name       string     `json:"name"`
		FinishedAt *time.Time `json:"finished_at"`
		RemovedAt  *time.Time `json:"removed_at"`
	} `json:"estimators"`
	Answers []storedAnswer `json:"answers"`
}

func (v answersView) name(id string) string {
	for _, e := range v.Estimators {
		if e.UserID == id {
			return e.Name
		}
	}
	return id
}

// latest is each estimator's latest submitted revision for a factor.
func (v answersView) latest(pointer string) []storedAnswer {
	by := map[string]storedAnswer{}
	for _, a := range v.Answers {
		if a.Pointer == pointer && a.Revision >= by[a.Estimator].Revision {
			by[a.Estimator] = a
		}
	}
	out := make([]storedAnswer, 0, len(by))
	for _, a := range by {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return v.name(out[i].Estimator) < v.name(out[j].Estimator) })
	return out
}

// estimateNumbers are the parts of an answer's estimate a pool uses.
type estimateNumbers struct {
	Min        string         `json:"min"`
	ML         string         `json:"ml"`
	Max        string         `json:"max"`
	Confidence string         `json:"confidence"`
	Sources    []model.Source `json:"sources"`
}

type calibrationSnapshot struct {
	Class     string  `json:"class"`
	RangeRate *string `json:"range_rate,omitempty"`
	AsOf      string  `json:"as_of"`
}

func (v answersView) poolAnswer(a storedAnswer) (estimate.Answer, estimateNumbers, calibrationSnapshot, error) {
	var n estimateNumbers
	var c calibrationSnapshot
	if err := json.Unmarshal(a.Estimate, &n); err != nil {
		return estimate.Answer{}, n, c, err
	}
	if err := json.Unmarshal(a.Calibration, &c); err != nil {
		return estimate.Answer{}, n, c, err
	}
	return estimate.Answer{Estimator: a.Estimator, Name: v.name(a.Estimator), Revision: a.Revision, Min: n.Min, ML: n.ML, Max: n.Max,
		Confidence: n.Confidence, Class: c.Class, RangeRate: c.RangeRate, AsOf: c.AsOf}, n, c, nil
}

func (a *API) requestAnswers(ctx context.Context, tx pgx.Tx, id string) (answersView, error) {
	var v answersView
	var b []byte
	if err := tx.QueryRow(ctx, "SELECT estimate.request_answers($1)", id).Scan(&b); err != nil {
		return v, err
	}
	err := json.Unmarshal(b, &v)
	return v, err
}

// factorRows are a request's factors.
func requestFactors(ctx context.Context, tx pgx.Tx, id string) ([]estimate.Factor, error) {
	rows, err := tx.Query(ctx, "SELECT pointer, factor, '', unit, definition FROM estimate.request_factor WHERE request_id = $1 ORDER BY pointer", id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[estimate.Factor])
}

// getRequestAnswers shows the submitted answers side by side, per factor,
// with each estimator's calibration when they answered and the pools'
// previews (AC-15).
func (a *API) getRequestAnswers(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permScenarioView}) {
		return
	}
	ctx := r.Context()
	type factorView struct {
		estimate.Factor
		Answers  []storedAnswer              `json:"answers"`
		Previews map[string]*estimate.Pooled `json:"previews"`
	}
	var out struct {
		Request    requestItem  `json:"request"`
		Estimators any          `json:"estimators"`
		Factors    []factorView `json:"factors"`
	}
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		it, err := a.loadRequest(ctx, tx, r.PathValue("id"))
		if err != nil {
			return err
		}
		out.Request = it
		v, err := a.requestAnswers(ctx, tx, it.ID)
		if err != nil {
			return err
		}
		out.Estimators = v.Estimators
		fs, err := requestFactors(ctx, tx, it.ID)
		if err != nil {
			return err
		}
		for _, f := range fs {
			fv := factorView{Factor: f, Answers: []storedAnswer{}, Previews: map[string]*estimate.Pooled{}}
			var pool []estimate.Answer
			for _, ans := range v.Answers {
				if ans.Pointer == f.Pointer {
					fv.Answers = append(fv.Answers, ans)
				}
			}
			for _, ans := range v.latest(f.Pointer) {
				if ans.Declined != nil {
					continue
				}
				pa, _, _, err := v.poolAnswer(ans)
				if err == nil && pa.Confidence == it.Confidence {
					pool = append(pool, pa)
				}
			}
			for _, m := range []string{estimate.MethodEqual, estimate.MethodCalibration} {
				if pr, err := estimate.Pool(m, pool, it.Confidence); err == nil {
					fv.Previews[m] = &pr
				}
			}
			out.Factors = append(out.Factors, fv)
		}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type acceptFactor struct {
	Pointer    string          `json:"pointer"`
	Method     string          `json:"method"`
	Estimators []string        `json:"estimators"`
	Estimate   json.RawMessage `json:"estimate"`
}

// acceptRequest accepts factors of a request into a new version of its
// scenario (AC-16 to AC-19): each by one answer, a pool of answers, or the
// analyst's own estimate, with the provenance the database verifies.
func (a *API) acceptRequest(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		ExpectedVersion *int           `json:"expected_version"`
		ChangeNote      string         `json:"change_note"`
		Factors         []acceptFactor `json:"factors"`
	}
	if !a.anywhere(w, r, p, []authz.Permission{permScenarioView}) || !decode(w, r, &body) {
		return
	}
	if body.ExpectedVersion == nil || len(body.Factors) == 0 || len(body.Factors) > 60 {
		problem(w, http.StatusBadRequest, "invalid_value", "expected_version (the scenario version you reviewed) and 1 to 60 factors are required", nil)
		return
	}
	if !checkText(w, "change_note", body.ChangeNote, 1000, true, false) {
		return
	}
	ctx := r.Context()
	var it requestItem
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		it, err = a.loadRequest(ctx, tx, r.PathValue("id"))
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if !a.mayRequest(w, r, p, it.BUID) {
		return
	}
	if it.Status == "cancelled" {
		problem(w, http.StatusConflict, "refused", "the request was cancelled", nil)
		return
	}

	var version int
	var digest string
	var bad []model.Problem
	err = authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		var cur int
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT s.current_version, v.document FROM risk.scenario s
			JOIN risk.scenario_version v ON v.scenario_id = s.id AND v.version = s.current_version WHERE s.id = $1`, it.ScenarioID).Scan(&cur, &raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if cur != *body.ExpectedVersion {
			return errStale
		}
		v, err := a.requestAnswers(ctx, tx, it.ID)
		if err != nil {
			return err
		}
		fs, err := requestFactors(ctx, tx, it.ID)
		if err != nil {
			return err
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		var methods []string
		for _, af := range body.Factors {
			i := slices.IndexFunc(fs, func(f estimate.Factor) bool { return f.Pointer == af.Pointer })
			if i < 0 {
				bad = append(bad, model.Problem{Pointer: af.Pointer, Message: "is not a factor of this request"})
				continue
			}
			e, problems := buildAccepted(it, fs[i], af, v)
			if len(problems) > 0 {
				bad = append(bad, problems...)
				continue
			}
			if !setAt(doc, af.Pointer, e) {
				bad = append(bad, model.Problem{Pointer: af.Pointer, Message: "the scenario no longer estimates this factor at this level"})
				continue
			}
			methods = append(methods, af.Method)
		}
		if len(bad) > 0 {
			return nil
		}
		b, _ := json.Marshal(doc)
		d, problems := model.Validate(model.KindScenario, b)
		if problems != nil {
			bad = problems
			return nil
		}
		version, digest = cur+1, d.Digest
		note := strings.TrimSpace(body.ChangeNote)
		if _, err := tx.Exec(ctx, "INSERT INTO risk.scenario_version (scenario_id, version, document, digest, change_note) VALUES ($1, $2, $3, $4, $5)",
			it.ScenarioID, version, d.Canonical, d.Digest, note); err != nil {
			return err
		}
		ectx := audit.WithTx(ctx, tx)
		if err := a.Audit.Emit(ectx, audit.Event{Type: "scenario.version_saved", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "scenario:" + it.ScenarioID, BUID: it.BUID, Attributes: map[string]string{
				"version": strconv.Itoa(version), "digest": d.Digest, "change_note": note}}); err != nil {
			return err
		}
		slices.Sort(methods)
		return a.Audit.Emit(ectx, audit.Event{Type: "estimate.accepted", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "estimate_request:" + it.ID, BUID: it.BUID, Attributes: map[string]string{
				"scenario": it.ScenarioID, "version": strconv.Itoa(version), "factors": strconv.Itoa(len(body.Factors)),
				"methods": strings.Join(slices.Compact(methods), ",")}})
	})
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, errStale), errors.As(err, &pg) && pg.Code == "PF017": // a version saved meanwhile
		problem(w, http.StatusConflict, "stale_version", "the scenario has a newer version than the one you reviewed", nil)
	case errors.As(err, &pg) && pg.Code == "PF016":
		var ps []model.Problem
		for _, line := range strings.Split(pg.Detail, "\n") {
			if ptr, msg, ok := strings.Cut(line, ": "); ok {
				ps = append(ps, model.Problem{Pointer: ptr, Message: msg})
			}
		}
		problem(w, http.StatusUnprocessableEntity, "invalid_document", pg.Message, map[string]any{"problems": ps})
	case err != nil:
		fail(w, err)
	case len(bad) > 0:
		problem(w, http.StatusUnprocessableEntity, "invalid_acceptance", "", map[string]any{"problems": bad})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"scenario_id": it.ScenarioID, "version": version, "digest": digest})
	}
}

var errStale = errors.New("estimateapi: stale scenario version")

// buildAccepted makes the accepted estimate of one factor with its
// provenance (design §3.4, §3.5).
func buildAccepted(it requestItem, f estimate.Factor, af acceptFactor, v answersView) (map[string]any, []model.Problem) {
	at := func(msg string) []model.Problem { return []model.Problem{{Pointer: af.Pointer, Message: msg}} }
	if !slices.Contains([]string{estimate.MethodSingle, estimate.MethodEqual, estimate.MethodCalibration, estimate.MethodOwn}, af.Method) {
		return nil, at("method is single, equal, calibration or own")
	}
	if (af.Method == estimate.MethodOwn) != (len(af.Estimate) > 0 && string(af.Estimate) != "null") {
		return nil, at("an estimate is given with the own method, and only with it")
	}
	// The answers used: the listed estimators' latest submitted estimates
	// (every such answer when none is listed).
	latest := map[string]storedAnswer{}
	for _, ans := range v.latest(af.Pointer) {
		if ans.Declined == nil {
			latest[ans.Estimator] = ans
		}
	}
	chosen := af.Estimators
	if chosen == nil {
		for id := range latest {
			chosen = append(chosen, id)
		}
	}
	if !distinctUUIDs(chosen) {
		return nil, at("estimators are distinct user ids")
	}
	sort.Slice(chosen, func(i, j int) bool { return v.name(chosen[i]) < v.name(chosen[j]) })
	var answers []estimate.Answer
	var numbers []estimateNumbers
	var cals []calibrationSnapshot
	for _, id := range chosen {
		ans, ok := latest[id]
		if !ok {
			return nil, at(v.name(id) + " has no submitted estimate for this factor")
		}
		pa, n, c, err := v.poolAnswer(ans)
		if err != nil {
			return nil, at("an answer cannot be read")
		}
		answers, numbers, cals = append(answers, pa), append(numbers, n), append(cals, c)
	}

	var e map[string]any
	weights := make([]string, len(answers))
	if af.Method == estimate.MethodOwn {
		canonical, problems := model.ValidateEstimate(f.Unit, af.Estimate)
		if problems != nil {
			out := make([]model.Problem, len(problems))
			for i, pr := range problems {
				out[i] = model.Problem{Pointer: af.Pointer + pr.Pointer, Message: pr.Message}
			}
			return nil, out
		}
		_ = json.Unmarshal(canonical, &e)
		for i := range weights {
			weights[i] = "0"
		}
	} else {
		pooled, err := estimate.Pool(af.Method, answers, it.Confidence)
		if err != nil {
			return nil, at(strings.TrimPrefix(err.Error(), "estimate: pool: "))
		}
		copy(weights, pooled.Weights)
		rationale := map[string]string{
			estimate.MethodSingle:      "The answer of %s to estimate request %s.",
			estimate.MethodEqual:       "Equal-weight average of %s to estimate request %s.",
			estimate.MethodCalibration: "Calibration-weighted average of %s to estimate request %s.",
		}[af.Method]
		who := answers[0].Name
		if af.Method != estimate.MethodSingle {
			who = strconv.Itoa(len(answers)) + " answers"
		}
		e = map[string]any{"min": pooled.Min, "ml": pooled.ML, "max": pooled.Max, "unit": f.Unit, "confidence": pooled.Confidence,
			"rationale": fmt.Sprintf(rationale, who, it.ID)}
		var sources []any
		seen := map[string]bool{}
		for _, n := range numbers {
			for _, s := range n.Sources {
				k := s.Type + "\x00" + s.Ref
				if seen[k] || s.Type == model.SourceElicitation || len(sources) >= model.MaxSources-1 {
					continue
				}
				seen[k] = true
				src := map[string]any{"type": s.Type, "ref": s.Ref}
				if s.Note != "" {
					src["note"] = s.Note
				}
				sources = append(sources, src)
			}
		}
		e["sources"] = sources
	}
	// The elicitation source, then the provenance.
	srcs, _ := e["sources"].([]any)
	if len(srcs) >= model.MaxSources {
		srcs = srcs[:model.MaxSources-1]
	}
	e["sources"] = append([]any{map[string]any{"type": model.SourceElicitation, "ref": it.ID}}, srcs...)
	used := make([]any, len(answers))
	for i, pa := range answers {
		c := map[string]any{"class": cals[i].Class, "as_of": cals[i].AsOf}
		if cals[i].RangeRate != nil {
			c["range_rate"] = *cals[i].RangeRate
		}
		used[i] = map[string]any{"estimator": pa.Estimator, "name": pa.Name, "revision": pa.Revision, "weight": weights[i],
			"min": numbers[i].Min, "ml": numbers[i].ML, "max": numbers[i].Max, "confidence": numbers[i].Confidence, "calibration": c}
	}
	conf, _ := canon.Decimal(it.Confidence)
	e["elicitation"] = map[string]any{"request": it.ID, "method": af.Method, "confidence": conf, "answers": used}
	return e, nil
}

// setAt replaces the estimate at a pointer of a document; false when there
// is none there.
func setAt(doc map[string]any, pointer string, e map[string]any) bool {
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	var cur any = doc
	for i, part := range parts {
		last := i == len(parts)-1
		switch c := cur.(type) {
		case map[string]any:
			if last {
				if _, ok := c[part].(map[string]any); !ok {
					return false
				}
				c[part] = e
				return true
			}
			cur = c[part]
		case []any:
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n >= len(c) {
				return false
			}
			if last {
				if _, ok := c[n].(map[string]any); !ok {
					return false
				}
				c[n] = e
				return true
			}
			cur = c[n]
		default:
			return false
		}
	}
	return false
}
