package estimateapi

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

	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-004 T-07 (AC-04, AC-05, AC-07 to AC-10; design §3.3, §6.2): the
// estimator's inbox. Everything goes through estimate_definer's functions,
// which check on every call that the caller is a current estimator of the
// request holding estimate.submit at its BU (404 otherwise).

const permEstimateSubmit authz.Permission = "estimate.submit"

type inboxItem struct {
	ID           string     `json:"id"`
	Title        string     `json:"title"`
	Status       string     `json:"status"`
	DueAt        time.Time  `json:"due_at"`
	Confidence   string     `json:"confidence"`
	ScenarioName *string    `json:"scenario_name"`
	Factors      int        `json:"factors"`
	Answered     int        `json:"answered"`
	FinishedAt   *time.Time `json:"finished_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// listInbox lists the requests addressed to the caller (AC-05, AC-07).
func (a *API) listInbox(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permEstimateSubmit}) {
		return
	}
	items := []inboxItem{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT * FROM estimate.my_requests()")
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, pgx.RowToStructByPos[inboxItem])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": items})
}

func estimatorView(ctx context.Context, tx pgx.Tx, id string) (json.RawMessage, error) {
	if !uuidRE.MatchString(id) {
		return nil, errNotFound
	}
	var b []byte
	err := tx.QueryRow(ctx, "SELECT estimate.request_for_estimator($1)", id).Scan(&b)
	return b, err
}

// getInboxRequest is one request as its estimator sees it: the text, the
// shared context, the factors, the reference classes and their own answers
// (AC-07).
func (a *API) getInboxRequest(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permEstimateSubmit}) {
		return
	}
	var view json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		view, err = estimatorView(r.Context(), tx, r.PathValue("id"))
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type answerBody struct {
	Pointer  string          `json:"pointer"`
	Estimate json.RawMessage `json:"estimate"`
	Declined string          `json:"declined"`
}

// saveAnswers saves the caller's answers to some factors as drafts, or
// submits them (AC-08 to AC-10), each as a new revision, in one
// transaction. Submitted revisions are recorded in the trail.
func (a *API) saveAnswers(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Answers []answerBody `json:"answers"`
		Submit  bool         `json:"submit"`
	}
	if !a.anywhere(w, r, p, []authz.Permission{permEstimateSubmit}) || !decode(w, r, &body) {
		return
	}
	if len(body.Answers) == 0 || len(body.Answers) > 60 {
		problem(w, http.StatusBadRequest, "invalid_value", "answers lists 1 to 60 factors", nil)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	// The request as the estimator sees it gives the factors' units.
	var view struct {
		Request struct {
			ID   string `json:"id"`
			BUID string `json:"bu_id"`
		} `json:"request"`
		Factors []struct {
			Pointer string `json:"pointer"`
			Unit    string `json:"unit"`
		} `json:"factors"`
	}
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		raw, err := estimatorView(ctx, tx, id)
		if err == nil {
			err = json.Unmarshal(raw, &view)
		}
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	units := map[string]string{}
	for _, f := range view.Factors {
		units[f.Pointer] = f.Unit
	}
	type checked struct {
		pointer  string
		estimate []byte
		declined *string
	}
	var answers []checked
	var bad []model.Problem
	seen := map[string]bool{}
	for _, ans := range body.Answers {
		unit, ok := units[ans.Pointer]
		hasEstimate := len(ans.Estimate) > 0 && string(ans.Estimate) != "null"
		switch {
		case !ok:
			bad = append(bad, model.Problem{Pointer: ans.Pointer, Message: "is not a factor of this request"})
			continue
		case seen[ans.Pointer]:
			bad = append(bad, model.Problem{Pointer: ans.Pointer, Message: "is answered twice"})
			continue
		case hasEstimate == (strings.TrimSpace(ans.Declined) != ""):
			bad = append(bad, model.Problem{Pointer: ans.Pointer, Message: "answer with an estimate, or decline with a reason"})
			continue
		}
		seen[ans.Pointer] = true
		if !hasEstimate {
			if !checkText(w, "declined", ans.Declined, 1000, true, false) {
				return
			}
			d := strings.TrimSpace(ans.Declined)
			answers = append(answers, checked{pointer: ans.Pointer, declined: &d})
			continue
		}
		canonical, problems := model.ValidateEstimate(unit, ans.Estimate)
		for _, pr := range problems {
			bad = append(bad, model.Problem{Pointer: ans.Pointer + pr.Pointer, Message: pr.Message})
		}
		answers = append(answers, checked{pointer: ans.Pointer, estimate: canonical})
	}
	if len(bad) > 0 {
		problem(w, http.StatusUnprocessableEntity, "invalid_answer", "", map[string]any{"problems": bad})
		return
	}
	var out json.RawMessage
	err = authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		bu := view.Request.BUID
		for _, ans := range answers {
			var rev int
			var est any
			if ans.estimate != nil {
				est = string(ans.estimate)
			}
			if err := tx.QueryRow(ctx, "SELECT estimate.save_answer($1, $2, $3::jsonb, $4, $5)", id, ans.pointer, est, ans.declined, body.Submit).Scan(&rev); err != nil {
				return err
			}
			if !body.Submit {
				continue // drafts are the estimator's own until submitted
			}
			if err := a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: "estimate.answer_saved", Severity: audit.SeverityLow, Actor: p.UserID,
				Target: "estimate_request:" + id, BUID: bu, Attributes: map[string]string{
					"pointer": ans.pointer, "revision": strconv.Itoa(rev), "declined": strconv.FormatBool(ans.declined != nil)}}); err != nil {
				return err
			}
		}
		var err error
		out, err = estimatorView(ctx, tx, id)
		return err
	})
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "PF016" {
		problem(w, http.StatusUnprocessableEntity, "invalid_answer", pg.Message, map[string]any{"detail_lines": strings.Split(pg.Detail, "\n")})
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
