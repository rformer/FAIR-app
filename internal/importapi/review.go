package importapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/registerapi"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-10a (F-011-AC-10 to AC-12, AC-14, AC-25, AC-26; design §3.4 as
// amended): the review of proposals. Proposals are listed to the holders
// of their kind's view permission at their BU; accepting one writes the
// target's version through the risk API's own save code in the reviewer's
// transaction (riskapi.Create, Save, Archive), then records the provenance
// and the link (integration.accepted), all or nothing.

// reviewAnywhere answers 404 unless the caller may read some kind of
// record that proposals change.
func (a *API) reviewAnywhere(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	for _, perm := range []authz.Permission{"library.view", "control.view", "register.view"} {
		bus, err := a.Authz.BUsWith(r.Context(), p, perm)
		if err != nil {
			server.WriteAuthzError(w, err)
			return false
		}
		if len(bus) > 0 {
			return true
		}
	}
	notFound(w)
	return false
}

func (a *API) listProposals(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.reviewAnywhere(w, r, p) {
		return
	}
	q := r.URL.Query()
	opt := func(k string, allowed ...string) (any, bool) {
		v := q.Get(k)
		if v == "" {
			return nil, true
		}
		if len(allowed) > 0 {
			for _, x := range allowed {
				if v == x {
					return v, true
				}
			}
			problem(w, http.StatusBadRequest, "invalid_value", k+" is one of "+strings.Join(allowed, ", "), nil)
			return nil, false
		}
		if !uuidRE.MatchString(v) {
			problem(w, http.StatusBadRequest, "invalid_value", k+" is an id", nil)
			return nil, false
		}
		return v, true
	}
	state, ok1 := opt("state", "pending", "accepted", "rejected", "superseded")
	kind, ok2 := opt("kind", "asset", "asset_group", "control", "risk", "reference_class")
	integ, ok3 := opt("integration")
	bu, ok4 := opt("bu")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return
	}
	if q.Get("state") == "" {
		state = "pending"
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := []json.RawMessage{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT integration.proposals($1, $2, $3, $4, $5, $6)", state, kind, integ, bu, limit+1, max(offset, 0))
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
	writeJSON(w, http.StatusOK, map[string]any{"proposals": out, "more": more})
}

// readProposal reads id as the caller in tx: the full JSON and its parts.
func readProposal(r *http.Request, tx pgx.Tx, id string) (json.RawMessage, review, error) {
	var raw json.RawMessage
	if err := tx.QueryRow(r.Context(), "SELECT integration.proposal_get($1)", id).Scan(&raw); err != nil {
		return nil, review{}, err
	}
	var pr review
	err := json.Unmarshal(raw, &pr)
	return raw, pr, err
}

func (a *API) getProposal(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.reviewAnywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	out := map[string]any{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		raw, pr, err := readProposal(r, tx, id)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return err
		}
		out["current"], out["proposed"], out["problems"], out["diff"] = nil, nil, []any{}, nil
		if pr.State != "pending" {
			return nil
		}
		m, err := mergeFor(r.Context(), tx, p, pr)
		var um errUnmergeable
		switch {
		case errors.As(err, &um):
			out["problems"] = []map[string]string{{"pointer": "", "message": um.msg}}
			return nil
		case errors.Is(err, riskapi.ErrNotFound), errors.Is(err, registerapi.ErrNotFound):
			out["problems"] = []map[string]string{{"pointer": "", "message": "the record it changes is not visible to you"}}
			return nil
		case err != nil:
			return err
		}
		if m.exists {
			out["current"] = map[string]any{"version": m.version, "document": m.current, "archived": m.archived}
		}
		if m.doc == nil {
			return nil // an archive
		}
		canonical, problems := m.validate(pr.TargetType)
		if problems != nil {
			out["problems"] = problems
			return nil
		}
		out["proposed"] = json.RawMessage(canonical)
		if m.exists && pr.TargetType != "risk" {
			d, err := model.DiffDocuments(pr.TargetType, m.current, canonical)
			if err != nil {
				return err
			}
			out["diff"] = d
		}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type acceptBody struct {
	ExpectedVersion *int   `json:"expected_version"`
	ChangeNote      string `json:"change_note"`
}

func (a *API) acceptProposal(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.reviewAnywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var body acceptBody
	if !decodeBody(w, r, &body) {
		return
	}
	if a.Risk == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "the risk API is not configured", nil)
		return
	}
	var out json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		out, err = a.acceptOne(r.Context(), tx, p, id, body.ExpectedVersion, body.ChangeNote, false)
		return err
	})
	if a.answerDecision(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// errNoRegister: risk proposals need the register API.
var errNoRegister = errors.New("importapi: the register API is not configured")

// MaxBatchAccept is how many proposals one batch accept takes.
const MaxBatchAccept = 200

// acceptMany accepts up to 200 proposals in one transaction, each with its
// own checks: all or nothing (T-10b).
func (a *API) acceptMany(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.reviewAnywhere(w, r, p) {
		return
	}
	var body struct {
		Proposals []struct {
			ID              string `json:"id"`
			ExpectedVersion *int   `json:"expected_version"`
		} `json:"proposals"`
		ChangeNote string `json:"change_note"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if len(body.Proposals) == 0 || len(body.Proposals) > MaxBatchAccept {
		problem(w, http.StatusBadRequest, "invalid_value", "proposals: 1 to 200", map[string]any{"limit": MaxBatchAccept})
		return
	}
	seen := map[string]bool{}
	for _, x := range body.Proposals {
		if !uuidRE.MatchString(x.ID) || seen[x.ID] {
			problem(w, http.StatusBadRequest, "invalid_value", "every proposal id once", nil)
			return
		}
		seen[x.ID] = true
	}
	if a.Risk == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "the risk API is not configured", nil)
		return
	}
	out := []json.RawMessage{}
	var failed string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		for _, x := range body.Proposals {
			j, err := a.acceptOne(r.Context(), tx, p, x.ID, x.ExpectedVersion, body.ChangeNote, false)
			if err != nil {
				failed = x.ID
				return err
			}
			out = append(out, j)
		}
		return nil
	})
	if err != nil {
		w.Header().Set("X-Fair-Failed-Proposal", failed) // which one refused the batch
	}
	if a.answerDecision(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": out})
}

// acceptOne accepts proposal id in tx as p: merged as p reads its target,
// written through the risk or register API's save code, then recorded.
// expected is the target's version reviewed; auto (descriptive-only
// changes at a batch) uses the target's current version.
func (a *API) acceptOne(ctx context.Context, tx pgx.Tx, p authz.Principal, id string, expected *int, changeNote string, auto bool) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := tx.QueryRow(ctx, "SELECT integration.proposal_get($1)", id).Scan(&raw); err != nil {
		return nil, err
	}
	var pr review
	if err := json.Unmarshal(raw, &pr); err != nil {
		return nil, err
	}
	if pr.State != "pending" {
		return nil, errDecided
	}
	note := strings.TrimSpace(changeNote)
	if note == "" {
		note = "Accepted from " + pr.IntegrationName + " (" + pr.ExternalID + ")"
		if auto {
			note = "Accepted automatically from " + pr.IntegrationName + " (" + pr.ExternalID + "): names and descriptions only"
		}
	}
	if pr.TargetType == "risk" && a.Register == nil {
		return nil, errNoRegister
	}
	m, err := mergeFor(ctx, tx, p, pr)
	if err != nil {
		return nil, err
	}
	if auto {
		expected = &m.version
	}
	var target string
	var version *int
	switch {
	case pr.Action == "archive":
		target = *pr.TargetID
		if err := a.Risk.Archive(ctx, tx, p, sectionOf(pr.TargetType), target, "Removed at the source ("+pr.IntegrationName+")"); err != nil {
			return nil, err
		}
	case !m.exists && pr.TargetType == "risk":
		newID, err := a.Register.CreateRisk(ctx, tx, p, pr.BU, m.doc, note)
		if err != nil {
			return nil, err
		}
		target, version = newID, ptr(1)
	case !m.exists:
		newID, _, err := a.Risk.Create(ctx, tx, p, sectionOf(pr.TargetType), pr.BU, pr.TargetType, m.doc, note, nil)
		if err != nil {
			return nil, err
		}
		target, version = newID, ptr(1)
	case expected == nil:
		return nil, errExpected
	case pr.TargetType == "risk":
		v, err := a.Register.SaveRisk(ctx, tx, p, m.id, *expected, m.doc, note)
		if err != nil {
			return nil, err
		}
		target, version = m.id, &v
	default:
		v, _, err := a.Risk.Save(ctx, tx, p, sectionOf(pr.TargetType), m.id, *expected, m.doc, note, nil)
		if err != nil {
			return nil, err
		}
		target, version = m.id, &v
	}
	var out json.RawMessage
	err = tx.QueryRow(ctx, "SELECT integration.accepted($1, $2, $3)", id, target, version).Scan(&out)
	return out, err
}

func (a *API) rejectProposal(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.reviewAnywhere(w, r, p) {
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
	if !decodeBody(w, r, &body) {
		return
	}
	var out json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT integration.reject($1, $2)", id, body.Reason).Scan(&out)
	})
	if a.answerDecision(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

var (
	errDecided  = errors.New("importapi: the proposal was decided")
	errExpected = errors.New("importapi: expected_version is required")
)

func ptr(n int) *int { return &n }

// answerDecision answers an accept's or reject's error; false without one.
func (a *API) answerDecision(w http.ResponseWriter, err error) bool {
	var problems model.Problems
	var um errUnmergeable
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return false
	case errors.Is(err, errDecided), errors.As(err, &pg) && pg.Code == "PF031" && pg.Hint == "proposal_decided":
		problem(w, http.StatusConflict, "proposal_decided", "the proposal was decided already", nil)
	case errors.Is(err, errExpected):
		problem(w, http.StatusBadRequest, "invalid_value", "expected_version (the version you reviewed it against) is required", nil)
	case errors.As(err, &problems):
		problem(w, http.StatusUnprocessableEntity, "invalid_document", "the merged document is not valid", map[string]any{"problems": problems})
	case errors.As(err, &um):
		problem(w, http.StatusUnprocessableEntity, "unmergeable", um.msg, nil)
	case errors.Is(err, riskapi.ErrNotFound):
		notFound(w)
	case errors.Is(err, riskapi.ErrForbidden):
		problem(w, http.StatusForbidden, "forbidden", "accepting needs the edit permission of the record at its business unit", nil)
	case errors.Is(err, errNoRegister):
		problem(w, http.StatusServiceUnavailable, "unavailable", "the register API is not configured", nil)
	case errors.Is(err, registerapi.ErrNotFound):
		notFound(w)
	case errors.Is(err, registerapi.ErrForbidden):
		problem(w, http.StatusForbidden, "forbidden", "accepting needs register.edit at the risk's business unit", nil)
	case errors.Is(err, registerapi.ErrClosed):
		problem(w, http.StatusConflict, "closed", "the risk is closed; reopen it first", nil)
	case errors.Is(err, registerapi.ErrStale):
		problem(w, http.StatusConflict, "stale_version", "the risk changed since the version you reviewed", nil)
	case errors.Is(err, riskapi.ErrArchived):
		problem(w, http.StatusConflict, "archived", "the record is archived; restore it first", nil)
	case errors.Is(err, riskapi.ErrStale), errors.As(err, &pg) && pg.Code == "PF017":
		problem(w, http.StatusConflict, "stale_version", "the record changed since the version you reviewed", nil)
	case errors.Is(err, riskapi.ErrCurrency):
		problem(w, http.StatusConflict, "currency_not_set", "amounts cannot be saved until the installation currency is set", nil)
	case errors.As(err, &pg) && pg.Code == "PF031" && pg.Hint == "reason_required":
		problem(w, http.StatusBadRequest, "reason_required", pg.Message, nil)
	default:
		fail(w, err)
	}
	return true
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object with the documented fields", nil)
		return false
	}
	return true
}
