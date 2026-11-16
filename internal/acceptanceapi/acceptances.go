package acceptanceapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-008 T-05 (F-008-AC-01 to AC-08, AC-14, AC-16, AC-19; design §3.3, §6).

// effectiveSQL is an acceptance's state as read: an active or suspended one
// on or past its expiry date reads as expired before the job ends it
// (design §3.2, Availability NFR).
const effectiveSQL = `CASE WHEN x.state IN ('active', 'suspended') AND x.expires_on <= current_date THEN 'expired' ELSE x.state END`

// reviewSQL is why an active acceptance needs review (AC-14, design §3.3):
// its risk's exposure is stale, its treatment (as the caller sees it) is no
// longer accept, or the risk moved since it was approved. Null when the
// caller does not see the risk.
const reviewSQL = `CASE WHEN r.id IS NULL THEN NULL WHEN (` + effectiveSQL + `) <> 'active' THEN '{}'::text[] ELSE array_remove(ARRAY[
	  CASE WHEN (` + register.StatusSQL + `) <> 'current' THEN 'stale' END,
	  CASE WHEN EXISTS (SELECT 1 FROM register.treatment t WHERE t.risk_id = r.id AND t.decision IS DISTINCT FROM 'accept') THEN 'treatment' END,
	  CASE WHEN r.bu_id IS DISTINCT FROM x.approved_bu_id THEN 'moved' END], NULL) END`

// roundSQL counts the approvals of an acceptance's current round.
const roundSQL = `(SELECT count(*) FROM acceptance.step s WHERE s.acceptance_id = x.id AND s.kind = 'approved'
	  AND s.n > (SELECT max(q.n) FROM acceptance.step q WHERE q.acceptance_id = x.id AND q.kind IN ('requested', 'review_requested')))`

const columns = `x.id::text, x.bu_id::text, x.risk_id::text, r.title, r.owner::text, x.renews::text, ` + effectiveSQL + `, x.state, x.end_reason, x.tier,
	x.tier_bu_id::text, x.approvals_needed, ` + roundSQL + `, x.mean::float8, x.expires_on, x.approved_bu_id::text, x.requested_by::text, x.requested_at,
	x.activated_at, x.ended_at, x.seq, ` + reviewSQL

// from joins the risk (as the caller sees it) and its link stats.
const from = ` FROM acceptance.acceptance x LEFT JOIN register.risk r ON r.id = x.risk_id` + register.LinkStats

type row struct {
	m     map[string]any
	owner *string
}

func scan(rows pgx.Row) (row, error) {
	var (
		id, bu, risk, state, stored, tierBU, by string
		title, owner, renews, endReason, appr   *string
		tier, needed                            int
		approvals, seq                          int64
		mean                                    float64
		expires                                 time.Time
		requested                               time.Time
		activated, ended                        *time.Time
		review                                  []string
	)
	if err := rows.Scan(&id, &bu, &risk, &title, &owner, &renews, &state, &stored, &endReason, &tier, &tierBU, &needed, &approvals, &mean, &expires,
		&appr, &by, &requested, &activated, &ended, &seq, &review); err != nil {
		return row{}, err
	}
	if review == nil {
		review = []string{}
	}
	return row{owner: owner, m: map[string]any{"id": id, "bu_id": bu, "risk_id": risk, "risk_title": title, "renews": renews, "state": state,
		"stored_state": stored, "end_reason": endReason, "tier": tier, "tier_bu_id": tierBU, "approvals_needed": needed, "approvals": approvals,
		"mean": mean, "expires_on": expires.Format(time.DateOnly), "approved_bu_id": appr, "requested_by": by, "requested_at": requested,
		"activated_at": activated, "ended_at": ended, "seq": seq, "needs_review": review}}, nil
}

var states = []string{"pending", "active", "suspended", "expired", "ended", "needs_review"}

// listAcceptances lists the acceptances the caller sees (AC-19): ?state=
// (or needs_review), ?bu= (with &subtree=false, that BU only), ?risk=,
// ?expiring_within= days, ?limit= 1 to 200 (50), ?offset=; newest first.
func (a *API) listAcceptances(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	q := r.URL.Query()
	where := []string{"true"}
	args := []any{}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	switch v := q.Get("state"); {
	case v == "":
	case v == "needs_review":
		where = append(where, "cardinality("+reviewSQL+") > 0")
	case slices.Contains(states, v):
		where = append(where, "("+effectiveSQL+") = "+arg(v))
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "state is pending, active, suspended, expired, ended or needs_review", nil)
		return
	}
	if v := q.Get("risk"); v != "" {
		if !uuidRE.MatchString(v) {
			problem(w, http.StatusBadRequest, "invalid_value", "risk is a risk id", nil)
			return
		}
		where = append(where, "x.risk_id = "+arg(v)+"::uuid")
	}
	if v := q.Get("bu"); v != "" {
		if !uuidRE.MatchString(v) {
			problem(w, http.StatusBadRequest, "invalid_value", "bu is a business unit id", nil)
			return
		}
		if q.Get("subtree") == "false" {
			where = append(where, "x.bu_id = "+arg(v)+"::uuid")
		} else {
			where = append(where, "x.bu_id IN (SELECT acceptance.subtree("+arg(v)+"::uuid))")
		}
	}
	if v := q.Get("expiring_within"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 3650 {
			problem(w, http.StatusBadRequest, "invalid_value", "expiring_within is 0 to 3,650 days", nil)
			return
		}
		where = append(where, "("+effectiveSQL+") = 'active' AND x.expires_on <= current_date + "+arg(n)+"::integer")
	}
	limit, offset := 50, 0
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 200 {
			problem(w, http.StatusBadRequest, "invalid_value", "limit is 1 to 200", nil)
			return
		}
		limit = n
	}
	if s := q.Get("offset"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 1_000_000 {
			problem(w, http.StatusBadRequest, "invalid_value", "offset is 0 or more", nil)
			return
		}
		offset = n
	}
	sql := "SELECT " + columns + from + " WHERE " + strings.Join(where, " AND ") + " ORDER BY x.seq DESC LIMIT " + arg(limit+1) + " OFFSET " + arg(offset)
	out := []map[string]any{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			x, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, x.m)
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
	if err := a.requesters(r, p, out); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acceptances": out, "more": more})
}

// inbox lists the pending and suspended acceptances the caller may decide
// (AC-08): acceptance.approve at their tier's BU, neither the requester nor
// the risk's owner, not decided by the caller in this round.
func (a *API) inbox(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	held, err := a.Authz.BUsWith(r.Context(), p, permApprove)
	if err != nil {
		server.WriteAuthzError(w, err)
		return
	}
	bus := make([]string, 0, len(held))
	for b := range held {
		bus = append(bus, b)
	}
	out := []map[string]any{}
	if len(bus) > 0 {
		err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
			rows, err := tx.Query(r.Context(), "SELECT "+columns+from+` WHERE x.state IN ('pending', 'suspended') AND x.tier_bu_id = ANY ($1::uuid[])
				AND x.requested_by <> $2::uuid AND r.owner IS DISTINCT FROM $2::uuid
				AND NOT EXISTS (SELECT 1 FROM acceptance.step s WHERE s.acceptance_id = x.id AND s.actor = $2::uuid AND s.kind IN ('approved', 'rejected')
				  AND s.n > (SELECT max(q.n) FROM acceptance.step q WHERE q.acceptance_id = x.id AND q.kind IN ('requested', 'review_requested')))
				ORDER BY x.requested_at, x.seq LIMIT 200`, bus, p.UserID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				x, err := scan(rows)
				if err != nil {
					return err
				}
				out = append(out, x.m)
			}
			return rows.Err()
		})
		if err != nil {
			fail(w, err)
			return
		}
	}
	if err := a.requesters(r, p, out); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acceptances": out})
}

// tiers answers the tiers in force (design §3.4), for the forms.
func (a *API) tiers(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	l, err := a.Settings.Limits()
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "the acceptance settings cannot be read", nil)
		return
	}
	out := []map[string]any{}
	for _, t := range l.Tiers() {
		out = append(out, map[string]any{"tier": t.N, "max_mean": t.Max, "levels_up": t.LevelsUp, "root": t.LevelsUp == nil, "approvals": t.Approvals})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tiers": out, "max_duration_days": l.MaxDurationDays})
}

type step struct {
	N      int             `json:"n"`
	Kind   string          `json:"kind"`
	Actor  *string         `json:"actor"`
	At     time.Time       `json:"at"`
	Reason *string         `json:"reason"`
	Data   json.RawMessage `json:"data"`
}

// getAcceptance answers an acceptance (AC-16): its head, why it needs
// review, its history with the evidence, and what the caller may do.
func (a *API) getAcceptance(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var x row
	var steps []step
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		var err error
		x, err = scan(tx.QueryRow(ctx, "SELECT "+columns+from+" WHERE x.id = $1", id))
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT n, kind, actor::text, at, reason, data FROM acceptance.step WHERE acceptance_id = $1 ORDER BY n", id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s step
			if err := rows.Scan(&s.N, &s.Kind, &s.Actor, &s.At, &s.Reason, &s.Data); err != nil {
				return err
			}
			steps = append(steps, s)
		}
		return rows.Err()
	})
	if err != nil {
		fail(w, err)
		return
	}
	m := x.m
	state := m["state"].(string)
	me := p.UserID
	sod := m["requested_by"] != me && (x.owner == nil || *x.owner != me)
	approver := a.Authz.Check(r.Context(), p, permApprove, m["tier_bu_id"].(string)) == nil
	decided := false
	round := 0
	for _, s := range steps {
		if s.Kind == "requested" || s.Kind == "review_requested" {
			round = s.N
		}
	}
	for _, s := range steps {
		if s.N > round && (s.Kind == "approved" || s.Kind == "rejected") && s.Actor != nil && *s.Actor == me {
			decided = true
		}
	}
	m["steps"] = steps
	ids := []string{m["requested_by"].(string)}
	for _, s := range steps {
		if s.Actor != nil {
			ids = append(ids, *s.Actor)
		}
	}
	names, err := a.people(r, p, ids)
	if err != nil {
		fail(w, err)
		return
	}
	m["names"] = names
	if len(steps) > 0 && steps[0].Kind == "requested" {
		m["evidence"] = steps[0].Data
	}
	m["may_decide"] = approver && sod && !decided && (state == "pending" || state == "suspended")
	m["may_withdraw"] = m["requested_by"] == me && state == "pending"
	m["may_revoke"] = approver && sod && (state == "active" || state == "suspended")
	m["may_renew"] = state == "active" && a.Authz.Check(r.Context(), p, permRequest, m["bu_id"].(string)) == nil
	writeJSON(w, http.StatusOK, m)
}

type requestBody struct {
	RiskID        string  `json:"risk_id"`
	Justification string  `json:"justification"`
	Conditions    string  `json:"conditions"`
	ExpiresOn     string  `json:"expires_on"`
	Renews        *string `json:"renews"`
}

// requestAcceptance requests acceptance of a risk, or its renewal (AC-01,
// AC-02, AC-11); the database checks everything.
func (a *API) requestAcceptance(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var body requestBody
	if !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.RiskID) || (body.Renews != nil && !uuidRE.MatchString(*body.Renews)) {
		problem(w, http.StatusBadRequest, "invalid_value", "risk_id (and renews) are ids", nil)
		return
	}
	expires, ok := dateOf(w, body.ExpiresOn)
	if !ok {
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT acceptance.request($1, $2, $3, $4, $5)::text", body.RiskID, body.Justification, body.Conditions, expires,
			body.Renews).Scan(&id)
	})
	if err != nil {
		fail(w, err)
		return
	}
	a.answer(w, r, p, id, http.StatusCreated)
}

// answer writes acceptance id's head after a change.
func (a *API) answer(w http.ResponseWriter, r *http.Request, p authz.Principal, id string, status int) {
	var x row
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		x, err = scan(tx.QueryRow(r.Context(), "SELECT "+columns+from+" WHERE x.id = $1", id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, status, map[string]any{"id": id}) // changed, then out of sight
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, status, x.m)
}

func dateOf(w http.ResponseWriter, s string) (string, bool) {
	if _, err := time.Parse(time.DateOnly, s); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_expiry", "expires_on is a date (YYYY-MM-DD)",
			map[string]any{"problems": []map[string]string{{"pointer": "/expires_on", "message": "is a date (YYYY-MM-DD)"}}})
		return "", false
	}
	return s, true
}

type decisionBody struct {
	Decision  string  `json:"decision"`
	Rationale string  `json:"rationale"`
	ExpiresOn *string `json:"expires_on"`
}

// decideAcceptance approves or rejects (AC-05, AC-06, AC-07).
func (a *API) decideAcceptance(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	id, ok := a.target(w, r, p)
	if !ok {
		return
	}
	var body decisionBody
	if !decode(w, r, &body) {
		return
	}
	var expires any
	if body.ExpiresOn != nil {
		s, ok := dateOf(w, *body.ExpiresOn)
		if !ok {
			return
		}
		expires = s
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT acceptance.decide($1, $2, $3, $4)", id, body.Decision, body.Rationale, expires)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	a.answer(w, r, p, id, http.StatusOK)
}

type reasonBody struct {
	Reason string `json:"reason"`
}

func (a *API) withdrawAcceptance(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.ending(w, r, p, "SELECT acceptance.withdraw($1, $2)")
}

func (a *API) revokeAcceptance(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.ending(w, r, p, "SELECT acceptance.revoke($1, $2)")
}

// ending withdraws (AC-03) or revokes (AC-15), with a reason.
func (a *API) ending(w http.ResponseWriter, r *http.Request, p authz.Principal, sql string) {
	id, ok := a.target(w, r, p)
	if !ok {
		return
	}
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	reason, ok := reasonOf(w, body.Reason)
	if !ok {
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), sql, id, reason)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	a.answer(w, r, p, id, http.StatusOK)
}

func (a *API) target(w http.ResponseWriter, r *http.Request, p authz.Principal) (string, bool) {
	if !a.anywhere(w, r, p) {
		return "", false
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return "", false
	}
	return id, true
}

// people answers the display names of ids who requested or took a step on
// an acceptance the caller sees (acceptance.people), by id.
func (a *API) people(r *http.Request, p authz.Principal, ids []string) (map[string]string, error) {
	names := map[string]string{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT user_id::text, name FROM acceptance.people($1::uuid[])", ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, name string
			if err := rows.Scan(&id, &name); err != nil {
				return err
			}
			names[id] = name
		}
		return rows.Err()
	})
	return names, err
}

// requesters fills each acceptance's requested_by_name in one call.
func (a *API) requesters(r *http.Request, p authz.Principal, out []map[string]any) error {
	if len(out) == 0 {
		return nil
	}
	ids := make([]string, 0, len(out))
	for _, x := range out {
		ids = append(ids, x["requested_by"].(string))
	}
	names, err := a.people(r, p, ids)
	if err != nil {
		return err
	}
	for _, x := range out {
		x["requested_by_name"] = nil
		if n, ok := names[x["requested_by"].(string)]; ok {
			x["requested_by_name"] = n
		}
	}
	return nil
}

// myPermissions says which acceptance permissions the caller holds at ?bu=
// (for the pages, which offer only what the API would allow).
func (a *API) myPermissions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	bu := r.URL.Query().Get("bu")
	if !uuidRE.MatchString(bu) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu is a business unit id", nil)
		return
	}
	out := map[string]bool{}
	for _, perm := range []authz.Permission{permView, permRequest, permApprove} {
		out[string(perm)] = a.Authz.Check(r.Context(), p, perm, bu) == nil
	}
	writeJSON(w, http.StatusOK, out)
}
