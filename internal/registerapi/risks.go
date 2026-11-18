package registerapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-007 T-04 (F-007-AC-01 to AC-05, AC-19, AC-21, AC-22; design §6, §8):
// risks.

const target = "register_risk:"

type head struct {
	ID, BU, State string
	Version       int
}

// readHead reads a risk's head as the caller sees it (errNotFound
// otherwise).
func readHead(ctx context.Context, tx pgx.Tx, id string) (head, error) {
	var h head
	err := tx.QueryRow(ctx, "SELECT id::text, bu_id::text, state, current_version FROM register.risk WHERE id = $1", id).Scan(&h.ID, &h.BU, &h.State, &h.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return h, errNotFound
	}
	return h, err
}

// headOf reads a risk's head in its own transaction.
func (a *API) headOf(ctx context.Context, p authz.Principal, id string) (head, error) {
	var h head
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		h, err = readHead(ctx, tx, id)
		return err
	})
	return h, err
}

// currentDoc reads the current version's document.
func currentDoc(ctx context.Context, tx pgx.Tx, h head) ([]byte, error) {
	var b []byte
	err := tx.QueryRow(ctx, "SELECT document FROM register.risk_version WHERE risk_id = $1 AND version = $2", h.ID, h.Version).Scan(&b)
	return b, err
}

// insertVersion adds version v of risk id.
func insertVersion(ctx context.Context, tx pgx.Tx, id string, v int, doc []byte, digest, note string) error {
	_, err := tx.Exec(ctx, "INSERT INTO register.risk_version (risk_id, version, document, digest, change_note) VALUES ($1, $2, $3, $4, $5)",
		id, v, doc, digest, note)
	return err
}

// linkEvents records the scenarios linked and unlinked between two
// documents (from nil: every link is new).
func (a *API) linkEvents(ctx context.Context, p authz.Principal, id, bu string, version int, from, to []byte) error {
	ids := func(b []byte) []string {
		if b == nil {
			return nil
		}
		r, err := register.Decode(b)
		if err != nil {
			return nil
		}
		out := make([]string, 0, len(r.Scenarios))
		for _, l := range r.Scenarios {
			out = append(out, l.ScenarioID)
		}
		return out
	}
	before, after := ids(from), ids(to)
	for _, s := range after {
		if !slices.Contains(before, s) {
			if err := a.emit(ctx, audit.Event{Type: "register.scenario_linked", Severity: audit.SeverityLow, Actor: p.UserID, Target: target + id, BUID: bu,
				Attributes: map[string]string{"scenario": s, "version": strconv.Itoa(version)}}); err != nil {
				return err
			}
		}
	}
	for _, s := range before {
		if !slices.Contains(after, s) {
			if err := a.emit(ctx, audit.Event{Type: "register.scenario_unlinked", Severity: audit.SeverityLow, Actor: p.UserID, Target: target + id, BUID: bu,
				Attributes: map[string]string{"scenario": s, "version": strconv.Itoa(version)}}); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkNote checks a change note (the reason of a change).
func checkNote(w http.ResponseWriter, note string) (string, bool) {
	return reasonOf(w, note)
}

type createBody struct {
	BUID       string          `json:"bu_id"`
	Document   json.RawMessage `json:"document"`
	ChangeNote string          `json:"change_note"`
}

// createRisk creates a risk with its first version (AC-01, AC-02).
func (a *API) createRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	var body createBody
	if !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.BUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id is a business unit id", nil)
		return
	}
	note, ok := checkNote(w, body.ChangeNote)
	if !ok || !a.mayEdit(w, r, p, body.BUID) {
		return
	}
	doc, digest, problems := register.Validate(body.Document)
	if problems != nil {
		invalid(w, problems)
		return
	}
	if d, _ := register.Decode(doc); d.State != "open" {
		invalid(w, model.Problems{{Pointer: "/state", Message: "is open when a risk is created"}})
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		id, err = a.createTx(r.Context(), tx, p, body.BUID, doc, digest, note)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "version": 1, "digest": digest})
}

type saveBody struct {
	Document        json.RawMessage `json:"document"`
	ExpectedVersion *int            `json:"expected_version"`
	ChangeNote      string          `json:"change_note"`
}

// riskTo resolves the path's risk and checks register.edit at its BU.
func (a *API) riskTo(w http.ResponseWriter, r *http.Request, p authz.Principal) (head, bool) {
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
	return h, a.mayEdit(w, r, p, h.BU)
}

// saveRisk saves a new version: fields, links and pins (AC-02, AC-03).
// Closing and reopening have their own routes.
func (a *API) saveRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	h, ok := a.riskTo(w, r, p)
	if !ok {
		return
	}
	var body saveBody
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
	if h.State == "closed" {
		problem(w, http.StatusConflict, "closed", "the risk is closed; reopen it to change it", nil)
		return
	}
	doc, digest, problems := register.Validate(body.Document)
	if problems != nil {
		invalid(w, problems)
		return
	}
	if d, _ := register.Decode(doc); d.State != "open" {
		invalid(w, model.Problems{{Pointer: "/state", Message: "is open; a risk is closed with POST …/close"}})
		return
	}
	version := *body.ExpectedVersion + 1
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return a.saveTx(r.Context(), tx, p, h, version, doc, digest, note)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": h.ID, "version": version, "digest": digest})
}

type reasonBody struct {
	Reason string `json:"reason"`
}

// setState closes or reopens a risk: a new version with the state (and the
// close reason), nothing else changed (AC-04).
func (a *API) setState(w http.ResponseWriter, r *http.Request, p authz.Principal, state string) {
	h, ok := a.riskTo(w, r, p)
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
	if h.State == state {
		problem(w, http.StatusConflict, "same_state", "the risk is "+state+" already", nil)
		return
	}
	var out map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := audit.WithTx(r.Context(), tx)
		prev, err := currentDoc(ctx, tx, h)
		if err != nil {
			return err
		}
		doc, digest, err := register.WithState(prev, state, reason)
		if err != nil {
			return err
		}
		version := h.Version + 1
		if err := insertVersion(ctx, tx, h.ID, version, doc, digest, reason); err != nil {
			return err
		}
		typ := "register.risk_closed"
		if state == "open" {
			typ = "register.risk_reopened"
		}
		out = map[string]any{"id": h.ID, "version": version, "digest": digest}
		return a.emit(ctx, audit.Event{Type: typ, Severity: audit.SeverityLow, Actor: p.UserID, Target: target + h.ID, BUID: h.BU,
			Attributes: map[string]string{"version": strconv.Itoa(version), "reason": reason}})
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) closeRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setState(w, r, p, "closed")
}

func (a *API) reopenRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setState(w, r, p, "open")
}

type moveBody struct {
	ToBUID string `json:"to_bu_id"`
	Reason string `json:"reason"`
}

// moveRisk moves a risk with its versions, links and treatment (AC-05).
func (a *API) moveRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	h, ok := a.riskTo(w, r, p)
	if !ok {
		return
	}
	var body moveBody
	if !decode(w, r, &body) {
		return
	}
	reason, ok := reasonOf(w, body.Reason)
	if !ok {
		return
	}
	if !uuidRE.MatchString(body.ToBUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "to_bu_id is a business unit id", nil)
		return
	}
	if !a.mayEdit(w, r, p, body.ToBUID) {
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := audit.WithTx(r.Context(), tx)
		var from string
		if err := tx.QueryRow(ctx, "SELECT register.move_risk($1, $2)::text", h.ID, body.ToBUID).Scan(&from); err != nil {
			return err
		}
		if err := a.emit(ctx, audit.Event{Type: "register.risk_moved", Severity: audit.SeverityLow, Actor: p.UserID, Target: target + h.ID, BUID: body.ToBUID,
			Attributes: map[string]string{"from_bu": from, "to_bu": body.ToBUID, "reason": reason}}); err != nil {
			return err
		}
		// The exposure aggregate belongs to the risk's BU: a new one there.
		return a.requestExposure(ctx, tx, h.ID)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": h.ID, "bu_id": body.ToBUID})
}

// F-007 T-10: a risk's status computed in the query from its links
// (register.StatusSQL over register.LinkStats), not by a definer function
// per row.
const riskFrom = ` FROM register.risk r LEFT JOIN register.category c ON c.id = r.category_id` + register.LinkStats

// statusSQL is a risk's exposure status (AC-08) given st.
const statusSQL = register.StatusSQL

// exposureSQL is register.ExposureSQL (the caller's view of a risk's exposure).
func exposureSQL(path string) string { return register.ExposureSQL(path) }

const riskColumns = `r.id::text, r.bu_id::text, r.state, r.title, r.owner::text, r.category_id::text, c.name, r.current_version, r.created_at,
	r.created_by::text, r.seq, st.n, r.exposure_aggregate_id::text,
	jsonb_build_object('status', ` + statusSQL + `, 'reasons', '[]'::jsonb),
	(SELECT jsonb_build_object('version', t.current_version, 'decision', t.decision, 'next_due', t.next_due, 'overdue', coalesce(t.next_due < current_date, false))
	 FROM register.treatment t WHERE t.risk_id = r.id),
	` + acceptanceSQL

// acceptanceSQL is register.AcceptanceSQL.
const acceptanceSQL = register.AcceptanceSQL

func scanRisk(row pgx.Row) (map[string]any, error) {
	var (
		id, bu, state, by     string
		title, owner, cat, cn *string
		version               int
		created               time.Time
		seq, scenarios        int64
		aggregate             *string
		status, treatment     []byte
		accepted              []byte
	)
	if err := row.Scan(&id, &bu, &state, &title, &owner, &cat, &cn, &version, &created, &by, &seq, &scenarios, &aggregate, &status, &treatment, &accepted); err != nil {
		return nil, err
	}
	out := map[string]any{"id": id, "bu_id": bu, "state": state, "title": title, "owner": owner, "category": nil, "current_version": version,
		"created_at": created, "created_by": by, "seq": seq, "scenarios": scenarios, "exposure_aggregate_id": aggregate, "status": json.RawMessage(status)}
	if cat != nil {
		out["category"] = map[string]any{"id": *cat, "name": cn}
	}
	// The plan's summary as the caller sees it (treatment.view, RLS): null
	// without one or without the permission.
	out["owner_name"] = nil // ownerNames fills it
	out["acceptance"] = nil
	if accepted != nil {
		out["acceptance"] = json.RawMessage(accepted)
	}
	out["treatment"] = nil
	if treatment != nil {
		out["treatment"] = json.RawMessage(treatment)
	}
	return out, nil
}

var listSorts = map[string]string{"newest": "r.seq DESC", "title": "lower(r.title), r.seq DESC",
	// The exposure as the caller sees it (AC-14, AC-19); unseen or none last.
	"mean": exposureSQL("{ale,mean}") + " DESC NULLS LAST, r.seq DESC",
	"p90":  exposureSQL("{ale,percentiles,p90}") + " DESC NULLS LAST, r.seq DESC"}

// ownerNames fills each risk's owner_name in one call (register.owner_names:
// owners of risks the caller sees).
func ownerNames(ctx context.Context, tx pgx.Tx, risks []map[string]any) error {
	var ids []string
	for _, x := range risks {
		if o, ok := x["owner"].(*string); ok && o != nil && !slices.Contains(ids, *o) {
			ids = append(ids, *o)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, "SELECT user_id::text, name FROM register.owner_names($1::uuid[])", ids)
	if err != nil {
		return err
	}
	names := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return err
		}
		names[id] = name
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range risks {
		if o, ok := x["owner"].(*string); ok && o != nil {
			if n, ok := names[*o]; ok {
				x["owner_name"] = n
			}
		}
	}
	return nil
}

// listRisks lists the risks the caller sees (AC-19): ?bu= (with
// &subtree=false, that BU only), ?owner=, ?category=, ?state=, ?status=
// (the exposure status, AC-08, AC-09), ?decision= and ?overdue=true (the
// treatment, among the risks whose treatment the caller sees, AC-19),
// ?sort=newest|title|mean|p90, ?limit= 1 to 200 (50), ?offset=.
func (a *API) listRisks(w http.ResponseWriter, r *http.Request, p authz.Principal) {
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
	for _, f := range []struct{ name, col string }{{"owner", "r.owner"}, {"category", "r.category_id"}} {
		if v := q.Get(f.name); v != "" {
			if !uuidRE.MatchString(v) {
				problem(w, http.StatusBadRequest, "invalid_value", f.name+" is an id", nil)
				return
			}
			where = append(where, f.col+" = "+arg(v)+"::uuid")
		}
	}
	if v := q.Get("bu"); v != "" {
		if !uuidRE.MatchString(v) {
			problem(w, http.StatusBadRequest, "invalid_value", "bu is a business unit id", nil)
			return
		}
		if q.Get("subtree") == "false" {
			where = append(where, "r.bu_id = "+arg(v)+"::uuid")
		} else {
			where = append(where, "r.bu_id IN (SELECT register.subtree("+arg(v)+"::uuid))")
		}
	}
	if v := q.Get("state"); v != "" {
		if v != "open" && v != "closed" {
			problem(w, http.StatusBadRequest, "invalid_value", "state is open or closed", nil)
			return
		}
		where = append(where, "r.state = "+arg(v))
	}
	if v := q.Get("status"); v != "" {
		if !slices.Contains(statuses, v) {
			problem(w, http.StatusBadRequest, "invalid_value", "status is current, stale, unquantified or computing", nil)
			return
		}
		where = append(where, "("+statusSQL+") = "+arg(v))
	}
	const seesTreatment = "r.bu_id = ANY ((SELECT authz.visible_bus('treatment', 'read'))::uuid[])"
	switch v := q.Get("decision"); v {
	case "":
	case "none":
		where = append(where, seesTreatment, "NOT EXISTS (SELECT 1 FROM register.treatment t WHERE t.risk_id = r.id AND t.decision IS NOT NULL)")
	case "mitigate", "transfer", "avoid", "accept":
		where = append(where, seesTreatment, "EXISTS (SELECT 1 FROM register.treatment t WHERE t.risk_id = r.id AND t.decision = "+arg(v)+")")
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "decision is mitigate, transfer, avoid, accept or none", nil)
		return
	}
	switch q.Get("overdue") {
	case "", "false":
	case "true":
		where = append(where, seesTreatment, "EXISTS (SELECT 1 FROM register.treatment t WHERE t.risk_id = r.id AND t.next_due < current_date)")
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "overdue is true or false", nil)
		return
	}
	// F-008 T-05: by acceptance (as the caller sees acceptances).
	switch v := q.Get("acceptance"); v {
	case "":
	case "none":
		where = append(where, "("+acceptanceSQL+") IS NULL")
	case "active", "pending", "suspended", "expired":
		where = append(where, "("+acceptanceSQL+") ->> 'state' = "+arg(v))
	case "needs_review":
		where = append(where, "jsonb_array_length(("+acceptanceSQL+") -> 'needs_review') > 0")
	case "expiring": // within 30 days
		where = append(where, "("+acceptanceSQL+") ->> 'state' = 'active' AND (("+acceptanceSQL+") ->> 'expires_on')::date <= current_date + 30")
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "acceptance is active, pending, suspended, expired, needs_review, expiring or none", nil)
		return
	}
	order, ok := listSorts[q.Get("sort")]
	if q.Get("sort") == "" {
		order, ok = listSorts["newest"], true
	}
	if !ok {
		problem(w, http.StatusBadRequest, "invalid_value", "sort is newest, title, mean or p90", nil)
		return
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
	sql := "SELECT " + riskColumns + riskFrom + " WHERE " + strings.Join(where, " AND ") +
		" ORDER BY " + order + " LIMIT " + arg(limit+1) + " OFFSET " + arg(offset)
	risks := []map[string]any{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			x, err := scanRisk(rows)
			if err != nil {
				return err
			}
			risks = append(risks, x)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return ownerNames(r.Context(), tx, risks)
	})
	if err != nil {
		fail(w, err)
		return
	}
	more := len(risks) > limit
	if more {
		risks = risks[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"risks": risks, "more": more})
}

// getRisk answers a risk: its head with its exposure status, current
// version, links with their pins and newer runs, and its exposure (AC-06
// to AC-10, AC-19).
func (a *API) getRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var out map[string]any
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		risk, err := scanRisk(tx.QueryRow(ctx, "SELECT "+riskColumns+riskFrom+" WHERE r.id = $1", id))
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		// One risk: its status with every reason.
		var status []byte
		if err := tx.QueryRow(ctx, "SELECT register.exposure_status($1)", id).Scan(&status); err != nil {
			return err
		}
		risk["status"] = json.RawMessage(status)
		if err := ownerNames(ctx, tx, []map[string]any{risk}); err != nil {
			return err
		}
		var (
			version          int
			doc              []byte
			digest, note, by string
			at               time.Time
		)
		if err := tx.QueryRow(ctx, `SELECT version, document, digest, change_note, author::text, created_at FROM register.risk_version
			WHERE risk_id = $1 AND version = $2`, id, risk["current_version"]).Scan(&version, &doc, &digest, &note, &by, &at); err != nil {
			return err
		}
		ls, err := links(ctx, tx, id, doc)
		if err != nil {
			return err
		}
		// F-011 AC-24: controls its scenarios rely on that are no longer
		// in place, on each link and for the risk.
		sids := make([]string, len(ls))
		for i, l := range ls {
			sids[i] = l["scenario_id"].(string)
		}
		lapses, err := integration.ControlLapsed(ctx, tx, sids)
		if err != nil {
			return err
		}
		all := []integration.Lapse{}
		for _, l := range ls {
			mine := lapses[l["scenario_id"].(string)]
			if mine == nil {
				mine = []integration.Lapse{}
			}
			l["control_lapsed"] = mine
			all = append(all, mine...)
		}
		risk["control_lapsed"] = all
		agg, _ := risk["exposure_aggregate_id"].(*string)
		exp, err := exposure(ctx, tx, agg, ls)
		if err != nil {
			return err
		}
		out = map[string]any{"risk": risk, "links": ls, "exposure": exp,
			"version": map[string]any{"version": version, "document": json.RawMessage(doc), "digest": digest, "change_note": note, "author": by, "created_at": at}}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// listRiskVersions lists a risk's versions and, with treatment.view, its
// treatment's, merged newest first (AC-03), each with its stream.
func (a *API) listRiskVersions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	versions := []map[string]any{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		if _, err := readHead(r.Context(), tx, id); err != nil {
			return err
		}
		rows, err := tx.Query(r.Context(), `SELECT 'risk', version, digest, change_note, author::text, created_at FROM register.risk_version WHERE risk_id = $1
			UNION ALL
			SELECT 'treatment', version, digest, change_note, author::text, created_at FROM register.treatment_version WHERE risk_id = $1
			ORDER BY 6 DESC, 1, 2 DESC`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v int
			var stream, digest, note, by string
			var at time.Time
			if err := rows.Scan(&stream, &v, &digest, &note, &by, &at); err != nil {
				return err
			}
			versions = append(versions, map[string]any{"stream": stream, "version": v, "digest": digest, "change_note": note, "author": by, "created_at": at})
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		// F-011 AC-25: versions an integration's proposal made.
		prov, err := integration.ProvenanceOf(r.Context(), tx, "risk", id)
		if err != nil {
			return err
		}
		for _, v := range versions {
			if v["stream"] == "risk" {
				if pv, ok := prov[v["version"].(int)]; ok {
					v["provenance"] = pv
				}
			}
		}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

// diffRisk answers the differences between ?from= and ?to= of the risk,
// or with ?stream=treatment of its treatment (AC-03).
func (a *API) diffRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	from, err1 := strconv.Atoi(r.URL.Query().Get("from"))
	to, err2 := strconv.Atoi(r.URL.Query().Get("to"))
	if err1 != nil || err2 != nil || from < 1 || to < 1 || from == to {
		problem(w, http.StatusBadRequest, "invalid_value", "from and to are two versions", nil)
		return
	}
	table := "register.risk_version"
	switch r.URL.Query().Get("stream") {
	case "", "risk":
	case "treatment":
		table = "register.treatment_version"
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "stream is risk or treatment", nil)
		return
	}
	var changes []register.Change
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		if _, err := readHead(r.Context(), tx, id); err != nil {
			return err
		}
		docs := map[int][]byte{}
		rows, err := tx.Query(r.Context(), "SELECT version, document FROM "+table+" WHERE risk_id = $1 AND version IN ($2, $3)", id, from, to)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v int
			var b []byte
			if err := rows.Scan(&v, &b); err != nil {
				return err
			}
			docs[v] = b
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(docs) != 2 {
			return errNotFound
		}
		changes, err = register.Diff(docs[from], docs[to])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "from": from, "to": to, "changes": changes})
}
