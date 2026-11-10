package estimateapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/estimate"
	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-004 T-06 (AC-01 to AC-06; design §5, §6.1): estimate requests.

const (
	permScenarioView    authz.Permission = "scenario.view"
	permScenarioEdit    authz.Permission = "scenario.edit"
	permEstimateRequest authz.Permission = "estimate.request"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var errNotFound = errors.New("estimateapi: not found")

// fail answers a database or audit error.
func fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, errNotFound), errors.As(err, &pg) && pg.Code == "P0002":
		problem(w, http.StatusNotFound, "not_found", "", nil)
	case errors.Is(err, authz.ErrNoDBContext):
		problem(w, http.StatusUnauthorized, "unauthenticated", "", nil)
	case errors.As(err, &pg) && pg.Code == "42501":
		problem(w, http.StatusForbidden, "forbidden", "", nil)
	case errors.As(err, &pg) && pg.Code == "PF016":
		// A refused value: the database lists each problem as "pointer: message".
		var ps []map[string]string
		for _, line := range strings.Split(pg.Detail, "\n") {
			if ptr, msg, ok := strings.Cut(line, ": "); ok {
				ps = append(ps, map[string]string{"pointer": ptr, "message": msg})
			}
		}
		problem(w, http.StatusUnprocessableEntity, "invalid_value", strings.TrimPrefix(pg.Message, "estimate: "), map[string]any{"problems": ps})
	case errors.As(err, &pg) && pg.Code == "PF022":
		// A limit or a state: the database's reason is for the user.
		problem(w, http.StatusConflict, "refused", strings.TrimPrefix(pg.Message, "estimate."), nil)
	case errors.As(err, &pg) && (pg.Code == "23514" || pg.Code == "23505"):
		problem(w, http.StatusUnprocessableEntity, "invalid_value", pg.Message, nil)
	default:
		problem(w, http.StatusServiceUnavailable, "unavailable", "", nil) // includes an event that could not be recorded
	}
}

// mayRequest answers and returns false unless the caller may send and
// change requests at bu: estimate.request and scenario.edit there (403 for
// someone who can see the scenario, 404 for anyone else).
func (a *API) mayRequest(w http.ResponseWriter, r *http.Request, p authz.Principal, bu string) bool {
	for _, perm := range []authz.Permission{permEstimateRequest, permScenarioEdit} {
		err := a.Authz.Check(r.Context(), p, perm, bu)
		if err == nil {
			continue
		}
		var su *authz.StepUpError
		if errors.As(err, &su) || errors.Is(err, authz.ErrStepUpRequired) {
			server.WriteAuthzError(w, err)
			return false
		}
		if a.Authz.Check(r.Context(), p, permScenarioView, bu) == nil {
			problem(w, http.StatusForbidden, "forbidden", "sending and changing estimate requests needs estimate.request and scenario.edit at this business unit", nil)
			return false
		}
		problem(w, http.StatusNotFound, "not_found", "", nil)
		return false
	}
	return true
}

// checkText refuses empty, long, multi-line (unless allowed) or secret-
// looking text.
func checkText(w http.ResponseWriter, name, s string, max int, required, multiline bool) bool {
	t := strings.TrimSpace(s)
	switch {
	case required && t == "":
		problem(w, http.StatusBadRequest, "invalid_value", name+" is required", nil)
	case utf8.RuneCountInString(s) > max:
		problem(w, http.StatusBadRequest, "invalid_value", fmt.Sprintf("%s is at most %d characters", name, max), nil)
	case !multiline && strings.ContainsAny(s, "\r\n"):
		problem(w, http.StatusBadRequest, "invalid_value", name+" is a single line", nil)
	case audit.LooksSecret(s):
		problem(w, http.StatusBadRequest, "invalid_value", name+" looks like a secret", nil)
	default:
		return true
	}
	return false
}

type reference struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

type createBody struct {
	ScenarioID   string      `json:"scenario_id"`
	Title        string      `json:"title"`
	Instructions string      `json:"instructions"`
	Confidence   string      `json:"confidence"`
	DueAt        time.Time   `json:"due_at"`
	Factors      []string    `json:"factors"`
	Context      []string    `json:"context"`
	Estimators   []string    `json:"estimators"`
	References   []reference `json:"references"`
}

func distinctUUIDs(ids []string) bool {
	seen := map[string]bool{}
	for _, id := range ids {
		if !uuidRE.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// scenarioAt is a scenario's head and current version as the caller sees it.
type scenarioAt struct {
	bu      string
	version int
	doc     *model.Scenario
	asset   map[string]any
	tc      map[string]any
}

func loadScenario(ctx context.Context, tx pgx.Tx, id string) (*scenarioAt, error) {
	var s scenarioAt
	var archived *time.Time
	if err := tx.QueryRow(ctx, "SELECT bu_id::text, current_version, archived_at FROM risk.scenario WHERE id = $1", id).Scan(&s.bu, &s.version, &archived); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errNotFound
		}
		return nil, err
	}
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT document FROM risk.scenario_version WHERE scenario_id = $1 AND version = $2", id, s.version).Scan(&raw); err != nil {
		return nil, err
	}
	d, problems := model.Validate(model.KindScenario, raw)
	if problems != nil {
		return nil, fmt.Errorf("estimateapi: stored scenario %s: %w", id, problems)
	}
	s.doc = d.Value.(*model.Scenario)
	rows, err := tx.Query(ctx, "SELECT pointer, to_document FROM risk.scenario_pin WHERE scenario_id = $1 AND version = $2 AND pointer IN ('/asset', '/threat_community')", id, s.version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ptr string
		var b []byte
		if err := rows.Scan(&ptr, &b); err != nil {
			return nil, err
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if ptr == "/asset" {
			s.asset = m
		} else {
			s.tc = m
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if archived != nil {
		return &s, errArchived
	}
	return &s, nil
}

var errArchived = errors.New("estimateapi: the scenario is archived")

// createRequest sends an estimate request (AC-01, AC-02, AC-05).
func (a *API) createRequest(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body createBody
	if !a.anywhere(w, r, p, []authz.Permission{permScenarioView}) || !decode(w, r, &body) {
		return
	}
	switch {
	case !uuidRE.MatchString(body.ScenarioID):
		problem(w, http.StatusBadRequest, "invalid_value", "scenario_id (a UUID) is required", nil)
		return
	case len(body.Factors) == 0 || len(body.Factors) > 60:
		problem(w, http.StatusBadRequest, "invalid_value", "factors lists 1 to 60 pointers", nil)
		return
	case len(body.Estimators) == 0 || len(body.Estimators) > 50 || !distinctUUIDs(body.Estimators):
		problem(w, http.StatusBadRequest, "invalid_value", "estimators lists 1 to 50 distinct user ids", nil)
		return
	case len(body.References) > 20:
		problem(w, http.StatusBadRequest, "invalid_value", "at most 20 references", nil)
		return
	case body.DueAt.IsZero():
		problem(w, http.StatusBadRequest, "invalid_value", "due_at is required", nil)
		return
	}
	if !checkText(w, "title", body.Title, 200, true, false) || !checkText(w, "instructions", body.Instructions, 10000, false, true) {
		return
	}
	conf := "0.9"
	if body.Confidence != "" {
		c, err := canon.Decimal(body.Confidence)
		if err != nil || c == "0" || !strings.HasPrefix(c, "0.") {
			problem(w, http.StatusBadRequest, "invalid_value", "confidence is between 0 and 1, exclusive", nil)
			return
		}
		conf = c
	}
	fields := body.Context
	if fields == nil {
		fields = estimate.ContextFields
	}
	refs := map[string]bool{}
	for _, ref := range body.References {
		if !uuidRE.MatchString(ref.ID) || ref.Version < 1 || refs[ref.ID] {
			problem(w, http.StatusBadRequest, "invalid_value", "references are distinct {id, version} of reference classes", nil)
			return
		}
		refs[ref.ID] = true
	}

	ctx := r.Context()
	var s *scenarioAt
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		s, err = loadScenario(ctx, tx, body.ScenarioID)
		return err
	})
	if errors.Is(err, errArchived) {
		problem(w, http.StatusConflict, "archived", "the scenario is archived; restore it before asking for estimates", nil)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	if !a.mayRequest(w, r, p, s.bu) {
		return
	}
	var factors []estimate.Factor
	var bad []map[string]string
	for _, ptr := range body.Factors {
		f, ok := estimate.FactorAt(s.doc, ptr)
		switch {
		case !ok:
			bad = append(bad, map[string]string{"pointer": ptr, "message": "is not an estimate this scenario's levels require"})
		case slices.ContainsFunc(factors, func(g estimate.Factor) bool { return g.Pointer == ptr }):
			bad = append(bad, map[string]string{"pointer": ptr, "message": "is listed twice"})
		default:
			factors = append(factors, f)
		}
	}
	if len(bad) > 0 {
		problem(w, http.StatusUnprocessableEntity, "invalid_factors", "", map[string]any{"problems": bad})
		return
	}
	snapshot, err := estimate.Snapshot(s.doc, s.asset, s.tc, fields)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_value", err.Error(), nil)
		return
	}
	contextJSON, _ := json.Marshal(snapshot)

	var id string
	err = authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO estimate.request (bu_id, scenario_id, scenario_version, title, instructions, confidence, due_at, context)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id::text`,
			s.bu, body.ScenarioID, s.version, strings.TrimSpace(body.Title), body.Instructions, conf, body.DueAt, contextJSON).Scan(&id); err != nil {
			return err
		}
		for _, f := range factors {
			if _, err := tx.Exec(ctx, "INSERT INTO estimate.request_factor (request_id, pointer, factor, unit, definition) VALUES ($1, $2, $3, $4, $5)",
				id, f.Pointer, f.Factor, f.Unit, f.Definition); err != nil {
				return err
			}
		}
		for _, u := range body.Estimators {
			if _, err := tx.Exec(ctx, "INSERT INTO estimate.request_estimator (request_id, user_id) VALUES ($1, $2)", id, u); err != nil {
				return err
			}
		}
		for _, ref := range body.References {
			if _, err := tx.Exec(ctx, "INSERT INTO estimate.request_reference (request_id, entry_id, version) VALUES ($1, $2, $3)", id, ref.ID, ref.Version); err != nil {
				return err
			}
		}
		return a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: "estimate.request_created", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "estimate_request:" + id, BUID: s.bu, Attributes: map[string]string{
				"scenario": body.ScenarioID, "scenario_version": strconv.Itoa(s.version), "factors": strconv.Itoa(len(factors)),
				"estimators": strconv.Itoa(len(body.Estimators)), "references": strconv.Itoa(len(body.References)),
				"due_at": body.DueAt.UTC().Format(time.RFC3339), "confidence": conf}})
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "scenario_version": s.version})
}

type requestItem struct {
	ID              string     `json:"id"`
	BUID            string     `json:"bu_id"`
	ScenarioID      string     `json:"scenario_id"`
	ScenarioVersion int        `json:"scenario_version"`
	Title           string     `json:"title"`
	Instructions    string     `json:"instructions"`
	Confidence      string     `json:"confidence"`
	DueAt           time.Time  `json:"due_at"`
	Status          string     `json:"status"`
	Affected        *string    `json:"affected"`
	CancelReason    *string    `json:"cancel_reason,omitempty"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	EndedAt         *time.Time `json:"ended_at"`
	Factors         int        `json:"factors"`
	Estimators      int        `json:"estimators"`
}

const requestColumns = `q.id::text, q.bu_id::text, q.scenario_id::text, q.scenario_version, q.title, q.instructions, q.confidence::text, q.due_at, q.status,
	q.affected, q.cancel_reason, q.created_by::text, q.created_at, q.ended_at,
	(SELECT count(*)::int FROM estimate.request_factor f WHERE f.request_id = q.id),
	(SELECT count(*)::int FROM estimate.request_estimator e WHERE e.request_id = q.id AND e.removed_at IS NULL)`

// listEstimators lists the people the caller may name as estimators at a
// BU (AC-01): id and name of each active person holding estimate.submit
// there, for a holder of estimate.request and scenario.edit at it; 404
// otherwise (estimate.estimators, migration 0100).
func (a *API) listEstimators(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permEstimateRequest}) {
		return
	}
	bu := r.URL.Query().Get("bu")
	if !uuidRE.MatchString(bu) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu (a UUID) is required", nil)
		return
	}
	var out json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT estimate.estimators($1)", bu).Scan(&out)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"estimators": out})
}

// listRequests lists a scenario's requests, newest first (AC-04).
func (a *API) listRequests(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permScenarioView}) {
		return
	}
	sid := r.URL.Query().Get("scenario")
	if !uuidRE.MatchString(sid) {
		problem(w, http.StatusBadRequest, "invalid_value", "scenario (a UUID) is required", nil)
		return
	}
	items := []requestItem{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT "+requestColumns+" FROM estimate.request q WHERE q.scenario_id = $1 ORDER BY q.seq DESC", sid)
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, pgx.RowToStructByPos[requestItem])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": items})
}

func (a *API) loadRequest(ctx context.Context, tx pgx.Tx, id string) (requestItem, error) {
	if !uuidRE.MatchString(id) {
		return requestItem{}, errNotFound
	}
	rows, err := tx.Query(ctx, "SELECT "+requestColumns+" FROM estimate.request q WHERE q.id = $1", id)
	if err != nil {
		return requestItem{}, err
	}
	it, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[requestItem])
	if errors.Is(err, pgx.ErrNoRows) {
		return it, errNotFound
	}
	return it, err
}

// getRequest reads a request with its factors, estimators, references and
// context (AC-02, AC-04).
func (a *API) getRequest(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p, []authz.Permission{permScenarioView}) {
		return
	}
	ctx := r.Context()
	out := map[string]any{}
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		it, err := a.loadRequest(ctx, tx, r.PathValue("id"))
		if err != nil {
			return err
		}
		out["request"] = it
		var c []byte
		if err := tx.QueryRow(ctx, "SELECT context FROM estimate.request WHERE id = $1", it.ID).Scan(&c); err != nil {
			return err
		}
		out["context"] = json.RawMessage(c)
		type factor struct {
			Pointer         string     `json:"pointer"`
			Factor          string     `json:"factor"`
			Unit            string     `json:"unit"`
			Definition      string     `json:"definition"`
			AcceptedVersion *int       `json:"accepted_version"`
			AcceptedAt      *time.Time `json:"accepted_at"`
		}
		rows, err := tx.Query(ctx, "SELECT pointer, factor, unit, definition, accepted_version, accepted_at FROM estimate.request_factor WHERE request_id = $1 ORDER BY pointer", it.ID)
		if err != nil {
			return err
		}
		fs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[factor])
		if err != nil {
			return err
		}
		out["factors"] = fs
		type estimator struct {
			UserID     string     `json:"user_id"`
			AddedBy    string     `json:"added_by"`
			AddedAt    time.Time  `json:"added_at"`
			RemovedAt  *time.Time `json:"removed_at"`
			FinishedAt *time.Time `json:"finished_at"`
		}
		rows, err = tx.Query(ctx, "SELECT user_id::text, added_by::text, added_at, removed_at, finished_at FROM estimate.request_estimator WHERE request_id = $1 ORDER BY added_at, user_id", it.ID)
		if err != nil {
			return err
		}
		es, err := pgx.CollectRows(rows, pgx.RowToStructByPos[estimator])
		if err != nil {
			return err
		}
		out["estimators"] = es
		type ref struct {
			ID      string `json:"id"`
			Version int    `json:"version"`
			Digest  string `json:"digest"`
			Name    string `json:"name"`
		}
		rows, err = tx.Query(ctx, "SELECT entry_id::text, version, digest, convert_from(document, 'UTF8')::jsonb ->> 'name' FROM estimate.request_reference WHERE request_id = $1 ORDER BY entry_id", it.ID)
		if err != nil {
			return err
		}
		rs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ref])
		if err != nil {
			return err
		}
		out["references"] = rs
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// changeRequest extends the due date and adds or removes estimators while
// the request is open (AC-03).
func (a *API) changeRequest(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		DueAt            *time.Time `json:"due_at"`
		AddEstimators    []string   `json:"add_estimators"`
		RemoveEstimators []string   `json:"remove_estimators"`
		Reason           string     `json:"reason"`
	}
	if !a.anywhere(w, r, p, []authz.Permission{permScenarioView}) || !decode(w, r, &body) {
		return
	}
	if body.DueAt == nil && len(body.AddEstimators) == 0 && len(body.RemoveEstimators) == 0 {
		problem(w, http.StatusBadRequest, "invalid_value", "change due_at, add_estimators or remove_estimators", nil)
		return
	}
	if len(body.AddEstimators) > 50 || len(body.RemoveEstimators) > 50 || !distinctUUIDs(body.AddEstimators) || !distinctUUIDs(body.RemoveEstimators) {
		problem(w, http.StatusBadRequest, "invalid_value", "estimators are distinct user ids, at most 50", nil)
		return
	}
	if !checkText(w, "reason", body.Reason, 1000, false, false) {
		return
	}
	a.withRequest(w, r, p, func(ctx context.Context, tx pgx.Tx, it requestItem) error {
		for _, u := range body.AddEstimators {
			if _, err := tx.Exec(ctx, "INSERT INTO estimate.request_estimator (request_id, user_id) VALUES ($1, $2)", it.ID, u); err != nil {
				return err
			}
		}
		var removed int
		if err := tx.QueryRow(ctx, "SELECT estimate.change_request($1, $2, $3)", it.ID, body.DueAt, body.RemoveEstimators).Scan(&removed); err != nil {
			return err
		}
		attrs := map[string]string{"scenario": it.ScenarioID, "added": strconv.Itoa(len(body.AddEstimators)), "removed": strconv.Itoa(removed)}
		if body.DueAt != nil {
			attrs["due_at"] = body.DueAt.UTC().Format(time.RFC3339)
		}
		return a.Audit.Emit(audit.WithReason(audit.WithTx(ctx, tx), strings.TrimSpace(body.Reason)), audit.Event{Type: "estimate.request_changed",
			Severity: audit.SeverityLow, Actor: p.UserID, Target: "estimate_request:" + it.ID, BUID: it.BUID, Attributes: attrs})
	})
}

// cancelRequest cancels an open request with a reason (AC-03).
func (a *API) cancelRequest(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !a.anywhere(w, r, p, []authz.Permission{permScenarioView}) || !decode(w, r, &body) || !checkText(w, "reason", body.Reason, 1000, true, false) {
		return
	}
	a.withRequest(w, r, p, func(ctx context.Context, tx pgx.Tx, it requestItem) error {
		if _, err := tx.Exec(ctx, "SELECT estimate.cancel_request($1, $2)", it.ID, body.Reason); err != nil {
			return err
		}
		return a.Audit.Emit(audit.WithReason(audit.WithTx(ctx, tx), strings.TrimSpace(body.Reason)), audit.Event{Type: "estimate.request_cancelled",
			Severity: audit.SeverityLow, Actor: p.UserID, Target: "estimate_request:" + it.ID, BUID: it.BUID,
			Attributes: map[string]string{"scenario": it.ScenarioID}})
	})
}

// withRequest runs a change of a visible request the caller may change,
// and answers with the request as it is after.
func (a *API) withRequest(w http.ResponseWriter, r *http.Request, p authz.Principal, change func(context.Context, pgx.Tx, requestItem) error) {
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
	err = authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := change(ctx, tx, it); err != nil {
			return err
		}
		var err error
		it, err = a.loadRequest(ctx, tx, it.ID)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"request": it})
}
