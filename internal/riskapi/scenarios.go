package riskapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Scenarios (F-003 T-05; AC-01 to AC-06, AC-15, AC-21, AC-26, AC-28, AC-29;
// design §5, §6.1).

const (
	permScenarioView = "scenario.view"
	permScenarioEdit = "scenario.edit"
)

// Page sizes.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

type scenarioItem struct {
	ID                string     `json:"id"`
	BUID              string     `json:"bu_id"`
	Name              *string    `json:"name"`
	Owner             *string    `json:"owner"`
	AssetID           *string    `json:"asset_id"`
	ThreatCommunityID *string    `json:"threat_community_id"`
	CurrentVersion    int        `json:"current_version"`
	ArchivedAt        *time.Time `json:"archived_at"`
	CreatedAt         time.Time  `json:"created_at"`
	CreatedBy         string     `json:"created_by"`
	Seq               int64      `json:"-"`
}

type versionItem struct {
	Version    int             `json:"version"`
	Digest     string          `json:"digest"`
	Author     string          `json:"author"`
	CreatedAt  time.Time       `json:"created_at"`
	ChangeNote string          `json:"change_note"`
	Document   json.RawMessage `json:"document,omitempty"`
}

type pinItem struct {
	Pointer string `json:"pointer"`
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version int    `json:"version"`
	Digest  string `json:"digest"`
}

var scenarioColumns = []string{"id", "bu_id", "name", "owner", "asset_id", "threat_community_id", "current_version", "archived_at", "created_at", "created_by", "seq"}

func (a *API) listScenarios(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, permScenarioView) {
		return
	}
	q := r.URL.Query()
	limit := DefaultLimit
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxLimit {
			problem(w, http.StatusBadRequest, "invalid_value", "limit is 1 to 200", nil)
			return
		}
		limit = n
	}
	var cursor *int64
	if s := q.Get("cursor"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 1 {
			problem(w, http.StatusBadRequest, "invalid_value", "cursor is the next_cursor of the previous page", nil)
			return
		}
		cursor = &n
	}
	// The filter's text is built from constants only; values are parameters.
	var conds []string
	args := []any{cursor}
	for _, f := range []struct{ param, column string }{{"bu", "bu_id"}, {"owner", "owner"}, {"asset", "asset_id"}, {"threat_community", "threat_community_id"}} {
		v := q.Get(f.param)
		if v == "" {
			continue
		}
		if !uuidRE.MatchString(v) {
			problem(w, http.StatusBadRequest, "invalid_value", f.param+" must be a UUID", nil)
			return
		}
		args = append(args, v)
		conds = append(conds, "t."+f.column+" = $"+strconv.Itoa(len(args))+"::uuid")
	}
	switch q.Get("archived") {
	case "", "false":
		conds = append(conds, "t.archived_at IS NULL")
	case "true":
		conds = append(conds, "t.archived_at IS NOT NULL")
	case "all":
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "archived is false (the default), true or all", nil)
		return
	}
	nq := authz.NewestQuery{Table: "risk.scenario", ResourceType: "scenario", Columns: scenarioColumns, OrderBy: "seq", Limit: limit + 1,
		Filter: strings.Join(conds, " AND ")}
	sql, err := nq.SQL()
	if err != nil {
		fail(w, err)
		return
	}
	var items []scenarioItem
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), selectScenario(sql), args...)
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, pgx.RowToStructByPos[scenarioItem])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	out := map[string]any{"scenarios": items}
	if items == nil {
		out["scenarios"] = []scenarioItem{}
	}
	if len(items) > limit {
		out["scenarios"] = items[:limit]
		out["next_cursor"] = strconv.FormatInt(items[limit-1].Seq, 10)
	}
	writeJSON(w, http.StatusOK, out)
}

// selectScenario wraps a query returning scenarioColumns with the casts the
// item needs.
func selectScenario(inner string) string {
	return `SELECT id::text, bu_id::text, name, owner::text, asset_id::text, threat_community_id::text, current_version, archived_at,
		created_at, created_by::text, seq FROM (` + inner + `) s`
}

// scenarioBody is a create or save request.
type scenarioBody struct {
	BUID            string          `json:"bu_id"`
	Document        json.RawMessage `json:"document"`
	ChangeNote      string          `json:"change_note"`
	ExpectedVersion *int            `json:"expected_version"`
}

// checkNote checks a change note (the reason of the change, AC-15): 1 to
// 1,000 characters, nothing that looks like a secret.
func checkNote(w http.ResponseWriter, note string) bool {
	note = strings.TrimSpace(note)
	switch {
	case note == "" || utf8.RuneCountInString(note) > 1000:
		problem(w, http.StatusBadRequest, "invalid_value", "change_note is required, at most 1,000 characters", nil)
	case audit.LooksSecret(note):
		problem(w, http.StatusBadRequest, "invalid_value", "change_note looks like a secret", nil)
	default:
		return true
	}
	return false
}

// validDocument validates a scenario document, answering 422 if invalid.
func validDocument(w http.ResponseWriter, kind string, raw json.RawMessage) *model.Document {
	if len(raw) == 0 {
		invalid(w, model.Problems{{Pointer: "", Message: "the document is required"}})
		return nil
	}
	doc, problems := model.Validate(kind, raw)
	if problems != nil {
		invalid(w, problems)
		return nil
	}
	return doc
}

var errNoCurrency = errors.New("riskapi: the installation currency is not set")

// needsCurrency refuses a document holding amounts before the installation
// currency is set (design §3.4).
func needsCurrency(ctx context.Context, tx pgx.Tx, doc *model.Document) error {
	if !bytes.Contains(doc.Canonical, []byte(`"unit":"currency"`)) {
		return nil
	}
	var c string
	if err := tx.QueryRow(ctx, "SELECT coalesce((SELECT currency FROM risk.instance), '')").Scan(&c); err != nil {
		return err
	}
	if c == "" {
		return errNoCurrency
	}
	return nil
}

func (a *API) failSave(w http.ResponseWriter, err error) {
	if errors.Is(err, errNoCurrency) {
		problem(w, http.StatusConflict, "currency_not_set", "amounts cannot be saved until the installation currency is set (risk currency set)", nil)
		return
	}
	fail(w, err)
}

func (a *API) createScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body scenarioBody
	if !a.viewAnywhere(w, r, p, permScenarioView) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.BUID) || body.ExpectedVersion != nil {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id (a UUID) is required; expected_version is for saving a version", nil)
		return
	}
	if !a.editAt(w, r, p, permScenarioEdit, permScenarioView, body.BUID) || !checkNote(w, body.ChangeNote) {
		return
	}
	doc := validDocument(w, model.KindScenario, body.Document)
	if doc == nil {
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		if err := needsCurrency(ctx, tx, doc); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "INSERT INTO risk.scenario (bu_id) VALUES ($1) RETURNING id::text", body.BUID).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO risk.scenario_version (scenario_id, version, document, digest, change_note)
			VALUES ($1, 1, $2, $3, $4)`, id, doc.Canonical, doc.Digest, strings.TrimSpace(body.ChangeNote)); err != nil {
			return err
		}
		return a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: "scenario.created", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "scenario:" + id, BUID: body.BUID,
			Attributes: map[string]string{"version": "1", "digest": doc.Digest, "change_note": strings.TrimSpace(body.ChangeNote)}})
	})
	if err != nil {
		a.failSave(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "version": 1, "digest": doc.Digest})
}

// head reads a scenario's head as the caller (RLS), or errNotFound.
func (a *API) head(ctx context.Context, p authz.Principal, id string) (scenarioItem, error) {
	var h scenarioItem
	if !uuidRE.MatchString(id) {
		return h, errNotFound
	}
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectScenario("SELECT "+strings.Join(scenarioColumns, ", ")+" FROM risk.scenario WHERE id = $1"), id)
		if err != nil {
			return err
		}
		h, err = pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[scenarioItem])
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		return err
	})
	return h, err
}

func (a *API) saveScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body scenarioBody
	if !a.viewAnywhere(w, r, p, permScenarioView) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	h, err := a.head(r.Context(), p, id)
	if err != nil {
		fail(w, err)
		return
	}
	if body.BUID != "" || body.ExpectedVersion == nil {
		problem(w, http.StatusBadRequest, "invalid_value", "expected_version (the version the change was made from) is required; a scenario moves with /move", nil)
		return
	}
	if !a.editAt(w, r, p, permScenarioEdit, permScenarioView, h.BUID) || !checkNote(w, body.ChangeNote) {
		return
	}
	doc := validDocument(w, model.KindScenario, body.Document)
	if doc == nil {
		return
	}
	version := *body.ExpectedVersion + 1
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		if err := needsCurrency(ctx, tx, doc); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO risk.scenario_version (scenario_id, version, document, digest, change_note)
			VALUES ($1, $2, $3, $4, $5)`, id, version, doc.Canonical, doc.Digest, strings.TrimSpace(body.ChangeNote)); err != nil {
			return err
		}
		return a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: "scenario.version_saved", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "scenario:" + id, BUID: h.BUID,
			Attributes: map[string]string{"version": strconv.Itoa(version), "digest": doc.Digest, "change_note": strings.TrimSpace(body.ChangeNote)}})
	})
	if err != nil {
		a.failSave(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "version": version, "digest": doc.Digest})
}

// version reads one version of a scenario as the caller, with its document.
func (a *API) version(ctx context.Context, p authz.Principal, id string, v int) (versionItem, []pinItem, error) {
	var out versionItem
	var pins []pinItem
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		var doc []byte
		err := tx.QueryRow(ctx, `SELECT version, digest, author::text, created_at, change_note, document FROM risk.scenario_version
			WHERE scenario_id = $1 AND version = $2`, id, v).Scan(&out.Version, &out.Digest, &out.Author, &out.CreatedAt, &out.ChangeNote, &doc)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		out.Document = doc
		rows, err := tx.Query(ctx, `SELECT pointer, to_kind, to_id::text, to_version, to_digest FROM risk.scenario_pin
			WHERE scenario_id = $1 AND version = $2 ORDER BY pointer`, id, v)
		if err != nil {
			return err
		}
		pins, err = pgx.CollectRows(rows, pgx.RowToStructByPos[pinItem])
		return err
	})
	if pins == nil {
		pins = []pinItem{}
	}
	return out, pins, err
}

func (a *API) getScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, permScenarioView) {
		return
	}
	h, err := a.head(r.Context(), p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	v, pins, err := a.version(r.Context(), p, h.ID, h.CurrentVersion)
	if err != nil {
		fail(w, err)
		return
	}
	// The stored document is canonical and valid; the view is computed.
	doc, problems := model.Validate(model.KindScenario, v.Document)
	if problems != nil {
		fail(w, problems)
		return
	}
	cur, err := a.currency(r.Context(), p)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scenario": h, "version": v, "pins": pins, "currency": cur,
		"taxonomy": model.Taxonomy(doc.Value.(*model.Scenario)),
	})
}

func (a *API) listScenarioVersions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, permScenarioView) {
		return
	}
	h, err := a.head(r.Context(), p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	var out []versionItem
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT version, digest, author::text, created_at, change_note, NULL::bytea FROM risk.scenario_version
			WHERE scenario_id = $1 ORDER BY version DESC`, h.ID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (versionItem, error) {
			var v versionItem
			var doc []byte
			err := row.Scan(&v.Version, &v.Digest, &v.Author, &v.CreatedAt, &v.ChangeNote, &doc)
			return v, err
		})
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out})
}

func (a *API) getScenarioVersion(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, permScenarioView) {
		return
	}
	h, err := a.head(r.Context(), p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	n, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || n < 1 {
		notFound(w)
		return
	}
	v, pins, err := a.version(r.Context(), p, h.ID, n)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scenario_id": h.ID, "version": v, "pins": pins})
}

// currency reads the installation currency ("" if not set).
func (a *API) currency(ctx context.Context, p authz.Principal) (*string, error) {
	var c string
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT coalesce((SELECT currency FROM risk.instance), '')").Scan(&c)
	})
	if err != nil || c == "" {
		return nil, err
	}
	return &c, nil
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, permScenarioView, "library.view", "control.view") {
		return
	}
	c, err := a.currency(r.Context(), p)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"currency": c})
}
