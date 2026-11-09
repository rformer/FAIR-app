package riskapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Scenarios (T-05), library entries and controls (T-06) share one shape:
// a head with append-only versions (design §4.1, §5, §6.1). A resource
// describes one of them; the handlers in scenarios.go, library.go and
// controls.go name the routes (and the contract's operationIds).

// Page sizes.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

type filter struct{ param, column string }

type resource struct {
	label        string // "scenario", "library entry", "control": in messages
	event        string // scenario, library, control: event targets, response keys
	createdType  string // the event recording a creation (catalogued)
	savedType    string // the event recording a new version (catalogued)
	resourceType string // as registered with apply_bu_rls
	head         string // risk.<head>
	versions     string // risk.<versions>
	headColumn   string // the versions' reference to the head
	pins         string // risk.<pins>, or "" when the kind holds none
	view, edit   authz.Permission
	kinds        []string // document kinds; more than one: the request names it
	shared       bool     // shared down the BU tree (ADR-007 amendment 2)
	filters      []filter // list filters on summary columns, by UUID
	// selectHead wraps a query returning the head table's columns into the
	// columns of headItem.
	columns []string
}

var (
	scenarios = resource{label: "scenario", event: "scenario", createdType: "scenario.created", savedType: "scenario.version_saved", resourceType: "scenario", head: "scenario", versions: "scenario_version",
		headColumn: "scenario_id", pins: "scenario_pin", view: permScenarioView, edit: permScenarioEdit, kinds: []string{model.KindScenario},
		filters: []filter{{"bu", "bu_id"}, {"owner", "owner"}, {"asset", "asset_id"}, {"threat_community", "threat_community_id"}},
		columns: []string{"id", "bu_id", "'scenario'::text AS kind", "name", "owner", "asset_id", "threat_community_id", "current_version", "archived_at", "created_at", "created_by", "seq"}}
	library = resource{label: "library entry", event: "library", createdType: "library.created", savedType: "library.version_saved", resourceType: "library", head: "library_entry", versions: "library_version",
		headColumn: "entry_id", pins: "library_pin", view: "library.view", edit: "library.edit",
		kinds:   []string{model.KindAsset, model.KindAssetGroup, model.KindThreatCommunity, model.KindLossProfile},
		shared:  true,
		filters: []filter{{"bu", "bu_id"}},
		columns: []string{"id", "bu_id", "kind", "name", "NULL::uuid AS owner", "NULL::uuid AS asset_id", "NULL::uuid AS threat_community_id", "current_version", "archived_at", "created_at", "created_by", "seq"}}
	controls = resource{label: "control", event: "control", createdType: "control.created", savedType: "control.version_saved", resourceType: "control", head: "control", versions: "control_version",
		headColumn: "control_id", view: "control.view", edit: "control.edit", kinds: []string{model.KindControl}, shared: true,
		filters: []filter{{"bu", "bu_id"}},
		columns: []string{"id", "bu_id", "'control'::text AS kind", "name", "NULL::uuid AS owner", "NULL::uuid AS asset_id", "NULL::uuid AS threat_community_id", "current_version", "archived_at", "created_at", "created_by", "seq"}}
)

const (
	permScenarioView = "scenario.view"
	permScenarioEdit = "scenario.edit"
)

// headItem is a head as the API shows it; the scenario-only summary is
// left out of other kinds.
type headItem struct {
	ID                string     `json:"id"`
	BUID              string     `json:"bu_id"`
	Kind              string     `json:"kind"`
	Name              *string    `json:"name"`
	Owner             *string    `json:"owner,omitempty"`
	AssetID           *string    `json:"asset_id,omitempty"`
	ThreatCommunityID *string    `json:"threat_community_id,omitempty"`
	CurrentVersion    int        `json:"current_version"`
	ArchivedAt        *time.Time `json:"archived_at"`
	CreatedAt         time.Time  `json:"created_at"`
	CreatedBy         string     `json:"created_by"`
	Seq               int64      `json:"-"`
	// Inherited marks an entry owned by an ancestor of the caller's BUs,
	// read by inheritance and never editable by them (ADR-007 amendment 2).
	Inherited bool `json:"inherited"`
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

// selectHead wraps a query returning the head table's columns with the
// casts headItem needs and whether the row is inherited.
func (res resource) selectHead(inner string) string {
	return `SELECT id::text, bu_id::text, kind, name, owner::text, asset_id::text, threat_community_id::text, current_version, archived_at,
		created_at, created_by::text, seq,
		NOT (bu_id = ANY ((SELECT authz.visible_bus('` + res.resourceType + `', 'read'))::uuid[])) FROM (` + inner + `) s`
}

// tableColumns are the head table's own columns that list queries read.
func (res resource) tableColumns() []string {
	var out []string
	for _, c := range res.columns {
		if !strings.Contains(c, " ") {
			out = append(out, c)
		}
	}
	return out
}

// headSelect is the select list over the head table (literals included).
func (res resource) headSelect(prefix string) string {
	out := make([]string, len(res.columns))
	for i, c := range res.columns {
		if strings.Contains(c, " ") {
			out[i] = c
		} else {
			out[i] = prefix + c
		}
	}
	return strings.Join(out, ", ")
}

func (a *API) list(res resource, w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, res.view) {
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
	for _, f := range res.filters {
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
	if len(res.kinds) > 1 {
		if k := q.Get("kind"); k != "" {
			if !slices.Contains(res.kinds, k) {
				problem(w, http.StatusBadRequest, "invalid_value", "kind is one of "+strings.Join(res.kinds, ", "), nil)
				return
			}
			args = append(args, k)
			conds = append(conds, "t.kind = $"+strconv.Itoa(len(args)))
		}
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
	nq := authz.NewestQuery{Table: "risk." + res.head, ResourceType: res.resourceType, Columns: res.tableColumns(), OrderBy: "seq",
		Limit: limit + 1, Filter: strings.Join(conds, " AND "), SharedDown: res.shared}
	inner, err := nq.SQL()
	if err != nil {
		fail(w, err)
		return
	}
	// Literal columns (kind, the scenario summary of other kinds) are added
	// around the list query.
	sql := res.selectHead("SELECT "+res.headSelect("q.")+" FROM ("+inner+") q") + " ORDER BY s.seq DESC"
	var items []headItem
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), sql, args...)
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, pgx.RowToStructByPos[headItem])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if items == nil {
		items = []headItem{}
	}
	out := map[string]any{}
	if len(items) > limit {
		out["next_cursor"] = strconv.FormatInt(items[limit-1].Seq, 10)
		items = items[:limit]
	}
	out[res.listKey()] = items
	writeJSON(w, http.StatusOK, out)
}

// itemKey is one item's member in responses: scenario, entry, control.
func (res resource) itemKey() string {
	if res.event == "library" {
		return "entry"
	}
	return res.event
}

// listKey is the list's member in responses: scenarios, entries, controls.
func (res resource) listKey() string {
	switch res.event {
	case "library":
		return "entries"
	case "control":
		return "controls"
	}
	return "scenarios"
}

// documentBody is a create or save request.
type documentBody struct {
	BUID            string          `json:"bu_id"`
	Kind            string          `json:"kind"`
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

// validDocument validates a document, answering 422 if invalid.
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

func failSave(w http.ResponseWriter, err error) {
	if errors.Is(err, errNoCurrency) {
		problem(w, http.StatusConflict, "currency_not_set", "amounts cannot be saved until the installation currency is set (risk currency set)", nil)
		return
	}
	fail(w, err)
}

// event records a change in tx: the resource's created or saved type.
func (a *API) event(ctx context.Context, tx pgx.Tx, res resource, p authz.Principal, eventType, id, bu, kind string, version int, doc *model.Document, note string) error {
	attrs := map[string]string{"version": strconv.Itoa(version), "digest": doc.Digest, "change_note": note}
	if len(res.kinds) > 1 {
		attrs["kind"] = kind
	}
	return a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: eventType, Severity: audit.SeverityLow, Actor: p.UserID,
		Target: res.event + ":" + id, BUID: bu, Attributes: attrs})
}

func (a *API) create(res resource, w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body documentBody
	if !a.viewAnywhere(w, r, p, res.view) || !decode(w, r, &body) {
		return
	}
	kind := res.kinds[0]
	if len(res.kinds) > 1 {
		kind = body.Kind
	}
	switch {
	case !uuidRE.MatchString(body.BUID) || body.ExpectedVersion != nil:
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id (a UUID) is required; expected_version is for saving a version", nil)
		return
	case len(res.kinds) == 1 && body.Kind != "":
		problem(w, http.StatusBadRequest, "invalid_value", "kind is only for library entries", nil)
		return
	case !slices.Contains(res.kinds, kind):
		problem(w, http.StatusBadRequest, "invalid_value", "kind is one of "+strings.Join(res.kinds, ", "), nil)
		return
	}
	seen := a.Authz.Check(r.Context(), p, res.view, body.BUID) == nil
	if !a.editAt(w, r, p, res.edit, body.BUID, seen) || !checkNote(w, body.ChangeNote) {
		return
	}
	doc := validDocument(w, kind, body.Document)
	if doc == nil {
		return
	}
	note := strings.TrimSpace(body.ChangeNote)
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		if err := needsCurrency(ctx, tx, doc); err != nil {
			return err
		}
		q, args := "INSERT INTO risk."+res.head+" (bu_id) VALUES ($1) RETURNING id::text", []any{body.BUID}
		if len(res.kinds) > 1 {
			q, args = "INSERT INTO risk."+res.head+" (bu_id, kind) VALUES ($1, $2) RETURNING id::text", []any{body.BUID, kind}
		}
		if err := tx.QueryRow(ctx, q, args...).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO risk."+res.versions+" ("+res.headColumn+", version, document, digest, change_note) VALUES ($1, 1, $2, $3, $4)",
			id, doc.Canonical, doc.Digest, note); err != nil {
			return err
		}
		return a.event(ctx, tx, res, p, res.createdType, id, body.BUID, kind, 1, doc, note)
	})
	if err != nil {
		failSave(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "version": 1, "digest": doc.Digest})
}

// head reads a head as the caller (RLS, inherited read included), or
// errNotFound.
func (a *API) head(ctx context.Context, res resource, p authz.Principal, id string) (headItem, error) {
	var h headItem
	if !uuidRE.MatchString(id) {
		return h, errNotFound
	}
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, res.selectHead("SELECT "+res.headSelect("")+" FROM risk."+res.head+" WHERE id = $1"), id)
		if err != nil {
			return err
		}
		h, err = pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[headItem])
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		return err
	})
	return h, err
}

func (a *API) save(res resource, w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body documentBody
	if !a.viewAnywhere(w, r, p, res.view) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	h, err := a.head(r.Context(), res, p, id)
	if err != nil {
		fail(w, err)
		return
	}
	if body.BUID != "" || body.Kind != "" || body.ExpectedVersion == nil {
		problem(w, http.StatusBadRequest, "invalid_value", "expected_version (the version the change was made from) is required; the BU and kind do not change here", nil)
		return
	}
	// The caller sees it (RLS answered): 403 without the edit permission,
	// for an inherited entry too.
	if !a.editAt(w, r, p, res.edit, h.BUID, true) || !checkNote(w, body.ChangeNote) {
		return
	}
	doc := validDocument(w, h.Kind, body.Document)
	if doc == nil {
		return
	}
	note := strings.TrimSpace(body.ChangeNote)
	version := *body.ExpectedVersion + 1
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		if err := needsCurrency(ctx, tx, doc); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO risk."+res.versions+" ("+res.headColumn+", version, document, digest, change_note) VALUES ($1, $2, $3, $4, $5)",
			id, version, doc.Canonical, doc.Digest, note); err != nil {
			return err
		}
		return a.event(ctx, tx, res, p, res.savedType, id, h.BUID, h.Kind, version, doc, note)
	})
	if err != nil {
		failSave(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "version": version, "digest": doc.Digest})
}

// version reads one version as the caller, with its document and pins.
func (a *API) version(ctx context.Context, res resource, p authz.Principal, id string, v int) (versionItem, []pinItem, error) {
	var out versionItem
	pins := []pinItem{}
	err := authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		var doc []byte
		err := tx.QueryRow(ctx, "SELECT version, digest, author::text, created_at, change_note, document FROM risk."+res.versions+
			" WHERE "+res.headColumn+" = $1 AND version = $2", id, v).Scan(&out.Version, &out.Digest, &out.Author, &out.CreatedAt, &out.ChangeNote, &doc)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		out.Document = doc
		if res.pins == "" {
			return nil
		}
		rows, err := tx.Query(ctx, "SELECT pointer, to_kind, to_id::text, to_version, to_digest FROM risk."+res.pins+
			" WHERE "+res.headColumn+" = $1 AND version = $2 ORDER BY pointer", id, v)
		if err != nil {
			return err
		}
		pins, err = pgx.CollectRows(rows, pgx.RowToStructByPos[pinItem])
		return err
	})
	return out, pins, err
}

func (a *API) get(res resource, w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, res.view) {
		return
	}
	h, err := a.head(r.Context(), res, p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	v, pins, err := a.version(r.Context(), res, p, h.ID, h.CurrentVersion)
	if err != nil {
		fail(w, err)
		return
	}
	cur, err := a.currency(r.Context(), p)
	if err != nil {
		fail(w, err)
		return
	}
	out := map[string]any{res.itemKey(): h, "version": v, "currency": cur}
	if res.pins != "" {
		out["pins"] = pins
	}
	if res.event == "scenario" {
		// The stored document is canonical and valid; the view is computed.
		doc, problems := model.Validate(model.KindScenario, v.Document)
		if problems != nil {
			fail(w, problems)
			return
		}
		out["taxonomy"] = model.Taxonomy(doc.Value.(*model.Scenario))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) versions(res resource, w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, res.view) {
		return
	}
	h, err := a.head(r.Context(), res, p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	var out []versionItem
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT version, digest, author::text, created_at, change_note FROM risk."+res.versions+
			" WHERE "+res.headColumn+" = $1 ORDER BY version DESC", h.ID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (versionItem, error) {
			var v versionItem
			err := row.Scan(&v.Version, &v.Digest, &v.Author, &v.CreatedAt, &v.ChangeNote)
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

func (a *API) getVersion(res resource, w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, res.view) {
		return
	}
	h, err := a.head(r.Context(), res, p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	n, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || n < 1 {
		notFound(w)
		return
	}
	v, pins, err := a.version(r.Context(), res, p, h.ID, n)
	if err != nil {
		fail(w, err)
		return
	}
	out := map[string]any{"id": h.ID, "version": v}
	if res.pins != "" {
		out["pins"] = pins
	}
	writeJSON(w, http.StatusOK, out)
}

// currency reads the installation currency (nil if not set).
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
	if !a.viewAnywhere(w, r, p, permScenarioView, library.view, controls.view) {
		return
	}
	c, err := a.currency(r.Context(), p)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"currency": c})
}
