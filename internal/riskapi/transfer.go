package riskapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Export and import in the fair.risk.v1 format (F-003 T-11; AC-24, AC-25;
// design §6.5; docs/formats/fair-risk-v1.md).

// MaxExportIDs bounds each list of ids an export names.
const MaxExportIDs = 1000

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// pinKey names one version of an entry or control.
type pinKey struct {
	id      string
	version int64
}

// exportRisk answers a file with the selected scenarios, library entries
// and controls, all their versions, and every version they pin that is not
// otherwise in it (from the pin rows); only what the requester sees.
func (a *API) exportRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, permScenarioView, library.view, controls.view) {
		return
	}
	q := r.URL.Query()
	sel := map[string][]string{}
	for _, res := range []resource{scenarios, library, controls} {
		param := res.listKey()
		if res.event == "library" {
			param = "library"
		}
		for _, id := range strings.Split(q.Get(param), ",") {
			if id = strings.TrimSpace(id); id == "" {
				continue
			}
			if !uuidRE.MatchString(id) {
				problem(w, http.StatusBadRequest, "invalid_value", param+" lists UUIDs", nil)
				return
			}
			sel[res.event] = append(sel[res.event], id)
		}
		if len(sel[res.event]) > MaxExportIDs {
			problem(w, http.StatusBadRequest, "invalid_value", fmt.Sprintf("at most %d ids each", MaxExportIDs), nil)
			return
		}
	}
	bu := q.Get("bu")
	if bu != "" && !uuidRE.MatchString(bu) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu must be a UUID", nil)
		return
	}
	archived := q.Get("archived") == "true"
	if bu == "" && len(sel["scenario"])+len(sel["library"])+len(sel["control"]) == 0 {
		problem(w, http.StatusBadRequest, "invalid_value", "name scenarios, library or controls, or a bu whose subtree to export", nil)
		return
	}
	var file risk.Transfer
	var body []byte
	var digest string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		in := map[string]map[string]bool{}
		for _, res := range []resource{library, controls, scenarios} {
			ids := slices.Clone(sel[res.event])
			if bu != "" {
				cond := " AND archived_at IS NULL"
				if archived {
					cond = ""
				}
				rows, err := tx.Query(ctx, "SELECT id::text FROM risk."+res.head+" WHERE risk.in_subtree($1, bu_id)"+cond+" ORDER BY seq", bu)
				if err != nil {
					return err
				}
				more, err := pgx.CollectRows(rows, pgx.RowTo[string])
				if err != nil {
					return err
				}
				ids = append(ids, more...)
			}
			slices.Sort(ids)
			ids = slices.Compact(ids)
			in[res.event] = map[string]bool{}
			for _, id := range ids {
				item, err := a.exportItem(ctx, tx, res, id)
				if err != nil {
					return err
				}
				in[res.event][id] = true
				switch res.event {
				case "scenario":
					file.Scenarios = append(file.Scenarios, item)
				case "library":
					file.Library = append(file.Library, item)
				default:
					file.Controls = append(file.Controls, item)
				}
			}
		}
		// Every version a selected item pins, from the pin rows, unless the
		// item it belongs to is in the file.
		seen := map[pinKey]bool{}
		for _, src := range []struct {
			pins, head string
			ids        map[string]bool
		}{{"scenario_pin", "scenario_id", in["scenario"]}, {"library_pin", "entry_id", in["library"]}} {
			for id := range src.ids {
				rows, err := tx.Query(ctx, "SELECT to_kind, to_id::text, to_version, to_digest, to_document FROM risk."+src.pins+" WHERE "+src.head+" = $1", id)
				if err != nil {
					return err
				}
				pins, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (risk.TransferPinned, error) {
					var t risk.TransferPinned
					var doc []byte
					err := row.Scan(&t.Kind, &t.ID, &t.Version, &t.Digest, &doc)
					t.Document = doc
					return t, err
				})
				if err != nil {
					return err
				}
				for _, t := range pins {
					k := pinKey{t.ID, t.Version}
					if seen[k] || in["library"][t.ID] || in["control"][t.ID] {
						continue
					}
					seen[k] = true
					file.Pinned = append(file.Pinned, t)
				}
			}
		}
		slices.SortFunc(file.Pinned, func(x, y risk.TransferPinned) int {
			if c := strings.Compare(x.ID, y.ID); c != 0 {
				return c
			}
			return int(x.Version - y.Version)
		})
		var c string
		if err := tx.QueryRow(ctx, "SELECT coalesce((SELECT currency FROM risk.instance), '')").Scan(&c); err != nil {
			return err
		}
		if c != "" {
			file.Currency = &c
		}
		file.ExportedAt = time.Now()
		var err error
		if body, digest, err = file.Encode(); err != nil {
			return err
		}
		return a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: "risk.exported", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "risk:export", BUID: bu, Attributes: map[string]string{"digest": digest,
				"scenarios": strconv.Itoa(len(file.Scenarios)), "library": strconv.Itoa(len(file.Library)),
				"controls": strconv.Itoa(len(file.Controls)), "pinned": strconv.Itoa(len(file.Pinned))}})
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="fair-risk-`+file.ExportedAt.UTC().Format("20060102T150405Z")+`.json"`)
	w.Header().Set("X-Fair-Digest", "sha256="+digest)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// exportItem reads one item the caller sees, with all its versions.
func (a *API) exportItem(ctx context.Context, tx pgx.Tx, res resource, id string) (risk.TransferItem, error) {
	item := risk.TransferItem{ID: id}
	kindCol := "'" + res.event + "'"
	if res.event == "library" {
		kindCol = "kind"
	}
	if err := tx.QueryRow(ctx, "SELECT "+kindCol+" FROM risk."+res.head+" WHERE id = $1", id).Scan(&item.Kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return item, errNotFound
		}
		return item, err
	}
	rows, err := tx.Query(ctx, "SELECT version, digest, change_note, document FROM risk."+res.versions+" WHERE "+res.headColumn+" = $1 ORDER BY version", id)
	if err != nil {
		return item, err
	}
	item.Versions, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (risk.TransferVersion, error) {
		var v risk.TransferVersion
		var doc []byte
		err := row.Scan(&v.Version, &v.Digest, &v.ChangeNote, &doc)
		v.Document = doc
		return v, err
	})
	return item, err
}

// importProblem is one reason an import is refused, at an item and a
// pointer into its document.
type importProblem struct {
	Item    string `json:"item"`
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}

type importedItem struct {
	Section  string `json:"section"`
	Kind     string `json:"kind"`
	SourceID string `json:"source_id"`
	SourceV  int64  `json:"source_version,omitempty"` // pinned snapshots
	ID       string `json:"id"`
	Versions int    `json:"versions"`
	Reused   bool   `json:"reused,omitempty"` // a snapshot the importer already had
}

// errDryRun rolls a dry run back after it has run.
var errDryRun = errors.New("riskapi: dry run")

// planned is one item to create, in the order it is created.
type planned struct {
	res      resource
	section  string
	item     risk.TransferItem
	snapshot bool
	newID    string
	docs     []*model.Document // validated, before pins are re-mapped
	notes    []string
}

func tier(kind string) int {
	switch kind {
	case model.KindAssetGroup:
		return 1
	case model.KindScenario:
		return 2
	}
	return 0
}

// importRisk recreates a file's items in one BU (AC-25): every item a new
// entry with its versions replayed (pins re-pointed to the new entries);
// a pinned snapshot reuses the importer's own version when it has exactly
// that one, else becomes a new entry at version 1. Every problem is listed
// before anything is written; the import is one transaction; ?dry_run=true
// runs it and rolls it back.
func (a *API) importRisk(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		BUID string          `json:"bu_id"`
		File json.RawMessage `json:"file"`
	}
	if !a.viewAnywhere(w, r, p, permScenarioView, library.view, controls.view) {
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, risk.MaxTransferBytes+64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body is {bu_id, file}", nil)
		return
	}
	dryRun := r.URL.Query().Get("dry_run") == "true"
	if !uuidRE.MatchString(body.BUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id (a UUID) is required", nil)
		return
	}
	file, err := risk.ParseTransfer(body.File)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_file", err.Error(), nil)
		return
	}
	sourceDigest, fullDigest := "unknown", "unknown" // the file's, in canonical form
	if b, d, err := file.Encode(); err == nil && len(b) > 0 {
		sourceDigest, fullDigest = d[:12], d
	}
	// Permissions: the edit permission at the BU for every kind included.
	needs := map[authz.Permission]bool{}
	if len(file.Scenarios) > 0 {
		needs[scenarios.edit] = true
	}
	if len(file.Library) > 0 {
		needs[library.edit] = true
	}
	if len(file.Controls) > 0 {
		needs[controls.edit] = true
	}
	for _, t := range file.Pinned {
		if t.Kind == model.KindControl {
			needs[controls.edit] = true
		} else {
			needs[library.edit] = true
		}
	}
	for _, perm := range []authz.Permission{scenarios.edit, library.edit, controls.edit} {
		if !needs[perm] {
			continue
		}
		view := authz.Permission(strings.TrimSuffix(string(perm), ".edit") + ".view")
		seen := a.Authz.Check(r.Context(), p, view, body.BUID) == nil
		if !a.editAt(w, r, p, perm, body.BUID, seen) {
			return
		}
	}

	// Check every document before writing anything.
	var problems []importProblem
	bad := func(item, ptr, msg string) { problems = append(problems, importProblem{item, ptr, msg}) }
	var plan []*planned
	amounts := false
	add := func(res resource, section string, it risk.TransferItem, snapshot bool) {
		ref := section + "/" + it.ID
		pl := &planned{res: res, section: section, item: it, snapshot: snapshot, newID: newUUID()}
		if !uuidRE.MatchString(it.ID) {
			bad(ref, "", "the id is not a UUID")
		}
		if !slices.Contains(res.kinds, it.Kind) {
			bad(ref, "", "kind "+it.Kind+" does not belong in "+section)
			return
		}
		if len(it.Versions) == 0 {
			bad(ref, "", "an item has at least one version")
		}
		for i, v := range it.Versions {
			vref := ref + "/v" + strconv.FormatInt(v.Version, 10)
			if !snapshot && v.Version != int64(i+1) {
				bad(vref, "", "versions run from 1 in order")
			}
			doc, ps := model.Validate(it.Kind, v.Document)
			for _, x := range ps {
				bad(vref, x.Pointer, x.Message)
			}
			if doc == nil {
				continue
			}
			if doc.Digest != v.Digest {
				bad(vref, "", "the document does not match its digest")
			}
			note := strings.TrimSpace(v.ChangeNote)
			if snapshot {
				note = "Imported pinned version " + strconv.FormatInt(v.Version, 10) + " of " + it.ID
			}
			if note == "" || len([]rune(note)) > 1000 || audit.LooksSecret(note) {
				bad(vref, "", "the change note is missing, too long or looks like a secret")
			}
			if strings.Contains(string(doc.Canonical), `"unit":"currency"`) {
				amounts = true
			}
			pl.docs = append(pl.docs, doc)
			pl.notes = append(pl.notes, note)
		}
		plan = append(plan, pl)
	}
	for _, it := range file.Library {
		add(library, "library", it, false)
	}
	for _, it := range file.Controls {
		add(controls, "controls", it, false)
	}
	for _, it := range file.Scenarios {
		add(scenarios, "scenarios", it, false)
	}
	for _, t := range file.Pinned {
		res := library
		if t.Kind == model.KindControl {
			res = controls
		}
		add(res, "pinned", risk.TransferItem{ID: t.ID, Kind: t.Kind, Versions: []risk.TransferVersion{{Version: t.Version, Digest: t.Digest, Document: t.Document}}}, true)
	}
	seenItems := map[string]bool{}
	for _, pl := range plan {
		k := pl.item.ID
		if pl.snapshot {
			k += "@" + strconv.FormatInt(pl.item.Versions[0].Version, 10)
		}
		if seenItems[k] {
			bad(pl.section+"/"+pl.item.ID, "", "listed twice")
		}
		seenItems[k] = true
	}

	var created []importedItem
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		var cur string
		if err := tx.QueryRow(ctx, "SELECT coalesce((SELECT currency FROM risk.instance), '')").Scan(&cur); err != nil {
			return err
		}
		if amounts && (cur == "" || file.Currency == nil || *file.Currency != cur) {
			bad("", "/currency", "the file's amounts are in "+deref(file.Currency)+"; this installation's currency is "+orNone(cur))
		}
		// Where each pinned version will be: re-pointed into the file, or
		// an existing version the importer sees.
		where := map[pinKey]pinKey{}
		for _, pl := range plan {
			if !pl.snapshot {
				for _, v := range pl.item.Versions {
					where[pinKey{pl.item.ID, v.Version}] = pinKey{pl.newID, v.Version}
				}
				continue
			}
			v := pl.item.Versions[0]
			var have bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM risk."+pl.res.versions+" WHERE "+pl.res.headColumn+" = $1 AND version = $2 AND digest = $3)",
				pl.item.ID, v.Version, v.Digest).Scan(&have); err != nil {
				return err
			}
			if have {
				pl.newID = ""
				where[pinKey{pl.item.ID, v.Version}] = pinKey{pl.item.ID, v.Version}
			} else {
				where[pinKey{pl.item.ID, v.Version}] = pinKey{pl.newID, 1}
			}
		}
		// Every pin of every document resolves; documents are re-pointed.
		for _, pl := range plan {
			if pl.newID == "" {
				continue
			}
			for i, doc := range pl.docs {
				vref := pl.section + "/" + pl.item.ID + "/v" + strconv.FormatInt(pl.item.Versions[i].Version, 10)
				nd, err := model.RemapPins(pl.item.Kind, doc.Canonical, func(pin model.PinRef) (string, int64, error) {
					if to, ok := where[pinKey{pin.ID, pin.Version}]; ok {
						return to.id, to.version, nil
					}
					var visible bool
					table, col := "library_version", "entry_id"
					if pin.Kind == model.KindControl {
						table, col = "control_version", "control_id"
					}
					if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM risk."+table+" WHERE "+col+" = $1 AND version = $2)", pin.ID, pin.Version).Scan(&visible); err != nil {
						return "", 0, err
					}
					if !visible {
						bad(vref, pin.Pointer, fmt.Sprintf("pins %s %s version %d, which is neither in the file nor visible to you", pin.Kind, pin.ID, pin.Version))
					}
					return pin.ID, pin.Version, nil
				})
				if err != nil {
					return err
				}
				// Provenance cannot be verified where its requests are not
				// (F-004 AC-31): it arrives marked imported.
				if pl.item.Kind == model.KindScenario {
					if nd, err = model.MarkProvenanceImported(nd.Canonical); err != nil {
						return err
					}
				}
				pl.docs[i] = nd
			}
		}
		if len(problems) > 0 {
			return errInvalidImport
		}
		// Create, in dependency order: entries, then groups, then scenarios.
		order := slices.Clone(plan)
		slices.SortStableFunc(order, func(x, y *planned) int { return tier(x.item.Kind) - tier(y.item.Kind) })
		for _, pl := range order {
			out := importedItem{Section: pl.section, Kind: pl.item.Kind, SourceID: pl.item.ID, ID: pl.newID, Versions: len(pl.docs)}
			if pl.snapshot {
				out.SourceV = pl.item.Versions[0].Version
			}
			if pl.newID == "" {
				out.ID, out.Reused = pl.item.ID, true
				created = append(created, out)
				continue
			}
			q, args := "INSERT INTO risk."+pl.res.head+" (id, bu_id) VALUES ($1, $2)", []any{pl.newID, body.BUID}
			if len(pl.res.kinds) > 1 {
				q, args = "INSERT INTO risk."+pl.res.head+" (id, bu_id, kind) VALUES ($1, $2, $3)", []any{pl.newID, body.BUID, pl.item.Kind}
			}
			if _, err := tx.Exec(ctx, q, args...); err != nil {
				return err
			}
			for i, doc := range pl.docs {
				if _, err := tx.Exec(ctx, "INSERT INTO risk."+pl.res.versions+" ("+pl.res.headColumn+", version, document, digest, change_note) VALUES ($1, $2, $3, $4, $5)",
					pl.newID, i+1, doc.Canonical, doc.Digest, pl.notes[i]); err != nil {
					return err
				}
			}
			last := pl.docs[len(pl.docs)-1]
			if err := a.event(ctx, tx, pl.res, p, pl.res.createdType, pl.newID, body.BUID, pl.item.Kind, len(pl.docs), last,
				"Imported from "+risk.TransferFormat+" file "+sourceDigest, nil); err != nil {
				return err
			}
			created = append(created, out)
		}
		if err := a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: "risk.imported", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "risk:import", BUID: body.BUID, Attributes: map[string]string{"source_digest": fullDigest,
				"scenarios": strconv.Itoa(len(file.Scenarios)), "library": strconv.Itoa(len(file.Library)),
				"controls": strconv.Itoa(len(file.Controls)), "pinned": strconv.Itoa(len(file.Pinned))}}); err != nil {
			return err
		}
		if dryRun {
			return errDryRun
		}
		return nil
	})
	switch {
	case errors.Is(err, errInvalidImport):
		problem(w, http.StatusUnprocessableEntity, "invalid_import", "nothing was imported", map[string]any{"problems": problems})
		return
	case errors.Is(err, errDryRun):
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "created": created, "problems": []importProblem{}})
		return
	case err != nil:
		failSave(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"dry_run": false, "created": created, "problems": []importProblem{}})
}

var errInvalidImport = errors.New("riskapi: invalid import")

func deref(s *string) string {
	if s == nil {
		return "no currency"
	}
	return *s
}

func orNone(s string) string {
	if s == "" {
		return "not set"
	}
	return s
}
