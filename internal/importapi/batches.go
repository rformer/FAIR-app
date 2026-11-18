package importapi

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-08 (F-011-AC-06 to AC-09; design §3.2): batches.

// Counts are a run's counts (AC-08). New, changed and unchanged are the
// valid records by their match: no link yet, linked with another digest,
// linked with the same digest (or the one a reviewer last rejected).
type Counts struct {
	Received  int `json:"received"`
	Valid     int `json:"valid"`
	Refused   int `json:"refused"`
	New       int `json:"new"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
	Proposed  int `json:"proposed"`
	// Applied are descriptive-only proposals accepted at once (auto_accept,
	// T-10b), as the pusher, where they hold the edit permission.
	Applied int `json:"applied"`
}

// match is a valid record's match (a dry run's preview).
type match struct {
	N          int    `json:"n"`
	Kind       string `json:"kind"`
	ExternalID string `json:"external_id"`
	Match      string `json:"match"` // new, changed, unchanged
	TargetID   string `json:"target_id,omitempty"`
}

type target struct {
	ID         string          `json:"id"`
	BU         string          `json:"bu_id"`
	Kind       string          `json:"kind"`
	Mapping    json.RawMessage `json:"mapping"`
	AutoAccept bool            `json:"auto_accept"`
}

// errBatch: a batch refused whole (it is not the format), answered 422.
type errBatch struct{ msg string }

func (e errBatch) Error() string { return e.msg }

// MaxPreview is how many matches a dry run answers.
const MaxPreview = 200

func (a *API) pushBatch(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("integration")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	q := r.URL.Query()
	dry := q.Get("dry_run") == "true"
	trigger := q.Get("trigger")
	if trigger != "" && trigger != "schedule" && trigger != "manual" {
		problem(w, http.StatusBadRequest, "invalid_value", "trigger is schedule or manual (the integration's own service account only)", nil)
		return
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" && ct != "text/csv" {
		problem(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "send application/json (fair.integration.v1) or text/csv", nil)
		return
	}
	body, ok := readBody(w, r, integration.MaxBody)
	if !ok {
		return
	}
	var res batchOut
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		res, err = a.runBatch(r.Context(), tx, p, id, ct, body, dry, trigger, nil)
		return err
	})
	run, counts, batch, preview := res.run, res.counts, res.batch, res.preview
	var eb errBatch
	if errors.As(err, &eb) {
		problem(w, http.StatusUnprocessableEntity, "invalid_batch", eb.msg, nil)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	out := map[string]any{"dry_run": dry, "counts": counts, "refused": nonNil(batch.Refused)}
	if dry {
		out["matches"] = nonNilMatches(preview)
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["run"] = run
	writeJSON(w, http.StatusCreated, out)
}

// batchOut is a batch's result.
type batchOut struct {
	run     json.RawMessage
	counts  Counts
	batch   *integration.Batch
	preview []match
}

// runBatch receives a batch for integration id in tx as p: parsed,
// matched, staged and proposed (a dry run only matches). hook, when given,
// runs before the run finishes (the register import accepts its creates
// there, T-14).
func (a *API) runBatch(ctx context.Context, tx pgx.Tx, p authz.Principal, id, ct string, body []byte, dry bool, trigger string,
	hook func(runID string, counts *Counts) error) (batchOut, error) {
	var (
		run     json.RawMessage
		counts  Counts
		batch   *integration.Batch
		preview []match
	)
	err := func() error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT integration.batch_target($1)", id).Scan(&raw); err != nil {
			return err
		}
		var t target
		if err := json.Unmarshal(raw, &t); err != nil {
			return err
		}
		var err error
		if ct == "text/csv" {
			var m integration.Mapping
			if err := json.Unmarshal(t.Mapping, &m); err != nil {
				return errBatch{"the integration's mapping is not a CSV mapping"}
			}
			batch, err = integration.ParseCSV(body, t.Kind, m)
		} else {
			batch, err = integration.ParseJSON(body, t.Kind)
		}
		if errors.Is(err, integration.ErrBatch) {
			return errBatch{strings.TrimPrefix(err.Error(), "integration: batch refused: ")}
		}
		if err != nil {
			return err
		}
		// Business units: inside the integration's subtree (AC-02).
		var refs []string
		for _, rec := range batch.Records {
			if rec.BU != "" && !slices.Contains(refs, rec.BU) {
				refs = append(refs, rec.BU)
			}
		}
		bus := map[string]string{} // ref -> BU id
		if len(refs) > 0 {
			rows, err := tx.Query(ctx, "SELECT ref, bu_id::text FROM integration.resolve_bus($1, $2)", id, refs)
			if err != nil {
				return err
			}
			for rows.Next() {
				var ref, bu string
				if err := rows.Scan(&ref, &bu); err != nil {
					rows.Close()
					return err
				}
				bus[ref] = bu
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		batch.Reject(func(rec integration.Record) (string, string, bool) {
			if rec.BU != "" && bus[rec.BU] == "" {
				return "/bu", "is not a live business unit inside the integration's subtree", true
			}
			return "", "", false
		})
		// Matches by external ID (AC-07).
		// The records' external IDs and their groups' members (T-11).
		ext := make([]string, 0, len(batch.Records))
		inBatch := map[string]bool{} // assets of this batch
		members := map[int][]string{}
		for _, rec := range batch.Records {
			ext = append(ext, rec.ExternalID)
			switch rec.Kind {
			case integration.KindAsset:
				inBatch[rec.ExternalID] = true
			case integration.KindAssetGroup:
				var g integration.AssetGroup
				if err := json.Unmarshal(rec.Data, &g); err != nil {
					return err
				}
				members[rec.N] = g.Members
				ext = append(ext, g.Members...)
			}
		}
		type link struct{ kind, target, last, rejected string }
		links := map[string]link{}
		rows, err := tx.Query(ctx, `SELECT external_id, target_type, target_id::text, coalesce(last_digest, ''), coalesce(rejected_digest, '')
			FROM integration.match($1, $2)`, id, ext)
		if err != nil {
			return err
		}
		for rows.Next() {
			var e string
			var l link
			if err := rows.Scan(&e, &l.kind, &l.target, &l.last, &l.rejected); err != nil {
				rows.Close()
				return err
			}
			links[e] = l
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// A record matches its link's kind; a control status names its
		// control the first time (T-09).
		batch.Reject(func(rec integration.Record) (string, string, bool) {
			l, linked := links[rec.ExternalID]
			switch {
			case linked && l.kind != targetType[rec.Kind] && targetType[rec.Kind] != "":
				return "/kind", "the external ID is linked to a " + l.kind, true
			case !linked && rec.Kind == integration.KindControlStatus && controlOf(rec) == "":
				return "/control", "is required the first time an external ID is sent: the platform control it reports on", true
			}
			// A group's members are assets of this integration: linked, or
			// in this batch (design §3.5).
			for i, m := range members[rec.N] {
				if ml, ok := links[m]; ok && ml.kind == "asset" || inBatch[m] {
					continue
				}
				return "/members/" + strconv.Itoa(i), "is not an asset of this integration: send it in the same batch or accept it first", true
			}
			return "", "", false
		})
		counts = Counts{Received: batch.Received(), Valid: len(batch.Records), Refused: batch.Refusals}
		// Loss events are written, not proposed (T-12): matched against
		// the events the integration holds by digest.
		type held struct {
			digest   string
			archived bool
		}
		events := map[string]held{}
		if t.Kind == "loss_events" {
			rows, err := tx.Query(ctx, "SELECT external_id, coalesce(digest, ''), archived FROM integration.loss_event_match($1, $2)", id, ext)
			if err != nil {
				return err
			}
			for rows.Next() {
				var e string
				var h held
				if err := rows.Scan(&e, &h.digest, &h.archived); err != nil {
					rows.Close()
					return err
				}
				events[e] = h
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		var lossEvents []map[string]any
		var props []proposal
		var changedExt []string
		for _, rec := range batch.Records {
			m := match{N: rec.N, Kind: rec.Kind, ExternalID: rec.ExternalID}
			l, linked := links[rec.ExternalID]
			tt := targetType[rec.Kind]
			bu := bus[rec.BU]
			if bu == "" {
				bu = t.BU // a control status names no BU: the integration's
			}
			p := proposal{ExternalID: rec.ExternalID, TargetType: tt, BU: bu, Document: rec.Data, Digest: rec.Digest}
			h, isHeld := events[rec.ExternalID]
			switch {
			case rec.Kind == integration.KindLossEvent:
				var e integration.LossEvent
				if err := json.Unmarshal(rec.Data, &e); err != nil {
					return err
				}
				switch {
				case !isHeld:
					m.Match = "new"
					counts.New++
				case h.digest == rec.Digest && !h.archived:
					m.Match = "unchanged"
					counts.Unchanged++
				default:
					m.Match = "changed"
					counts.Changed++
				}
				ev := map[string]any{"external_id": rec.ExternalID, "bu_id": bu, "occurred_on": e.OccurredOn, "event_type": e.EventType,
					"amounts": e.Amounts, "digest": rec.Digest}
				if e.Description != "" {
					ev["description"] = e.Description
				}
				if e.Amounts == nil {
					ev["amounts"] = map[string]any{}
				}
				lossEvents = append(lossEvents, ev)
			case !linked:
				m.Match = "new"
				counts.New++
				p.Action = "create"
				if rec.Kind == integration.KindControlStatus {
					c := controlOf(rec)
					p.Action, p.TargetID = "update", &c
				}
			case rec.Digest == l.last || rec.Digest == l.rejected:
				m.Match, m.TargetID = "unchanged", l.target
				counts.Unchanged++
			default:
				m.Match, m.TargetID = "changed", l.target
				counts.Changed++
				target := l.target
				p.Action, p.TargetID = "update", &target
				changedExt = append(changedExt, rec.ExternalID)
			}
			if p.Action != "" && tt != "" {
				props = append(props, p)
			}
			if len(preview) < MaxPreview {
				preview = append(preview, m)
			}
		}
		// Descriptive-only changes, against the record last accepted.
		if len(changedExt) > 0 {
			prev := map[string]json.RawMessage{}
			rows, err := tx.Query(ctx, "SELECT external_id, document FROM integration.last_applied($1, $2)", id, changedExt)
			if err != nil {
				return err
			}
			for rows.Next() {
				var e string
				var d json.RawMessage
				if err := rows.Scan(&e, &d); err != nil {
					rows.Close()
					return err
				}
				prev[e] = d
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			kinds := map[string]string{}
			for _, rec := range batch.Records {
				kinds[rec.ExternalID] = rec.Kind
			}
			for i := range props {
				if props[i].Action == "update" {
					props[i].DescriptiveOnly = descriptiveOnly(kinds[props[i].ExternalID], prev[props[i].ExternalID], props[i].Document)
				}
			}
		}
		counts.Proposed = len(props)
		if dry {
			return nil
		}
		var runID string
		if err := tx.QueryRow(ctx, "SELECT integration.begin_run($1, $2, $3)::text", id, nullable(trigger), batch.Complete).Scan(&runID); err != nil {
			return err
		}
		records, err := json.Marshal(batch.Records)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT integration.stage($1, $2)", runID, records); err != nil {
			return err
		}
		if t.Kind == "loss_events" {
			if lossEvents == nil {
				lossEvents = []map[string]any{}
			}
			ej, err := json.Marshal(lossEvents)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "SELECT integration.put_loss_events($1, $2)", runID, ej); err != nil {
				return err
			}
		}
		pj, err := json.Marshal(props)
		if err != nil {
			return err
		}
		if props == nil {
			pj = []byte("[]")
		}
		if err := tx.QueryRow(ctx, "SELECT integration.propose($1, $2)", runID, pj).Scan(&counts.Proposed); err != nil {
			return err
		}
		// auto_accept (AC-13): descriptive-only proposals accepted at once as
		// the pusher, each in its own savepoint; one the pusher may not
		// write stays pending.
		if t.AutoAccept && a.Risk != nil {
			var ids []string
			rows, err := tx.Query(ctx, "SELECT integration.run_descriptive($1)::text", runID)
			if err != nil {
				return err
			}
			for rows.Next() {
				var x string
				if err := rows.Scan(&x); err != nil {
					rows.Close()
					return err
				}
				ids = append(ids, x)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, pid := range ids {
				sp, err := tx.Begin(ctx)
				if err != nil {
					return err
				}
				if _, err := a.acceptOne(ctx, sp, p, pid, nil, "", true); err != nil {
					if rb := sp.Rollback(ctx); rb != nil {
						return rb
					}
					continue
				}
				if err := sp.Commit(ctx); err != nil {
					return err
				}
				counts.Applied++
			}
		}
		if hook != nil {
			if err := hook(runID, &counts); err != nil {
				return err
			}
		}
		// Proposals left waiting: one notice for the run (F-009).
		if _, err := tx.Exec(ctx, "SELECT integration.notify_waiting($1)", runID); err != nil {
			return err
		}
		cj, _ := json.Marshal(counts)
		refused, _ := json.Marshal(nonNil(batch.Refused))
		return tx.QueryRow(ctx, "SELECT integration.finish_run($1, $2, $3)", runID, cj, refused).Scan(&run)
	}()
	return batchOut{run, counts, batch, preview}, err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nonNil(r []integration.Refusal) []integration.Refusal {
	if r == nil {
		return []integration.Refusal{}
	}
	return r
}

func nonNilMatches(m []match) []match {
	if m == nil {
		return []match{}
	}
	return m
}

func (a *API) getRun(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.anywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var run json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT integration.run_get($1)", id).Scan(&run)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}
