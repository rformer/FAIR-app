package importapi

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"slices"
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
	ID      string          `json:"id"`
	BU      string          `json:"bu_id"`
	Kind    string          `json:"kind"`
	Mapping json.RawMessage `json:"mapping"`
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
	var (
		run     json.RawMessage
		counts  Counts
		batch   *integration.Batch
		preview []match
	)
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
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
		bus := map[string]bool{}
		if len(refs) > 0 {
			rows, err := tx.Query(ctx, "SELECT ref FROM integration.resolve_bus($1, $2)", id, refs)
			if err != nil {
				return err
			}
			for rows.Next() {
				var ref string
				if err := rows.Scan(&ref); err != nil {
					rows.Close()
					return err
				}
				bus[ref] = true
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		batch.Reject(func(rec integration.Record) (string, string, bool) {
			if rec.BU != "" && !bus[rec.BU] {
				return "/bu", "is not a live business unit inside the integration's subtree", true
			}
			return "", "", false
		})
		// Matches by external ID (AC-07).
		ext := make([]string, len(batch.Records))
		for i, rec := range batch.Records {
			ext[i] = rec.ExternalID
		}
		type link struct{ target, last, rejected string }
		links := map[string]link{}
		rows, err := tx.Query(ctx, "SELECT external_id, target_id::text, coalesce(last_digest, ''), coalesce(rejected_digest, '') FROM integration.match($1, $2)", id, ext)
		if err != nil {
			return err
		}
		for rows.Next() {
			var e string
			var l link
			if err := rows.Scan(&e, &l.target, &l.last, &l.rejected); err != nil {
				rows.Close()
				return err
			}
			links[e] = l
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		counts = Counts{Received: batch.Received(), Valid: len(batch.Records), Refused: batch.Refusals}
		for _, rec := range batch.Records {
			m := match{N: rec.N, Kind: rec.Kind, ExternalID: rec.ExternalID}
			l, linked := links[rec.ExternalID]
			switch {
			case !linked:
				m.Match = "new"
				counts.New++
			case rec.Digest == l.last || rec.Digest == l.rejected:
				m.Match, m.TargetID = "unchanged", l.target
				counts.Unchanged++
			default:
				m.Match, m.TargetID = "changed", l.target
				counts.Changed++
			}
			if len(preview) < MaxPreview {
				preview = append(preview, m)
			}
		}
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
		cj, _ := json.Marshal(counts)
		refused, _ := json.Marshal(nonNil(batch.Refused))
		return tx.QueryRow(ctx, "SELECT integration.finish_run($1, $2, $3)", runID, cj, refused).Scan(&run)
	})
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
