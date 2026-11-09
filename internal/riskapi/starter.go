package riskapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// The starter library (F-003 T-10, AC-11; design §6.6): read by anyone who
// may read the library somewhere, never edited; copied into a BU as an
// ordinary library entry that records its origin.

type starterItem struct {
	Key          string          `json:"key"`
	Release      string          `json:"release"`
	Kind         string          `json:"kind"`
	Name         string          `json:"name"`
	Illustrative bool            `json:"illustrative"`
	Guidance     string          `json:"guidance"`
	Digest       string          `json:"digest"`
	Document     json.RawMessage `json:"document"`
}

var starterKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

func (a *API) starterList(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, library.view) {
		return
	}
	var out []starterItem
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT key, release, kind, convert_from(document, 'UTF8')::jsonb ->> 'name', illustrative, guidance, digest, document
			FROM risk.starter_entry ORDER BY key`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (starterItem, error) {
			var s starterItem
			var doc []byte
			err := row.Scan(&s.Key, &s.Release, &s.Kind, &s.Name, &s.Illustrative, &s.Guidance, &s.Digest, &doc)
			s.Document = doc
			return s, err
		})
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []starterItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

func (a *API) starterCopy(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		BUID       string `json:"bu_id"`
		ChangeNote string `json:"change_note"`
	}
	if !a.viewAnywhere(w, r, p, library.view) || !decode(w, r, &body) {
		return
	}
	key := r.PathValue("key")
	if !starterKeyRE.MatchString(key) {
		notFound(w)
		return
	}
	if !uuidRE.MatchString(body.BUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id (a UUID) is required", nil)
		return
	}
	if strings.TrimSpace(body.ChangeNote) == "" {
		body.ChangeNote = "Copied from the starter library (" + key + ")"
	}
	seen := a.Authz.Check(r.Context(), p, library.view, body.BUID) == nil
	if !a.editAt(w, r, p, library.edit, body.BUID, seen) || !checkNote(w, body.ChangeNote) {
		return
	}
	var id, kind, origin string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		ctx := r.Context()
		var doc []byte
		err := tx.QueryRow(ctx, "SELECT kind, document, key || '@' || release FROM risk.starter_entry WHERE key = $1", key).Scan(&kind, &doc, &origin)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		d, problems := model.Validate(kind, doc)
		if problems != nil {
			return problems
		}
		if err := needsCurrency(ctx, tx, d); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT risk.copy_starter($1, $2, $3)::text", key, body.BUID, strings.TrimSpace(body.ChangeNote)).Scan(&id); err != nil {
			return err
		}
		return a.Audit.Emit(audit.WithTx(ctx, tx), audit.Event{Type: "library.starter_copied", Severity: audit.SeverityLow, Actor: p.UserID,
			Target: "library:" + id, BUID: body.BUID, Attributes: map[string]string{"kind": kind, "origin": origin}})
	})
	if err != nil {
		failSave(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "version": 1, "kind": kind, "origin": origin})
}
