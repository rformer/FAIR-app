package importapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-12 (F-011-AC-17 to AC-19; design §3.5, §6.2): loss events, read
// under RLS as library records, and reference classes derived from them.

// lossEvent is a loss event as a viewer reads it.
type lossEvent struct {
	ID            string          `json:"id"`
	BU            string          `json:"bu_id"`
	IntegrationID string          `json:"integration_id"`
	ExternalID    string          `json:"external_id"`
	OccurredOn    string          `json:"occurred_on"`
	EventType     string          `json:"event_type"`
	Description   *string         `json:"description"`
	Amounts       json.RawMessage `json:"amounts"`
	ArchivedAt    *time.Time      `json:"archived_at"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

const lossEventColumns = `id::text, bu_id::text, integration_id::text, external_id, occurred_on::text, event_type, description, amounts,
	archived_at, created_at, updated_at FROM integration.loss_event`

func scanLossEvent(row pgx.CollectableRow) (lossEvent, error) {
	var e lossEvent
	err := row.Scan(&e.ID, &e.BU, &e.IntegrationID, &e.ExternalID, &e.OccurredOn, &e.EventType, &e.Description, &e.Amounts,
		&e.ArchivedAt, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

// libraryAnywhere answers 404 and returns false unless the caller holds
// library.view at some BU.
func (a *API) libraryAnywhere(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	bus, err := a.Authz.BUsWith(r.Context(), p, "library.view")
	if err != nil {
		server.WriteAuthzError(w, err)
		return false
	}
	if len(bus) == 0 {
		notFound(w)
		return false
	}
	return true
}

// listLossEvents answers the loss events the caller sees (RLS), newest
// first; filters bu (its subtree), type, from, to, archived.
func (a *API) listLossEvents(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.libraryAnywhere(w, r, p) {
		return
	}
	q := r.URL.Query()
	var bu, typ, from, to *string
	for name, dst := range map[string]**string{"bu": &bu, "type": &typ, "from": &from, "to": &to} {
		if v := q.Get(name); v != "" {
			*dst = &v
		}
	}
	if bu != nil && !uuidRE.MatchString(*bu) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu is a business unit id", nil)
		return
	}
	for _, d := range []*string{from, to} {
		if d != nil {
			if _, err := time.Parse(time.DateOnly, *d); err != nil {
				problem(w, http.StatusBadRequest, "invalid_value", "from and to are dates (YYYY-MM-DD)", nil)
				return
			}
		}
	}
	archived := q.Get("archived") == "true"
	limit, offset := 50, 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			problem(w, http.StatusBadRequest, "invalid_value", "limit is 1 to 200", nil)
			return
		}
		limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problem(w, http.StatusBadRequest, "invalid_value", "offset is 0 or more", nil)
			return
		}
		offset = n
	}
	var out []lossEvent
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT "+lossEventColumns+`
			WHERE ($1::uuid IS NULL OR bu_id = $1 OR bu_id IN (SELECT c.descendant_id FROM iam.bu_closure c WHERE c.ancestor_id = $1))
			  AND ($2::text IS NULL OR event_type = $2) AND ($3::date IS NULL OR occurred_on >= $3) AND ($4::date IS NULL OR occurred_on < $4)
			  AND ($5 OR archived_at IS NULL)
			ORDER BY occurred_on DESC, seq DESC LIMIT $6 OFFSET $7`, bu, typ, from, to, archived, limit, offset)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, scanLossEvent)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []lossEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"loss_events": out})
}

func (a *API) getLossEvent(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.libraryAnywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var e lossEvent
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), "SELECT "+lossEventColumns+" WHERE id = $1", id)
		if err != nil {
			return err
		}
		e, err = pgx.CollectExactlyOneRow(rows, scanLossEvent)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		notFound(w)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// getDerivation answers a reference class's derivation and the data it
// computes now (library.view at the class's BU).
func (a *API) getDerivation(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.derivationCall(w, r, p, "SELECT integration.get_derivation($1)", nil)
}

// putDerivation sets a reference class's derivation (library.edit at its
// BU); a new version is proposed when the data differs.
func (a *API) putDerivation(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Filter   json.RawMessage `json:"filter"`
		DataKind string          `json:"data_kind"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if len(body.Filter) == 0 {
		body.Filter = json.RawMessage("null")
	}
	a.derivationCall(w, r, p, "SELECT integration.set_derivation($1, $2, $3)", []any{body.Filter, body.DataKind})
}

func (a *API) deleteDerivation(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.libraryAnywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT integration.delete_derivation($1)", id)
		return err
	})
	if derivationFail(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) derivationCall(w http.ResponseWriter, r *http.Request, p authz.Principal, sql string, args []any) {
	if !a.libraryAnywhere(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		notFound(w)
		return
	}
	var out json.RawMessage
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), sql, append([]any{id}, args...)...).Scan(&out)
	})
	if derivationFail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// derivationFail answers a derivation function's refusal; false when err
// is nil.
func derivationFail(w http.ResponseWriter, err error) bool {
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return false
	case errors.As(err, &pg) && pg.Code == "PF031" && pg.Hint == "invalid_derivation":
		problem(w, http.StatusUnprocessableEntity, "invalid_derivation", "the derivation is not valid",
			map[string]any{"problems": []map[string]string{{"pointer": pg.Detail, "message": pg.Message}}})
	case errors.As(err, &pg) && pg.Code == "PF031" && (pg.Hint == "not_reference_class" || pg.Hint == "archived"):
		problem(w, http.StatusConflict, pg.Hint, pg.Message, nil)
	default:
		fail(w, err)
	}
	return true
}
