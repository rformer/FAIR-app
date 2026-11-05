package auditapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// --- Legal holds (F-002 T-19; AC-29; design §5, §6.7) -----------------------

// Hold is a legal hold as the API shows it.
type Hold struct {
	ID                string            `json:"hold_id"`
	Filter            json.RawMessage   `json:"filter"`
	Reason            string            `json:"reason"`
	PlacedBy          string            `json:"placed_by"`
	PlacedAt          time.Time         `json:"placed_at"`
	ReleasedBy        *string           `json:"released_by"`
	ReleasedAt        *time.Time        `json:"released_at"`
	ReleaseReason     *string           `json:"release_reason"`
	ArchivesCheckedAt *time.Time        `json:"archives_checked_at"` // null: archived segments not checked yet
	Segments          int64             `json:"segments"`            // segments held, so far
	Status            string            `json:"status"`              // active or released
	Names             map[string]string `json:"names"`
}

// holder requires audit.hold at the root. Without it: 403 for someone the
// Audit API otherwise exists for (audit.view somewhere), else 404.
func (a *API) holder(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	root, err := a.rootBU(r.Context())
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "")
		return false
	}
	err = a.Authz.Check(r.Context(), p, "audit.hold", root)
	if err == nil {
		return true
	}
	if !errors.Is(err, authz.ErrDenied) {
		server.WriteAuthzError(w, err)
		return false
	}
	if bus, verr := a.Authz.BUsWith(r.Context(), p, "audit.view"); verr == nil && len(bus) > 0 {
		problem(w, http.StatusForbidden, "forbidden", "audit.hold at the root is required")
		return false
	}
	notFound(w)
	return false
}

func (a *API) loadHolds(ctx context.Context, tx pgx.Tx, id string) ([]Hold, error) {
	q := `SELECT id::text, filter, reason, placed_by::text, placed_at, released_by::text, released_at, release_reason,
		archives_checked_at, segments, names FROM audit.holds()`
	args := []any{}
	if id != "" {
		q += " WHERE id = $1"
		args = append(args, id)
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Hold, error) {
		var h Hold
		var names []byte
		err := row.Scan(&h.ID, &h.Filter, &h.Reason, &h.PlacedBy, &h.PlacedAt, &h.ReleasedBy, &h.ReleasedAt, &h.ReleaseReason,
			&h.ArchivesCheckedAt, &h.Segments, &names)
		if err == nil {
			err = json.Unmarshal(names, &h.Names)
		}
		h.Status = "active"
		if h.ReleasedAt != nil {
			h.Status = "released"
		}
		return h, err
	})
}

// listHolds: GET /holds, newest first (recorded as a read).
func (a *API) listHolds(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.holder(w, r, p) {
		return
	}
	var holds []Hold
	err := a.read(r.Context(), p, audit.Event{Type: "audit.searched", Attributes: map[string]string{"view": "holds", "filter": "{}"}},
		func(tx pgx.Tx) (int, error) {
			var err error
			holds, err = a.loadHolds(r.Context(), tx, "")
			return len(holds), err
		})
	if err != nil {
		fail(w, err)
		return
	}
	if holds == nil {
		holds = []Hold{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"holds": holds})
}

// placeHold: POST /holds {filter, reason}: the hold and its event in one
// transaction (AC-29).
func (a *API) placeHold(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.holder(w, r, p) {
		return
	}
	var body struct {
		Filter map[string]string `json:"filter"`
		Reason string            `json:"reason"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body is {filter, reason}")
		return
	}
	if body.Filter == nil {
		body.Filter = map[string]string{}
	}
	if msg := checkFilter(body.Filter); msg != "" {
		problem(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	fj, _ := json.Marshal(body.Filter)
	var hold Hold
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(r.Context(), "SELECT audit.hold_place($1, $2)::text", fj, body.Reason).Scan(&id); err != nil {
			return err
		}
		hs, err := a.loadHolds(r.Context(), tx, id)
		if err != nil || len(hs) != 1 {
			return errors.Join(err, errors.New("the new hold is not listed"))
		}
		hold = hs[0]
		return a.Audit.Emit(audit.WithTx(r.Context(), tx), audit.Event{Type: "audit.hold_placed", Severity: audit.SeverityHigh, Actor: p.UserID,
			Target: "audit:hold:" + id, Reason: hold.Reason, Attributes: map[string]string{
				"hold_id": id, "filter": string(fj), "online_segments": strconv.FormatInt(hold.Segments, 10)}})
	})
	if err != nil {
		holdFail(w, err)
		return
	}
	w.Header().Set("Location", Prefix+"/holds/"+hold.ID)
	writeJSON(w, http.StatusCreated, hold)
}

// releaseHold: POST /holds/{id}/release {reason}.
func (a *API) releaseHold(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.holder(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !isUUID(id) {
		notFound(w)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", "the body is {reason}")
		return
	}
	var hold Hold
	found := true
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		hs, err := a.loadHolds(r.Context(), tx, id)
		if err != nil {
			return err
		}
		if len(hs) == 0 {
			found = false
			return nil
		}
		var released []int64
		if err := tx.QueryRow(r.Context(), "SELECT audit.hold_release($1, $2)", id, body.Reason).Scan(&released); err != nil {
			return err
		}
		if hs, err = a.loadHolds(r.Context(), tx, id); err != nil {
			return err
		}
		hold = hs[0]
		return a.Audit.Emit(audit.WithTx(r.Context(), tx), audit.Event{Type: "audit.hold_released", Severity: audit.SeverityHigh, Actor: p.UserID,
			Target: "audit:hold:" + id, Reason: *hold.ReleaseReason, Attributes: map[string]string{
				"hold_id": id, "filter": string(hold.Filter), "segments_released": strconv.Itoa(len(released))}})
	})
	switch {
	case err != nil:
		holdFail(w, err)
	case !found:
		notFound(w)
	default:
		writeJSON(w, http.StatusOK, hold)
	}
}

// holdFail answers a database error: a refused value is 400, a hold that
// is no longer active 409, a missing permission 403.
func holdFail(w http.ResponseWriter, err error) {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "PF003":
			problem(w, http.StatusConflict, "not_active", pe.Message)
			return
		case "PF008":
			problem(w, http.StatusForbidden, "forbidden", pe.Message)
			return
		}
	}
	fail(w, err)
}
