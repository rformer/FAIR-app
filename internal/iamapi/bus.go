package iamapi

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// Restricted BU administration (T-30; AC-59 to AC-64; design §6
// /bus/{id}/restriction, /bus/{id}/rollup-mode). The BU tree is read with
// bu.view (404 without it anywhere); restriction is managed with
// bu.restrict at the BU's parent, checked by the database (403).
// Restricting and tightening a roll-up apply at once; un-restricting and
// loosening answer 202 with an approval request (T-26), applied after a
// second person approved it. BU creation, renaming, moving and archiving
// are T-30b's (buadmin.go).

type buItem struct {
	ID         string     `json:"id"`
	ParentID   *string    `json:"parent_id"`
	Code       string     `json:"code"`
	Name       string     `json:"name"`
	Depth      int        `json:"depth"`
	Restricted bool       `json:"restricted"`
	RollupMode string     `json:"rollup_mode"`
	ArchivedAt *time.Time `json:"archived_at"`
	Manageable bool       `json:"manageable"` // the caller holds bu.restrict at the parent
}

func (a *API) buView(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	return a.somewhere(w, r, p, "bu.view")
}

func (a *API) bus(r *http.Request, p authz.Principal, id string) ([]buItem, error) {
	var out []buItem
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, parent_id::text, code, name, depth, restricted, rollup_mode, archived_at, manageable
			FROM iam.bu_list($1)`, nilIfEmpty(id))
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[buItem])
		return err
	})
	return out, err
}

func (a *API) listBUs(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.buView(w, r, p) {
		return
	}
	out, err := a.bus(r, p, "")
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []buItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"bus": out})
}

func (a *API) getBU(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.buView(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	out, err := a.bus(r, p, id)
	if err != nil {
		fail(w, err)
		return
	}
	if len(out) == 0 {
		fail(w, errNotFound)
		return
	}
	writeJSON(w, http.StatusOK, out[0])
}

// pendingOr answers 202 with the approval request, or 200 when the change
// applied at once (no approval needed).
func pendingOr(w http.ResponseWriter, approval *string, done map[string]any) {
	if approval != nil {
		writeJSON(w, http.StatusAccepted, map[string]any{"approval_id": *approval, "status": "pending"})
		return
	}
	writeJSON(w, http.StatusOK, done)
}

func (a *API) setRestriction(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Restricted *bool  `json:"restricted"`
		Reason     string `json:"reason"`
	}
	if !a.buView(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	if body.Restricted == nil {
		problem(w, http.StatusBadRequest, "invalid_value", "restricted is required", nil)
		return
	}
	var approval *string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.bu_set_restricted($1, $2, $3)::text", id, *body.Restricted, body.Reason).Scan(&approval)
	})
	if err != nil {
		fail(w, err)
		return
	}
	pendingOr(w, approval, map[string]any{"id": id, "restricted": *body.Restricted})
}

func (a *API) setRollupMode(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Mode   string `json:"mode"`
		Reason string `json:"reason"`
	}
	if !a.buView(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	switch body.Mode {
	case "excluded", "aggregate", "full":
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "mode is excluded, aggregate or full", nil)
		return
	}
	var approval *string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.bu_set_rollup($1, $2::iam.bu_rollup_mode, $3)::text", id, body.Mode, body.Reason).Scan(&approval)
	})
	if err != nil {
		fail(w, err)
		return
	}
	pendingOr(w, approval, map[string]any{"id": id, "rollup_mode": body.Mode})
}

// applyBUApproval applies an approved un-restriction or roll-up loosening.
func (a *API) applyBUApproval(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		ApprovalID string `json:"approval_id"`
	}
	if !a.buView(w, r, p) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.ApprovalID) {
		problem(w, http.StatusBadRequest, "invalid_value", "approval_id is an id", nil)
		return
	}
	var outcome string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.bu_apply_approval($1)", body.ApprovalID).Scan(&outcome)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": outcome})
}
