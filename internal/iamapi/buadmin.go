package iamapi

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// BU administration (T-30b; AC-15, AC-16, AC-17; design §6 /bus). Without
// bu.view anywhere the routes do not exist (404); bu.manage is checked by
// the database from the signed context (403): at the parent to create, at
// the BU or its parent to rename and archive, at both the current and the
// new parent to move, at the root for the maximum depth. Every change
// takes a reason and is audited high.
//
// A move is shown before it applies: ?dry_run=true, or a request without
// the preview's fingerprint (409 confirm_required), answers the preview;
// sending its "confirm" back applies it (200), or, when a BU that is not
// itself restricted leaves a restricted subtree, asks for a second
// administrator's approval (202, applied by POST /bus/apply).

func (a *API) createBU(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		ParentID   string `json:"parent_id"`
		Code       string `json:"code"`
		Name       string `json:"name"`
		Restricted *bool  `json:"restricted"`
		Reason     string `json:"reason"`
	}
	if !a.buView(w, r, p) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.ParentID) {
		problem(w, http.StatusBadRequest, "invalid_value", "parent_id is an id", nil)
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.bu_create($1, $2, $3, $4, $5)::text",
			body.ParentID, body.Code, body.Name, body.Restricted, body.Reason).Scan(&id)
	})
	if err != nil {
		fail(w, err)
		return
	}
	out, err := a.bus(r, p, id)
	if err != nil || len(out) == 0 {
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})
		return
	}
	writeJSON(w, http.StatusCreated, out[0])
}

func (a *API) renameBU(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name   *string `json:"name"`
		Reason string  `json:"reason"`
	}
	if !a.buView(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	if body.Name == nil {
		problem(w, http.StatusBadRequest, "invalid_value", "name is required (the code does not change)", nil)
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT iam.bu_rename($1, $2, $3)", id, *body.Name, body.Reason)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) archiveBU(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
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
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT iam.bu_archive($1, $2)", id, body.Reason)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) moveBU(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		ParentID string `json:"parent_id"`
		Confirm  string `json:"confirm"`
		Reason   string `json:"reason"`
	}
	if !a.buView(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	if !uuidRE.MatchString(body.ParentID) {
		problem(w, http.StatusBadRequest, "invalid_value", "parent_id is an id", nil)
		return
	}
	dryRun := r.URL.Query().Get("dry_run") == "true"
	var raw []byte
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.bu_move($1, $2, $3, $4, $5)", id, body.ParentID, body.Reason,
			nilIfEmpty(body.Confirm), dryRun).Scan(&raw)
	})
	if err != nil {
		fail(w, err)
		return
	}
	var res struct {
		Status     string          `json:"status"`
		Preview    json.RawMessage `json:"preview"`
		ApprovalID *string         `json:"approval_id"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		fail(w, err)
		return
	}
	switch res.Status {
	case "preview", "moved":
		writeJSON(w, http.StatusOK, map[string]any{"status": res.Status, "preview": res.Preview})
	case "pending":
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending", "approval_id": res.ApprovalID, "preview": res.Preview})
	default: // confirm_required
		problem(w, http.StatusConflict, "confirm_required",
			"review the preview and send its confirm value to apply the move", map[string]any{"preview": res.Preview})
	}
}

func (a *API) getMaxDepth(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.buView(w, r, p) {
		return
	}
	var maxDepth, deepest int
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT max_depth, deepest FROM iam.bu_depth_info()").Scan(&maxDepth, &deepest)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"max_depth": maxDepth, "deepest": deepest})
}

func (a *API) setMaxDepth(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		MaxDepth *int   `json:"max_depth"`
		Reason   string `json:"reason"`
	}
	if !a.buView(w, r, p) || !decode(w, r, &body) {
		return
	}
	if body.MaxDepth == nil {
		problem(w, http.StatusBadRequest, "invalid_value", "max_depth is required", nil)
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT iam.bu_set_max_depth($1, $2)", *body.MaxDepth, body.Reason)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"max_depth": *body.MaxDepth})
}
