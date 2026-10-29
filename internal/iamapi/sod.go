package iamapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/pkg/authz"
)

// Separation of duties (T-27; AC-29, AC-53; design §6 /sod-rules,
// /sod-exceptions, /approvals). Rules and exceptions are visible to holders
// of role.view somewhere (404 otherwise); sod.manage adds, enables and
// disables rules and revokes exceptions; role.manage requests an exception
// and applies it once a holder of sod.manage, not the requester, approved it
// (the T-26 engine). Approvals are listed and decided by their requesters
// and eligible approvers.

type sodRule struct {
	ID          string    `json:"id"`
	PermissionA string    `json:"permission_a"`
	PermissionB string    `json:"permission_b"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Builtin     bool      `json:"builtin"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (a *API) roleView(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	return a.somewhere(w, r, p, "role.view")
}

func (a *API) listSoDRules(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	out := []sodRule{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, permission_a, permission_b, description, enabled, builtin, created_at, updated_at
			FROM iam.sod_rule_list()`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (sodRule, error) {
			var s sodRule
			err := row.Scan(&s.ID, &s.PermissionA, &s.PermissionB, &s.Description, &s.Enabled, &s.Builtin, &s.CreatedAt, &s.UpdatedAt)
			return s, err
		})
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

func (a *API) createSoDRule(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		PermissionA string `json:"permission_a"`
		PermissionB string `json:"permission_b"`
		Description string `json:"description"`
		Reason      string `json:"reason"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.sod_rule_create($1, $2, $3, $4)::text",
			body.PermissionA, body.PermissionB, body.Description, body.Reason).Scan(&id)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *API) updateSoDRule(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Enabled *bool  `json:"enabled"`
		Reason  string `json:"reason"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	if body.Enabled == nil {
		problem(w, http.StatusBadRequest, "invalid_value", "enabled is required", nil)
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT iam.sod_rule_set_enabled($1, $2, $3)", id, *body.Enabled, body.Reason)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type sodException struct {
	ID          string     `json:"id"`
	RoleID      string     `json:"role_id"`
	RoleName    string     `json:"role_name"`
	RoleStatus  string     `json:"role_status"`
	RuleID      string     `json:"rule_id"`
	PermissionA string     `json:"permission_a"`
	PermissionB string     `json:"permission_b"`
	Reason      string     `json:"reason"`
	RequestedBy string     `json:"requested_by"`
	ApprovedBy  string     `json:"approved_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	EndedAt     *time.Time `json:"ended_at"`
	EndedReason *string    `json:"ended_reason"`
}

func (a *API) listSoDExceptions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	out := []sodException{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, role_id::text, role_name, role_status, rule_id::text, permission_a, permission_b,
			reason, requested_by::text, approved_by::text, created_at, expires_at, ended_at, ended_reason FROM iam.sod_exception_list()`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (sodException, error) {
			var x sodException
			err := row.Scan(&x.ID, &x.RoleID, &x.RoleName, &x.RoleStatus, &x.RuleID, &x.PermissionA, &x.PermissionB, &x.Reason,
				&x.RequestedBy, &x.ApprovedBy, &x.CreatedAt, &x.ExpiresAt, &x.EndedAt, &x.EndedReason)
			return x, err
		})
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exceptions": out})
}

// requestSoDException asks for an exception; it answers 202 with the
// approval request to be decided.
func (a *API) requestSoDException(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		RoleID    string    `json:"role_id"`
		RuleID    string    `json:"rule_id"`
		ExpiresAt time.Time `json:"expires_at"`
		Reason    string    `json:"reason"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.RoleID) || !uuidRE.MatchString(body.RuleID) {
		problem(w, http.StatusBadRequest, "invalid_value", "role_id and rule_id are ids", nil)
		return
	}
	var approval string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.sod_exception_request($1, $2, $3, $4)::text",
			body.RoleID, body.RuleID, body.ExpiresAt, body.Reason).Scan(&approval)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"approval_id": approval, "status": "pending"})
}

// applySoDException turns an approved request into the exception.
func (a *API) applySoDException(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		ApprovalID string `json:"approval_id"`
	}
	if !a.roleView(w, r, p) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.ApprovalID) {
		problem(w, http.StatusBadRequest, "invalid_value", "approval_id is an id", nil)
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.sod_exception_apply($1)::text", body.ApprovalID).Scan(&id)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *API) revokeSoDException(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.roleView(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	var roleStatus string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.sod_exception_revoke($1, $2)", id, r.URL.Query().Get("reason")).Scan(&roleStatus)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "role_status": roleStatus})
}

// --- approvals (T-26's engine over HTTP) -----------------------------------

type approvalItem struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	TargetRef      string          `json:"target_ref"`
	Reason         string          `json:"reason"`
	Payload        json.RawMessage `json:"payload"`
	BUID           string          `json:"bu_id,omitempty"`
	RequestedBy    string          `json:"requested_by"`
	Status         string          `json:"status"`
	DecidedBy      string          `json:"decided_by,omitempty"`
	DecisionReason string          `json:"decision_reason,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	DecidedAt      *time.Time      `json:"decided_at"`
	ConsumedAt     *time.Time      `json:"consumed_at"`
}

func approvalErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, approvals.ErrNotFound):
		problem(w, http.StatusNotFound, "not_found", "", nil)
	case errors.Is(err, approvals.ErrSelfApproval):
		problem(w, http.StatusForbidden, "self_approval", "the approver must be a different person than the requester", nil)
	case errors.Is(err, approvals.ErrNotAuthorized):
		problem(w, http.StatusForbidden, "forbidden", "you may not decide this kind of request", nil)
	case errors.Is(err, approvals.ErrNotApplicable):
		problem(w, http.StatusConflict, "not_applicable", "the request is not pending, or has expired", nil)
	case errors.Is(err, approvals.ErrInvalid):
		problem(w, http.StatusBadRequest, "invalid_value", err.Error(), nil)
	default:
		fail(w, err)
	}
}

func (a *API) listApprovals(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	out := []approvalItem{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, kind, target_ref, reason, payload, coalesce(bu_id::text, ''), requested_by::text,
			status, coalesce(decided_by::text, ''), coalesce(decision_reason, ''), created_at, expires_at, decided_at, consumed_at
			FROM iam.approval_list($1)`, r.URL.Query().Get("pending") == "true")
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (approvalItem, error) {
			var x approvalItem
			err := row.Scan(&x.ID, &x.Kind, &x.TargetRef, &x.Reason, &x.Payload, &x.BUID, &x.RequestedBy, &x.Status, &x.DecidedBy,
				&x.DecisionReason, &x.CreatedAt, &x.ExpiresAt, &x.DecidedAt, &x.ConsumedAt)
			return x, err
		})
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
}

func (a *API) getApproval(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	req, err := approvals.Service{DB: a.DB}.Get(r.Context(), p, id)
	if err != nil {
		approvalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, approvalItem{ID: req.ID, Kind: req.Kind, TargetRef: req.TargetRef, Reason: req.Reason, Payload: req.Payload,
		BUID: req.BUID, RequestedBy: req.RequestedBy, Status: string(req.Status), DecidedBy: req.DecidedBy, DecisionReason: req.DecisionReason,
		CreatedAt: req.CreatedAt, ExpiresAt: req.ExpiresAt, DecidedAt: req.DecidedAt, ConsumedAt: req.ConsumedAt})
}

func (a *API) decideApproval(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Approve *bool  `json:"approve"`
		Reason  string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	if body.Approve == nil {
		problem(w, http.StatusBadRequest, "invalid_value", "approve is required", nil)
		return
	}
	st, err := approvals.Service{DB: a.DB}.Decide(r.Context(), p, id, *body.Approve, body.Reason)
	if err != nil {
		approvalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": st})
}
