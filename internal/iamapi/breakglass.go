package iamapi

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// Break-glass administration (T-34; AC-39, AC-41, AC-45; design §5.7).
// Every route needs breakglass.manage at the root (404 otherwise; the
// database checks it too). Enabling after install asks for a
// breakglass.enable approval (202); once a second holder of
// breakglass.manage approved it, POST /breakglass/apply enables it and
// answers each holder's one-time enrollment code, shown once. Disabling
// needs no approval and ends the accounts' sessions at once. The sign-in
// itself is internal/authn/breakglass.

// EnrollmentCodePrefix starts every enrollment code (for secret scanners).
const EnrollmentCodePrefix = "fbg_"

// NewEnrollmentCode returns a code and its SHA-256 (what the database keeps).
func NewEnrollmentCode() (string, []byte, error) {
	code, err := authn.NewToken(EnrollmentCodePrefix)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256([]byte(code))
	return code, sum[:], nil
}

func (a *API) breakglassManage(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	root, err := a.rootBU(r.Context())
	if err == nil && a.Authz.Check(r.Context(), p, "breakglass.manage", root) == nil {
		return true
	}
	problem(w, http.StatusNotFound, "not_found", "", nil)
	return false
}

func (a *API) getBreakglass(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.breakglassManage(w, r, p) {
		return
	}
	var enabled bool
	var accounts json.RawMessage
	var pending *string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT enabled, accounts, pending_approval::text FROM iam.breakglass_status()").Scan(&enabled, &accounts, &pending)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "accounts": accounts, "pending_approval": pending})
}

type holder struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (a *API) enableBreakglass(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Holders []holder `json:"holders"`
		Reason  string   `json:"reason"`
	}
	if !a.breakglassManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	hs, _ := json.Marshal(body.Holders)
	var approval string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.breakglass_request_enable($1, $2)::text", hs, body.Reason).Scan(&approval)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"approval_id": approval, "status": "pending",
		"detail": "a second holder of breakglass.manage must approve; then POST /api/v1/breakglass/apply"})
}

// codes makes one enrollment code per holder: the codes, and their hashes
// for the database.
func codes(n int) ([]string, [][]byte, error) {
	var plain []string
	var hashes [][]byte
	for range n {
		c, h, err := NewEnrollmentCode()
		if err != nil {
			return nil, nil, err
		}
		plain, hashes = append(plain, c), append(hashes, h)
	}
	return plain, hashes, nil
}

func (a *API) applyBreakglass(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		ApprovalID string `json:"approval_id"`
	}
	if !a.breakglassManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.ApprovalID) {
		problem(w, http.StatusBadRequest, "invalid_value", "approval_id must be an approval id", nil)
		return
	}
	plain, hashes, err := codes(2)
	if err != nil {
		fail(w, err)
		return
	}
	var out []struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}
	var raw []byte
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.breakglass_apply_enable($1, $2)", body.ApprovalID, hashes).Scan(&raw)
	})
	if err != nil {
		fail(w, err)
		return
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		fail(w, err)
		return
	}
	accounts := make([]map[string]any, 0, len(out))
	expires := time.Now().Add(24 * time.Hour).UTC()
	for i, o := range out {
		accounts = append(accounts, map[string]any{"user_id": o.UserID, "email": o.Email, "enrollment_code": plain[i], "expires_at": expires})
	}
	server.SecretResponse(w, http.StatusConflict, map[string]any{"error": "secret_not_replayed",
		"detail": "the enrollment codes were returned to the first request and are not kept; issue new ones per account"})
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "accounts": accounts,
		"detail": "give each holder their code out of band; it registers a security key at /api/v1/auth/breakglass/enroll within 24 hours"})
}

func (a *API) disableBreakglass(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !a.breakglassManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	var n int
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.breakglass_disable($1)", body.Reason).Scan(&n)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "accounts_disabled": n})
}

func (a *API) newBreakglassCode(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !a.breakglassManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	code, hash, err := NewEnrollmentCode()
	if err != nil {
		fail(w, err)
		return
	}
	var exp time.Time
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.breakglass_new_code($1, $2, $3)", id, hash, body.Reason).Scan(&exp)
	})
	if err != nil {
		fail(w, err)
		return
	}
	server.SecretResponse(w, http.StatusConflict, map[string]any{"error": "secret_not_replayed",
		"detail": "the code was returned to the first request and is not kept; issue another"})
	writeJSON(w, http.StatusCreated, map[string]any{"user_id": id, "enrollment_code": code, "expires_at": exp.UTC()})
}
