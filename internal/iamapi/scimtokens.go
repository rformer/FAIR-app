package iamapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// SCIM tokens (T-21, AC-08): bearer tokens for one IdP's SCIM client,
// valid only at /scim/v2. The token is shown once; the database keeps its
// SHA-256. They expire (90 days by default, at most a year) and are
// rotated by issuing another and revoking the old one. scim.manage
// (checked by the database), audited.

// TokenPrefix starts every SCIM token (for secret scanners).
const TokenPrefix = "fscim_"

func (a *API) listSCIMTokens(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	type token struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		Prefix     string     `json:"prefix"`
		CreatedAt  time.Time  `json:"created_at"`
		CreatedBy  *string    `json:"created_by"`
		ExpiresAt  time.Time  `json:"expires_at"`
		LastUsedAt *time.Time `json:"last_used_at"`
		RevokedAt  *time.Time `json:"revoked_at"`
	}
	out := []token{}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, name, prefix, created_at, created_by::text, expires_at, last_used_at, revoked_at
			FROM iam.scim_token_list($1)`, id)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (token, error) {
			var t token
			err := row.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.CreatedBy, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)
			return t, err
		})
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (a *API) createSCIMToken(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name          string `json:"name"`
		ExpiresInDays *int   `json:"expires_in_days"`
		Reason        string `json:"reason"`
	}
	if !a.view(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	days := 90
	if body.ExpiresInDays != nil {
		days = *body.ExpiresInDays
	}
	if days < 1 || days > 365 {
		problem(w, http.StatusBadRequest, "invalid_value", "expires_in_days is 1 to 365", nil)
		return
	}
	raw := make([]byte, 32) // 256 bits
	if _, err := rand.Read(raw); err != nil {
		fail(w, err)
		return
	}
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	expires := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	var tid string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.scim_token_create($1, $2, $3, $4, $5, $6)::text",
			id, body.Name, sum[:], token[:12], expires, body.Reason).Scan(&tid)
	})
	if err != nil {
		fail(w, err)
		return
	}
	// The only time the token is shown: a replayed request (same
	// Idempotency-Key) is told it was issued, and the token is never stored.
	server.SecretResponse(w, http.StatusConflict, map[string]any{"error": "secret_not_replayed", "id": tid,
		"detail": "the token was returned to the first request and is not kept; revoke it and issue another if it was lost"})
	writeJSON(w, http.StatusCreated, map[string]any{"id": tid, "token": token, "prefix": token[:12], "expires_at": expires.UTC()})
}

func (a *API) revokeSCIMToken(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p) {
		return
	}
	id, tid := r.PathValue("id"), r.PathValue("token")
	if !uuidRE.MatchString(id) || !uuidRE.MatchString(tid) {
		fail(w, errNotFound)
		return
	}
	var revoked bool
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.scim_token_revoke($1, $2, $3)", id, tid, r.URL.Query().Get("reason")).Scan(&revoked)
	})
	if err != nil {
		fail(w, err)
		return
	}
	if !revoked {
		fail(w, errNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
