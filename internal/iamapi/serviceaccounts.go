package iamapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// Service accounts (T-33; AC-36, AC-37, AC-38; design §6 /service-accounts).
// An account belongs to a BU and holds explicit API scopes: live,
// non-privileged permissions. Every route needs service_account.manage
// somewhere (404 otherwise); the database checks it at the account's BU.
// Scopes the caller holds at the BU apply at once; the others answer 202
// with a T-26 approval, applied by POST /service-accounts/apply after
// another holder of service_account.manage approved it.
//
// Credentials: client secrets (auth_method client_credentials), shown once
// and stored as HMACs under the token pepper, or certificates (mtls) pinned
// by SHA-256 thumbprint. Both expire within token.max_lifetime. The gateway
// exchanges them for access tokens at /api/v1/oauth/token.

type serviceAccount struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	BUID             string     `json:"bu_id"`
	BUCode           string     `json:"bu_code"`
	AuthMethod       string     `json:"auth_method"`
	Status           string     `json:"status"`
	DisabledReason   *string    `json:"disabled_reason"`
	Scopes           []string   `json:"scopes"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	LastUsedAt       *time.Time `json:"last_used_at"`
	LiveSecrets      int        `json:"live_secrets"`
	LiveCertificates int        `json:"live_certificates"`
}

func (a *API) saManage(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	return a.somewhere(w, r, p, "service_account.manage")
}

func (a *API) serviceAccounts(tx pgx.Tx, r *http.Request, id string) ([]serviceAccount, error) {
	rows, err := tx.Query(r.Context(), `SELECT id::text, name, bu_id::text, bu_code, auth_method, status, disabled_reason, scopes,
		created_by::text, created_at, last_used_at, live_secrets, live_certificates FROM iam.service_account_list($1)`, nilIfEmpty(id))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[serviceAccount])
}

// oneServiceAccount answers the account (status) or 404.
func (a *API) oneServiceAccount(w http.ResponseWriter, r *http.Request, p authz.Principal, id string, status int) {
	var out []serviceAccount
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) (err error) {
		out, err = a.serviceAccounts(tx, r, id)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if len(out) == 0 {
		fail(w, errNotFound)
		return
	}
	writeJSON(w, status, out[0])
}

func (a *API) listServiceAccounts(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.saManage(w, r, p) {
		return
	}
	var out []serviceAccount
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) (err error) {
		out, err = a.serviceAccounts(tx, r, "")
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []serviceAccount{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_accounts": out})
}

func (a *API) getServiceAccount(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.saManage(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	a.oneServiceAccount(w, r, p, id, http.StatusOK)
}

// pendingScopes answers 202 for scopes waiting on an approval.
func pendingScopes(w http.ResponseWriter, approval string, unheld []string) {
	writeJSON(w, http.StatusAccepted, map[string]any{"approval_id": approval, "status": "pending", "unheld_scopes": unheld,
		"detail": "you do not hold these scopes at the BU; another holder of service_account.manage there must approve them"})
}

func (a *API) createServiceAccount(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name       string   `json:"name"`
		BUID       string   `json:"bu_id"`
		Scopes     []string `json:"scopes"`
		AuthMethod string   `json:"auth_method"`
		Reason     string   `json:"reason"`
	}
	if !a.saManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.BUID) {
		problem(w, http.StatusBadRequest, "invalid_value", "bu_id must be a BU id", nil)
		return
	}
	var id, approval *string
	var unheld []string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT id::text, approval_id::text, unheld FROM iam.service_account_create($1, $2, $3, $4, $5)",
			body.Name, body.BUID, body.Scopes, body.AuthMethod, body.Reason).Scan(&id, &approval, &unheld)
	})
	if err != nil {
		fail(w, err)
		return
	}
	if approval != nil {
		pendingScopes(w, *approval, unheld)
		return
	}
	a.oneServiceAccount(w, r, p, *id, http.StatusCreated)
}

func (a *API) updateServiceAccount(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name   *string  `json:"name"`
		Scopes []string `json:"scopes"`
		Reason string   `json:"reason"`
	}
	if !a.saManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	if body.Scopes != nil && len(body.Scopes) == 0 {
		problem(w, http.StatusBadRequest, "invalid_value", "a service account needs at least one scope", nil)
		return
	}
	var approval *string
	var unheld []string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT approval_id::text, unheld FROM iam.service_account_update($1, $2, $3, $4)",
			id, body.Name, body.Scopes, body.Reason).Scan(&approval, &unheld)
	})
	if err != nil {
		fail(w, err)
		return
	}
	if approval != nil {
		pendingScopes(w, *approval, unheld)
		return
	}
	a.oneServiceAccount(w, r, p, id, http.StatusOK)
}

func (a *API) applyServiceAccount(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		ApprovalID string `json:"approval_id"`
	}
	if !a.saManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	if !uuidRE.MatchString(body.ApprovalID) {
		problem(w, http.StatusBadRequest, "invalid_value", "approval_id must be an approval id", nil)
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.service_account_apply($1)::text", body.ApprovalID).Scan(&id)
	})
	if err != nil {
		fail(w, err)
		return
	}
	a.oneServiceAccount(w, r, p, id, http.StatusOK)
}

func (a *API) serviceAccountAction(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !a.saManage(w, r, p) {
		return
	}
	id, action := r.PathValue("id"), r.PathValue("action")
	if !uuidRE.MatchString(id) || (action != "disable" && action != "enable") {
		fail(w, errNotFound)
		return
	}
	if !decode(w, r, &body) {
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), "SELECT iam.service_account_set_status($1, $2, $3)", id, action == "enable", body.Reason)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	a.oneServiceAccount(w, r, p, id, http.StatusOK)
}

// Client secrets ----------------------------------------------------------

func (a *API) listSASecrets(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.saManage(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	type secret struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		Prefix     string     `json:"prefix"`
		CreatedAt  time.Time  `json:"created_at"`
		CreatedBy  *string    `json:"created_by"`
		ExpiresAt  time.Time  `json:"expires_at"`
		LastUsedAt *time.Time `json:"last_used_at"`
		RevokedAt  *time.Time `json:"revoked_at"`
	}
	var out []secret
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, name, prefix, created_at, created_by::text, expires_at, last_used_at, revoked_at
			FROM iam.sa_secret_list($1)`, id)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[secret])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []secret{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (a *API) createSASecret(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name          string `json:"name"`
		ExpiresInDays *int   `json:"expires_in_days"` // default: token.max_lifetime
		Reason        string `json:"reason"`
	}
	if !a.saManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	var expires *time.Time
	if body.ExpiresInDays != nil {
		if *body.ExpiresInDays < 1 {
			problem(w, http.StatusBadRequest, "invalid_value", "expires_in_days is at least 1", nil)
			return
		}
		t := time.Now().Add(time.Duration(*body.ExpiresInDays) * 24 * time.Hour)
		expires = &t
	}
	secret, err := authn.NewToken(authn.SecretPrefix)
	if err != nil {
		fail(w, err)
		return
	}
	sum, err := authn.TokenHMAC(a.TokenPepper, secret)
	if errors.Is(err, authn.ErrTokenPepper) {
		problem(w, http.StatusServiceUnavailable, "unavailable", "service-account secrets are not configured (FAIR_TOKEN_PEPPER_FILE)", nil)
		return
	}
	var tid string
	var exp time.Time
	err = authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT id::text, expires_at FROM iam.sa_secret_create($1, $2, $3, $4, $5, $6)",
			id, body.Name, sum, secret[:12], expires, body.Reason).Scan(&tid, &exp)
	})
	if err != nil {
		fail(w, err)
		return
	}
	// Shown once (AC-37): a replay is told it was issued, and the secret
	// is never stored.
	server.SecretResponse(w, http.StatusConflict, map[string]any{"error": "secret_not_replayed", "id": tid,
		"detail": "the secret was returned to the first request and is not kept; revoke it and issue another if it was lost"})
	writeJSON(w, http.StatusCreated, map[string]any{"id": tid, "client_id": id, "client_secret": secret, "prefix": secret[:12],
		"expires_at": exp.UTC()})
}

func (a *API) revokeSACredential(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.saManage(w, r, p) {
		return
	}
	id, cid := r.PathValue("id"), r.PathValue("credential")
	if !uuidRE.MatchString(id) || !uuidRE.MatchString(cid) {
		fail(w, errNotFound)
		return
	}
	var revoked bool
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.sa_credential_revoke($1, $2, $3)", id, cid, r.URL.Query().Get("reason")).Scan(&revoked)
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

// Certificates (mTLS) -------------------------------------------------------

func (a *API) listSACertificates(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.saManage(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	type cert struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		Thumbprint string     `json:"thumbprint_sha256"`
		Subject    string     `json:"subject"`
		NotBefore  time.Time  `json:"not_before"`
		NotAfter   time.Time  `json:"not_after"`
		CreatedAt  time.Time  `json:"created_at"`
		CreatedBy  string     `json:"created_by"`
		ExpiresAt  time.Time  `json:"expires_at"`
		LastUsedAt *time.Time `json:"last_used_at"`
		RevokedAt  *time.Time `json:"revoked_at"`
	}
	var out []cert
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, name, thumbprint, subject, not_before, not_after, created_at, created_by::text,
			expires_at, last_used_at, revoked_at FROM iam.sa_certificate_list($1)`, id)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[cert])
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []cert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

// clientCertificate parses a PEM client certificate and checks what can be
// checked without a CA: a leaf whose key FIPS 140 TLS accepts (RSA of at
// least 2048 bits, ECDSA P-256/P-384/P-521), usable for client
// authentication.
func clientCertificate(pemText string) (*x509.Certificate, string) {
	block, rest := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "certificate must be one PEM CERTIFICATE block"
	}
	if next, _ := pem.Decode(rest); next != nil {
		return nil, "certificate must be one PEM CERTIFICATE block (the client's own, not a chain)"
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "certificate does not parse"
	}
	if c.BasicConstraintsValid && c.IsCA {
		return nil, "a CA certificate cannot authenticate a client"
	}
	if len(c.ExtKeyUsage) > 0 && !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) && !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, "the certificate's extended key usage does not allow client authentication"
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, "RSA keys must be at least 2048 bits"
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return nil, "ECDSA keys must be on P-256, P-384 or P-521"
		}
	default:
		return nil, "the key must be RSA or ECDSA"
	}
	return c, ""
}

func (a *API) addSACertificate(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name        string `json:"name"`
		Certificate string `json:"certificate"` // PEM
		Reason      string `json:"reason"`
	}
	if !a.saManage(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	c, why := clientCertificate(body.Certificate)
	if c == nil {
		problem(w, http.StatusBadRequest, "invalid_certificate", why, nil)
		return
	}
	sum := sha256.Sum256(c.Raw)
	var cid string
	var exp time.Time
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT id::text, expires_at FROM iam.sa_certificate_add($1, $2, $3, $4, $5, $6, $7)",
			id, body.Name, sum[:], c.Subject.String(), c.NotBefore, c.NotAfter, body.Reason).Scan(&cid, &exp)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": cid, "client_id": id, "thumbprint_sha256": hex.EncodeToString(sum[:]),
		"subject": c.Subject.String(), "expires_at": exp.UTC()})
}
