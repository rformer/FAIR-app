package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/authn/oidc"
	"github.com/rformer/fair-app/internal/authn/saml"
)

// OIDC serves the OpenID Connect routes of the iam service, behind the
// gateway (F-001 T-16; design §5.1, §6):
//
//	GET /api/v1/auth/oidc/{idp}/login?return=/path   redirect to the IdP (code + PKCE)
//	GET /api/v1/auth/oidc/{idp}/callback             the IdP's redirect back
//
// A verified ID token for an active user is answered with a login ticket,
// as for SAML.
type OIDC struct {
	Logins
	HTTP *http.Client // to the IdPs' token and JWKS endpoints (default: TLS 1.2+)
	rp   *oidc.RP
}

// OIDCPrefix is where the OIDC routes live.
const OIDCPrefix = "/api/v1/auth/oidc/"

// RedirectURL is an IdP's redirect URI (register it at the IdP).
func (h *OIDC) RedirectURL(idp string) string { return h.Origin + OIDCPrefix + idp + "/callback" }

// Handler serves the routes.
func (h *OIDC) Handler() http.Handler {
	h.rp = &oidc.RP{RedirectURL: h.RedirectURL, Store: oidcStore{h.DB}, HTTP: h.HTTP, Now: h.now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+OIDCPrefix+"{idp}/login", h.login)
	mux.HandleFunc("GET "+OIDCPrefix+"{idp}/callback", h.callback)
	return mux
}

// idp loads an enabled OIDC IdP; its client secret is read from the file
// its configuration names (a mounted secret, never stored in the database).
func (h *OIDC) idp(ctx context.Context, id string) (oidc.IDP, error) {
	if !uuidRE.MatchString(id) {
		return oidc.IDP{}, errUnknownIDP
	}
	var kind string
	var raw []byte
	err := h.DB.QueryRow(ctx, "SELECT kind, metadata FROM iam.idp_for_login($1)", id).Scan(&kind, &raw)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && kind != "oidc" && kind != "keycloak") {
		return oidc.IDP{}, errUnknownIDP
	}
	if err != nil {
		return oidc.IDP{}, err
	}
	var md struct {
		Issuer       string          `json:"issuer"`
		AuthURL      string          `json:"authorization_endpoint"`
		TokenURL     string          `json:"token_endpoint"`
		JWKSURL      string          `json:"jwks_uri"`
		JWKS         json.RawMessage `json:"jwks"`
		ClientID     string          `json:"client_id"`
		SecretFile   string          `json:"client_secret_file"`
		Scopes       []string        `json:"scopes"`
		SubjectClaim string          `json:"subject_claim"`
	}
	if err := json.Unmarshal(raw, &md); err != nil {
		return oidc.IDP{}, fmt.Errorf("authn: IdP %s metadata: %w", id, err)
	}
	if md.Issuer == "" || md.AuthURL == "" || md.TokenURL == "" || md.ClientID == "" || md.SecretFile == "" ||
		(md.JWKSURL == "" && len(md.JWKS) == 0) {
		return oidc.IDP{}, fmt.Errorf("authn: IdP %s metadata lacks issuer, endpoints, keys, client_id or client_secret_file", id)
	}
	secret, err := os.ReadFile(md.SecretFile) // #nosec G304 G703 -- the IdP's configured secret file
	if err != nil {
		return oidc.IDP{}, fmt.Errorf("authn: IdP %s client secret: %w", id, err)
	}
	return oidc.IDP{ID: id, Issuer: md.Issuer, AuthURL: md.AuthURL, TokenURL: md.TokenURL, JWKSURL: md.JWKSURL, JWKS: md.JWKS,
		ClientID: md.ClientID, ClientSecret: strings.TrimSpace(string(secret)), Scopes: md.Scopes, SubjectClaim: md.SubjectClaim}, nil
}

func (h *OIDC) login(w http.ResponseWriter, r *http.Request) {
	idp, err := h.idp(r.Context(), r.PathValue("idp"))
	if err != nil {
		h.fail(w, r, "", err)
		return
	}
	returnTo := r.URL.Query().Get("return")
	if !saml.LocalPath(returnTo) {
		returnTo = "/"
	}
	u, err := h.rp.Start(r.Context(), idp, returnTo)
	if err != nil {
		h.fail(w, r, idp.ID, err)
		return
	}
	http.Redirect(w, r, u, http.StatusFound) // #nosec G710 -- the IdP's authorization endpoint from its configuration
}

func (h *OIDC) callback(w http.ResponseWriter, r *http.Request) {
	idp, err := h.idp(r.Context(), r.PathValue("idp"))
	if err != nil {
		h.fail(w, r, "", err)
		return
	}
	q := r.URL.Query()
	login, err := h.rp.Callback(r.Context(), idp, q.Get("state"), q.Get("code"), q.Get("error"))
	if errors.Is(err, oidc.ErrInvalid) {
		h.deny(w, r, idp.ID, nil, err.Error())
		return
	}
	if err != nil {
		h.fail(w, r, idp.ID, err)
		return
	}
	attrs := map[string]any{"idp": idp.ID, "subject": login.Subject, "external_id": login.ExternalID, "amr": login.AMR,
		"acr": login.ACR, "client": clientIP(r)}
	mfa := map[string]any{}
	if len(login.AMR) > 0 {
		mfa["oidc_amr"] = login.AMR
	}
	if login.ACR != "" {
		mfa["oidc_acr"] = login.ACR
	}
	authTime := h.now()
	if login.AuthTime != nil {
		authTime = *login.AuthTime
	}
	h.complete(w, r, idp.ID, login.ExternalID, Ticket{AuthMethod: "oidc", MFA: mfa, AuthTime: authTime.Unix(), ReturnTo: login.ReturnTo}, attrs)
}

// oidcStore is oidc.Store in the database (shared by every iam replica).
type oidcStore struct{ db *pgxpool.Pool }

func (s oidcStore) SaveState(ctx context.Context, idp string, st oidc.Started, expires time.Time) error {
	_, err := s.db.Exec(ctx, "SELECT iam.oidc_state_save($1, $2, $3, $4, $5, $6)", idp, st.State, st.Nonce, st.Verifier, st.ReturnTo, expires)
	return err
}

func (s oidcStore) ConsumeState(ctx context.Context, idp, state string) (oidc.Started, error) {
	st := oidc.Started{State: state}
	err := s.db.QueryRow(ctx, "SELECT nonce, code_verifier, return_to FROM iam.oidc_state_consume($1, $2)", idp, state).
		Scan(&st.Nonce, &st.Verifier, &st.ReturnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return oidc.Started{}, oidc.ErrUnknownState
	}
	return st, err
}
