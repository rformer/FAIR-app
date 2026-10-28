package authn

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/authn/saml"
	"github.com/rformer/fair-app/pkg/authz"
)

// SAML serves the SAML SP routes of the iam service, behind the gateway
// (F-001 T-15; design §5.1, §6):
//
//	GET  /api/v1/auth/saml/{idp}/login?return=/path   SP-initiated: redirect to the IdP
//	POST /api/v1/auth/saml/{idp}/acs                  the IdP's response (HTTP-POST)
//	GET  /api/v1/auth/saml/{idp}/metadata             this SP's metadata, for the IdP
//
// A valid response for an active user is answered with a login ticket in
// TicketHeader, which the gateway turns into a session. Users see a
// generic failure; the audit trail has the reason.
type SAML struct {
	DB      *pgxpool.Pool     // app_rw
	Origin  string            // the platform's public origin, e.g. https://fair.example.com
	Tickets authz.KeyProvider // signs login tickets
	Logger  *slog.Logger
	Now     func() time.Time
}

// Prefix is where the SAML routes live.
const Prefix = "/api/v1/auth/saml/"

func (h *SAML) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// EntityID is this SP's entity ID (the audience IdPs assert to).
func (h *SAML) EntityID() string { return h.Origin + "/api/v1/auth/saml" }

// ACSURL is an IdP's assertion consumer service URL.
func (h *SAML) ACSURL(idp string) string { return h.Origin + Prefix + idp + "/acs" }

func (h *SAML) sp() saml.SP {
	return saml.SP{EntityID: h.EntityID(), ACSURL: h.ACSURL, Store: dbStore{h.DB}, Now: h.now}
}

// Handler serves the routes.
func (h *SAML) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Prefix+"{idp}/login", h.login)
	mux.HandleFunc("POST "+Prefix+"{idp}/acs", h.acs)
	mux.HandleFunc("GET "+Prefix+"{idp}/metadata", h.metadata)
	return mux
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// errUnknownIdP: no enabled SAML IdP with that id.
var errUnknownIDP = errors.New("authn: unknown identity provider")

// idp loads an enabled SAML IdP.
func (h *SAML) idp(ctx context.Context, id string) (saml.IDP, error) {
	if !uuidRE.MatchString(id) {
		return saml.IDP{}, errUnknownIDP
	}
	var kind string
	var raw []byte
	err := h.DB.QueryRow(ctx, "SELECT kind, metadata FROM iam.idp_for_login($1)", id).Scan(&kind, &raw)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && kind != "saml") {
		return saml.IDP{}, errUnknownIDP
	}
	if err != nil {
		return saml.IDP{}, err
	}
	var md struct {
		EntityID          string   `json:"entity_id"`
		SSOURL            string   `json:"sso_url"`
		Certificates      []string `json:"certificates"`
		AllowIDPInitiated bool     `json:"allow_idp_initiated"`
	}
	if err := json.Unmarshal(raw, &md); err != nil {
		return saml.IDP{}, fmt.Errorf("authn: IdP %s metadata: %w", id, err)
	}
	idp := saml.IDP{ID: id, EntityID: md.EntityID, SSOURL: md.SSOURL, AllowIDPInitiated: md.AllowIDPInitiated}
	for _, p := range md.Certificates {
		blk, _ := pem.Decode([]byte(p))
		if blk == nil {
			return saml.IDP{}, fmt.Errorf("authn: IdP %s: a certificate is not PEM", id)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return saml.IDP{}, fmt.Errorf("authn: IdP %s: %w", id, err)
		}
		idp.Certs = append(idp.Certs, c)
	}
	if idp.EntityID == "" || idp.SSOURL == "" || len(idp.Certs) == 0 {
		return saml.IDP{}, fmt.Errorf("authn: IdP %s metadata lacks entity_id, sso_url or certificates", id)
	}
	return idp, nil
}

func (h *SAML) login(w http.ResponseWriter, r *http.Request) {
	idp, err := h.idp(r.Context(), r.PathValue("idp"))
	if err != nil {
		h.fail(w, r, "", err)
		return
	}
	u, err := h.sp().Start(r.Context(), idp, r.URL.Query().Get("return"))
	if err != nil {
		h.fail(w, r, idp.ID, err)
		return
	}
	http.Redirect(w, r, u, http.StatusFound) // #nosec G710 -- the IdP's SSO URL from its configuration, not user input
}

func (h *SAML) acs(w http.ResponseWriter, r *http.Request) {
	idp, err := h.idp(r.Context(), r.PathValue("idp"))
	if err != nil {
		h.fail(w, r, "", err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2*saml.MaxResponseBytes)
	if err := r.ParseForm(); err != nil {
		h.deny(w, r, idp.ID, nil, "unreadable form")
		return
	}
	login, err := h.sp().Validate(r.Context(), idp, r.PostForm.Get("SAMLResponse"))
	if errors.Is(err, saml.ErrInvalid) {
		h.deny(w, r, idp.ID, nil, err.Error())
		return
	}
	if err != nil {
		h.fail(w, r, idp.ID, err)
		return
	}
	attrs := map[string]any{"idp": idp.ID, "name_id": login.NameID, "assertion_id": login.AssertionID, "idp_initiated": login.IDPInitiated,
		"authn_context": login.AuthnContextClassRef, "client": clientIP(r)}
	var userID, status string
	err = h.DB.QueryRow(r.Context(), "SELECT user_id::text, status FROM iam.login_user($1, $2)", idp.ID, login.NameID).Scan(&userID, &status)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		h.deny(w, r, idp.ID, attrs, "unknown user") // JIT provisioning is T-23
		return
	case err != nil:
		h.fail(w, r, idp.ID, err)
		return
	case status != "active":
		attrs["user_id"] = userID
		h.deny(w, r, idp.ID, attrs, "user "+status)
		return
	}
	authTime := h.now()
	if login.AuthnInstant != nil {
		authTime = *login.AuthnInstant
	}
	mfa := map[string]any{}
	if login.AuthnContextClassRef != "" {
		mfa["saml_authn_context"] = login.AuthnContextClassRef
	}
	tok, err := IssueTicket(h.Tickets, Ticket{UserID: userID, AuthMethod: "saml", IDPID: idp.ID, MFA: mfa,
		AuthTime: authTime.Unix(), ReturnTo: login.ReturnTo}, h.now())
	if err != nil {
		h.fail(w, r, idp.ID, err)
		return
	}
	attrs["user_id"] = userID
	if err := h.event(r.Context(), "authn.login.success", "info", userID, idp.ID, attrs, ""); err != nil {
		h.fail(w, r, idp.ID, err) // audit failures fail closed (ADR-006)
		return
	}
	w.Header().Set(TicketHeader, tok)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// metadata is this SP's SAML metadata for an IdP: entity ID and ACS.
func (h *SAML) metadata(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("idp")
	if _, err := h.idp(r.Context(), id); err != nil {
		h.fail(w, r, "", err)
		return
	}
	type acs struct {
		Binding  string `xml:"Binding,attr"`
		Location string `xml:"Location,attr"`
		Index    int    `xml:"index,attr"`
	}
	md := struct {
		XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
		EntityID string   `xml:"entityID,attr"`
		SPSSO    struct {
			AuthnRequestsSigned  bool   `xml:"AuthnRequestsSigned,attr"`
			WantAssertionsSigned bool   `xml:"WantAssertionsSigned,attr"`
			Protocol             string `xml:"protocolSupportEnumeration,attr"`
			NameIDFormat         string `xml:"NameIDFormat"`
			ACS                  acs    `xml:"AssertionConsumerService"`
		} `xml:"SPSSODescriptor"`
	}{EntityID: h.EntityID()}
	md.SPSSO.WantAssertionsSigned = true
	md.SPSSO.Protocol = "urn:oasis:names:tc:SAML:2.0:protocol"
	md.SPSSO.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	md.SPSSO.ACS = acs{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: h.ACSURL(id), Index: 0}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(md)
}

func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" { // set by the gateway
		return strings.TrimSpace(strings.Split(f, ",")[0])
	}
	return r.RemoteAddr
}

func (h *SAML) event(ctx context.Context, typ, severity, actor, idp string, attrs map[string]any, reason string) error {
	b, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	var idpArg any
	if idp != "" {
		idpArg = idp
	}
	_, err = h.DB.Exec(ctx, "SELECT iam.authn_event($1, $2, $3, $4, $5, $6)", typ, severity, actor, idpArg, b, reason)
	return err
}

// deny refuses a login: audited with the reason, generic to the user.
func (h *SAML) deny(w http.ResponseWriter, r *http.Request, idp string, attrs map[string]any, reason string) {
	if attrs == nil {
		attrs = map[string]any{"idp": idp, "client": clientIP(r)}
	}
	if err := h.event(r.Context(), "authn.login.denied", "low", "anonymous", idp, attrs, reason); err != nil && h.Logger != nil {
		h.Logger.Error("auditing a denied login", "error", err.Error())
	}
	writeFailure(w, http.StatusUnauthorized)
}

func (h *SAML) fail(w http.ResponseWriter, r *http.Request, idp string, err error) {
	if errors.Is(err, errUnknownIDP) {
		writeFailure(w, http.StatusNotFound)
		return
	}
	if h.Logger != nil {
		h.Logger.Error("SAML login", "idp", idp, "path", r.URL.Path, "error", err.Error())
	}
	writeFailure(w, http.StatusServiceUnavailable)
}

func writeFailure(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"sign_in_failed","detail":"Sign-in did not succeed. Try again, or contact your administrator."}`+"\n")
}

// dbStore is saml.Store in the database (shared by every iam replica).
type dbStore struct{ db *pgxpool.Pool }

func (s dbStore) SaveRequest(ctx context.Context, idp, id, returnTo string, expires time.Time) error {
	_, err := s.db.Exec(ctx, "SELECT iam.saml_request_save($1, $2, $3, $4)", idp, id, returnTo, expires)
	return err
}

func (s dbStore) ConsumeRequest(ctx context.Context, idp, id string) (string, error) {
	var rt *string
	if err := s.db.QueryRow(ctx, "SELECT iam.saml_request_consume($1, $2)", idp, id).Scan(&rt); err != nil {
		return "", err
	}
	if rt == nil {
		return "", saml.ErrUnknownRequest
	}
	return *rt, nil
}

func (s dbStore) RecordAssertion(ctx context.Context, idp, id string, until time.Time) error {
	var fresh bool
	if err := s.db.QueryRow(ctx, "SELECT iam.saml_assertion_record($1, $2, $3)", idp, id, until).Scan(&fresh); err != nil {
		return err
	}
	if !fresh {
		return saml.ErrReplay
	}
	return nil
}
