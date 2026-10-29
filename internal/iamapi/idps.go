package iamapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/pkg/authz"
)

var errNotFound = errors.New("iamapi: not found")

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type idp struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	Name         string          `json:"name"`
	EmailDomains []string        `json:"email_domains"`
	Metadata     json.RawMessage `json:"metadata"`
	Source       *string         `json:"metadata_source,omitempty"`
	MFARule      json.RawMessage `json:"mfa_evidence_rule"`
	Enabled      bool            `json:"enabled"`
	CreatedAt    time.Time       `json:"created_at"`
	Fingerprints []string        `json:"fingerprints"`
}

// load returns the IdPs (one when id is set) through the signed context.
func load(ctx context.Context, tx pgx.Tx, id string) ([]idp, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, kind, name, email_domains, metadata, metadata_source, mfa_evidence_rule, enabled, created_at
		FROM iam.idp_admin_list()`)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (idp, error) {
		var i idp
		err := r.Scan(&i.ID, &i.Kind, &i.Name, &i.EmailDomains, &i.Metadata, &i.Source, &i.MFARule, &i.Enabled, &i.CreatedAt)
		if err == nil {
			i.Fingerprints, _ = authn.TrustFingerprints(i.Kind, i.Metadata)
			if i.Fingerprints == nil {
				i.Fingerprints = []string{}
			}
		}
		return i, err
	})
	if err != nil || id == "" {
		return all, err
	}
	for _, i := range all {
		if i.ID == id {
			return []idp{i}, nil
		}
	}
	return nil, errNotFound
}

func (a *API) listIDPs(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p) {
		return
	}
	var out []idp
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		out, err = load(r.Context(), tx, "")
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []idp{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"idps": out})
}

func (a *API) getIDP(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	var out []idp
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		var err error
		out, err = load(r.Context(), tx, id)
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out[0])
}

func (a *API) createIDP(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Kind         string   `json:"kind"`
		Name         string   `json:"name"`
		EmailDomains []string `json:"email_domains"`
		Reason       string   `json:"reason"`
	}
	if !a.view(w, r, p) || !decode(w, r, &body) {
		return
	}
	if body.Kind != "saml" && body.Kind != "oidc" && body.Kind != "keycloak" {
		problem(w, http.StatusBadRequest, "invalid_value", "kind is saml, oidc or keycloak", nil)
		return
	}
	var id string
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), "SELECT iam.idp_admin_create($1, $2, $3, $4)::text", body.Kind, body.Name, body.EmailDomains, body.Reason).Scan(&id)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "enabled": false})
}

// settingKeys are the configuration fields an administrator sets per kind
// (the rest of the metadata comes from documents).
var settingKeys = map[string][]string{
	"saml":     {"allow_idp_initiated"},
	"oidc":     {"client_id", "client_secret_file", "scopes", "subject_claim"},
	"keycloak": {"client_id", "client_secret_file", "scopes", "subject_claim"},
}

// required are the metadata fields an IdP needs before it can be enabled.
var required = map[string][]string{
	"saml":     {"entity_id", "sso_url", "certificates"},
	"oidc":     {"issuer", "authorization_endpoint", "token_endpoint", "client_id", "client_secret_file"},
	"keycloak": {"issuer", "authorization_endpoint", "token_endpoint", "client_id", "client_secret_file"},
}

func (a *API) updateIDP(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name         *string         `json:"name"`
		EmailDomains []string        `json:"email_domains"`
		Enabled      *bool           `json:"enabled"`
		Settings     map[string]any  `json:"settings"`
		MFARule      json.RawMessage `json:"mfa_evidence_rule"`
		Reason       string          `json:"reason"`
	}
	if !a.view(w, r, p) || !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		cur, err := load(r.Context(), tx, id)
		if err != nil {
			return err
		}
		i := cur[0]
		md := map[string]any{}
		_ = json.Unmarshal(i.Metadata, &md)
		if len(body.Settings) > 0 {
			for k, v := range body.Settings {
				if !slices.Contains(settingKeys[i.Kind], k) {
					return badRequest("setting " + k + " does not apply to a " + i.Kind + " IdP")
				}
				if v == nil {
					delete(md, k)
				} else {
					md[k] = v
				}
			}
			b, _ := json.Marshal(md)
			if _, err := tx.Exec(r.Context(), "SELECT iam.idp_admin_set_metadata($1, $2, $3, $4, $5)", id, b, i.Source, i.Fingerprints, body.Reason); err != nil {
				return err
			}
		}
		if len(body.MFARule) > 0 { // null or {}: the standards defaults (T-18)
			rule := body.MFARule
			if string(rule) == "null" {
				rule = json.RawMessage("{}")
			}
			parsed, err := authn.ParseMFARule(i.Kind, rule)
			if err != nil {
				return badRequest(err.Error())
			}
			norm, _ := json.Marshal(parsed)
			if _, err := tx.Exec(r.Context(), "SELECT iam.idp_admin_set_mfa_rule($1, $2, $3)", id, norm, body.Reason); err != nil {
				return err
			}
		}
		if body.Enabled != nil && *body.Enabled {
			for _, k := range required[i.Kind] {
				if v, ok := md[k]; !ok || v == nil || v == "" {
					return badRequest("the IdP cannot be enabled without " + k)
				}
			}
			if i.Kind != "saml" && md["jwks_uri"] == nil && md["jwks"] == nil {
				return badRequest("the IdP cannot be enabled without jwks_uri or jwks")
			}
		}
		if body.Name != nil || body.EmailDomains != nil || body.Enabled != nil {
			_, err := tx.Exec(r.Context(), "SELECT iam.idp_admin_update($1, $2, $3, $4, $5)", id, body.Name, body.EmailDomains, body.Enabled, body.Reason)
			return err
		}
		return nil
	})
	if errors.As(err, new(badRequest)) {
		problem(w, http.StatusBadRequest, "invalid_value", err.Error(), nil)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type badRequest string

func (b badRequest) Error() string { return string(b) }

// uploadMetadata takes SAML metadata (XML), an OIDC discovery document or a
// JWKS file (JSON) as the request body.
func (a *API) uploadMetadata(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p) {
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, authn.MaxMetadataBytes+1))
	if err != nil || len(b) > authn.MaxMetadataBytes {
		problem(w, http.StatusRequestEntityTooLarge, "too_large", "metadata larger than 1 MiB", nil)
		return
	}
	a.applyMetadata(w, r, p, func(kind string) (authn.Metadata, error) {
		return a.parse(kind, b, "")
	}, "file", r.URL.Query().Get("confirm"), r.URL.Query().Get("reason"))
}

// fetchMetadata fetches the document from a URL: a SAML metadata URL, or an
// OIDC issuer (its discovery document). Air-gapped installs take files only.
func (a *API) fetchMetadata(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		URL     string   `json:"url"`
		Confirm []string `json:"confirm"`
		Reason  string   `json:"reason"`
	}
	if !a.view(w, r, p) || !decode(w, r, &body) {
		return
	}
	if a.airGapped() {
		problem(w, http.StatusConflict, "air_gapped", "an air-gapped install takes IdP metadata as uploaded files only", nil)
		return
	}
	a.applyMetadata(w, r, p, func(kind string) (authn.Metadata, error) {
		u, issuer := body.URL, ""
		if kind != "saml" {
			issuer = strings.TrimSuffix(strings.TrimSuffix(u, "/.well-known/openid-configuration"), "/")
			u = issuer + "/.well-known/openid-configuration"
		}
		doc, err := authn.FetchMetadata(r.Context(), u, a.Dev)
		if err != nil {
			return authn.Metadata{}, err
		}
		return a.parse(kind, doc, issuer)
	}, "url", strings.Join(body.Confirm, ","), body.Reason)
}

func (a *API) parse(kind string, doc []byte, issuer string) (authn.Metadata, error) {
	if kind == "saml" {
		return authn.ParseSAMLMetadata(doc, a.Dev)
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(doc, &probe) == nil {
		if _, ok := probe["keys"]; ok {
			return authn.ParseJWKS(doc)
		}
	}
	return authn.ParseOIDCDiscovery(doc, issuer, a.Dev)
}

// applyMetadata merges a parsed document into the IdP's metadata. A change
// of trust anchors needs confirm to list exactly the new fingerprints.
func (a *API) applyMetadata(w http.ResponseWriter, r *http.Request, p authz.Principal, parse func(kind string) (authn.Metadata, error),
	source, confirm, reason string) {
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return
	}
	var pinned *pinError
	err := authz.WithDBContext(r.Context(), a.DB, p.DBToken, func(tx pgx.Tx) error {
		cur, err := load(r.Context(), tx, id)
		if err != nil {
			return err
		}
		i := cur[0]
		parsed, err := parse(i.Kind)
		if err != nil {
			return err
		}
		md := map[string]any{}
		_ = json.Unmarshal(i.Metadata, &md)
		for k, v := range parsed.Fields {
			if v == nil {
				delete(md, k)
			} else {
				md[k] = v
			}
		}
		merged, err := json.Marshal(md)
		if err != nil {
			return err
		}
		fps, err := authn.TrustFingerprints(i.Kind, merged)
		if err != nil {
			return err
		}
		if len(i.Fingerprints) > 0 && !slices.Equal(fps, i.Fingerprints) {
			got := strings.Split(confirm, ",")
			slices.Sort(got)
			if !slices.Equal(got, fps) {
				pinned = &pinError{current: i.Fingerprints, proposed: fps}
				return pinned
			}
		}
		_, err = tx.Exec(r.Context(), "SELECT iam.idp_admin_set_metadata($1, $2, $3, $4, $5)", id, merged, source, fps, reason)
		return err
	})
	if pinned != nil {
		problem(w, http.StatusConflict, "confirm_fingerprints",
			"the IdP's trust anchors change; repeat the request confirming exactly the new fingerprints", map[string]any{
				"current": pinned.current, "fingerprints": pinned.proposed})
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type pinError struct{ current, proposed []string }

func (e *pinError) Error() string { return "iamapi: trust anchors change without confirmation" }
