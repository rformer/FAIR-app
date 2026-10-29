package authn

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/go-jose/go-jose/v4"
)

// IdP metadata (F-001 T-17; AC-03; design §10): SAML metadata XML, OIDC
// discovery documents and JWKS files are parsed into the JSON stored in
// iam.idp.metadata, whether they were uploaded or fetched from a URL. Each
// result has its trust anchors (SAML signing certificates, inline JWKS
// keys, the OIDC issuer and JWKS URI) as fingerprints; a change of trust
// anchors is applied only when an administrator confirms exactly the new
// fingerprints (pinning).

// MaxMetadataBytes bounds a metadata document.
const MaxMetadataBytes = 1 << 20

// ErrMetadata means the document is not acceptable metadata; the wrapped
// error says why.
var ErrMetadata = errors.New("authn: invalid IdP metadata")

func badMetadata(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMetadata, fmt.Sprintf(format, a...))
}

// Metadata is a parsed document: the fields it sets in iam.idp.metadata and
// its trust anchors.
type Metadata struct {
	Fields       map[string]any
	Fingerprints []string // sorted
}

// endpointOK: an absolute https URL (http only in development).
func endpointOK(raw string, dev bool) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && (u.Scheme == "https" || (dev && u.Scheme == "http")) && u.User == nil && u.Fragment == ""
}

// ParseSAMLMetadata reads an IdP's SAML metadata (an EntityDescriptor with
// an IDPSSODescriptor): its entity ID, HTTP-Redirect SSO endpoint and
// signing certificates.
func ParseSAMLMetadata(b []byte, dev bool) (Metadata, error) {
	if len(b) > MaxMetadataBytes {
		return Metadata{}, badMetadata("larger than %d bytes", MaxMetadataBytes)
	}
	if bytes.Contains(b, []byte("<!DOCTYPE")) || bytes.Contains(b, []byte("<!ENTITY")) {
		return Metadata{}, badMetadata("DTD present")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b); err != nil {
		return Metadata{}, badMetadata("not XML: %v", err)
	}
	const mdNS = "urn:oasis:names:tc:SAML:2.0:metadata"
	root := doc.Root()
	if root == nil || root.Tag != "EntityDescriptor" || root.NamespaceURI() != mdNS {
		return Metadata{}, badMetadata("not a SAML EntityDescriptor")
	}
	entity := root.SelectAttrValue("entityID", "")
	idp := root.FindElement("IDPSSODescriptor")
	if entity == "" || idp == nil {
		return Metadata{}, badMetadata("no entityID or IDPSSODescriptor")
	}
	sso := ""
	for _, s := range idp.FindElements("SingleSignOnService") {
		if s.SelectAttrValue("Binding", "") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
			sso = s.SelectAttrValue("Location", "")
			break
		}
	}
	if !endpointOK(sso, dev) {
		return Metadata{}, badMetadata("no HTTP-Redirect SingleSignOnService with an https Location")
	}
	var certs, fps []string
	for _, kd := range idp.FindElements("KeyDescriptor") {
		if use := kd.SelectAttrValue("use", ""); use != "" && use != "signing" {
			continue
		}
		for _, xc := range kd.FindElements(".//X509Certificate") {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Text()), ""))
			if err != nil {
				return Metadata{}, badMetadata("a signing certificate is not base64")
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return Metadata{}, badMetadata("a signing certificate: %v", err)
			}
			if err := strongKey(c.PublicKey); err != nil {
				return Metadata{}, err
			}
			certs = append(certs, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
			sum := sha256.Sum256(der)
			fps = append(fps, "cert:sha256:"+hex.EncodeToString(sum[:]))
		}
	}
	if len(certs) == 0 {
		return Metadata{}, badMetadata("no signing certificate")
	}
	slices.Sort(fps)
	return Metadata{Fields: map[string]any{"entity_id": entity, "sso_url": sso, "certificates": certs}, Fingerprints: slices.Compact(fps)}, nil
}

// strongKey: RSA of at least 2048 bits or ECDSA (FIPS 140).
func strongKey(k any) error {
	switch key := k.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return badMetadata("an RSA key of %d bits (at least 2048 are required)", key.N.BitLen())
		}
	case *ecdsa.PublicKey:
	default:
		return badMetadata("a key of type %T (RSA or ECDSA are accepted)", k)
	}
	return nil
}

// ParseOIDCDiscovery reads an OIDC discovery document: issuer, endpoints
// and JWKS URI. wantIssuer, when set (a fetched document), must match.
func ParseOIDCDiscovery(b []byte, wantIssuer string, dev bool) (Metadata, error) {
	var d struct {
		Issuer   string   `json:"issuer"`
		Auth     string   `json:"authorization_endpoint"`
		Token    string   `json:"token_endpoint"`
		JWKSURI  string   `json:"jwks_uri"`
		Response []string `json:"response_types_supported"`
	}
	if len(b) > MaxMetadataBytes {
		return Metadata{}, badMetadata("larger than %d bytes", MaxMetadataBytes)
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return Metadata{}, badMetadata("not a JSON discovery document: %v", err)
	}
	for name, u := range map[string]string{"issuer": d.Issuer, "authorization_endpoint": d.Auth, "token_endpoint": d.Token, "jwks_uri": d.JWKSURI} {
		if !endpointOK(u, dev) {
			return Metadata{}, badMetadata("%s %q is not an https URL", name, u)
		}
	}
	if wantIssuer != "" && strings.TrimSuffix(d.Issuer, "/") != strings.TrimSuffix(wantIssuer, "/") {
		return Metadata{}, badMetadata("the document's issuer %q is not %q", d.Issuer, wantIssuer)
	}
	if len(d.Response) > 0 && !slices.Contains(d.Response, "code") {
		return Metadata{}, badMetadata("the IdP does not support the authorization code flow")
	}
	fps := []string{"issuer:" + d.Issuer, "jwks_uri:" + d.JWKSURI}
	slices.Sort(fps)
	return Metadata{Fields: map[string]any{"issuer": d.Issuer, "authorization_endpoint": d.Auth, "token_endpoint": d.Token,
		"jwks_uri": d.JWKSURI}, Fingerprints: fps}, nil
}

// ParseJWKS reads a JWKS file (air-gapped OIDC): public RSA (2048+) or EC
// signing keys only. The keys replace any jwks_uri.
func ParseJWKS(b []byte) (Metadata, error) {
	if len(b) > MaxMetadataBytes {
		return Metadata{}, badMetadata("larger than %d bytes", MaxMetadataBytes)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(b, &set); err != nil {
		return Metadata{}, badMetadata("not a JWKS: %v", err)
	}
	var keep []jose.JSONWebKey
	var fps []string
	for _, k := range set.Keys {
		if !k.IsPublic() {
			return Metadata{}, badMetadata("key %q is private; upload public keys only", k.KeyID)
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if err := strongKey(k.Key); err != nil {
			return Metadata{}, err
		}
		tp, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			return Metadata{}, badMetadata("key %q: %v", k.KeyID, err)
		}
		keep = append(keep, k)
		fps = append(fps, "jwk:sha256:"+hex.EncodeToString(tp))
	}
	if len(keep) == 0 {
		return Metadata{}, badMetadata("no public signing key")
	}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: keep})
	if err != nil {
		return Metadata{}, err
	}
	slices.Sort(fps)
	return Metadata{Fields: map[string]any{"jwks": json.RawMessage(raw), "jwks_uri": nil}, Fingerprints: slices.Compact(fps)}, nil
}

// TrustFingerprints are the trust anchors of stored metadata of kind.
func TrustFingerprints(kind string, stored []byte) ([]string, error) {
	if len(stored) == 0 || string(stored) == "{}" {
		return nil, nil
	}
	var md map[string]json.RawMessage
	if err := json.Unmarshal(stored, &md); err != nil {
		return nil, err
	}
	var fps []string
	if kind == "saml" {
		var certs []string
		_ = json.Unmarshal(md["certificates"], &certs)
		for _, p := range certs {
			if blk, _ := pem.Decode([]byte(p)); blk != nil {
				sum := sha256.Sum256(blk.Bytes)
				fps = append(fps, "cert:sha256:"+hex.EncodeToString(sum[:]))
			}
		}
	} else {
		var iss, uri string
		_ = json.Unmarshal(md["issuer"], &iss)
		_ = json.Unmarshal(md["jwks_uri"], &uri)
		if iss != "" {
			fps = append(fps, "issuer:"+iss)
		}
		if uri != "" {
			fps = append(fps, "jwks_uri:"+uri)
		}
		if len(md["jwks"]) > 0 && string(md["jwks"]) != "null" {
			j, err := ParseJWKS(md["jwks"])
			if err == nil {
				fps = append(fps, j.Fingerprints...)
			}
		}
	}
	slices.Sort(fps)
	return slices.Compact(fps), nil
}

// FetchMetadata gets a metadata document from an administrator's URL:
// https only (http in development), TLS 1.2+, 10 s, 1 MiB, no redirects.
func FetchMetadata(ctx context.Context, raw string, dev bool) ([]byte, error) {
	if !endpointOK(raw, dev) {
		return nil, badMetadata("%q is not an https URL", raw)
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	c := &http.Client{Timeout: 10 * time.Second, Transport: t,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, badMetadata("%v", err)
	}
	resp, err := c.Do(req) // #nosec G704 -- an administrator's (idp.manage) metadata URL, https only, bounded
	if err != nil {
		return nil, badMetadata("fetching %s: %v", raw, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, badMetadata("fetching %s: HTTP %d", raw, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxMetadataBytes+1))
	if err != nil {
		return nil, badMetadata("reading %s: %v", raw, err)
	}
	if len(b) > MaxMetadataBytes {
		return nil, badMetadata("larger than %d bytes", MaxMetadataBytes)
	}
	return b, nil
}
