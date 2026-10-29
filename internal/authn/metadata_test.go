package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/rformer/fair-app/internal/authn/saml/samltest"
)

// SAMLMetadataXML is an IdP's metadata document with the given certificates.
func samlMetadataXML(sso string, certs ...[]byte) string {
	var kd strings.Builder
	for _, c := range certs {
		kd.WriteString(`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
			base64.StdEncoding.EncodeToString(c) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
	}
	return `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com/saml">
<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + kd.String() + `
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/post"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + sso + `"/>
</md:IDPSSODescriptor></md:EntityDescriptor>`
}

func selfSigned(t *testing.T, pub, priv any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseSAMLMetadata(t *testing.T) {
	k1, err := samltest.NewKey("idp-1")
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := samltest.NewKey("idp-2")
	md, err := ParseSAMLMetadata([]byte(samlMetadataXML("https://idp.example.com/sso", k1.Cert.Raw, k2.Cert.Raw)), false)
	if err != nil {
		t.Fatal(err)
	}
	if md.Fields["entity_id"] != "https://idp.example.com/saml" || md.Fields["sso_url"] != "https://idp.example.com/sso" {
		t.Fatalf("fields %v", md.Fields)
	}
	if certs := md.Fields["certificates"].([]string); len(certs) != 2 || certs[0] != k1.CertPEM() {
		t.Fatalf("certificates %v", certs)
	}
	if len(md.Fingerprints) != 2 || !strings.HasPrefix(md.Fingerprints[0], "cert:sha256:") {
		t.Fatalf("fingerprints %v", md.Fingerprints)
	}
	// The fingerprints of stored metadata are those of the document.
	stored, _ := json.Marshal(md.Fields)
	if fps, _ := TrustFingerprints("saml", stored); strings.Join(fps, ",") != strings.Join(md.Fingerprints, ",") {
		t.Fatalf("stored fingerprints %v, parsed %v", fps, md.Fingerprints)
	}

	weak, _ := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- a weak key the parser must refuse
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := ParseSAMLMetadata([]byte(samlMetadataXML("https://idp.example.com/sso", selfSigned(t, &ec.PublicKey, ec))), false); err != nil {
		t.Errorf("ECDSA certificate refused: %v", err)
	}
	refused := map[string]string{
		"http SSO":      samlMetadataXML("http://idp.example.com/sso", k1.Cert.Raw),
		"no certs":      samlMetadataXML("https://idp.example.com/sso"),
		"RSA-1024 cert": samlMetadataXML("https://idp.example.com/sso", selfSigned(t, &weak.PublicKey, weak)),
		"DTD":           `<!DOCTYPE x [<!ENTITY a "b">]>` + samlMetadataXML("https://idp.example.com/sso", k1.Cert.Raw),
		"not metadata":  `<x xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`,
		"SP metadata": strings.ReplaceAll(samlMetadataXML("https://idp.example.com/sso", k1.Cert.Raw),
			"IDPSSODescriptor", "SPSSODescriptor"),
		"not XML": "{}",
	}
	for name, doc := range refused {
		if _, err := ParseSAMLMetadata([]byte(doc), false); !errors.Is(err, ErrMetadata) {
			t.Errorf("%s: %v, want ErrMetadata", name, err)
		}
	}
	if _, err := ParseSAMLMetadata([]byte(samlMetadataXML("http://localhost/sso", k1.Cert.Raw)), true); err != nil {
		t.Errorf("development http SSO: %v", err)
	}
}

func TestParseOIDCDiscoveryAndJWKS(t *testing.T) {
	doc := `{"issuer":"https://idp.example.com/realms/a","authorization_endpoint":"https://idp.example.com/auth",
		"token_endpoint":"https://idp.example.com/token","jwks_uri":"https://idp.example.com/jwks","response_types_supported":["code","id_token"]}`
	md, err := ParseOIDCDiscovery([]byte(doc), "https://idp.example.com/realms/a/", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(md.Fingerprints, ",") != "issuer:https://idp.example.com/realms/a,jwks_uri:https://idp.example.com/jwks" {
		t.Fatalf("fingerprints %v", md.Fingerprints)
	}
	if _, err := ParseOIDCDiscovery([]byte(doc), "https://other.example.com", false); !errors.Is(err, ErrMetadata) {
		t.Errorf("issuer mismatch: %v", err)
	}
	if _, err := ParseOIDCDiscovery([]byte(strings.Replace(doc, "https://idp.example.com/token", "http://idp.example.com/token", 1)), "", false); !errors.Is(err, ErrMetadata) {
		t.Errorf("http token endpoint: %v", err)
	}
	if _, err := ParseOIDCDiscovery([]byte(strings.Replace(doc, `"code",`, "", 1)), "", false); !errors.Is(err, ErrMetadata) {
		t.Errorf("no code flow: %v", err)
	}

	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &rk.PublicKey, KeyID: "r", Use: "sig", Algorithm: "RS256"},
		{Key: &ek.PublicKey, KeyID: "e", Algorithm: "ES256"},
		{Key: &rk.PublicKey, KeyID: "enc", Use: "enc"},
	}}
	b, _ := json.Marshal(set)
	j, err := ParseJWKS(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Fingerprints) != 2 || j.Fields["jwks_uri"] != nil {
		t.Fatalf("JWKS %v %v", j.Fingerprints, j.Fields)
	}
	// Stored: the issuer and the inline keys are the anchors.
	stored, _ := json.Marshal(map[string]any{"issuer": "https://idp.example.com/realms/a", "jwks": j.Fields["jwks"]})
	fps, _ := TrustFingerprints("oidc", stored)
	if len(fps) != 3 || fps[0] != "issuer:https://idp.example.com/realms/a" {
		t.Fatalf("stored fingerprints %v", fps)
	}

	priv, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: rk, KeyID: "p"}}})
	weak, _ := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- a weak key the parser must refuse
	weakSet, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &weak.PublicKey, KeyID: "w"}}})
	encOnly, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rk.PublicKey, KeyID: "x", Use: "enc"}}})
	for name, doc := range map[string][]byte{"private key": priv, "RSA-1024": weakSet, "no signing key": encOnly, "not JSON": []byte("<x/>")} {
		if _, err := ParseJWKS(doc); !errors.Is(err, ErrMetadata) {
			t.Errorf("%s: %v, want ErrMetadata", name, err)
		}
	}
}

func TestFetchMetadata(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write(make([]byte, MaxMetadataBytes+1))
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	// The test server's certificate is not trusted: the fetch verifies TLS.
	if _, err := FetchMetadata(ctx, srv.URL+"/ok", false); !errors.Is(err, ErrMetadata) || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("untrusted certificate: %v", err)
	}
	plain := httptest.NewServer(srv.Config.Handler)
	defer plain.Close()
	if _, err := FetchMetadata(ctx, plain.URL+"/ok", false); !errors.Is(err, ErrMetadata) {
		t.Errorf("http URL in production: %v", err)
	}
	if b, err := FetchMetadata(ctx, plain.URL+"/ok", true); err != nil || string(b) != "ok" {
		t.Errorf("development http: %q %v", b, err)
	}
	if _, err := FetchMetadata(ctx, plain.URL+"/big", true); !errors.Is(err, ErrMetadata) {
		t.Errorf("oversized: %v", err)
	}
	if _, err := FetchMetadata(ctx, plain.URL+"/redirect", true); !errors.Is(err, ErrMetadata) {
		t.Errorf("redirect followed: %v", err)
	}
}

func TestDiscoveryRateLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := &Discovery{Logins: Logins{Now: func() time.Time { return now }}, PerMinute: 3}
	for i := range 3 {
		if !d.allow("10.0.0.1") {
			t.Fatalf("request %d refused", i)
		}
	}
	if d.allow("10.0.0.1") {
		t.Fatal("fourth request in a minute allowed")
	}
	if !d.allow("10.0.0.2") {
		t.Fatal("another client limited")
	}
	now = now.Add(20 * time.Second) // one token back
	if !d.allow("10.0.0.1") || d.allow("10.0.0.1") {
		t.Fatal("refill is not one request per 20 s")
	}
	// Over the HTTP surface: 429 with Retry-After.
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, DiscoverPath, strings.NewReader(`{}`))
	r.RemoteAddr = "10.0.0.1:5555"
	d.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("limited request: %d %v", rec.Code, rec.Header())
	}
}
