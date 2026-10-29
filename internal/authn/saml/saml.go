// Package saml is the platform's SAML 2.0 service provider (F-001 T-15;
// AC-01, AC-04; design §5.1, §7; ADR-009). Signature verification and
// assertion decoding are russellhaering/gosaml2 over goxmldsig; around them
// this package enforces what F-001 requires and the library leaves to
// callers or reports only as warnings:
//
//   - before the library sees it: a size limit, no DTD, exactly one
//     Assertion anywhere in the document and no EncryptedAssertion (XML
//     signature wrapping places a second, unsigned assertion), and FIPS-only
//     algorithms on every signature (RSA or ECDSA with SHA-256/384/512 and
//     SHA-256/384/512 digests; SHA-1 and DSA are refused);
//   - after it: exactly one signed assertion, Destination and an
//     AudienceRestriction naming this SP present and matching, the
//     assertion's Issuer, NotBefore and NotOnOrAfter within ±2 minutes, a
//     non-empty NameID;
//   - InResponseTo naming a pending AuthnRequest of this IdP, consumed once
//     (SP-initiated), or none at all where the IdP allows IdP-initiated
//     login;
//   - a replay cache of assertion IDs until they expire.
//
// Every refusal is ErrInvalid with the reason, for the audit log; users see
// a generic message.
package saml

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// Limits.
const (
	MaxResponseBytes = 256 << 10 // a decoded SAMLResponse
	MaxXMLTokens     = 20000
	Skew             = 2 * time.Minute // design §5.1
	RequestTTL       = 10 * time.Minute
)

// Accepted algorithms (FIPS 140: no SHA-1, no DSA).
var (
	signatureMethods = []string{
		dsig.RSASHA256SignatureMethod, dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod,
		dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod,
	}
	digestMethods = []string{
		"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#sha384",
		"http://www.w3.org/2001/04/xmlenc#sha512",
	}
)

// Errors.
var (
	// ErrInvalid: the response is refused; the wrapped error says why.
	ErrInvalid = errors.New("saml: response refused")
	// ErrUnknownRequest: no pending AuthnRequest with that ID for this IdP
	// (Store.ConsumeRequest).
	ErrUnknownRequest = errors.New("saml: no pending request")
	// ErrReplay: the assertion was seen before (Store.RecordAssertion).
	ErrReplay = errors.New("saml: assertion replayed")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// IDP is a configured SAML identity provider (IdP).
type IDP struct {
	ID                string // iam.idp id
	EntityID          string // its Issuer
	SSOURL            string // HTTP-Redirect binding
	Certs             []*x509.Certificate
	AllowIDPInitiated bool
}

// Store keeps pending AuthnRequests and the replay cache (shared by every
// iam replica: the database).
type Store interface {
	SaveRequest(ctx context.Context, idpID, requestID, returnTo string, expires time.Time) error
	// ConsumeRequest returns the pending request's return path and deletes
	// it; ErrUnknownRequest when there is none (or it expired).
	ConsumeRequest(ctx context.Context, idpID, requestID string) (returnTo string, err error)
	// RecordAssertion records an assertion ID until it expires; ErrReplay
	// when it is already recorded.
	RecordAssertion(ctx context.Context, idpID, assertionID string, until time.Time) error
}

// SP is this service provider.
type SP struct {
	EntityID string                    // the audience IdPs assert to
	ACSURL   func(idpID string) string // https://<origin>/api/v1/auth/saml/<idp>/acs
	Store    Store
	Now      func() time.Time
}

// Login is a validated assertion.
type Login struct {
	NameID               string
	NameIDFormat         string
	AuthnContextClassRef string              // for the MFA evidence rule (T-18)
	Attributes           map[string][]string // the assertion's attributes by name (MFA evidence, T-18)
	AuthnInstant         *time.Time          // the IdP's authentication time
	AssertionID          string
	ReturnTo             string // the path the user asked for ("/" when IdP-initiated)
	IDPInitiated         bool
}

func (s SP) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s SP) provider(idp IDP) *saml2.SAMLServiceProvider {
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      idp.SSOURL,
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      idp.EntityID,
		AssertionConsumerServiceURL: s.ACSURL(idp.ID),
		ServiceProviderIssuer:       s.EntityID,
		AudienceURI:                 s.EntityID,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: idp.Certs},
		AllowMissingAttributes:      true,
		Clock:                       dsig.NewFakeClockAt(s.now()),
		MaximumDecompressedBodySize: MaxResponseBytes,
		MaximumXMLTokens:            MaxXMLTokens,
		NameIdFormat:                "",
	}
}

// Start begins an SP-initiated login: the URL to send the browser to (the
// IdP, HTTP-Redirect binding) and the pending request recorded for
// InResponseTo. returnTo must be a local path.
func (s SP) Start(ctx context.Context, idp IDP, returnTo string) (string, error) {
	if !LocalPath(returnTo) {
		returnTo = "/"
	}
	sp := s.provider(idp)
	doc, err := sp.BuildAuthRequestDocument()
	if err != nil {
		return "", err
	}
	id := doc.Root().SelectAttrValue("ID", "")
	if id == "" {
		return "", errors.New("saml: AuthnRequest without ID")
	}
	if err := s.Store.SaveRequest(ctx, idp.ID, id, returnTo, s.now().Add(RequestTTL)); err != nil {
		return "", err
	}
	return sp.BuildAuthURLRedirect("", doc)
}

// LocalPath reports whether p is an absolute path on this site ("/x"), never another origin
// ("//host", "/\host", a scheme).
func LocalPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.ContainsAny(p, "\r\n") {
		return false
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == ""
}

// Validate checks an encoded SAMLResponse from idp (HTTP-POST binding).
func (s SP) Validate(ctx context.Context, idp IDP, encoded string) (Login, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return Login{}, invalid("not base64")
	}
	if err := precheck(raw); err != nil {
		return Login{}, err
	}
	now := s.now()
	sp := s.provider(idp)
	info, err := sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return Login{}, invalid("%v", err)
	}
	if len(info.Assertions) != 1 {
		return Login{}, invalid("%d assertions", len(info.Assertions))
	}
	a := info.Assertions[0]
	if !info.ResponseSignatureValidated && !a.SignatureValidated {
		return Login{}, invalid("neither the response nor the assertion is signed")
	}
	if info.WarningInfo != nil && info.WarningInfo.NotInAudience {
		return Login{}, invalid("not in the audience")
	}
	resp, err := responseAttrs(raw)
	if err != nil {
		return Login{}, err
	}
	if resp.destination != sp.AssertionConsumerServiceURL {
		return Login{}, invalid("Destination %q", resp.destination)
	}
	c := a.Conditions
	if len(c.AudienceRestrictions) == 0 {
		return Login{}, invalid("no AudienceRestriction")
	}
	notBefore, err1 := time.Parse(time.RFC3339, c.NotBefore)
	notAfter, err2 := time.Parse(time.RFC3339, c.NotOnOrAfter)
	if err1 != nil || err2 != nil {
		return Login{}, invalid("unreadable Conditions times")
	}
	if now.Add(Skew).Before(notBefore) || !now.Add(-Skew).Before(notAfter) {
		return Login{}, invalid("outside NotBefore %s / NotOnOrAfter %s", c.NotBefore, c.NotOnOrAfter)
	}
	if strings.TrimSpace(info.NameID) == "" {
		return Login{}, invalid("empty NameID")
	}

	login := Login{NameID: info.NameID, NameIDFormat: info.NameIDFormat, AuthnInstant: info.AuthnInstant, AssertionID: a.ID, ReturnTo: "/"}
	if as := a.AuthnStatement; as != nil && as.AuthnContext != nil && as.AuthnContext.AuthnContextClassRef != nil {
		login.AuthnContextClassRef = strings.TrimSpace(as.AuthnContext.AuthnContextClassRef.Value)
	}
	for name := range info.Values {
		if login.Attributes == nil {
			login.Attributes = map[string][]string{}
		}
		login.Attributes[name] = info.Values.GetAll(name)
	}
	// SP- or IdP-initiated: the response and its subject confirmation must
	// agree on InResponseTo, which must name a pending request of this IdP.
	scd := ""
	if a.Subject != nil && a.Subject.SubjectConfirmation != nil && a.Subject.SubjectConfirmation.SubjectConfirmationData != nil {
		scd = a.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo
	}
	switch {
	case resp.inResponseTo == "" && scd == "":
		if !idp.AllowIDPInitiated {
			return Login{}, invalid("IdP-initiated login is not enabled for this IdP")
		}
		login.IDPInitiated = true
	case resp.inResponseTo != scd:
		return Login{}, invalid("InResponseTo differs between the response (%q) and the assertion (%q)", resp.inResponseTo, scd)
	default:
		returnTo, err := s.Store.ConsumeRequest(ctx, idp.ID, resp.inResponseTo)
		if errors.Is(err, ErrUnknownRequest) {
			return Login{}, invalid("InResponseTo %q is not a pending request", resp.inResponseTo)
		}
		if err != nil {
			return Login{}, err
		}
		login.ReturnTo = returnTo
	}
	if err := s.Store.RecordAssertion(ctx, idp.ID, a.ID, notAfter.Add(Skew)); err != nil {
		if errors.Is(err, ErrReplay) {
			return Login{}, invalid("assertion %q replayed", a.ID)
		}
		return Login{}, err
	}
	return login, nil
}

type respAttrs struct{ destination, inResponseTo string }

// precheck inspects the raw document before any signature processing.
func precheck(raw []byte) error {
	if len(raw) > MaxResponseBytes {
		return invalid("response larger than %d bytes", MaxResponseBytes)
	}
	if bytes.Contains(raw, []byte("<!DOCTYPE")) || bytes.Contains(raw, []byte("<!ENTITY")) {
		return invalid("DTD present")
	}
	doc := etree.NewDocument()
	doc.ReadSettings.Permissive = false
	if err := doc.ReadFromBytes(raw); err != nil {
		return invalid("not XML: %v", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" || root.NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return invalid("not a SAML Response")
	}
	assertions, encrypted, signatures := 0, 0, 0
	var walk func(e *etree.Element) error
	walk = func(e *etree.Element) error {
		ns := e.NamespaceURI()
		switch {
		case e.Tag == "Assertion" && ns == "urn:oasis:names:tc:SAML:2.0:assertion":
			assertions++
		case e.Tag == "EncryptedAssertion":
			encrypted++
		case e.Tag == "SignatureMethod" && ns == dsig.Namespace:
			signatures++
			if alg := e.SelectAttrValue("Algorithm", ""); !slices.Contains(signatureMethods, alg) {
				return invalid("signature algorithm %q is not allowed (FIPS 140: RSA or ECDSA with SHA-256 or stronger)", alg)
			}
		case e.Tag == "DigestMethod" && ns == dsig.Namespace:
			if alg := e.SelectAttrValue("Algorithm", ""); !slices.Contains(digestMethods, alg) {
				return invalid("digest algorithm %q is not allowed", alg)
			}
		}
		for _, c := range e.ChildElements() {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return err
	}
	if encrypted > 0 {
		return invalid("encrypted assertions are not supported")
	}
	if assertions != 1 {
		return invalid("%d Assertion elements in the document (exactly one is allowed)", assertions)
	}
	if signatures == 0 {
		return invalid("unsigned")
	}
	return nil
}

func responseAttrs(raw []byte) (respAttrs, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return respAttrs{}, invalid("not XML")
	}
	r := doc.Root()
	return respAttrs{destination: r.SelectAttrValue("Destination", ""), inResponseTo: r.SelectAttrValue("InResponseTo", "")}, nil
}
