// Package samltest is a test SAML identity provider: it issues real,
// signed SAML Responses (goxmldsig, exclusive canonicalization, as IdPs
// sign) that tests change as an attacker would (F-001 T-15). Test use only.
package samltest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"sort"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Namespaces.
const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	Success     = "urn:oasis:names:tc:SAML:2.0:status:Success"
	MultiFactor = "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor"
)

// Key is an IdP signing key and its certificate.
type Key struct {
	Cert *x509.Certificate
	TLS  tls.Certificate
}

// NewKey makes an RSA-2048 key with a self-signed certificate.
func NewKey(cn string) (Key, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Key{}, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return Key{}, err
	}
	c, err := x509.ParseCertificate(der)
	return Key{Cert: c, TLS: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}}, err
}

// CertPEM is the certificate as PEM (for IdP configuration).
func (k Key) CertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.Cert.Raw}))
}

// Response describes a response to issue.
type Response struct {
	Now                         time.Time
	InResponseTo                string
	Destination, Recipient      string
	Audience                    string // "" omits the AudienceRestriction
	Issuer                      string
	NameID                      string
	NotBefore, NotOnOrAfter     time.Time
	Status                      string
	SignAssertion, SignResponse bool
	Signer                      *Key   // default: the issuing key
	Method                      string // signature method; default RSA-SHA256
	AssertionID                 string
	AuthnContextClassRef        string
	Attributes                  map[string][]string // an AttributeStatement when set
	// Dialect writes the XML as an IdP does: "" or "ping" (samlp/saml
	// prefixes), "entra" (the assertion in the default namespace), "okta"
	// (saml2p/saml2 prefixes).
	Dialect    string
	BeforeSign func(assertion *etree.Element) // change the assertion before signing
	AfterSign  func(doc *etree.Document)      // the attack
}

// Good is a valid response to inResponseTo ("" for IdP-initiated).
func Good(now time.Time, acs, audience, issuer, inResponseTo, nameID string) Response {
	return Response{Now: now, InResponseTo: inResponseTo, Destination: acs, Recipient: acs, Audience: audience, Issuer: issuer,
		NameID: nameID, NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute), Status: Success,
		SignAssertion: true, AssertionID: "_a" + RandID(), AuthnContextClassRef: MultiFactor}
}

// RandID is a random XML ID suffix.
func RandID() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// prefixes are the protocol and assertion prefixes of a dialect ("" is the
// default namespace).
func prefixes(dialect string) (p, a string) {
	switch dialect {
	case "entra":
		return "samlp", ""
	case "okta":
		return "saml2p", "saml2"
	}
	return "samlp", "saml"
}

func q(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

func xmlns(prefix string) string {
	if prefix == "" {
		return "xmlns"
	}
	return "xmlns:" + prefix
}

// Assertion is the response's assertion, unsigned.
func Assertion(r Response) *etree.Element {
	_, pa := prefixes(r.Dialect)
	a := etree.NewElement(q(pa, "Assertion"))
	a.CreateAttr(xmlns(pa), NSAssertion)
	a.CreateAttr("ID", r.AssertionID)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", ts(r.Now))
	a.CreateElement(q(pa, "Issuer")).SetText(r.Issuer)
	sub := a.CreateElement(q(pa, "Subject"))
	n := sub.CreateElement(q(pa, "NameID"))
	n.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	n.SetText(r.NameID)
	sc := sub.CreateElement(q(pa, "SubjectConfirmation"))
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement(q(pa, "SubjectConfirmationData"))
	scd.CreateAttr("NotOnOrAfter", ts(r.NotOnOrAfter))
	scd.CreateAttr("Recipient", r.Recipient)
	if r.InResponseTo != "" {
		scd.CreateAttr("InResponseTo", r.InResponseTo)
	}
	c := a.CreateElement(q(pa, "Conditions"))
	c.CreateAttr("NotBefore", ts(r.NotBefore))
	c.CreateAttr("NotOnOrAfter", ts(r.NotOnOrAfter))
	if r.Audience != "" {
		c.CreateElement(q(pa, "AudienceRestriction")).CreateElement(q(pa, "Audience")).SetText(r.Audience)
	}
	as := a.CreateElement(q(pa, "AuthnStatement"))
	as.CreateAttr("AuthnInstant", ts(r.Now.Add(-30*time.Second)))
	as.CreateAttr("SessionIndex", "_s1")
	if r.AuthnContextClassRef != "" {
		as.CreateElement(q(pa, "AuthnContext")).CreateElement(q(pa, "AuthnContextClassRef")).SetText(r.AuthnContextClassRef)
	}
	if len(r.Attributes) > 0 {
		st := a.CreateElement(q(pa, "AttributeStatement"))
		names := make([]string, 0, len(r.Attributes))
		for n := range r.Attributes {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			at := st.CreateElement(q(pa, "Attribute"))
			at.CreateAttr("Name", n)
			for _, v := range r.Attributes[n] {
				at.CreateElement(q(pa, "AttributeValue")).SetText(v)
			}
		}
	}
	return a
}

func sign(k Key, method string, el *etree.Element) (*etree.Element, error) {
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(k.TLS))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if method == "" {
		method = dsig.RSASHA256SignatureMethod
	}
	if err := ctx.SetSignatureMethod(method); err != nil {
		return nil, err
	}
	return ctx.SignEnveloped(el)
}

// Build issues the response, base64 encoded as the HTTP-POST binding sends it.
func (k Key) Build(r Response) (string, error) {
	signer := k
	if r.Signer != nil {
		signer = *r.Signer
	}
	a := Assertion(r)
	if r.BeforeSign != nil {
		r.BeforeSign(a)
	}
	doc := etree.NewDocument()
	pp, pa := prefixes(r.Dialect)
	root := doc.CreateElement(q(pp, "Response"))
	root.CreateAttr(xmlns(pp), NSProtocol)
	if pa != "" {
		root.CreateAttr(xmlns(pa), NSAssertion)
	}
	root.CreateAttr("ID", "_r"+RandID())
	root.CreateAttr("Version", "2.0")
	root.CreateAttr("IssueInstant", ts(r.Now))
	if r.Destination != "" {
		root.CreateAttr("Destination", r.Destination)
	}
	if r.InResponseTo != "" {
		root.CreateAttr("InResponseTo", r.InResponseTo)
	}
	iss := root.CreateElement(q(pa, "Issuer"))
	if pa == "" {
		iss.CreateAttr("xmlns", NSAssertion)
	}
	iss.SetText(r.Issuer)
	root.CreateElement(q(pp, "Status")).CreateElement(q(pp, "StatusCode")).CreateAttr("Value", r.Status)
	var err error
	if r.SignAssertion {
		if a, err = sign(signer, r.Method, a); err != nil {
			return "", err
		}
	}
	root.AddChild(a)
	if r.SignResponse {
		signed, err := sign(signer, r.Method, root)
		if err != nil {
			return "", err
		}
		doc.SetRoot(signed)
	}
	if r.AfterSign != nil {
		r.AfterSign(doc)
	}
	b, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
