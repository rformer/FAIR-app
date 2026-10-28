package saml

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/rformer/fair-app/internal/authn/saml/samltest"
)

// F-001 T-15 (AC-04; design §7): the SAML validation and its XML signature
// wrapping (XSW) negative corpus. The test IdP (samltest) signs real
// responses with goxmldsig; each case then changes one as an attacker would.

const (
	spEntity = "https://fair.example.test/saml"
	idpID    = "11111111-1111-4111-8111-111111111111"
	acs      = "https://fair.example.test/api/v1/auth/saml/" + idpID + "/acs"
	idpIss   = "https://idp.example.test/realm"
)

// memStore is Store in memory.
type memStore struct {
	mu       sync.Mutex
	requests map[string]string
	seen     map[string]bool
}

func (m *memStore) SaveRequest(_ context.Context, idp, id, returnTo string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[idp+"/"+id] = returnTo
	return nil
}

func (m *memStore) ConsumeRequest(_ context.Context, idp, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.requests[idp+"/"+id]
	if !ok {
		return "", ErrUnknownRequest
	}
	delete(m.requests, idp+"/"+id)
	return r, nil
}

func (m *memStore) RecordAssertion(_ context.Context, idp, id string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[idp+"/"+id] {
		return ErrReplay
	}
	m.seen[idp+"/"+id] = true
	return nil
}

type fixture struct {
	sp    SP
	idp   IDP
	key   samltest.Key
	store *memStore
	now   time.Time
}

func newKey(t *testing.T, cn string) samltest.Key {
	t.Helper()
	k, err := samltest.NewKey(cn)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{key: newKey(t, "idp"), store: &memStore{requests: map[string]string{}, seen: map[string]bool{}}, now: time.Now().UTC()}
	f.idp = IDP{ID: idpID, EntityID: idpIss, SSOURL: "https://idp.example.test/sso", Certs: []*x509.Certificate{f.key.Cert}}
	f.sp = SP{EntityID: spEntity, ACSURL: func(id string) string { return "https://fair.example.test/api/v1/auth/saml/" + id + "/acs" },
		Store: f.store, Now: func() time.Time { return f.now }}
	return f
}

func (f *fixture) good(req string) samltest.Response {
	return samltest.Good(f.now, acs, spEntity, idpIss, req, "user@example.test")
}

func (f *fixture) build(t *testing.T, r samltest.Response) string {
	t.Helper()
	s, err := f.key.Build(r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// start records a pending request, as the login redirect does.
func (f *fixture) start(t *testing.T, returnTo string) string {
	t.Helper()
	id := "_req" + samltest.RandID()
	if err := f.store.SaveRequest(context.Background(), idpID, id, returnTo, f.now.Add(RequestTTL)); err != nil {
		t.Fatal(err)
	}
	return id
}

func findAssertion(doc *etree.Document) *etree.Element { return doc.FindElement("//Assertion") }

// evilAssertion is an attacker's unsigned assertion for admin.
func evilAssertion(r samltest.Response) *etree.Element {
	r.NameID, r.AssertionID = "admin@example.test", "_evil"
	return samltest.Assertion(r)
}

func TestValidAssertionAccepted(t *testing.T) {
	f := newFixture(t)
	for name, mutate := range map[string]func(*samltest.Response){
		"assertion signed":          func(*samltest.Response) {},
		"response signed":           func(r *samltest.Response) { r.SignAssertion, r.SignResponse = false, true },
		"both signed":               func(r *samltest.Response) { r.SignResponse = true },
		"RSA-SHA512":                func(r *samltest.Response) { r.Method = dsig.RSASHA512SignatureMethod },
		"clock 90 s behind the IdP": func(r *samltest.Response) { r.NotBefore = f.now.Add(90 * time.Second) },
		"conditions just expired, within skew": func(r *samltest.Response) {
			// The subject confirmation is checked strictly by the library;
			// only the Conditions window gets the skew.
			r.BeforeSign = func(a *etree.Element) {
				a.FindElement("Conditions").SelectAttr("NotOnOrAfter").Value = f.now.Add(-90 * time.Second).Format(time.RFC3339)
			}
		},
	} {
		r := f.good(f.start(t, "/posture?tab=drift"))
		mutate(&r)
		l, err := f.sp.Validate(context.Background(), f.idp, f.build(t, r))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if l.NameID != "user@example.test" || l.ReturnTo != "/posture?tab=drift" || l.IDPInitiated ||
			l.AuthnContextClassRef != samltest.MultiFactor || l.AuthnInstant == nil {
			t.Errorf("%s: %+v", name, l)
		}
	}
}

// The XSW corpus and every other refusal: each must fail with ErrInvalid.
func TestNegativeCorpus(t *testing.T) {
	f := newFixture(t)
	other := newKey(t, "attacker")
	cases := map[string]func(r *samltest.Response){
		"unsigned":              func(r *samltest.Response) { r.SignAssertion = false },
		"signed by another key": func(r *samltest.Response) { r.Signer = &other },
		"SHA-1 signature":       func(r *samltest.Response) { r.Method = dsig.RSASHA1SignatureMethod },
		"NameID changed after signing": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) { doc.FindElement("//NameID").SetText("admin@example.test") }
		},
		"XSW1: evil assertion before the signed one": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) { doc.Root().InsertChildAt(findAssertion(doc).Index(), evilAssertion(*r)) }
		},
		"XSW2: evil assertion after the signed one": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) { doc.Root().AddChild(evilAssertion(*r)) }
		},
		"XSW3: signed assertion hidden in Extensions, evil one in its place": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) {
				root := doc.Root()
				signed := findAssertion(doc)
				root.RemoveChild(signed)
				ext := etree.NewElement("samlp:Extensions")
				ext.AddChild(signed)
				root.InsertChildAt(2, ext)
				root.AddChild(evilAssertion(*r))
			}
		},
		"XSW4: evil assertion wrapping the signed one": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) {
				root := doc.Root()
				signed := findAssertion(doc)
				root.RemoveChild(signed)
				evil := evilAssertion(*r)
				evil.AddChild(signed)
				root.AddChild(evil)
			}
		},
		"XSW5: evil assertion inside the signature's Object": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) {
				doc.FindElement("//Signature").CreateElement("ds:Object").AddChild(evilAssertion(*r))
			}
		},
		"XSW6: evil assertion reusing the signed assertion's ID": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) {
				evil := evilAssertion(*r)
				evil.SelectAttr("ID").Value = r.AssertionID
				doc.Root().InsertChildAt(findAssertion(doc).Index(), evil)
			}
		},
		"XSW7: signed response, unsigned assertion swapped in": func(r *samltest.Response) {
			r.SignAssertion, r.SignResponse = false, true
			r.AfterSign = func(doc *etree.Document) {
				root := doc.Root()
				root.RemoveChild(findAssertion(doc))
				root.AddChild(evilAssertion(*r))
			}
		},
		"encrypted assertion added": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) { doc.Root().CreateElement("saml:EncryptedAssertion") }
		},
		"DTD": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) { doc.InsertChildAt(0, etree.NewDirective(`DOCTYPE r [<!ENTITY x "admin">]`)) }
		},
		"expired":                   func(r *samltest.Response) { r.NotOnOrAfter = f.now.Add(-3 * time.Minute) },
		"not yet valid beyond skew": func(r *samltest.Response) { r.NotBefore = f.now.Add(3 * time.Minute) },
		"wrong audience":            func(r *samltest.Response) { r.Audience = "https://other-sp.example.test" },
		"no AudienceRestriction":    func(r *samltest.Response) { r.Audience = "" },
		"wrong Destination":         func(r *samltest.Response) { r.Destination = "https://evil.example.test/acs" },
		"no Destination":            func(r *samltest.Response) { r.Destination = "" },
		"wrong Recipient":           func(r *samltest.Response) { r.Recipient = "https://evil.example.test/acs" },
		"wrong issuer":              func(r *samltest.Response) { r.Issuer = "https://evil.example.test" },
		"failure status":            func(r *samltest.Response) { r.Status = "urn:oasis:names:tc:SAML:2.0:status:Requester" },
		"empty NameID":              func(r *samltest.Response) { r.NameID = "" },
		"unknown InResponseTo":      func(r *samltest.Response) { r.InResponseTo = "_never-sent" },
		"InResponseTo differs between response and assertion": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) { doc.Root().SelectAttr("InResponseTo").Value = "_other" }
		},
		"IdP-initiated where not allowed": func(r *samltest.Response) { r.InResponseTo = "" },
		"oversized": func(r *samltest.Response) {
			r.AfterSign = func(doc *etree.Document) {
				doc.Root().CreateElement("samlp:Extensions").SetText(strings.Repeat("A", MaxResponseBytes))
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := f.good(f.start(t, "/"))
			mutate(&r)
			_, err := f.sp.Validate(context.Background(), f.idp, f.build(t, r))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted or wrong error: %v", err)
			}
			// Where F-001's own check must be the one that refuses (the
			// library or FIPS mode may refuse too: defence in depth).
			if want := ownReason(name); want != "" && !strings.Contains(err.Error(), want) {
				t.Fatalf("refused, but not by F-001's check (%q): %v", want, err)
			}
			t.Log(err)
		})
	}
}

// ownReason is the refusal F-001's pre-check gives for a corpus case.
func ownReason(name string) string {
	switch {
	case strings.HasPrefix(name, "XSW") && !strings.HasPrefix(name, "XSW7"):
		return "Assertion elements in the document"
	case name == "SHA-1 signature":
		return "is not allowed (FIPS 140"
	case name == "DTD":
		return "DTD present"
	case name == "encrypted assertion added":
		return "encrypted assertions are not supported"
	}
	return ""
}

// Comments inside the NameID cannot truncate it (canonicalization drops
// comments, so a comment added after signing keeps the signature valid).
func TestNameIDCommentInjection(t *testing.T) {
	f := newFixture(t)
	r := f.good(f.start(t, "/"))
	r.NameID = "admin@example.test.evil.test"
	r.AfterSign = func(doc *etree.Document) {
		n := doc.FindElement("//NameID")
		n.SetText("")
		n.AddChild(etree.NewText("admin@example.test"))
		n.AddChild(etree.NewComment(""))
		n.AddChild(etree.NewText(".evil.test"))
	}
	l, err := f.sp.Validate(context.Background(), f.idp, f.build(t, r))
	if err == nil && l.NameID != "admin@example.test.evil.test" {
		t.Fatalf("NameID truncated by a comment: %q", l.NameID)
	}
}

func TestReplayAndRequestSingleUse(t *testing.T) {
	f := newFixture(t)
	req := f.start(t, "/")
	encoded := f.build(t, f.good(req))
	if _, err := f.sp.Validate(context.Background(), f.idp, encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sp.Validate(context.Background(), f.idp, encoded); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replayed response accepted: %v", err)
	}
	// A second response to the same request (new assertion ID) is refused too.
	if _, err := f.sp.Validate(context.Background(), f.idp, f.build(t, f.good(req))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a request answered twice: %v", err)
	}
	// IdP-initiated where allowed: no pending request, the return path is /.
	f.idp.AllowIDPInitiated = true
	idpInitiated := f.build(t, f.good(""))
	l, err := f.sp.Validate(context.Background(), f.idp, idpInitiated)
	if err != nil || !l.IDPInitiated || l.ReturnTo != "/" {
		t.Fatalf("IdP-initiated: %+v %v", l, err)
	}
	// With no request to consume, only the replay cache stops a replay.
	if _, err := f.sp.Validate(context.Background(), f.idp, idpInitiated); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replayed IdP-initiated response: %v", err)
	}
}

func TestStartAndLocalPath(t *testing.T) {
	f := newFixture(t)
	u, err := f.sp.Start(context.Background(), f.idp, "//evil.example.test/x")
	if err != nil || !strings.HasPrefix(u, "https://idp.example.test/sso?SAMLRequest=") {
		t.Fatalf("%q %v", u, err)
	}
	if len(f.store.requests) != 1 {
		t.Fatalf("pending requests %v", f.store.requests)
	}
	for _, rt := range f.store.requests {
		if rt != "/" {
			t.Fatalf("an off-site return path was kept: %q", rt)
		}
	}
	for p, want := range map[string]bool{"/": true, "/posture?x=1": true, "//evil": false, "/\\evil": false, "https://evil": false,
		"evil": false, "/a\r\nSet-Cookie: x": false} {
		if LocalPath(p) != want {
			t.Errorf("LocalPath(%q) = %v", p, !want)
		}
	}
}

// IdP dialects (AC-01 interop; live tenants are an open item): the XML as
// Entra ID (assertion in the default namespace, assertion signed), Okta
// (saml2p/saml2 prefixes, response and assertion signed) and Ping
// (samlp/saml, assertion signed) write it, with their usual context classes.
func TestIDPDialects(t *testing.T) {
	f := newFixture(t)
	for _, d := range []struct {
		dialect, class string
		signResponse   bool
	}{
		{"entra", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", false},
		{"okta", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", true},
		{"ping", "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor", false},
	} {
		r := f.good(f.start(t, "/x"))
		r.Dialect, r.AuthnContextClassRef, r.SignResponse = d.dialect, d.class, d.signResponse
		l, err := f.sp.Validate(context.Background(), f.idp, f.build(t, r))
		if err != nil || l.NameID != "user@example.test" || l.AuthnContextClassRef != d.class || l.ReturnTo != "/x" {
			t.Errorf("%s: %+v %v", d.dialect, l, err)
		}
		// The wrapping defence holds in every dialect.
		w := f.good(f.start(t, "/"))
		w.Dialect = d.dialect
		w.AfterSign = func(doc *etree.Document) {
			e := w
			e.NameID, e.AssertionID = "admin@example.test", "_evil"
			doc.Root().AddChild(samltest.Assertion(e))
		}
		if _, err := f.sp.Validate(context.Background(), f.idp, f.build(t, w)); err == nil || !strings.Contains(err.Error(), "Assertion elements") {
			t.Errorf("%s: wrapped response: %v", d.dialect, err)
		}
	}
}
