package profilepkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testPackage() *Package {
	return &Package{
		Format: Format,
		Profile: Meta{ID: "test-profile", Title: "Test", Family: "fedramp", Version: "1.0.0", Base: "profiles/test.json",
			Sources: []Source{{Path: "bindings/session.idle_timeout.yaml", SHA256: strings.Repeat("a", 64)}}, Generator: "test"},
		Settings: map[string]Setting{
			"session.idle_timeout": {Type: "duration", Direction: "lower_is_stricter", Default: "15m0s", Bound: "30m0s",
				Params: []string{"ac-11_odp.02"}, Origin: Origin{SourceParam: "ac-11_odp.02", SourceConstraint: "fifteen (15) minutes"}},
			"auth.lockout_threshold": {Type: "int", Direction: "lower_is_stricter", Default: 3, Bound: 5,
				Origin: Origin{PlatformChoice: "test"}},
			"tls.min_version": {Type: "enum", Direction: "ordered", Order: []string{"1.0", "1.1", "1.2", "1.3"}, Default: "1.3", Bound: "1.2",
				Origin: Origin{PlatformChoice: "test"}},
			"audit.enabled": {Type: "bool", Direction: "true_is_stricter", Default: true, Bound: true,
				Origin: Origin{PlatformChoice: "test"}},
		},
		HardFloor: map[string]Floor{"tls.min_version": {Value: "1.2"}, "audit.enabled": {Value: true}},
	}
}

func encode(t *testing.T, p *Package) []byte {
	t.Helper()
	b, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignVerify(t *testing.T) {
	key := newKey(t)
	b := encode(t, testPackage())
	sig, err := Sign(key, b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Verify(&key.PublicKey, b, sig)
	if err != nil {
		t.Fatal(err)
	}
	if p.Profile.ID != "test-profile" || p.Settings["session.idle_timeout"].Bound != "30m0s" {
		t.Fatalf("decoded %+v", p.Profile)
	}

	// Tamper tests: any change to the package or the signature, or another
	// key, is refused.
	tampered := []byte(strings.Replace(string(b), `"30m0s"`, `"31m0s"`, 1))
	if _, err := Verify(&key.PublicKey, tampered, sig); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered package: %v", err)
	}
	for i := range b {
		flipped := append([]byte(nil), b...)
		flipped[i] ^= 0x01
		if VerifySignature(&key.PublicKey, flipped, sig) == nil {
			t.Fatalf("flipping byte %d still verifies", i)
		}
	}
	badSig := []byte(strings.Replace(string(sig), string(sig[10]), string(sig[10]+1), 1))
	if _, err := Verify(&key.PublicKey, b, badSig); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered signature: %v", err)
	}
	if _, err := Verify(&newKey(t).PublicKey, b, sig); !errors.Is(err, ErrSignature) {
		t.Errorf("other key: %v", err)
	}
	if _, err := Verify(&key.PublicKey, b, nil); !errors.Is(err, ErrSignature) {
		t.Errorf("unsigned: %v", err)
	}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := Sign(p384, b); err == nil {
		t.Error("signed with a P-384 key")
	}
}

// Decode refuses anything that is not a valid, canonical package, so a
// correctly signed but malformed package is still refused.
func TestDecodeRejects(t *testing.T) {
	if _, err := Decode(encode(t, testPackage())); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(p *Package)) []byte {
		p := testPackage()
		f(p)
		return encode(t, p)
	}
	set := func(key string, f func(s *Setting)) func(p *Package) {
		return func(p *Package) {
			s := p.Settings[key]
			f(&s)
			p.Settings[key] = s
		}
	}
	good := string(encode(t, testPackage()))
	cases := map[string][]byte{
		"unknown field":           []byte(strings.Replace(good, `"format"`, `"extra": 1, "format"`, 1)),
		"trailing data":           []byte(good + "{}"),
		"not canonical":           []byte(strings.ReplaceAll(good, "  ", "\t")),
		"wrong format":            mutate(func(p *Package) { p.Format = "v0" }),
		"no settings":             mutate(func(p *Package) { p.Settings = nil }),
		"default weaker":          mutate(set("session.idle_timeout", func(s *Setting) { s.Default = "45m0s" })),
		"bound below floor":       mutate(set("tls.min_version", func(s *Setting) { s.Bound = "1.1"; s.Default = "1.1" })),
		"floor off":               mutate(set("audit.enabled", func(s *Setting) { s.Bound = false })),
		"bad duration":            mutate(set("session.idle_timeout", func(s *Setting) { s.Default = "fifteen" })),
		"int as string":           mutate(set("auth.lockout_threshold", func(s *Setting) { s.Default = "3" })),
		"enum outside order":      mutate(set("tls.min_version", func(s *Setting) { s.Default = "2.0" })),
		"unknown type":            mutate(set("audit.enabled", func(s *Setting) { s.Type = "set" })),
		"wrong direction":         mutate(set("audit.enabled", func(s *Setting) { s.Direction = "sideways" })),
		"no origin":               mutate(set("audit.enabled", func(s *Setting) { s.Origin = Origin{} })),
		"two origins":             mutate(set("session.idle_timeout", func(s *Setting) { s.Origin.PlatformChoice = "also" })),
		"source without text":     mutate(set("session.idle_timeout", func(s *Setting) { s.Origin.SourceConstraint = "" })),
		"floor for unknown key":   mutate(func(p *Package) { p.HardFloor["nope"] = Floor{Value: true} }),
		"floor of the wrong type": mutate(func(p *Package) { p.HardFloor["audit.enabled"] = Floor{Value: "yes"} }),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(b); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// release builds a signed release of two packages.
func release(t *testing.T, key *ecdsa.PrivateKey) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	m := Manifest{Format: ManifestFormat, Generator: "test"}
	for _, id := range []string{"one", "two"} {
		p := testPackage()
		p.Profile.ID = id
		b := encode(t, p)
		f := FileName(id, "1.0.0")
		files[f] = b
		m.Packages = append(m.Packages, ManifestEntry{File: f, ID: id, Version: "1.0.0", SHA256: Digest(b)})
	}
	mb, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = mb
	sigs, err := SignRelease(key, "manifest.json", files)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 3 {
		t.Fatalf("%d signatures, want 3", len(sigs))
	}
	for n, s := range sigs {
		files[n] = s
	}
	return files
}

func TestVerifyRelease(t *testing.T) {
	key := newKey(t)
	files := release(t, key)
	pkgs, err := VerifyRelease(&key.PublicKey, "manifest.json", files)
	if err != nil || len(pkgs) != 2 {
		t.Fatalf("%d packages, %v", len(pkgs), err)
	}

	clone := func() map[string][]byte {
		c := map[string][]byte{}
		for k, v := range files {
			c[k] = v
		}
		return c
	}
	attacker := newKey(t)
	cases := map[string]func(f map[string][]byte){
		"manifest unsigned": func(f map[string][]byte) { delete(f, "manifest.json.sig") },
		"package unsigned":  func(f map[string][]byte) { delete(f, "profile-one-1.0.0.json.sig") },
		"package missing":   func(f map[string][]byte) { delete(f, "profile-one-1.0.0.json") },
		"manifest tampered": func(f map[string][]byte) {
			f["manifest.json"] = []byte(strings.Replace(string(f["manifest.json"]), "test", "evil", 1))
		},
		"signatures swapped": func(f map[string][]byte) { f["profile-one-1.0.0.json.sig"] = f["profile-two-1.0.0.json.sig"] },
		"packages swapped": func(f map[string][]byte) {
			f["profile-one-1.0.0.json"], f["profile-two-1.0.0.json"] = f["profile-two-1.0.0.json"], f["profile-one-1.0.0.json"]
		},
		"package and signature swapped": func(f map[string][]byte) {
			// both correctly signed, but not what the manifest pins under this name
			f["profile-one-1.0.0.json"], f["profile-one-1.0.0.json.sig"] = f["profile-two-1.0.0.json"], f["profile-two-1.0.0.json.sig"]
		},
		"re-signed by another key": func(f map[string][]byte) {
			p := testPackage()
			p.Profile.ID = "one"
			s := p.Settings["session.idle_timeout"]
			s.Bound = "60m0s"
			p.Settings["session.idle_timeout"] = s
			b := encode(t, p)
			f["profile-one-1.0.0.json"] = b
			f["profile-one-1.0.0.json.sig"], _ = Sign(attacker, b)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := clone()
			mutate(f)
			if _, err := VerifyRelease(&key.PublicKey, "manifest.json", f); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A whole release re-signed by another key is refused by the real key.
	if _, err := VerifyRelease(&key.PublicKey, "manifest.json", release(t, attacker)); !errors.Is(err, ErrSignature) {
		t.Fatalf("release signed by another key: %v", err)
	}
}

func TestSignReleaseRefusesUnpinned(t *testing.T) {
	key := newKey(t)
	files := release(t, key)
	files["profile-one-1.0.0.json"] = encode(t, testPackage()) // id "test-profile", digest differs from the pin
	if _, err := SignRelease(key, "manifest.json", files); err == nil {
		t.Fatal("signed a package that does not match its pin")
	}
}

func TestLoadKeys(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	sec1, _ := x509.MarshalECPrivateKey(key)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	b := encode(t, testPackage())
	pk, err := LoadPublicKey(write("pub.pem", "PUBLIC KEY", pub))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{write("sec1.pem", "EC PRIVATE KEY", sec1), write("pkcs8.pem", "PRIVATE KEY", pkcs8)} {
		k, err := LoadPrivateKey(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		sig, err := Sign(k, b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(pk, b, sig); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(p384)
	if _, err := LoadPrivateKey(write("p384.pem", "PRIVATE KEY", der)); err == nil {
		t.Error("loaded a P-384 signing key")
	}
	if _, err := LoadPrivateKey(write("junk.pem", "PRIVATE KEY", []byte("junk"))); err == nil {
		t.Error("loaded junk")
	}
}
