package keys

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The simulation engine's channel (F-005 T-10, design §11; ADR-013): the
// risk service connects to engine-gate over mutual TLS, each side pinning
// the other's certificate by SHA-256. Both certificates are self-signed
// ECDSA P-256; no CA is involved.
//
//	risk/engine-client/tls.crt, tls.key   the risk service's client certificate   FAIR_ENGINE_CLIENT_DIR
//	risk/engine-client/gate.sha256        pins of the gate's certificates
//	engine-gate/tls/tls.crt, tls.key      the gate's server certificate           FAIR_ENGINE_GATE_TLS_DIR
//	engine-gate/tls/client.sha256         pins of the risk service's certificates
//
// A pin file holds one lowercase hex SHA-256 of a certificate's DER per
// line. Rotation (-kind engine) replaces both certificates and keeps the
// previous pins next to the new ones, so the gate and the risk service can
// be rolled out in either order.
const (
	EngineGate      = "engine-gate" // F-005 T-10
	EngineClientDir = "engine-client"
	TLSDir          = "tls"
	CertFile        = "tls.crt"
	KeyFile         = "tls.key"
	ClientPins      = "client.sha256"
	GatePins        = "gate.sha256"
	KindEngine      = "engine"

	// EngineHost is the engine Service's name, in the gate's certificate.
	EngineHost = "engine.fair-platform.svc"
	// EngineCertValidity is how long an engine certificate is valid; rotate
	// before it ends (`iam keys check` fails on an expired one).
	EngineCertValidity = 397 * 24 * time.Hour
)

var pinRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Pin is the SHA-256 of a certificate's DER, as pin files hold it.
func Pin(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ReadPins reads a pin file: one SHA-256 per line; blank lines and lines
// starting with # are ignored. An empty file is an error.
func ReadPins(file string) ([]string, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied key file
	if err != nil {
		return nil, err
	}
	var pins []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if !pinRE.MatchString(l) {
			return nil, fmt.Errorf("%s: %q is not a SHA-256 pin", file, l)
		}
		pins = append(pins, l)
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("%s: no pins", file)
	}
	return pins, nil
}

// ReadCertificate reads a PEM certificate file.
func ReadCertificate(file string) (*x509.Certificate, error) {
	blk, err := readPEM(file)
	if err != nil {
		return nil, err
	}
	if blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: want a CERTIFICATE, found %s", file, blk.Type)
	}
	return x509.ParseCertificate(blk.Bytes)
}

type engineCert struct {
	der []byte
	key *ecdsa.PrivateKey
}

func newEngineCert(cn string, server bool, now time.Time) (engineCert, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return engineCert{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return engineCert{}, err
	}
	t := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"FAIR Risk Platform"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(EngineCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if server {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		t.DNSNames = []string{EngineHost, "engine"}
	} else {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if err != nil {
		return engineCert{}, err
	}
	return engineCert{der, k}, nil
}

// writeEngine writes both sides' certificates and pins; previous pins are
// kept after the new ones.
func writeEngine(w *writer, dir string, now time.Time, prevClient, prevGate []string) {
	client, err := newEngineCert("fair-risk engine client", false, now)
	if err != nil {
		w.err = errors.Join(w.err, err)
		return
	}
	gate, err := newEngineCert(EngineHost, true, now)
	if err != nil {
		w.err = errors.Join(w.err, err)
		return
	}
	pins := func(cur string, prev []string) []byte {
		out := []string{cur}
		for _, p := range prev {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
		return []byte(strings.Join(out, "\n") + "\n")
	}
	cdir, gdir := filepath.Join(dir, Risk, EngineClientDir), filepath.Join(dir, EngineGate, TLSDir)
	// The pins first: if writing stops half way, each side still accepts
	// the other's certificate, old or new.
	w.file(filepath.Join(gdir, ClientPins), pins(Pin(client.der), prevClient))
	w.file(filepath.Join(cdir, GatePins), pins(Pin(gate.der), prevGate))
	w.file(filepath.Join(cdir, CertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: client.der}))
	w.private(filepath.Join(cdir, KeyFile), client.key)
	w.file(filepath.Join(gdir, CertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gate.der}))
	w.private(filepath.Join(gdir, KeyFile), gate.key)
}

// rotateEngine replaces both certificates, keeping the current pins as the
// previous ones (and dropping older ones).
func rotateEngine(dir string, now time.Time) (string, error) {
	cur := func(file string) ([]string, error) {
		c, err := ReadCertificate(file)
		if err != nil {
			return nil, err
		}
		return []string{Pin(c.Raw)}, nil
	}
	prevClient, err := cur(filepath.Join(dir, Risk, EngineClientDir, CertFile))
	if err != nil {
		return "", err
	}
	prevGate, err := cur(filepath.Join(dir, EngineGate, TLSDir, CertFile))
	if err != nil {
		return "", err
	}
	w := &writer{overwrite: true}
	writeEngine(w, dir, now, prevClient, prevGate)
	return kid("engine", now), w.err
}

// checkEngine checks the engine channel's keys: each side's certificate
// matches its key, is valid now, and is pinned by the other side.
func checkEngine(dir string, now time.Time) error {
	var errs []error
	side := func(sub string, server bool) *x509.Certificate {
		c, err := ReadCertificate(filepath.Join(sub, CertFile))
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		keys, err := privateKeyFile(filepath.Join(sub, KeyFile))
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&keys.PublicKey) {
			errs = append(errs, fmt.Errorf("%s: the certificate is not the key's", sub))
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			errs = append(errs, fmt.Errorf("%s: the certificate is valid %s to %s; rotate with -kind engine", sub, c.NotBefore.Format(time.DateOnly), c.NotAfter.Format(time.DateOnly)))
		}
		want := x509.ExtKeyUsageClientAuth
		if server {
			want = x509.ExtKeyUsageServerAuth
		}
		if !slices.Contains(c.ExtKeyUsage, want) {
			errs = append(errs, fmt.Errorf("%s: the certificate lacks its extended key usage", sub))
		}
		return c
	}
	cdir, gdir := filepath.Join(dir, Risk, EngineClientDir), filepath.Join(dir, EngineGate, TLSDir)
	client, gate := side(cdir, false), side(gdir, true)
	pinned := func(pinsFile string, c *x509.Certificate, what string) {
		pins, err := ReadPins(pinsFile)
		if err != nil {
			errs = append(errs, err)
			return
		}
		if c != nil && !slices.Contains(pins, Pin(c.Raw)) {
			errs = append(errs, fmt.Errorf("%s does not pin %s: the channel would be refused", pinsFile, what))
		}
	}
	pinned(filepath.Join(gdir, ClientPins), client, "the risk service's certificate")
	pinned(filepath.Join(cdir, GatePins), gate, "the gate's certificate")
	return errors.Join(errs...)
}

func privateKeyFile(file string) (*ecdsa.PrivateKey, error) {
	blk, err := readPEM(file)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: want an ECDSA P-256 key", file)
	}
	return ek, nil
}
