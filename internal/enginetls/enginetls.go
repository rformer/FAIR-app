// Package enginetls is the TLS of the simulation engine's channel (F-005
// T-10, design §11; ADR-013): mutual TLS 1.2 or later with the platform's
// settings (FIPS 140 module), each side pinning the other's self-signed
// certificate by SHA-256 (internal/keys: engine.go). Certificates and pins
// are re-read on every handshake, so a rotation (`iam keys rotate -kind
// engine`) is picked up without a restart.
package enginetls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/rformer/fair-app/internal/keys"
	"github.com/rformer/fair-app/internal/server"
)

// ErrNotPinned refuses a peer whose certificate is not pinned.
var ErrNotPinned = errors.New("enginetls: the peer's certificate is not pinned")

// ServerConfig is engine-gate's side: its certificate from dir
// (FAIR_ENGINE_GATE_TLS_DIR), a client certificate required and accepted
// only when client.sha256 pins it.
func ServerConfig(dir string, now func() time.Time) (*tls.Config, error) {
	if _, err := load(dir); err != nil {
		return nil, err
	}
	c := server.TLSConfig()
	c.NextProtos = []string{"h2"}
	c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return load(dir) }
	// The client's chain is not built to a CA: the pin is the trust.
	c.ClientAuth = tls.RequireAnyClientCert
	c.VerifyPeerCertificate = pinned(filepath.Join(dir, keys.ClientPins), x509.ExtKeyUsageClientAuth, now)
	return c, nil
}

// ClientConfig is the risk service's side: its client certificate from dir
// (FAIR_ENGINE_CLIENT_DIR), and the gate accepted only when gate.sha256
// pins its certificate.
func ClientConfig(dir string, now func() time.Time) (*tls.Config, error) {
	if _, err := load(dir); err != nil {
		return nil, err
	}
	c := server.TLSConfig()
	c.NextProtos = []string{"h2"}
	c.ServerName = keys.EngineHost
	c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return load(dir) }
	// The gate's certificate is self-signed and pinned: chain verification
	// is replaced by the pin check below, which runs on every handshake.
	c.InsecureSkipVerify = true // #nosec G402 -- verified by VerifyPeerCertificate (SHA-256 pin, validity, usage)
	c.VerifyPeerCertificate = pinned(filepath.Join(dir, keys.GatePins), x509.ExtKeyUsageServerAuth, now)
	return c, nil
}

func load(dir string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, keys.CertFile), filepath.Join(dir, keys.KeyFile))
	if err != nil {
		return nil, fmt.Errorf("enginetls: %s: %w", dir, err)
	}
	return &cert, nil
}

// pinned checks the peer's leaf certificate: its SHA-256 is in the pin
// file, it is valid now, and it has the expected extended key usage.
func pinned(pinFile string, usage x509.ExtKeyUsage, now func() time.Time) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("enginetls: the peer presented no certificate")
		}
		pins, err := keys.ReadPins(pinFile)
		if err != nil {
			return fmt.Errorf("enginetls: %w", err)
		}
		if !slices.Contains(pins, keys.Pin(raw[0])) {
			return ErrNotPinned
		}
		c, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return fmt.Errorf("enginetls: %w", err)
		}
		if t := now(); t.Before(c.NotBefore) || t.After(c.NotAfter) {
			return fmt.Errorf("enginetls: the peer's certificate is valid %s to %s", c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
		}
		if !slices.Contains(c.ExtKeyUsage, usage) {
			return errors.New("enginetls: the peer's certificate lacks its extended key usage")
		}
		return nil
	}
}
