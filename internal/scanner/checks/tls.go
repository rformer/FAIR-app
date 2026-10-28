package checks

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

// 3. Every platform Service port and ingress endpoint speaks TLS 1.2 or
// later, refuses TLS 1.0/1.1 and non-approved cipher suites, and presents a
// certificate valid for more than 30 days. The legacy-version and cipher
// probes send hand-built ClientHellos and read only the ServerHello, so
// they need no cryptography: the scanner's FIPS-mode TLS stack could not
// offer those versions or suites itself.
func tlsEndpoints(cfg Config) check {
	c := check{Meta: Meta{ID: "tls_endpoints", Title: "Platform endpoints use TLS 1.2+, approved suites and current certificates",
		Controls:    []string{"SC-8", "SC-13", "SC-23"},
		Remediation: "Serve the endpoint with the platform TLS settings (TLS 1.2 minimum, ECDHE AES-GCM suites) and renew its certificate."}}
	c.run = func(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]scanner.Finding, error) {
		objs, err := listAll(ctx, r, kube.Services, s)
		if err != nil {
			return nil, err
		}
		type service struct {
			Metadata meta `json:"metadata"`
			Spec     struct {
				Type  string `json:"type"`
				Ports []struct {
					Port     int    `json:"port"`
					Protocol string `json:"protocol"`
				} `json:"ports"`
			} `json:"spec"`
		}
		svcs, err := decode[service](objs)
		if err != nil {
			return nil, err
		}
		endpoints := map[string]string{} // address -> SNI host
		for _, sv := range svcs {
			if sv.Spec.Type == "ExternalName" {
				continue
			}
			host := sv.Metadata.Name + "." + sv.Metadata.Namespace + ".svc"
			for _, p := range sv.Spec.Ports {
				if p.Protocol == "" || p.Protocol == "TCP" {
					endpoints[net.JoinHostPort(host, fmt.Sprint(p.Port))] = host
				}
			}
		}
		for _, e := range cfg.IngressEndpoints {
			if h, _, err := net.SplitHostPort(e); err == nil {
				endpoints[e] = h
			}
		}
		var out []scanner.Finding
		for _, addr := range sortedKeys(endpoints) {
			res := probeEndpoint(ctx, cfg, addr, endpoints[addr])
			if len(res.problems) == 0 {
				continue
			}
			sort.Strings(res.problems)
			detail := map[string]any{"endpoint": addr, "problems": res.problems}
			if res.version != "" {
				detail["negotiated"] = res.version + " " + res.suite
			}
			if !res.notAfter.IsZero() {
				detail["certificate_not_after"] = res.notAfter.UTC().Format(time.RFC3339)
			}
			out = append(out, c.finding(res.severity, "endpoint/"+addr, detail, ""))
		}
		return out, nil
	}
	return c
}

type probeResult struct {
	problems       []string
	severity       string
	version, suite string
	notAfter       time.Time
}

func (p *probeResult) add(severity, problem string) {
	p.problems = append(p.problems, problem)
	rank := map[string]int{"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	if rank[severity] > rank[p.severity] {
		p.severity = severity
	}
}

func probeEndpoint(ctx context.Context, cfg Config, addr, host string) probeResult {
	var res probeResult
	conn, err := cfg.dial(ctx, addr)
	if err != nil {
		res.add("low", "unreachable: "+err.Error())
		return res
	}
	var state *tls.ConnectionState
	tc := tls.Client(conn, &tls.Config{
		ServerName:         sni(host),
		InsecureSkipVerify: true, // #nosec G402 -- inspection only: version, suite and expiry are checked, nothing is sent
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			state = &cs
			return nil
		},
	})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	herr := tc.HandshakeContext(ctx)
	_ = tc.Close()
	var rh tls.RecordHeaderError
	switch {
	case errors.As(herr, &rh):
		res.add("high", "plaintext (not TLS)")
		return res
	case state == nil:
		res.add("high", "no TLS 1.2+ handshake: "+fmt.Sprint(herr))
	default: // mTLS servers may refuse the probe after this point; the state is what matters
		res.version, res.suite = tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite)
		if len(state.PeerCertificates) > 0 {
			res.notAfter = state.PeerCertificates[0].NotAfter
			switch left := res.notAfter.Sub(cfg.now()); {
			case left <= 0:
				res.add("high", "certificate expired")
			case left < 30*24*time.Hour:
				res.add("medium", fmt.Sprintf("certificate expires in %d days", int(left.Hours()/24)))
			}
		}
	}
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if ok, _ := rawAccepts(ctx, cfg, addr, host, v, legacySuites); ok {
			res.add("high", "accepts "+tls.VersionName(v))
		}
	}
	if ok, suite := rawAccepts(ctx, cfg, addr, host, tls.VersionTLS12, weakSuites); ok {
		res.add("medium", "accepts non-approved cipher suite "+suiteName(suite))
	}
	return res
}

// Suites the platform never accepts on TLS 1.2: CBC, RSA key exchange,
// 3DES, ChaCha20 (not FIPS-approved).
var weakSuites = []uint16{0xc013, 0xc014, 0xc009, 0xc00a, 0xc027, 0xc023, 0x002f, 0x0035, 0x003c, 0x009c, 0x009d,
	0x000a, 0xc012, 0xcca8, 0xcca9}

// Suites a TLS 1.0/1.1 server would choose from.
var legacySuites = []uint16{0xc013, 0xc014, 0xc009, 0xc00a, 0x002f, 0x0035, 0x000a}

func suiteName(id uint16) string {
	n := tls.CipherSuiteName(id)
	if strings.HasPrefix(n, "0x") {
		return fmt.Sprintf("0x%04X", id)
	}
	return n
}

func sni(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// rawAccepts sends a ClientHello for version offering only suites and
// reports whether the server answers with a ServerHello for that version,
// and the suite it chose.
func rawAccepts(ctx context.Context, cfg Config, addr, host string, version uint16, suites []uint16) (bool, uint16) {
	conn, err := cfg.dial(ctx, addr)
	if err != nil {
		return false, 0
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(clientHello(version, suites, sni(host))); err != nil {
		return false, 0
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 0x16 { // anything but a handshake record (alert, HTTP, ...)
		return false, 0
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n < 4+2+32+1 || n > 1<<14 {
		return false, 0
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil || body[0] != 0x02 { // ServerHello
		return false, 0
	}
	h := body[4:]
	if binary.BigEndian.Uint16(h[0:2]) != version {
		return false, 0
	}
	sid := int(h[34])
	if len(h) < 35+sid+2 {
		return false, 0
	}
	return true, binary.BigEndian.Uint16(h[35+sid : 37+sid])
}

// clientHello builds a minimal ClientHello record. Without the
// supported_versions extension it cannot negotiate TLS 1.3, so the server
// must answer with version or refuse.
func clientHello(version uint16, suites []uint16, serverName string) []byte {
	u16 := func(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) } // #nosec G115 -- small, bounded lengths
	var ext []byte
	if serverName != "" {
		name := []byte(serverName)
		ext = u16(ext, 0x0000)
		ext = u16(ext, len(name)+5)
		ext = u16(ext, len(name)+3)
		ext = append(ext, 0)
		ext = u16(ext, len(name))
		ext = append(ext, name...)
	}
	ext = append(ext, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18) // supported_groups
	ext = append(ext, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)                                     // ec_point_formats
	if version == tls.VersionTLS12 {
		algs := []byte{0x04, 0x03, 0x05, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01}
		ext = u16(ext, 0x000d)
		ext = u16(ext, len(algs)+2)
		ext = u16(ext, len(algs))
		ext = append(ext, algs...)
	}
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	var hello []byte
	hello = u16(hello, int(version))
	hello = append(hello, random...)
	hello = append(hello, 0) // no session id
	hello = u16(hello, 2*len(suites))
	for _, s := range suites {
		hello = u16(hello, int(s))
	}
	hello = append(hello, 1, 0) // null compression
	hello = u16(hello, len(ext))
	hello = append(hello, ext...)
	hs := append([]byte{0x01, 0, 0, 0}, hello...)
	hs[1], hs[2], hs[3] = byte(len(hello)>>16), byte(len(hello)>>8), byte(len(hello)) // #nosec G115 -- 24-bit length, by design
	rec := []byte{0x16, 0x03, 0x01}
	rec = u16(rec, len(hs))
	return append(rec, hs...)
}
