package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/settings"
)

// Package egress is the destination guard (F-009 T-08, F-009-AC-10, design
// §3.4; moved here by F-011 T-04 so that F-011's connectors share it): every
// outbound destination (F-009's email and webhooks, F-011's connector
// sources) passes it, at configuration and at every connection:
//   - the host must match the allow-list setting (notification.allowed_hosts,
//     integration.allowed_hosts): a name (any case), a
//     "*.suffix" (any name ending in .suffix, not suffix itself), or "*" (any
//     host); the empty set allows nothing;
//   - the host is resolved once, and refused if any of its addresses is
//     loopback, link-local, unspecified, multicast, broadcast or in the
//     cluster's ranges, or, in air-gapped mode, not private (RFC 1918,
//     RFC 4193);
//   - the connection goes to the checked address itself (no second lookup:
//     DNS rebinding cannot swap it), with a timeout; HTTP clients follow no
//     redirects and use no proxy from the environment.

// ErrRefused is a destination the guard refuses.
var ErrRefused = errors.New("egress: destination refused")

// Timeout bounds a connection and each exchange (design §3.4).
const Timeout = 10 * time.Second

// Resolver looks up a host's addresses (net.Resolver does).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Guard checks and dials destinations.
type Guard struct {
	Allowed   func() []string // the allow-list setting, as in force
	Setting   string          // its key, for refusals (default "the allow-list")
	Cluster   []netip.Prefix  // the cluster's ranges: never a destination
	AirGapped bool            // FAIR_DEPLOYMENT_MODE=air-gapped: private addresses only
	Resolver  Resolver        // default net.DefaultResolver

	allowForTest []netip.Prefix // tests only: ranges permitted despite the rules
}

// AllowingForTest is g permitting the given ranges (loopback test servers)
// despite the rules. It works only in a test binary: anywhere else it
// panics, so no service can loosen the guard this way.
func (g Guard) AllowingForTest(p ...netip.Prefix) Guard {
	if !testing.Testing() {
		panic("egress: AllowingForTest outside a test binary")
	}
	g.allowForTest = append(append([]netip.Prefix(nil), g.allowForTest...), p...)
	return g
}

// HostAllowed reports whether host matches the allow-list.
func HostAllowed(allowed []string, host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" {
		return false
	}
	for _, a := range allowed {
		a = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
		switch {
		case a == settings.SetAll:
			return true
		case strings.HasPrefix(a, "*."):
			if suffix := a[1:]; len(h) > len(suffix) && strings.HasSuffix(h, suffix) {
				return true
			}
		case a != "" && a == h:
			return true
		}
	}
	return false
}

// CheckHostPattern refuses an allow-list entry that is not a host name, a
// "*.suffix", "*" or an IP address (design §4).
func CheckHostPattern(p string) error {
	if p == settings.SetAll {
		return nil
	}
	if _, err := netip.ParseAddr(p); err == nil {
		return nil
	}
	name := strings.TrimPrefix(p, "*.")
	if name == "" || len(name) > 253 || strings.ContainsAny(name, "*/:@ ") {
		return fmt.Errorf("egress: %q is not a host name, *.suffix or *", p)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("egress: %q is not a host name, *.suffix or *", p)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("egress: %q is not a host name, *.suffix or *", p)
			}
		}
	}
	return nil
}

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

var alwaysRefused = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space: carrier and cloud internals
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64: would reach IPv4 addresses unchecked
}

// CheckAddr refuses an address no connection may go to.
func (g Guard) CheckAddr(a netip.Addr) error {
	a = a.Unmap()
	for _, p := range g.allowForTest {
		if p.Contains(a) {
			return nil
		}
	}
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast(), a.IsMulticast():
		return fmt.Errorf("%w: %s is a loopback, link-local, unspecified or multicast address", ErrRefused, a)
	}
	for _, p := range alwaysRefused {
		if p.Contains(a) {
			return fmt.Errorf("%w: %s is in %s", ErrRefused, a, p)
		}
	}
	for _, p := range g.Cluster {
		if p.Contains(a) {
			return fmt.Errorf("%w: %s is in the cluster's range %s", ErrRefused, a, p)
		}
	}
	if g.AirGapped {
		for _, p := range privateRanges {
			if p.Contains(a) {
				return nil
			}
		}
		return fmt.Errorf("%w: %s is outside the enclave's private ranges (air-gapped)", ErrRefused, a)
	}
	return nil
}

// Resolve checks host against the allow-list and resolves it, refusing it
// if any address is refused; it answers the addresses to dial.
func (g Guard) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	var allowed []string
	if g.Allowed != nil {
		allowed = g.Allowed()
	}
	if !HostAllowed(allowed, host) {
		setting := g.Setting
		if setting == "" {
			setting = "the allow-list"
		}
		return nil, fmt.Errorf("%w: %s is not in %s", ErrRefused, host, setting)
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if err := g.CheckAddr(a); err != nil {
			return nil, err
		}
		return []netip.Addr{a.Unmap()}, nil
	}
	r := g.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("egress: resolving %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("egress: %s has no address", host)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if err := g.CheckAddr(a); err != nil {
			return nil, fmt.Errorf("%s: %w", host, err) // any refused address refuses the host
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

// DialContext connects to addr ("host:port") through the guard: to a
// checked address, never a second lookup.
func (g Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := g.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: Timeout}
	var last error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, network, netip.AddrPortFrom(a, 0).Addr().String()+":"+port)
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// HTTPClient is the client webhooks are sent and sources fetched with: through the guard, TLS
// 1.2 or later with verified certificates (roots: the system's, or
// tlsConfig's), no proxy, no redirects, bounded time.
func (g Guard) HTTPClient(tlsConfig *tls.Config) *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if tlsConfig != nil {
		tc = tlsConfig.Clone()
		if tc.MinVersion < tls.VersionTLS12 {
			tc.MinVersion = tls.VersionTLS12
		}
	}
	return &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			Proxy:                  nil, // never the environment's proxy
			DialContext:            g.DialContext,
			TLSClientConfig:        tc,
			TLSHandshakeTimeout:    Timeout,
			ResponseHeaderTimeout:  Timeout,
			MaxResponseHeaderBytes: 16 << 10,
			DisableKeepAlives:      true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
