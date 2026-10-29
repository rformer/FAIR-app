package gateway

import (
	"compress/gzip"
	"context"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// Only a trusted proxy's header is believed; in X-Forwarded-For the client
// is the right-most address that is not a trusted proxy, so addresses a
// client prepends itself are ignored.
func TestClientIP(t *testing.T) {
	ingress := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	xff := Network{Header: "X-Forwarded-For", Trusted: ingress}
	xri := Network{Header: "X-Real-IP", Trusted: ingress}
	for _, tc := range []struct {
		name, remote, header string
		n                    Network
		want                 string
	}{
		{"no header configured", "198.51.100.1:443", "203.0.113.7", Network{}, "198.51.100.1"},
		{"header from an untrusted hop", "198.51.100.1:443", "203.0.113.7", xff, "198.51.100.1"},
		{"from the ingress", "10.1.2.3:443", "203.0.113.7", xff, "203.0.113.7"},
		{"a spoofed left-most entry", "10.1.2.3:443", "192.0.2.66, 203.0.113.7", xff, "203.0.113.7"},
		{"through two trusted hops", "10.1.2.3:443", "203.0.113.7, 10.9.9.9", xff, "203.0.113.7"},
		{"only trusted hops", "10.1.2.3:443", "10.9.9.9", xff, "10.9.9.9"},
		{"garbage stops at the last vouched hop", "10.1.2.3:443", "203.0.113.7, nonsense", xff, "10.1.2.3"},
		{"no header from the ingress", "10.1.2.3:443", "", xff, "10.1.2.3"},
		{"IPv6 client", "[fd00::1]:443", "2001:db8::42", xff, "2001:db8::42"},
		{"IPv4-mapped", "[::ffff:10.1.2.3]:443", "::ffff:203.0.113.7", xff, "203.0.113.7"},
		{"X-Real-IP from the ingress", "10.1.2.3:443", "203.0.113.7", xri, "203.0.113.7"},
		{"X-Real-IP spoofed", "198.51.100.1:443", "203.0.113.7", xri, "198.51.100.1"},
		{"X-Real-IP garbage", "10.1.2.3:443", "x", xri, "10.1.2.3"},
	} {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.header != "" {
			h := tc.n.Header
			if h == "" {
				h = "X-Forwarded-For"
			}
			r.Header.Set(h, tc.header)
		}
		if got := tc.n.ClientIP(r); got.String() != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func writeTSV(t *testing.T, dir, name, body string, gz bool) {
	t.Helper()
	p := filepath.Join(dir, name)
	if !gz {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	f, err := os.Create(p + ".gz") // #nosec G304 -- a test temp directory
	if err != nil {
		t.Fatal(err)
	}
	w := gzip.NewWriter(f)
	_, _ = w.Write([]byte(body))
	_ = w.Close()
	_ = f.Close()
}

func TestSameNetworkAndASN(t *testing.T) {
	dir := t.TempDir()
	writeTSV(t, dir, "ip2asn-v4.tsv", "203.0.113.0\t203.0.113.127\t64500\tUS\tEXAMPLE-A\n"+
		"203.0.113.128\t203.0.113.255\t64501\tUS\tEXAMPLE-B\n198.51.100.0\t198.51.100.255\t0\tNone\tNot routed\n", false)
	writeTSV(t, dir, "ip2asn-v6.tsv", "2001:db8::\t2001:db8:0:ffff:ffff:ffff:ffff:ffff\t64510\tUS\tEXAMPLE-6\n", true)
	db, err := LoadASNDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]int{"203.0.113.0": 64500, "203.0.113.127": 64500, "203.0.113.128": 64501, "2001:db8::5": 64510,
		"198.51.100.4": 0, "192.0.2.1": 0, "2001:db9::": 0, "::ffff:203.0.113.200": 64501} {
		got, ok := db.Lookup(addr(ip))
		if got != want || ok != (want != 0) {
			t.Errorf("ASN of %s: %d %t, want %d", ip, got, ok, want)
		}
	}

	prefixOnly := Network{}
	withASN := Network{ASN: db}
	wide := Network{V4Bits: 16, V6Bits: 48}
	for _, tc := range []struct {
		name          string
		n             Network
		recorded, now string
		want          bool
	}{
		{"same address", prefixOnly, "203.0.113.7", "203.0.113.7", true},
		{"same /24", prefixOnly, "203.0.113.7", "203.0.113.200", true},
		{"another /24", prefixOnly, "203.0.113.7", "203.0.114.7", false},
		{"same /64", prefixOnly, "2001:db8::1", "2001:db8::ffff:1", true},
		{"another /64", prefixOnly, "2001:db8::1", "2001:db8:0:1::1", false},
		{"IPv4 to IPv6", prefixOnly, "203.0.113.7", "2001:db8::1", false},
		{"IPv4-mapped is IPv4", prefixOnly, "203.0.113.7", "::ffff:203.0.113.9", true},
		{"same /24, another ASN", withASN, "203.0.113.7", "203.0.113.200", false},
		{"same /24, same ASN", withASN, "203.0.113.7", "203.0.113.100", true},
		{"neither has an ASN", withASN, "192.0.2.1", "192.0.2.9", true},
		{"wider prefixes", wide, "203.0.113.7", "203.0.200.7", true},
		{"wider prefixes, outside", wide, "203.0.113.7", "203.1.113.7", false},
	} {
		if got := tc.n.SameNetwork(addr(tc.recorded), addr(tc.now)); got != tc.want {
			t.Errorf("%s: %t, want %t", tc.name, got, tc.want)
		}
	}

	bad := map[string]string{
		"overlap":    "1.0.0.0\t1.0.0.255\t1\tUS\ta\n1.0.0.128\t1.0.1.0\t2\tUS\tb\n",
		"short line": "1.0.0.0\t1.0.0.255\n",
		"bad asn":    "1.0.0.0\t1.0.0.255\tAS1\tUS\ta\n",
		"reversed":   "1.0.0.9\t1.0.0.1\t1\tUS\ta\n",
		"mixed":      "1.0.0.0\t2001:db8::\t1\tUS\ta\n",
	}
	for name, body := range bad {
		d := t.TempDir()
		writeTSV(t, d, "ip2asn-v4.tsv", body, false)
		if _, err := LoadASNDB(d); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := LoadASNDB(t.TempDir()); err == nil || !strings.Contains(err.Error(), "no ip2asn") {
		t.Errorf("empty directory: %v", err)
	}
}
