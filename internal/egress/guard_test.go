package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rformer/fair-app/pkg/settings"
)

type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr // host -> answers, one per lookup
	calls   map[string]int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	as := f.answers[host]
	if len(as) == 0 {
		return nil, errors.New("no such host")
	}
	i := min(f.calls[host], len(as)-1)
	f.calls[host]++
	return as[i], nil
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, x := range s {
		out = append(out, netip.MustParseAddr(x))
	}
	return out
}

func TestHostAllowed(t *testing.T) {
	allowed := []string{"hooks.example.com", "*.corp.example", "10.1.2.3"}
	for host, want := range map[string]bool{
		"hooks.example.com": true, "HOOKS.example.com.": true, "x.hooks.example.com": false, "example.com": false,
		"a.corp.example": true, "a.b.corp.example": true, "corp.example": false, "evilcorp.example": false, "xcorp.example": false,
		"10.1.2.3": true, "10.1.2.4": false, "": false,
	} {
		if got := HostAllowed(allowed, host); got != want {
			t.Errorf("%q: %v", host, got)
		}
	}
	if HostAllowed(nil, "hooks.example.com") || HostAllowed([]string{}, "a") {
		t.Error("the empty set allowed a host")
	}
	if !HostAllowed([]string{settings.SetAll}, "anything.example") {
		t.Error("* allows any host")
	}
	for _, ok := range []string{"hooks.example.com", "*.corp.example", "*", "10.1.2.3", "fd00::1"} {
		if err := CheckHostPattern(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "*.", "a*.b", "https://x", "x:443", "a..b", "-a.b", "u@h", "a b", "*.*.b"} {
		if err := CheckHostPattern(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckAddr(t *testing.T) {
	g := Guard{Cluster: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")}}
	for _, bad := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255",
		"10.96.0.10", "100.64.1.1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"} {
		if err := g.CheckAddr(netip.MustParseAddr(bad)); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	for _, ok := range []string{"203.0.113.10", "10.1.2.3", "192.168.1.5", "2001:db8::1", "fd00::5"} {
		if err := g.CheckAddr(netip.MustParseAddr(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	// Air-gapped: private only.
	ag := Guard{AirGapped: true}
	for addr, want := range map[string]bool{"10.1.2.3": true, "172.16.0.1": true, "192.168.0.1": true, "fd00::1": true, "203.0.113.10": false, "2001:db8::1": false} {
		if got := ag.CheckAddr(netip.MustParseAddr(addr)) == nil; got != want {
			t.Errorf("air-gapped %s: %v", addr, got)
		}
	}
}

func TestResolve(t *testing.T) {
	r := &fakeResolver{answers: map[string][][]netip.Addr{
		"hooks.example.com": {addrs("203.0.113.10")},
		"mixed.example.com": {addrs("203.0.113.11", "127.0.0.1")},
		"meta.example.com":  {addrs("169.254.169.254")},
	}}
	g := Guard{Resolver: r, Allowed: func() []string { return []string{"*.example.com", "127.0.0.1"} }}
	if a, err := g.Resolve(context.Background(), "hooks.example.com"); err != nil || len(a) != 1 {
		t.Errorf("allowed: %v %v", a, err)
	}
	for _, h := range []string{"mixed.example.com", "meta.example.com", "127.0.0.1", "other.org"} {
		if _, err := g.Resolve(context.Background(), h); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", h, err)
		}
	}
	if _, err := g.Resolve(context.Background(), "missing.example.com"); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("an unknown host: %v", err)
	}
}

// The connection goes to the address checked: a second lookup that would
// answer otherwise (DNS rebinding) is never made.
func TestDialChecksAndPins(t *testing.T) {
	good, bad := listener(t), listener(t)
	gp, bp := netip.MustParseAddrPort(good.Addr().String()), netip.MustParseAddrPort(bad.Addr().String())
	if gp.Port() == bp.Port() {
		t.Skip("same port")
	}
	r := &fakeResolver{answers: map[string][][]netip.Addr{"hooks.example.com": {addrs("127.0.0.1"), addrs("127.0.0.2")}}}
	g := Guard{Resolver: r, Allowed: func() []string { return []string{"hooks.example.com"} },
		allowForTest: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	c, err := g.DialContext(context.Background(), "tcp", net.JoinHostPort("hooks.example.com", itoa(int(gp.Port()))))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if r.calls["hooks.example.com"] != 1 {
		t.Errorf("%d lookups", r.calls["hooks.example.com"])
	}
	// The next lookup answers 127.0.0.2, which the rules refuse.
	if _, err := g.DialContext(context.Background(), "tcp", net.JoinHostPort("hooks.example.com", itoa(int(gp.Port())))); !errors.Is(err, ErrRefused) {
		t.Errorf("a rebound name: %v", err)
	}
	// Without the test allowance, loopback is refused.
	g.allowForTest = nil
	if _, err := g.DialContext(context.Background(), "tcp", good.Addr().String()); !errors.Is(err, ErrRefused) {
		t.Errorf("loopback: %v", err)
	}
}

// No redirects and no proxy from the environment.
func TestHTTPClient(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	defer target.Close()
	u, _ := url.Parse(target.URL)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	g := Guard{Allowed: func() []string { return []string{"127.0.0.1"} }, allowForTest: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	c := g.HTTPClient(target.Client().Transport.(*http.Transport).TLSClientConfig)
	if tr := c.Transport.(*http.Transport); tr.Proxy != nil || tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Fatalf("transport: proxy %v, TLS %x", tr.Proxy != nil, tr.TLSClientConfig.MinVersion)
	}
	resp, err := c.Get("https://" + u.Host + "/hook")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "elsewhere") {
		t.Errorf("redirect followed: %d", resp.StatusCode)
	}
	// A host the list does not name never gets a connection.
	g.Allowed = func() []string { return nil }
	if _, err := g.HTTPClient(nil).Get("https://" + u.Host + "/hook"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("an unlisted host: %v", err)
	}
}

func listener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l
}

func itoa(n int) string { return strconv.Itoa(n) }

// F-011 T-04: a refusal names the allow-list setting the guard checks, and
// AllowingForTest permits only the ranges given (in a test binary).
func TestRefusalNamesTheSetting(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct{ setting, want string }{
		{"integration.allowed_hosts", "not in integration.allowed_hosts"},
		{"", "not in the allow-list"},
	} {
		_, err := Guard{Setting: c.setting}.Resolve(ctx, "cmdb.example.com")
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("setting %q: %v", c.setting, err)
		}
	}
	g := Guard{Allowed: func() []string { return []string{"127.0.0.1", "127.0.0.2"} }}.AllowingForTest(netip.MustParsePrefix("127.0.0.1/32"))
	if _, err := g.Resolve(ctx, "127.0.0.1"); err != nil {
		t.Errorf("the permitted range: %v", err)
	}
	if _, err := g.Resolve(ctx, "127.0.0.2"); !errors.Is(err, ErrRefused) {
		t.Errorf("another loopback address: %v", err)
	}
}
