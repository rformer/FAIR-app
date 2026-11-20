package vulnex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

const good = `exceptions:
  - id: CVE-2026-12345
    package: libfoo
    images: [engine]
    reason: Not reachable from the engine code paths; checked 2026-11-20.
    expires: 2027-01-15
    reviewed: 2026-11-20
  - id: GHSA-c2qf-rxjj-qqgw
    package: bar
    images: [all]
    reason: Test-only dependency, not in any shipped image layer.
    expires: 2026-12-01
    reviewed: 2026-11-01
`

// F-012 T-03 (F-012-AC-07): exceptions carry a reason and an expiry, apply
// to the images they name, and fail the scan once expired or malformed.
func TestExceptions(t *testing.T) {
	f, err := Parse([]byte(good), now)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(f.TrivyIgnore("engine")); !strings.Contains(got, "CVE-2026-12345 exp:2027-01-15\n") || !strings.Contains(got, "GHSA-c2qf-rxjj-qqgw exp:2026-12-01\n") {
		t.Errorf("engine:\n%s", got)
	}
	if got := string(f.TrivyIgnore("risk")); strings.Contains(got, "CVE-2026-12345") || !strings.Contains(got, "GHSA-c2qf-rxjj-qqgw") {
		t.Errorf("risk:\n%s", got)
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"expired":       {"expires: 2027-01-15", "expires: 2026-11-19", "expired on 2026-11-19"},
		"too long":      {"expires: 2027-01-15", "expires: 2027-03-01", "more than 90 days"},
		"no reason":     {"reason: Not reachable from the engine code paths; checked 2026-11-20.", "reason: ok", "a reason"},
		"bad id":        {"id: CVE-2026-12345", "id: something", "CVE, GHSA or GO"},
		"bad date":      {"expires: 2027-01-15", "expires: soon", "YYYY-MM-DD"},
		"unknown field": {"reviewed: 2026-11-20", "reviewed: 2026-11-20\n    owner: me", "owner"},
		"future review": {"reviewed: 2026-11-20", "reviewed: 2026-11-25", "future"},
	} {
		if _, err := Parse([]byte(strings.Replace(good, c.from, c.to, 1)), now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The repository's file is valid today.
func TestRepositoryExceptions(t *testing.T) {
	p := filepath.Join("..", "..", "security", "vuln-exceptions.yaml")
	if _, err := Load(p, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}
