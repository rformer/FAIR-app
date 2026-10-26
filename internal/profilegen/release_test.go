package profilegen

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/settings"
)

const checklistFile = "../../profiles/release-checklist.yaml"

var releaseNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

// fakeECFR serves the two eCFR versioner endpoints the gate reads.
type fakeECFR struct {
	amended []string // amendment dates in part 170
	text    string   // section 170.14 text
	status  int
	got     []string // request paths
}

func (f *fakeECFR) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.got = append(f.got, r.URL.Path+"?"+r.URL.RawQuery)
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	switch {
	case r.URL.Path == "/api/versioner/v1/versions/title-32.json" && r.URL.Query().Get("part") == "170":
		var vs []string
		for _, d := range f.amended {
			vs = append(vs, fmt.Sprintf(`{"date":%q,"amendment_date":%q,"identifier":"170.x"}`, d, d))
		}
		_, _ = fmt.Fprintf(w, `{"content_versions":[%s]}`, strings.Join(vs, ","))
	case strings.HasPrefix(r.URL.Path, "/api/versioner/v1/full/") && r.URL.Query().Get("section") == "170.14":
		_, _ = fmt.Fprintf(w, `<?xml version="1.0"?><DIV8 N="170.14" TYPE="SECTION"><HEAD>§ 170.14 CMMC Model.</HEAD><P>(3) <I>CMMC Level 2 security requirements.</I> %s</P></DIV8>`, f.text)
	default:
		http.NotFound(w, r)
	}
}

func current() *fakeECFR {
	return &fakeECFR{
		amended: []string{"2024-10-15", "2024-12-16"},
		text:    "The security requirements in CMMC Level 2 are identical to the\n   requirements in NIST SP 800-171 R2.",
	}
}

func ecfrFor(t *testing.T, f *fakeECFR) *ECFR {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &ECFR{Base: srv.URL, Client: srv.Client()}
}

func releaseInputs(checklist string) ReleaseInputs {
	return ReleaseInputs{PinDir: pinDir, ProfilesDir: profilesDir, BindingsDir: bindingsDir, PackagesDir: packagesDir,
		ChecklistFile: checklist, Defs: settings.F001Defs()}
}

func failed(r *Report) []string {
	var out []string
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c.Name+": "+c.Detail)
		}
	}
	return out
}

// Verification for T-07: the committed tree passes the release gate,
// including the online CMMC re-check, and a confirmed revision without its
// package blocks the release.
func TestReleaseCheck(t *testing.T) {
	f := current()
	r, err := ReleaseCheck(context.Background(), releaseInputs(checklistFile), ecfrFor(t, f), releaseNow)
	if err != nil {
		t.Fatal(err)
	}
	if r.Failed() {
		t.Fatalf("release checklist failed: %v", failed(r))
	}
	if len(r.Pins) < 20 || len(r.Checks) != 6 {
		t.Fatalf("%d pins, %d checks", len(r.Pins), len(r.Checks))
	}
	if !strings.Contains(f.got[1], "/full/2024-12-16/title-32.xml") {
		t.Errorf("section fetched as %s, want as of the latest amendment", f.got[1])
	}
	md := r.Markdown()
	for _, want := range []string{"| CMMC rule re-checked against the eCFR | PASS |", "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline_profile.json"} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q", want)
		}
	}

	// The rule moves CMMC Level 2 to Rev 3: no cmmc-l2-r3 package yet.
	b, err := os.ReadFile(checklistFile)
	if err != nil {
		t.Fatal(err)
	}
	rev3 := filepath.Join(t.TempDir(), "release-checklist.yaml")
	if err := os.WriteFile(rev3, []byte(strings.Replace(string(b), `revision: "2"`, `revision: "3"`, 1)), 0o600); err != nil { // #nosec G703 -- test temp dir
		t.Fatal(err)
	}
	r, err = ReleaseCheck(context.Background(), releaseInputs(rev3), nil, releaseNow)
	if err != nil {
		t.Fatal(err)
	}
	if fails := failed(r); len(fails) != 1 || !strings.Contains(fails[0], "no cmmc-l2-r3 package") {
		t.Fatalf("failures %v, want only the missing cmmc-l2-r3 package", fails)
	}
}

// The online re-check fails closed: an amendment after the confirmation,
// changed rule text, or an unreachable eCFR blocks the release.
func TestECFRConfirmFailsClosed(t *testing.T) {
	cl, err := LoadChecklist(checklistFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ecfrFor(t, current()).confirm(context.Background(), cl.CMMC); err != nil {
		t.Fatalf("current rule: %v", err)
	}
	cases := map[string]struct {
		edit func(f *fakeECFR)
		want string
	}{
		"part amended since":   {func(f *fakeECFR) { f.amended = append(f.amended, "2027-01-02") }, "amended on 2027-01-02"},
		"rule moves to Rev 3":  {func(f *fakeECFR) { f.text = strings.Replace(f.text, "R2", "R3", 1) }, "no longer reads"},
		"server error":         {func(f *fakeECFR) { f.status = http.StatusServiceUnavailable }, "503"},
		"no versions":          {func(f *fakeECFR) { f.amended = nil }, "no versions"},
		"malformed amend date": {func(f *fakeECFR) { f.amended = []string{"soon"} }, "amendment date"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := current()
			c.edit(f)
			_, err := ecfrFor(t, f).confirm(context.Background(), cl.CMMC)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestChecklistValidate(t *testing.T) {
	cl, err := LoadChecklist(checklistFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.CMMC.validate(releaseNow); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(c *CMMCConfirmation){
		"no confirmer":         func(c *CMMCConfirmation) { c.ConfirmedBy = " " },
		"no text":              func(c *CMMCConfirmation) { c.Text = "" },
		"confirmed in future":  func(c *CMMCConfirmation) { c.ConfirmedOn = "2026-11-01" },
		"bad date":             func(c *CMMCConfirmation) { c.PartAmended = "Dec 2024" },
		"section outside part": func(c *CMMCConfirmation) { c.Section = "171.14" },
	}
	for name, edit := range cases {
		c := cl.CMMC
		edit(&c)
		if c.validate(releaseNow) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadChecklist(writeTemp(t, "cmmc:\n  revison: \"2\"\n")); err == nil {
		t.Error("accepted an unknown key")
	}
}

func writeTemp(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.yaml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A pinned file that no longer matches its digest fails the gate.
func TestVerifyPinsDetectsChange(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{"files":[{"path":"a.json","source":"https://example.test/a.json","sha256":%q}]}`, digest([]byte("{}\n")))
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPins(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte("{ }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPins(dir); err == nil || !strings.Contains(err.Error(), "a.json") {
		t.Fatalf("changed pin: %v", err)
	}
}
