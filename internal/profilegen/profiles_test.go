package profilegen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/oscal"
)

const profilesDir = "../../profiles"

func generated(t *testing.T) map[string][]byte {
	t.Helper()
	files, err := InRepoProfiles(pinDir, profilesDir)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// The committed profiles are exactly what the generator produces from the
// pinned sources; regenerate with `go run ./cmd/profilegen profiles`.
func TestInRepoProfilesUpToDate(t *testing.T) {
	for name, want := range generated(t) {
		got, err := os.ReadFile(filepath.Join(profilesDir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("profiles/%s is stale; run go run ./cmd/profilegen profiles", name)
		}
	}
}

// resolveInRepo resolves an in-repo profile through T-02's resolver.
func resolveInRepo(t *testing.T, name string) obj {
	t.Helper()
	var doc obj
	if err := json.Unmarshal(generated(t)[name], &doc); err != nil {
		t.Fatal(err)
	}
	u := "repo:profiles/" + name
	got, err := Resolve(OverlayLoader{Docs: map[string]map[string]any{u: doc}, Next: loader(t)}, u)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	if kind, err := oscal.Validate(b); err != nil || kind != oscal.Catalog {
		t.Fatalf("%s: resolved catalog does not validate: %v", name, err)
	}
	return got
}

// T-04 verification ("package builds"): both profiles resolve and validate.
// Enterprise Baseline selects exactly NIST 800-53r5 Moderate.
func TestInRepoProfilesBuild(t *testing.T) {
	ent := resolveInRepo(t, "enterprise-baseline/profile.json")
	ref, err := loader(t).Load(source(t, loader(t), "nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range conformance(ent["catalog"].(obj), ref["catalog"].(obj)) {
		t.Errorf("enterprise-baseline vs NIST Moderate: %s", d)
	}

	cmmc := resolveInRepo(t, "cmmc-l2-r2/profile.json")
	var got []string
	outline(cmmc["catalog"].(obj), "", &got)
	controls := 0
	for _, e := range got {
		if strings.Contains(e, "/control:") {
			controls++
		}
	}
	var prof obj
	_ = json.Unmarshal(generated(t)["cmmc-l2-r2/profile.json"], &prof)
	want := len(list(list(prof["profile"].(obj)["imports"])[0].(obj)["include-controls"].([]any)[0].(obj)["with-ids"]))
	if controls != want {
		t.Fatalf("resolved cmmc-l2-r2 has %d controls, profile selects %d", controls, want)
	}
}

func TestCMMCMappingCoversSettingsRequirements(t *testing.T) {
	sup, err := LoadSupplement(filepath.Join(profilesDir, "cmmc-l2-r2", "supplement.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := CMMCMapping(pinDir, sup)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]MappingRow{}
	for _, r := range rows {
		by[r.R2ID] = r
	}
	// Requirements behind F-001 settings map to the controls their bindings use.
	for r2, ctl := range map[string]string{"3.1.8": "ac-7", "3.1.10": "ac-11", "3.1.11": "ac-12", "3.5.6": "ia-4", "3.5.3": "ia-2.1"} {
		if !slices.Contains(by[r2].Controls, ctl) {
			t.Errorf("%s maps to %v, want %s among them", r2, by[r2].Controls, ctl)
		}
	}
	for _, r := range rows {
		if len(r.Controls) == 0 && r.R2ID != "3.13.14" {
			t.Errorf("%s maps to no control", r.R2ID)
		}
	}
}

// The supplement cannot drift from NIST's data unnoticed.
func TestCMMCSupplementChecked(t *testing.T) {
	load := func(t *testing.T, edit func(string) string) error {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(profilesDir, "cmmc-l2-r2", "supplement.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(t.TempDir(), "supplement.yaml")
		if err := os.WriteFile(f, []byte(edit(string(b))), 0o600); err != nil {
			t.Fatal(err)
		}
		sup, err := LoadSupplement(f)
		if err != nil {
			return err
		}
		_, err = CMMCMapping(pinDir, sup)
		return err
	}
	cases := map[string]struct {
		edit func(string) string
		want string
	}{
		"note disagrees with NIST": {func(s string) string {
			return strings.Replace(s, `rev3_note: "Recategorized as NCO."`, `rev3_note: "Something else."`, 1)
		}, "NIST's change analysis says"},
		"missing entry": {func(s string) string {
			i := strings.Index(s, `  - r2_id: "3.7.1"`)
			j := strings.Index(s, `  - r2_id: "3.13.2"`)
			return s[:i] + s[j:]
		}, "no Rev 3 successor"},
		"unneeded entry": {func(s string) string {
			return s + "  - r2_id: \"3.1.1\"\n    rev3_note: x\n    appendix_d: { table: D-1, rev4_controls: [AC-2] }\n    controls: [ac-2]\n"
		}, "is not needed"},
		"withdrawn control": {func(s string) string { return strings.Replace(s, "controls: [ma-2]", "controls: [sc-19]", 1) }, "withdrawn in 800-53r5"},
		"unknown control":   {func(s string) string { return strings.Replace(s, "controls: [ma-2]", "controls: [zz-9]", 1) }, "does not have"},
		"unused erratum":    {func(s string) string { return strings.Replace(s, `r2_id: "3.11.4"`, `r2_id: "3.11.9"`, 1) }, "erratum 3.11.9 matches no row"},
		"unknown key":       {func(s string) string { return strings.Replace(s, "errata:", "erratum_list:", 1) }, "not found"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := load(t, c.edit); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestControlID(t *testing.T) {
	for in, want := range map[string]string{"AC-02": "ac-2", "AC-02(03)": "ac-2.3", "SI-04(16)": "si-4.16", "IR 7874": ""} {
		got, _ := controlID(in)
		if got != want {
			t.Errorf("controlID(%q) = %q, want %q", in, got, want)
		}
	}
}
