package profilegen

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/settings"
)

// Checklist is profiles/release-checklist.yaml: the release checklist items
// that need a recorded human confirmation (F-015 T-07; design §4.2, D-OQ1).
type Checklist struct {
	CMMC CMMCConfirmation `yaml:"cmmc"`
}

// CMMCConfirmation records which NIST SP 800-171 revision the CMMC rule
// requires, as confirmed against the eCFR. The release gate re-checks it
// online: any amendment to the part after PartAmended, or rule text that no
// longer reads Text, blocks the release until a person re-confirms.
type CMMCConfirmation struct {
	Revision    string `yaml:"revision"`     // "2": package cmmc-l2-r2 must exist
	Title       string `yaml:"title"`        // CFR title, "32"
	Part        string `yaml:"part"`         // "170"
	Section     string `yaml:"section"`      // "170.14"
	Citation    string `yaml:"citation"`     // "32 CFR 170.14(c)(3)"
	Text        string `yaml:"text"`         // the rule text that names the revision
	PartAmended string `yaml:"part_amended"` // the part's latest eCFR amendment date when confirmed
	ConfirmedBy string `yaml:"confirmed_by"`
	ConfirmedOn string `yaml:"confirmed_on"`
}

// LoadChecklist reads the checklist strictly.
func LoadChecklist(file string) (Checklist, error) {
	var c Checklist
	b, err := os.ReadFile(file) // #nosec G304 -- build-time input
	if err != nil {
		return c, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("release-checklist.yaml: %w", err)
	}
	return c, nil
}

// CMMCPackageID is the package a CMMC Level 2 revision ships as (§4.2).
func CMMCPackageID(revision string) string { return "cmmc-l2-r" + revision }

// Check is one release checklist result.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// Report is the release checklist outcome, kept as release evidence.
type Report struct {
	Checks []Check
	Pins   []profilepkg.Source
}

// Failed reports whether any check failed.
func (r *Report) Failed() bool {
	return slices.ContainsFunc(r.Checks, func(c Check) bool { return !c.OK })
}

func (r *Report) add(name string, err error, ok string) {
	if err != nil {
		r.Checks = append(r.Checks, Check{Name: name, Detail: err.Error()})
		return
	}
	r.Checks = append(r.Checks, Check{Name: name, OK: true, Detail: ok})
}

// Markdown renders the report.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Profile release checklist (F-015 T-07)\n\n| Check | Result | Detail |\n|---|---|---|\n")
	for _, c := range r.Checks {
		res := "PASS"
		if !c.OK {
			res = "**FAIL**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", c.Name, res, strings.ReplaceAll(c.Detail, "|", `\|`))
	}
	b.WriteString("\n## Pinned OSCAL sources\n\n| File | Source | SHA-256 |\n|---|---|---|\n")
	for _, p := range r.Pins {
		fmt.Fprintf(&b, "| %s | %s | `%s` |\n", p.Path, p.URL, p.SHA256)
	}
	return b.String()
}

// ReleaseInputs names what the checklist reads.
type ReleaseInputs struct {
	PinDir, ProfilesDir, BindingsDir, PackagesDir string
	ChecklistFile                                 string // profiles/release-checklist.yaml
	Defs                                          []settings.Def
}

// ReleaseCheck runs the release checklist. The offline checks always run:
// every OSCAL source matches its pinned digest, the committed profiles and
// packages are exactly what the pins and bindings produce, and the confirmed
// CMMC revision has a package. With ecfr set (the release pipeline), the CMMC
// confirmation is re-checked against the current eCFR. It returns an error
// only when the checklist itself cannot be read; failed checks are in the
// report.
func ReleaseCheck(ctx context.Context, in ReleaseInputs, ecfr *ECFR, now time.Time) (*Report, error) {
	r := &Report{}
	cl, err := LoadChecklist(in.ChecklistFile)
	if err != nil {
		return nil, err
	}

	pins, err := verifyPins(in.PinDir)
	r.Pins = pins
	r.add("OSCAL sources match their pinned SHA-256", err, fmt.Sprintf("%d files", len(pins)))

	r.add("In-repo OSCAL profiles are generated from the pins", checkInRepoProfiles(in.PinDir, in.ProfilesDir), "profiles/** current")

	digests, err := checkPackages(in)
	r.add("Profile packages rebuild byte for byte and match their manifest", err, digests)

	r.add("CMMC confirmation is complete", cl.CMMC.validate(now), fmt.Sprintf("%s: NIST SP 800-171 Rev %s, confirmed by %s on %s", cl.CMMC.Citation, cl.CMMC.Revision, cl.CMMC.ConfirmedBy, cl.CMMC.ConfirmedOn))

	specs, err := LoadPackageSpecs(filepath.Join(in.ProfilesDir, "packages.yaml"))
	if err == nil && !slices.ContainsFunc(specs, func(s PackageSpec) bool { return s.ID == CMMCPackageID(cl.CMMC.Revision) }) {
		err = fmt.Errorf("the CMMC rule requires 800-171 Rev %s, but packages.yaml has no %s package", cl.CMMC.Revision, CMMCPackageID(cl.CMMC.Revision))
	}
	r.add("A package exists for the CMMC rule's 800-171 revision", err, CMMCPackageID(cl.CMMC.Revision))

	if ecfr == nil {
		r.Checks = append(r.Checks, Check{Name: "CMMC rule re-checked against the eCFR", OK: true, Detail: "skipped (offline run; the release pipeline runs it with -online)"})
	} else {
		detail, err := ecfr.confirm(ctx, cl.CMMC)
		r.add("CMMC rule re-checked against the eCFR", err, detail)
	}
	return r, nil
}

func (c CMMCConfirmation) validate(now time.Time) error {
	for name, v := range map[string]string{"revision": c.Revision, "title": c.Title, "part": c.Part, "section": c.Section,
		"citation": c.Citation, "text": c.Text, "part_amended": c.PartAmended, "confirmed_by": c.ConfirmedBy, "confirmed_on": c.ConfirmedOn} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("cmmc.%s is empty", name)
		}
	}
	if !strings.HasPrefix(c.Section, c.Part+".") {
		return fmt.Errorf("section %s is not in part %s", c.Section, c.Part)
	}
	if _, err := time.Parse(time.DateOnly, c.PartAmended); err != nil {
		return fmt.Errorf("part_amended: %w", err)
	}
	on, err := time.Parse(time.DateOnly, c.ConfirmedOn)
	if err != nil {
		return fmt.Errorf("confirmed_on: %w", err)
	}
	if on.After(now) {
		return fmt.Errorf("confirmed_on %s is in the future", c.ConfirmedOn)
	}
	return nil
}

// verifyPins checks every file in MANIFEST.json against its SHA-256.
func verifyPins(pinDir string) ([]profilepkg.Source, error) {
	b, err := os.ReadFile(filepath.Join(pinDir, "MANIFEST.json")) // #nosec G304 -- build-time input directory
	if err != nil {
		return nil, err
	}
	var m struct {
		Files []struct {
			Path   string `json:"path"`
			Source string `json:"source"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("MANIFEST.json: %w", err)
	}
	var out []profilepkg.Source
	var errs []error
	for _, f := range m.Files {
		out = append(out, profilepkg.Source{Path: f.Path, URL: f.Source, SHA256: f.SHA256})
		b, err := os.ReadFile(filepath.Join(pinDir, filepath.FromSlash(f.Path))) // #nosec G304 -- path from the pinned manifest
		if err != nil {
			errs = append(errs, err)
		} else if digest(b) != f.SHA256 {
			errs = append(errs, fmt.Errorf("%s: sha256 %s, pinned %s", f.Path, digest(b), f.SHA256))
		}
	}
	if len(m.Files) == 0 {
		errs = append(errs, errors.New("MANIFEST.json pins no files"))
	}
	return out, errors.Join(errs...)
}

func checkInRepoProfiles(pinDir, profilesDir string) error {
	files, err := InRepoProfiles(pinDir, profilesDir)
	if err != nil {
		return err
	}
	var errs []error
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(profilesDir, filepath.FromSlash(name))) // #nosec G304 -- generated file name
		if err != nil || !bytes.Equal(got, want) {
			errs = append(errs, fmt.Errorf("profiles/%s is stale; run go run ./cmd/profilegen profiles", name))
		}
	}
	return errors.Join(errs...)
}

// checkPackages rebuilds the packages and compares them with the committed
// ones, returning the pinned digests.
func checkPackages(in ReleaseInputs) (string, error) {
	mb, err := os.ReadFile(filepath.Join(in.PackagesDir, ManifestFile)) // #nosec G304 -- build-time input
	if err != nil {
		return "", err
	}
	committed, err := profilepkg.DecodeManifest(mb)
	if err != nil {
		return "", err
	}
	files, err := BuildPackages(in.PinDir, in.ProfilesDir, in.BindingsDir, in.Defs, committed)
	if err != nil {
		return "", err
	}
	var errs []error
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(in.PackagesDir, name)) // #nosec G304 -- generated file name
		if err != nil || !bytes.Equal(got, want) {
			errs = append(errs, fmt.Errorf("profiles/packages/%s is stale; run go run ./cmd/profilegen packages", name))
		}
	}
	extra, err := filepath.Glob(filepath.Join(in.PackagesDir, "profile-*.json"))
	if err != nil {
		return "", err
	}
	for _, f := range extra {
		if _, ok := files[filepath.Base(f)]; !ok {
			errs = append(errs, fmt.Errorf("profiles/packages/%s is not generated", filepath.Base(f)))
		}
	}
	var d []string
	for _, e := range committed.Packages {
		d = append(d, e.File+" "+e.SHA256[:12])
	}
	return strings.Join(d, "; "), errors.Join(errs...)
}

// ECFR reads the Electronic Code of Federal Regulations (ecfr.gov) versioner
// API.
type ECFR struct {
	Base   string // https://www.ecfr.gov
	Client *http.Client
}

// NewECFR returns a client for ecfr.gov with the platform's TLS floor.
func NewECFR() *ECFR {
	return &ECFR{
		Base: "https://www.ecfr.gov",
		Client: &http.Client{
			Timeout:   2 * time.Minute,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment},
		},
	}
}

// confirm checks that the part has not been amended since the confirmation
// and that the section still contains the confirmed text.
func (e *ECFR) confirm(ctx context.Context, c CMMCConfirmation) (string, error) {
	latest, err := e.latestAmendment(ctx, c.Title, c.Part)
	if err != nil {
		return "", err
	}
	if latest != c.PartAmended {
		return "", fmt.Errorf("%s CFR part %s was amended on %s, after the confirmation (%s); re-confirm the CMMC rule's 800-171 revision and update profiles/release-checklist.yaml", c.Title, c.Part, latest, c.PartAmended)
	}
	text, err := e.sectionText(ctx, latest, c.Title, c.Part, c.Section)
	if err != nil {
		return "", err
	}
	if !strings.Contains(normalizeText(text), normalizeText(c.Text)) {
		return "", fmt.Errorf("%s no longer reads %q; re-confirm the CMMC rule's 800-171 revision", c.Citation, c.Text)
	}
	return fmt.Sprintf("part %s last amended %s; %s still reads %q", c.Part, latest, c.Citation, c.Text), nil
}

func (e *ECFR) get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.Base+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ecfr: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("ecfr: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ecfr: %s: %s", path, resp.Status)
	}
	return b, nil
}

// latestAmendment is the most recent amendment date of any section of the
// part.
func (e *ECFR) latestAmendment(ctx context.Context, title, part string) (string, error) {
	b, err := e.get(ctx, "/api/versioner/v1/versions/title-"+title+".json", url.Values{"part": {part}})
	if err != nil {
		return "", err
	}
	var v struct {
		ContentVersions []struct {
			AmendmentDate string `json:"amendment_date"`
		} `json:"content_versions"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", fmt.Errorf("ecfr versions: %w", err)
	}
	latest := ""
	for _, c := range v.ContentVersions {
		if _, err := time.Parse(time.DateOnly, c.AmendmentDate); err != nil {
			return "", fmt.Errorf("ecfr versions: amendment date %q", c.AmendmentDate)
		}
		latest = max(latest, c.AmendmentDate)
	}
	if latest == "" {
		return "", fmt.Errorf("ecfr: no versions of %s CFR part %s", title, part)
	}
	return latest, nil
}

// sectionText is the section's text as of date, markup removed.
func (e *ECFR) sectionText(ctx context.Context, date, title, part, section string) (string, error) {
	b, err := e.get(ctx, "/api/versioner/v1/full/"+date+"/title-"+title+".xml", url.Values{"part": {part}, "section": {section}})
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("ecfr section %s: %w", section, err)
		}
		if cd, ok := tok.(xml.CharData); ok {
			sb.Write(cd)
			sb.WriteByte(' ')
		}
	}
	return sb.String(), nil
}
