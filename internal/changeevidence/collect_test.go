package changeevidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/changeevidence/ghreplay"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
)

const asset = "/repos/acme/fair/releases/assets/"

// release signs v0.2.0's files with sign and publishes pub as its
// cosign.pub, as release-sign.yml does.
func release(t *testing.T, rp *ghreplay.Replay, sign, pub *ecdsa.PrivateKey) {
	t.Helper()
	m, err := releasemanifest.Encode(&releasemanifest.Manifest{
		Format: releasemanifest.Format, Release: "v0.2.0",
		Images: map[string]string{"iam": "ghcr.io/acme/fair-iam@sha256:" + strings.Repeat("d", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	sbom := []byte(`{"spdxVersion":"SPDX-2.3"}`)
	sums := []byte(fmt.Sprintf("%x  release-manifest.json\n%x  sbom-iam.spdx.json\n", sha256.Sum256(m), sha256.Sum256(sbom)))
	msig, err := profilepkg.Sign(sign, m)
	if err != nil {
		t.Fatal(err)
	}
	ssig, err := profilepkg.Sign(sign, sums)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&pub.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for id, b := range map[string][]byte{
		"201": m, "202": msig, "203": sums, "204": ssig,
		"205": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	} {
		rp.Set(asset+id, http.StatusOK, b)
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func token(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte("ghp_test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func options(t *testing.T, key *ecdsa.PublicKey) Options {
	t.Helper()
	ev, err := LoadFluxEvents("testdata/flux")
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Repository: "acme/fair", FleetRepository: "acme/fleet",
		From: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		RequiredChecks: []string{"test", "lint"}, ReleaseKey: key, FluxEvents: ev,
	}
}

// collect runs Collect over the recorded API; every request must be one
// the fixture lists.
func collect(t *testing.T, o Options, rp *ghreplay.Replay) *Report {
	t.Helper()
	gh, err := NewGitHub("https://api.github.test", token(t), rp)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Collect(context.Background(), gh, o)
	if err != nil {
		t.Fatal(err)
	}
	if m := rp.Misses(); len(m) > 0 {
		t.Fatalf("requests the fixture does not list:\n%s", strings.Join(m, "\n"))
	}
	return r
}

func fixture(t *testing.T) (*ghreplay.Replay, *ecdsa.PrivateKey) {
	t.Helper()
	rp, err := ghreplay.Load("testdata/github.json")
	if err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	release(t, rp, k, k)
	return rp, k
}

func findings(r *Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Code+" "+f.Subject)
	}
	return out
}

func TestCollect(t *testing.T) {
	rp, k := fixture(t)
	r := collect(t, options(t, &k.PublicKey), rp)
	want := []string{
		"apply_not_completed apply:beta:700",
		"apply_self_approved apply:alpha:701",
		"apply_without_pull_request apply:alpha:701",
		"apply_failed apply:beta:703",
		"apply_unapproved apply:beta:703",
		"commit_without_pull_request commit:acme/fair@d100000000000000000000000000000000000000",
		"deployment_failed deployment:beta:v0.1.1:2026-11-11T09:02:00Z",
		"deployment_unapproved deployment:beta:v0.1.1:2026-11-11T09:02:00Z",
		"deployment_unsigned_release deployment:beta:v0.1.1:2026-11-11T09:02:00Z",
		"release_source_refused instance:beta",
		"self_approval pull_request:acme/fair#7",
		"check_failed pull_request:acme/fair#9",
		"check_missing pull_request:acme/fair#9",
		"no_approval pull_request:acme/fair#9",
		"stale_approval pull_request:acme/fair#11",
		"no_approval pull_request:acme/fleet#4",
		"release_job_failed release:v0.1.1",
		"release_job_missing release:v0.1.1",
		"release_key_mismatch release:v0.1.1",
		"release_sums_unsigned release:v0.1.1",
		"release_unsigned release:v0.1.1",
	}
	got := findings(r)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The pages of a list are all read (the pull requests' second page,
	// the second page of a comparison).
	if rp.Count("/repos/acme/fair/pulls?base=main&direction=desc&per_page=100&sort=updated&state=closed&page=2") != 1 {
		t.Error("the second page of pull requests was not read")
	}
	var v011, v020 *Release
	for i := range r.Releases {
		switch r.Releases[i].Tag {
		case "v0.1.1":
			v011 = &r.Releases[i]
		case "v0.2.0":
			v020 = &r.Releases[i]
		}
	}
	if v011 == nil || v020 == nil || len(r.Releases) != 2 {
		t.Fatalf("releases: %+v", r.Releases)
	}
	if v011.Commits != 3 || !slices.Equal(v011.PullRequests, []string{"acme/fair#7", "acme/fair#9"}) {
		t.Errorf("v0.1.1: %d commits, %v", v011.Commits, v011.PullRequests)
	}
	if v020.ManifestSignature != "verified" || v020.SumsSignature != "verified" || v020.ReleaseKey != "matches" ||
		v020.Run == nil || v020.Run.ID != 500 || v020.Images["iam"] == "" || v020.Previous != "v0.1.1" {
		t.Errorf("v0.2.0: %+v", v020)
	}
	for _, p := range r.PullRequests {
		switch p.ID {
		case "acme/fair#12":
			if !slices.Equal(p.Approvers, []string{"bob"}) || len(p.Checks) != 2 || p.Checks[1].Conclusion != "success" {
				t.Errorf("#12: %+v", p)
			}
		case "acme/fair#10", "acme/fair#8", "acme/fleet#1":
			t.Errorf("%s was not merged in the period", p.ID)
		}
	}
	if len(r.Deployments) != 2 || r.Deployments[0].Status != "succeeded" || r.Deployments[0].FleetPullRequest != "acme/fleet#3" ||
		r.Deployments[1].Status != "failed" || r.Deployments[1].FleetCommit == "" {
		t.Errorf("deployments: %+v", r.Deployments)
	}

	j, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.CSV()
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "testdata/report.golden.json", j)
	golden(t, "testdata/report.golden.csv", c)

	// The same evidence gives the same bytes.
	rp2, _ := fixture(t)
	release(t, rp2, k, k)
	j2, err := collect(t, options(t, &k.PublicKey), rp2).JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(j, j2) {
		t.Error("two collections of the same evidence differ")
	}
}

func TestCollectInstance(t *testing.T) {
	rp, k := fixture(t)
	o := options(t, &k.PublicKey)
	o.Instance = "alpha"
	r := collect(t, o, rp)
	got := findings(r)
	slices.Sort(got)
	want := []string{
		"apply_self_approved apply:alpha:701",
		"apply_without_pull_request apply:alpha:701",
		"stale_approval pull_request:acme/fair#11",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings: %v, want %v", got, want)
	}
	var prs []string
	for _, p := range r.PullRequests {
		prs = append(prs, p.ID)
	}
	if !slices.Equal(prs, []string{"acme/fair#11", "acme/fair#12", "acme/fleet#3"}) {
		t.Errorf("pull requests: %v", prs)
	}
	if len(r.Releases) != 1 || r.Releases[0].Tag != "v0.2.0" || len(r.Deployments) != 1 || len(r.Applies) != 2 {
		t.Errorf("releases %d, deployments %d, applies %d", len(r.Releases), len(r.Deployments), len(r.Applies))
	}
	for _, a := range r.Applies {
		if a.Instance != "alpha" {
			t.Errorf("apply of %s", a.Instance)
		}
	}
}

// A release signed with another key, or carrying another cosign.pub, is
// not the release: its deployments are findings.
func TestCollectForeignSignature(t *testing.T) {
	rp, k := fixture(t)
	other := newKey(t)
	release(t, rp, other, other)
	r := collect(t, options(t, &k.PublicKey), rp)
	for _, want := range []string{
		"release_signature_invalid release:v0.2.0",
		"release_sums_invalid release:v0.2.0",
		"release_key_mismatch release:v0.2.0",
		"deployment_unsigned_release deployment:alpha:v0.2.0:2026-11-22T10:01:00Z",
	} {
		if !slices.Contains(findings(r), want) {
			t.Errorf("missing %q in %v", want, findings(r))
		}
	}
}

func TestOptionsRefused(t *testing.T) {
	k := newKey(t)
	rp, _ := fixture(t)
	gh, err := NewGitHub("https://api.github.test", token(t), rp)
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for name, o := range map[string]Options{
		"no repository":  {ReleaseKey: &k.PublicKey, From: from, To: from.Add(time.Hour)},
		"bad repository": {Repository: "acme/fair/x", ReleaseKey: &k.PublicKey, From: from, To: from.Add(time.Hour)},
		"no release key": {Repository: "acme/fair", From: from, To: from.Add(time.Hour)},
		"empty period":   {Repository: "acme/fair", ReleaseKey: &k.PublicKey, From: from, To: from},
		"bad fleet repo": {Repository: "acme/fair", FleetRepository: "../x", ReleaseKey: &k.PublicKey, From: from, To: from.Add(time.Hour)},
	} {
		if _, err := Collect(context.Background(), gh, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGitHubClient(t *testing.T) {
	tok := token(t)
	for _, base := range []string{"http://api.github.test", "https://user@api.github.test", "https://api.github.test?x=1", "api.github.test"} {
		if _, err := NewGitHub(base, tok, nil); err == nil {
			t.Errorf("%s accepted", base)
		}
	}
	dir := t.TempDir()
	for name, content := range map[string]string{"empty": "\n", "two": "a b\n", "lines": "a\nb\n"} {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewGitHub("https://api.github.test", f, nil); err == nil {
			t.Errorf("token file %q accepted", name)
		}
	}
	if _, err := NewGitHub("https://api.github.test", "", nil); err == nil {
		t.Error("no token file accepted")
	}
	g, err := NewGitHub("https://api.github.test/", tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := g.http.(*http.Client).Transport.(*http.Transport)
	if tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Error("the client accepts TLS below 1.2")
	}
	if _, err := g.nextPage(`<https://elsewhere.test/repos/a/b/pulls?page=2>; rel="next"`); err == nil {
		t.Error("a next page on another host was followed")
	}
	if n, err := g.nextPage(`<https://api.github.test/x?page=2>; rel="next", <https://api.github.test/x?page=9>; rel="last"`); err != nil || n != "https://api.github.test/x?page=2" {
		t.Errorf("next page %q, %v", n, err)
	}
	if _, err := g.asset(context.Background(), "https://elsewhere.test/asset"); err == nil {
		t.Error("an asset on another host was fetched")
	}
}

// The token goes only in the Authorization header of requests to the API.
func TestGitHubSendsToken(t *testing.T) {
	var seen []*http.Request
	d := doerFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	})
	g, err := NewGitHub("https://api.github.test", token(t), d)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	_ = g.get(context.Background(), "/repos/a/b", nil, &v)
	if len(seen) != 1 || seen[0].Header.Get("Authorization") != "Bearer ghp_test" || seen[0].Method != http.MethodGet ||
		strings.Contains(seen[0].URL.String(), "ghp_test") {
		t.Errorf("request: %+v", seen)
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestLoadFluxEventsRefusesUnattributed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "e.json"), []byte(`{"involvedObject":{"kind":"Kustomization","name":"fair-platform"},"timestamp":"2026-11-01T00:00:00Z","metadata":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFluxEvents(dir); err == nil {
		t.Error("an event without an instance was accepted")
	}
}

func TestCSVNeutralizes(t *testing.T) {
	r := &Report{Findings: []Finding{{Code: ReleaseSourceRefused, Subject: "instance:x", Detail: "=HYPERLINK(\"x\")"}}}
	c, err := r.CSV()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(c), `'=HYPERLINK`) {
		t.Errorf("formula not neutralized:\n%s", c)
	}
}

// Every finding code is documented.
func TestCodesDocumented(t *testing.T) {
	b, err := os.ReadFile("../../docs/formats/fair-change-evidence-v1.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range Codes {
		if !bytes.Contains(b, []byte("`"+c+"`")) {
			t.Errorf("%s is not in docs/formats/fair-change-evidence-v1.md", c)
		}
	}
}

func golden(t *testing.T, file string, got []byte) {
	t.Helper()
	if os.Getenv("FAIR_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(file, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file) // #nosec G304 -- a golden file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs (FAIR_UPDATE_GOLDEN=1 rewrites it):\n%s", file, got)
	}
}
