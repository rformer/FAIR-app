package releaseverify_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
	rt "github.com/rformer/fair-app/internal/releaseverify/releasetest"
)

// T-11 (design §3.5; ADR-019): the verifier uses the standard library
// alone, and none of its network clients.
func TestNoNetwork(t *testing.T) {
	g, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to inspect the build with")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, g, "list", "-deps", "-f", "{{if .Standard}}std {{end}}{{.ImportPath}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	// crypto/x509 brings net, net/url and net/netip (address types); no
	// client or server comes with them.
	forbidden := regexp.MustCompile(`^(net/http|net/rpc|net/smtp|net/mail|crypto/tls|os/exec|plugin|log/syslog)(/|$)`)
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if pkg, ok := strings.CutPrefix(l, "std "); ok {
			n++
			if forbidden.MatchString(pkg) {
				t.Errorf("depends on %s", pkg)
			}
			continue
		}
		if l != "github.com/rformer/fair-app/internal/releaseverify" {
			t.Errorf("depends on %s, outside the standard library", l)
		}
	}
	if n == 0 {
		t.Fatal("go list listed no standard packages (the check would prove nothing)")
	}
}

// The verifier's release manifest decoding accepts and refuses exactly
// what releasemanifest.Verify (releasegen verify) does.
func TestManifestMatchesReleasemanifest(t *testing.T) {
	k := rt.NewKey(t)
	other := rt.NewKey(t)
	img := "registry.invalid/fair-x@sha256:" + strings.Repeat("a", 64)
	good := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: "v1.0.0", Images: map[string]string{"x": img}, RBAC: []releasemanifest.RBACEntry{}}
	enc, err := releasemanifest.Encode(good)
	if err != nil {
		t.Fatal(err)
	}
	engine := `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{"engine":"` + img + `"},"rbac":[]}`
	engineOK := `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{"engine":"` + img + `"},"rbac":[],"engine_validation":{"image":"` + img + `","suite_version":"1","engine_version":"1","architecture":"amd64","passed":false,"run_at_unix_ms":1,"record_sha256":"` + strings.Repeat("b", 64) + `"}}`
	mirror := func(c, image, source, id, iss string) string {
		return `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{"x":"` + img + `"},"rbac":[],"mirrors":[{"component":"` + c + `","image":"` + image +
			`","source":"` + source + `","certificate_identity":"` + id + `","certificate_oidc_issuer":"` + iss + `"}]}`
	}
	mimg := "registry.invalid/mirror/m@sha256:" + strings.Repeat("e", 64)
	msrc := "publisher.invalid/m:1.0@sha256:" + strings.Repeat("e", 64)
	mid := "https://github.com/p/m/.github/workflows/release.yml@refs/tags/v1"
	miss := "https://token.actions.githubusercontent.com"
	withMirrors := *good
	withMirrors.Mirrors = []releasemanifest.Mirror{rt.MirrorOf("m", mimg)}
	encMirrors, err := releasemanifest.Encode(&withMirrors)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"encoded":                string(enc),
		"encoded with mirrors":   string(encMirrors),
		"mirror":                 mirror("m", mimg, msrc, mid, miss),
		"mirror bad component":   mirror("M_1", mimg, msrc, mid, miss),
		"mirror image component": mirror("x", mimg, msrc, mid, miss),
		"mirror tagged":          mirror("m", "registry.invalid/mirror/m:1", msrc, mid, miss),
		"mirror other digest":    mirror("m", mimg, "publisher.invalid/m:1.0@sha256:"+strings.Repeat("f", 64), mid, miss),
		"mirror identity regex":  mirror("m", mimg, msrc, "https://github.com/p/.*", miss),
		"mirror identity http":   mirror("m", mimg, msrc, "http://github.com/p", miss),
		"mirror issuer":          mirror("m", mimg, msrc, mid, "token"),
		"mirror repeated": strings.Replace(mirror("m", mimg, msrc, mid, miss), `}]}`, `},{"component":"m","image":"`+mimg+`","source":"`+msrc+
			`","certificate_identity":"`+mid+`","certificate_oidc_issuer":"`+miss+`"}]}`, 1),
		"mirror unknown field": strings.Replace(mirror("m", mimg, msrc, mid, miss), `"component"`, `"extra":1,"component"`, 1),
		"unknown field":        strings.Replace(string(enc), `"format"`, `"extra": 1, "format"`, 1),
		"other format":         strings.Replace(string(enc), releasemanifest.Format, "fair-platform-release-manifest/v2", 1),
		"no images":            `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{},"rbac":[]}`,
		"no release":           `{"format":"fair-platform-release-manifest/v1","release":"","images":{"x":"` + img + `"}}`,
		"tagged image":         `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{"x":"registry.invalid/x:1"}}`,
		"rbac namespace":       `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{"x":"` + img + `"},"rbac":[{"kind":"Role","name":"r","sha256":"` + strings.Repeat("c", 64) + `"}]}`,
		"rbac duplicate":       `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{"x":"` + img + `"},"rbac":[{"kind":"ClusterRole","name":"r","sha256":"` + strings.Repeat("c", 64) + `"},{"kind":"ClusterRole","name":"r","sha256":"` + strings.Repeat("d", 64) + `"}]}`,
		"rbac kind":            `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{"x":"` + img + `"},"rbac":[{"kind":"Secret","name":"r","sha256":"` + strings.Repeat("c", 64) + `"}]}`,
		"rbac optional":        `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{"x":"` + img + `"},"rbac":[{"kind":"ClusterRole","name":"r","sha256":"` + strings.Repeat("c", 64) + `","optional":"hook"},{"kind":"Role","namespace":"n","name":"r","sha256":"` + strings.Repeat("c", 64) + `","optional":"postgres.bundled"}]}`,
		"rbac optional bad":    `{"format":"fair-platform-release-manifest/v1","release":"v1","images":{"x":"` + img + `"},"rbac":[{"kind":"ClusterRole","name":"r","sha256":"` + strings.Repeat("c", 64) + `","optional":"always"}]}`,
		"engine no record":     engine,
		"engine record":        engineOK,
		"trailing data":        string(enc) + "{}",
		"not json":             "release",
	}
	for name, body := range cases {
		b := []byte(body)
		for _, signer := range []struct {
			name string
			key  []byte
		}{{"signed", rt.Sign(t, k, b)}, {"other key", rt.Sign(t, other, b)}, {"garbage signature", []byte("not base64!")}} {
			_, want := releasemanifest.Verify(&k.PublicKey, b, signer.key)
			_, got := releaseverify.VerifyManifest(&k.PublicKey, b, signer.key)
			if (want == nil) != (got == nil) {
				t.Errorf("%s, %s: releasemanifest %v, releaseverify %v", name, signer.name, want, got)
			}
		}
	}
}

// Detached signatures are profilepkg's (releasegen sign), and public keys
// read as profilepkg reads them.
func TestSignatureMatchesProfilepkg(t *testing.T) {
	k := rt.NewKey(t)
	b := []byte("SHA256SUMS content\n")
	sig := rt.Sign(t, k, b)
	if err := releaseverify.VerifySignature(&k.PublicKey, b, sig); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string][]byte{"other bytes": rt.Sign(t, k, []byte("x")), "empty": nil, "not base64": []byte("%%%")} {
		if releaseverify.VerifySignature(&k.PublicKey, b, s) == nil {
			t.Errorf("%s verified", name)
		}
		if (profilepkg.VerifySignature(&k.PublicKey, b, s) == nil) != (releaseverify.VerifySignature(&k.PublicKey, b, s) == nil) {
			t.Errorf("%s: profilepkg and releaseverify disagree", name)
		}
	}
	f := filepath.Join(t.TempDir(), "cosign.pub")
	if err := os.WriteFile(f, rt.PublicPEM(t, k), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := releaseverify.LoadPublicKey(f)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := profilepkg.LoadPublicKey(f)
	if err != nil || !a.Equal(b2) {
		t.Fatalf("keys differ: %v", err)
	}
}

func TestParseChecksums(t *testing.T) {
	h := strings.Repeat("ab", 32)
	ok := map[string]int{
		h + "  a\n":                       1,
		h + " *bin/fairctl\n" + h + "  b": 2,
		strings.ToUpper(h) + "  a\n":      1,
	}
	for in, n := range ok {
		got, err := releaseverify.ParseChecksums([]byte(in))
		if err != nil || len(got) != n {
			t.Errorf("%q: %v, %d lines", in, err, len(got))
		}
	}
	for _, in := range []string{"", "\n", h + " a\n", h + "  a\n\n", "xyz  a\n", h + "  /etc/passwd\n", h + "  ../a\n", h + "  a/../../b\n", "SHA256 (a) = " + h + "\n"} {
		if _, err := releaseverify.ParseChecksums([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// The provenance policy is F-012's admission policy's.
func TestReleasePolicyMatchesAdmission(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "fleet", "policy", "release.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	unq := func(re string) string {
		m := regexp.MustCompile(re).FindStringSubmatch(s)
		if m == nil {
			t.Fatalf("%s not in release.yaml", re)
		}
		return strings.ReplaceAll(m[1], `\\`, `\`)
	}
	if got := unq(`builder: id: =~"([^"]+)"`); got != releaseverify.ReleaseBuilder {
		t.Errorf("builder %s, policy %s", releaseverify.ReleaseBuilder, got)
	}
	if got := unq(`uri: =~"([^"]+)"`); got != releaseverify.ReleaseSource {
		t.Errorf("source %s, policy %s", releaseverify.ReleaseSource, got)
	}
	if got := unq(`entryPoint: "([^"]+)"`); got != releaseverify.ReleaseEntryPoint {
		t.Errorf("entry point %s, policy %s", releaseverify.ReleaseEntryPoint, got)
	}
	p := releaseverify.ReleasePolicy()
	st := func(pred map[string]any) releaseverify.Statement {
		raw, _ := json.Marshal(pred)
		return releaseverify.Statement{PredicateType: releaseverify.PredicateSLSA, Predicate: raw}
	}
	if !p.Allows(st(rt.DefaultProvenance("v1.2.3"))) || !p.Allows(st(rt.DefaultProvenance("v0.0.0-test"))) {
		t.Fatal("the release's provenance is refused")
	}
	for name, edit := range map[string]func(map[string]any){
		"other repository": func(m map[string]any) {
			m["invocation"].(map[string]any)["configSource"].(map[string]any)["uri"] = "git+https://github.com/someone/FAIR-app@refs/tags/v1.2.3"
		},
		"branch": func(m map[string]any) {
			m["invocation"].(map[string]any)["configSource"].(map[string]any)["uri"] = "git+https://github.com/rformer/FAIR-app@refs/heads/main"
		},
		"other workflow": func(m map[string]any) {
			m["invocation"].(map[string]any)["configSource"].(map[string]any)["entryPoint"] = ".github/workflows/ci.yml"
		},
		"other builder": func(m map[string]any) { m["builder"] = map[string]any{"id": "https://example.invalid/builder"} },
	} {
		pred := rt.DefaultProvenance("v1.2.3")
		edit(pred)
		if p.Allows(st(pred)) {
			t.Errorf("%s allowed", name)
		}
	}
}

// Signatures and attestations are found in each of cosign's forms: cosign
// save's per-image layouts, and tags or referrers in one layout holding
// every image.
func TestLayoutConventions(t *testing.T) {
	k := rt.NewKey(t)
	for _, mode := range []string{rt.Save, rt.Tag, rt.Referrer} {
		t.Run(mode, func(t *testing.T) {
			r := rt.Release{Key: k, Images: []rt.Image{{Component: "gateway", Mode: mode}, {Component: "iam", Mode: mode}}}
			o := releaseverify.Options{Key: &k.PublicKey, Provenance: releaseverify.ReleasePolicy()}
			dir := filepath.Join(t.TempDir(), "r")
			if mode != rt.Save {
				r.Layout = "oci"
				o.Layout = filepath.Join(dir, "oci")
			}
			rt.Build(t, dir, r)
			rep := releaseverify.Verify(dir, o)
			if !rep.Verified {
				t.Fatalf("refused: %+v", rep.Refusal)
			}
			if len(rep.Images) != 2 || len(rep.Steps) != 4 {
				t.Fatalf("report %+v", rep)
			}
		})
	}
}

func TestPackageManifestFormat(t *testing.T) {
	k := rt.NewKey(t)
	dir := filepath.Join(t.TempDir(), "p")
	w := rt.Build(t, dir, rt.Release{Key: k, Package: true, Files: map[string][]byte{"tools/fairctl-linux-amd64": []byte("binary")}})
	b, err := os.ReadFile(filepath.Join(dir, releaseverify.PackageManifestFile)) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	if _, err := releaseverify.DecodePackageManifest(b); err != nil {
		t.Fatal(err)
	}
	edit := func(f func(*releaseverify.PackageManifest)) []byte {
		pm := *w.Package
		pm.Files = append([]releaseverify.PackageFile(nil), pm.Files...)
		pm.Images = append([]releaseverify.PackageImage(nil), pm.Images...)
		f(&pm)
		b, _ := json.Marshal(pm)
		return b
	}
	bad := map[string][]byte{
		"format":         edit(func(m *releaseverify.PackageManifest) { m.Format = "fair.airgap-package.v2" }),
		"release":        edit(func(m *releaseverify.PackageManifest) { m.Release = "1.2.3" }),
		"source date":    edit(func(m *releaseverify.PackageManifest) { m.SourceDate = "2026-11-20" }),
		"minor date":     edit(func(m *releaseverify.PackageManifest) { m.MinorFirstReleased = "November" }),
		"upgrade self":   edit(func(m *releaseverify.PackageManifest) { m.UpgradeFrom = []string{m.Release} }),
		"absolute path":  edit(func(m *releaseverify.PackageManifest) { m.Files[0].Path = "/etc/passwd" }),
		"parent path":    edit(func(m *releaseverify.PackageManifest) { m.Files[0].Path = "../x" }),
		"windows path":   edit(func(m *releaseverify.PackageManifest) { m.Files[0].Path = `tools\x` }),
		"repeated file":  edit(func(m *releaseverify.PackageManifest) { m.Files = append(m.Files, m.Files[0]) }),
		"lists itself":   edit(func(m *releaseverify.PackageManifest) { m.Files[0].Path = releaseverify.PackageManifestFile }),
		"short digest":   edit(func(m *releaseverify.PackageManifest) { m.Files[0].SHA256 = "abc" }),
		"tagged image":   edit(func(m *releaseverify.PackageManifest) { m.Images[0].Image = "registry.invalid/x:1" }),
		"no files":       edit(func(m *releaseverify.PackageManifest) { m.Files = nil }),
		"no images":      edit(func(m *releaseverify.PackageManifest) { m.Images = nil }),
		"unknown field":  []byte(strings.Replace(string(b), `"format"`, `"x": 1, "format"`, 1)),
		"trailing value": append(append([]byte(nil), b...), []byte("{}")...),
	}
	for name, body := range bad {
		if _, err := releaseverify.DecodePackageManifest(body); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The report's text has no escape sequences unless colour is asked for.
func TestReportText(t *testing.T) {
	k := rt.NewKey(t)
	dir := filepath.Join(t.TempDir(), "r")
	rt.Build(t, dir, rt.Release{Key: k})
	rep := releaseverify.Verify(dir, releaseverify.Options{Key: &k.PublicKey})
	var out, errs strings.Builder
	rep.WriteText(&out, &errs, false)
	want := "ok - release manifest signed by the release key\n" +
		"ok - SHA256SUMS signed, and every file it lists matches\n" +
		"ok - fixture " + rep.Images[0].Image[strings.Index(rep.Images[0].Image, "@")+1:] + ": signed, SBOM and provenance attested\n" +
		"release verified (offline)\n"
	if out.String() != want || errs.Len() != 0 {
		t.Fatalf("text:\n%s\nwant:\n%s\nstderr: %s", out.String(), want, errs.String())
	}
	out.Reset()
	rep.WriteText(&out, &errs, true)
	if !strings.Contains(out.String(), "\x1b[32mok\x1b[0m - ") {
		t.Fatalf("colour: %q", out.String())
	}
}

// F-014 T-10 (design §3.17): mirrored third-party images verify by the
// release key's signature alone, must be listed by a package manifest with
// the same reference, and are refused without that signature.
func TestMirrors(t *testing.T) {
	k, other := rt.NewKey(t), rt.NewKey(t)
	build := func(t *testing.T, mirror rt.Image, edit func(*releaseverify.PackageManifest)) *releaseverify.Report {
		dir := filepath.Join(t.TempDir(), "p")
		w := rt.Build(t, dir, rt.Release{Key: k, Package: true, Images: []rt.Image{{Component: "iam"}}, Mirrors: []rt.Image{mirror}})
		if edit != nil {
			pm := *w.Package
			edit(&pm)
			rt.WritePackageManifest(t, dir, k, &pm)
		}
		return releaseverify.Verify(dir, releaseverify.Options{Key: &k.PublicKey, Package: true, Provenance: releaseverify.ReleasePolicy()})
	}
	r := build(t, rt.Image{Component: "cloudnative-pg"}, nil)
	if !r.Verified {
		t.Fatalf("refused: %+v", r.Refusal)
	}
	if len(r.Images) != 2 || r.Images[1].Component != "cloudnative-pg" ||
		!strings.Contains(r.Steps[len(r.Steps)-1].Message, "cloudnative-pg sha256:") || !strings.HasSuffix(r.Steps[len(r.Steps)-1].Message, ": mirrored, signed by the release key") {
		t.Errorf("images %+v, last step %+v", r.Images, r.Steps[len(r.Steps)-1])
	}
	for name, tc := range map[string]struct {
		img   rt.Image
		edit  func(*releaseverify.PackageManifest)
		check string
	}{
		"other key": {img: rt.Image{Component: "cloudnative-pg", SigKey: other}, check: releaseverify.CheckImageSignature},
		"not listed": {img: rt.Image{Component: "cloudnative-pg"}, check: releaseverify.CheckPackageManifest, edit: func(pm *releaseverify.PackageManifest) {
			pm.Images = slices.DeleteFunc(slices.Clone(pm.Images), func(i releaseverify.PackageImage) bool { return i.Component == "cloudnative-pg" })
		}},
		"listed by another reference": {img: rt.Image{Component: "cloudnative-pg"}, check: releaseverify.CheckPackageManifest, edit: func(pm *releaseverify.PackageManifest) {
			pm.Images = slices.Clone(pm.Images)
			for i := range pm.Images {
				if pm.Images[i].Component == "cloudnative-pg" {
					pm.Images[i].Image = "registry.invalid/other@sha256:" + strings.Repeat("9", 64)
				}
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := build(t, tc.img, tc.edit)
			if r.Verified || r.Refusal == nil || r.Refusal.Check != tc.check || r.Refusal.Subject != "cloudnative-pg" {
				t.Errorf("verified %v, refusal %+v", r.Verified, r.Refusal)
			}
		})
	}
}
