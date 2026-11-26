package fleet

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

const root = "../.."

var components = []string{"iam", "gateway", "posture", "posture-scanner", "fips-probe", "audit", "risk", "notify", "integrate", "engine-gate", "engine"}

func images() map[string]string {
	m := map[string]string{}
	for _, c := range components {
		m[c] = "ghcr.io/rformer/fair-" + c + "@sha256:" + strings.Repeat("0", 64)
	}
	return m
}

func render(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "artifact")
	err := Render(Options{Release: "v0.0.0-test", Images: images(), Deploy: filepath.Join(root, "deploy/k8s"),
		Keys: filepath.Join(root, "deploy/k8s/keys"), Observability: filepath.Join(root, "deploy/observability")}, out)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// readAll returns every file of dir by relative path.
func readAll(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- the repository's own files and a test directory
		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)] = strings.ReplaceAll(string(b), "\r\n", "\n")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func yamlDocs(t *testing.T, text string) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := yaml.NewDecoder(strings.NewReader(text))
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			if err.Error() == "EOF" {
				return out
			}
			t.Fatal(err)
		}
		if d != nil {
			out = append(out, d)
		}
	}
}

func noComments(text string) string {
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		if !strings.HasPrefix(strings.TrimSpace(sc.Text()), "#") {
			b.WriteString(sc.Text() + "\n")
		}
	}
	return b.String()
}

var varRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// TestRenderRelease renders deploy/k8s as a release: the reconciliation
// steps hold what design §3.6 orders, every image is the release's by
// digest, and only the SaaS patches' placeholders are left.
func TestRenderRelease(t *testing.T) {
	out := render(t)
	files := readAll(t, out)
	for _, d := range Dirs {
		if _, ok := files[d+"/kustomization.yaml"]; !ok {
			t.Errorf("no %s/kustomization.yaml", d)
		}
	}
	var rel Release
	if err := json.Unmarshal([]byte(files["release.json"]), &rel); err != nil || rel.Format != Format || rel.Release != "v0.0.0-test" || len(rel.Images) != len(components) {
		t.Errorf("release.json: %+v %v", rel, err)
	}
	kinds := map[string][]string{}
	for name, text := range files {
		if !strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, "kustomization.yaml") {
			continue
		}
		dir, _, _ := strings.Cut(name, "/")
		for _, d := range yamlDocs(t, text) {
			md, _ := d["metadata"].(map[string]any)
			kinds[dir] = append(kinds[dir], d["kind"].(string)+"/"+md["name"].(string))
			if d["kind"] == "Job" && dig(d, "spec", "ttlSecondsAfterFinished") != nil {
				t.Errorf("%s: Job %s keeps ttlSecondsAfterFinished (Flux would rerun it)", name, md["name"])
			}
		}
		body := noComments(text)
		if strings.Contains(body, ":REPLACE_WITH_DIGEST") || strings.Contains(body, "REPLACE_WITH_ENGINE_DIGEST") {
			t.Errorf("%s: an image placeholder is left", name)
		}
		for _, m := range regexp.MustCompile(`image: (\S+)`).FindAllStringSubmatch(body, -1) {
			if !strings.Contains(m[1], "@sha256:") {
				t.Errorf("%s: image %s not by digest", name, m[1])
			}
		}
		for _, m := range placeholderRE.FindAllString(body, -1) {
			if m != "REPLACE_WITH_BUCKET" && m != "REPLACE_WITH_HOST_PORT" || !strings.HasPrefix(name, "platform/audit") && !strings.HasPrefix(name, "platform/risk") {
				t.Errorf("%s: %s left for no patch", name, m)
			}
		}
	}
	for dir, want := range map[string][]string{
		DirNamespaces:    {"Namespace/fair-platform", "Namespace/fair-fips-probe", "Namespace/fair-observability", "NetworkPolicy/default-deny"},
		DirMigrate:       {"Job/iam-migrate", "ServiceAccount/iam", "NetworkPolicy/iam-migrate-egress"},
		DirPlatform:      {"Deployment/iam", "Deployment/iam-worker", "Deployment/audit", "Deployment/risk", "Deployment/posture-scanner", "DaemonSet/fips-probe"},
		DirSecrets:       {"SecretStore/fair-instance-keys", "ExternalSecret/fair-iam-jwt", "ExternalSecret/iam-db-migrator", "Certificate/iam-tls"},
		DirObservability: {"Deployment/otelcol", "DaemonSet/otelcol-agent", "ConfigMap/otelcol-saas", "ConfigMap/otelcol-agent"},
	} {
		for _, w := range want {
			if !slices.Contains(kinds[dir], w) {
				t.Errorf("%s lacks %s (has %v)", dir, w, kinds[dir])
			}
		}
	}
	for _, k := range kinds[DirPlatform] {
		if strings.HasPrefix(k, "Job/") || strings.HasPrefix(k, "Namespace/") || k == "ServiceAccount/iam" {
			t.Errorf("platform holds %s", k)
		}
	}
	if _, ok := files["platform/breakglass-emergency.yaml"]; ok || strings.Contains(noComments(strings.Join(slices.Collect(mapValues(files)), "")), "-emergency") {
		t.Error("the emergency break-glass Job is in the release")
	}
	if !strings.Contains(files["platform/kustomization.yaml"], "keys/iam.yaml") {
		t.Error("the key mounts are not patched in")
	}
	if !strings.Contains(files["observability/k8s-saas.yaml"], "kustomize.toolkit.fluxcd.io/substitute: disabled") {
		t.Error("the Collector configurations are not exempt from substitution")
	}
}

// TestVariablesDefined: every post-build variable the release and the
// fleet's templates use is set by the example instance, and the example
// sets nothing unused.
func TestVariablesDefined(t *testing.T) {
	env := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(root, "deploy/fleet/instances/example/instance.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if k, _, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			env[k] = true
		}
	}
	used := map[string]string{}
	collect := func(name, text string) {
		for _, m := range varRE.FindAllStringSubmatch(noComments(text), -1) {
			used[m[1]] = name
		}
	}
	for name, text := range readAll(t, render(t)) {
		// Each document: the Collector's ConfigMaps are not substituted.
		for _, chunk := range sepRE.Split(text, -1) {
			if !strings.Contains(chunk, "kustomize.toolkit.fluxcd.io/substitute: disabled") {
				collect(name, chunk)
			}
		}
	}
	for _, d := range []string{"flux", "addons", "addons-config", "policy"} {
		for name, text := range readAll(t, filepath.Join(root, "deploy/fleet", d)) {
			collect(d+"/"+name, text)
		}
	}
	for v, where := range used {
		if !env[v] {
			t.Errorf("%s uses ${%s}, which the example instance does not set", where, v)
		}
	}
	for v := range env {
		if _, ok := used[v]; !ok {
			t.Errorf("the example instance sets %s, which nothing uses", v)
		}
	}
}

func fleetDocs(t *testing.T, dir string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for name, text := range readAll(t, filepath.Join(root, "deploy/fleet", dir)) {
		if strings.HasSuffix(name, ".yaml") && name != "kustomization.yaml" {
			out = append(out, yamlDocs(t, text)...)
		}
	}
	return out
}

func named(ds []map[string]any, kind, name string) map[string]any {
	for _, d := range ds {
		if d["kind"] == kind && dig(d, "metadata", "name") == name {
			return d
		}
	}
	return nil
}

// TestFluxObjects ties deploy/fleet/flux to design §3.6: the release source
// is verified with the release key, the steps run in order and wait, and
// nothing is reconciled from an unverified source.
func TestFluxObjects(t *testing.T) {
	ds := fleetDocs(t, "flux")
	src := named(ds, "OCIRepository", "fair-release")
	if src == nil || dig(src, "spec", "verify", "provider") != "cosign" || dig(src, "spec", "verify", "secretRef", "name") != "fair-release-key" {
		t.Fatalf("fair-release is not verified with the release key: %v", src)
	}
	if dig(src, "spec", "ref", "semver") != nil || dig(src, "spec", "ref", "tag") == "latest" {
		t.Error("the release is not pinned")
	}
	order := map[string]string{ // #nosec G101 -- step -> what it waits for, no credentials
		"fair-policy":        "fair-addons",
		"fair-namespaces":    "fair-policy",
		"fair-addons-config": "fair-namespaces",
		"fair-secrets":       "fair-addons-config",
		"fair-migrate":       "fair-secrets",
		"fair-platform":      "fair-migrate",
		"fair-observability": "fair-secrets",
	}
	release := map[string]bool{"fair-namespaces": true, "fair-secrets": true, "fair-migrate": true, "fair-platform": true, "fair-observability": true}
	n := 0
	for _, d := range ds {
		if d["kind"] != "Kustomization" {
			continue
		}
		n++
		name := dig(d, "metadata", "name").(string)
		if dig(d, "spec", "wait") != true {
			t.Errorf("%s does not wait for its objects", name)
		}
		var deps []string
		for _, x := range asList(dig(d, "spec", "dependsOn")) {
			deps = append(deps, dig(x, "name").(string))
		}
		if want := order[name]; want != "" && !slices.Contains(deps, want) {
			t.Errorf("%s depends on %v, want %s", name, deps, want)
		}
		ref := dig(d, "spec", "sourceRef", "name")
		if release[name] != (ref == "fair-release") {
			t.Errorf("%s: source %v", name, ref)
		}
		if subs := asList(dig(d, "spec", "postBuild", "substituteFrom")); len(subs) != 1 || dig(subs[0], "name") != "fair-instance" {
			t.Errorf("%s: substitutes from %v", name, subs)
		}
	}
	if n != len(order)+1 {
		t.Errorf("%d Kustomizations, want %d", n, len(order)+1)
	}
	if dig(named(ds, "Kustomization", "fair-migrate"), "spec", "force") != true {
		t.Error("fair-migrate does not replace the Job of a new release")
	}
	for _, p := range []string{"Provider", "Alert"} {
		var found bool
		for _, d := range ds {
			found = found || d["kind"] == p
		}
		if !found {
			t.Errorf("no notification %s", p)
		}
	}
}

func asList(v any) []any { l, _ := v.([]any); return l }

func mapValues(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for _, v := range m {
			if !yield(v) {
				return
			}
		}
	}
}

// TestAdmissionPolicy ties deploy/fleet/policy and the policy-controller's
// HelmRelease to AC-19.
func TestAdmissionPolicy(t *testing.T) {
	ds := fleetDocs(t, "policy")
	p := named(ds, "ClusterImagePolicy", "fair-release")
	if p == nil || dig(p, "spec", "mode") != "enforce" {
		t.Fatalf("no enforcing fair-release policy: %v", p)
	}
	auths := asList(dig(p, "spec", "authorities"))
	if len(auths) != 1 || dig(auths[0], "key", "secretRef", "name") != "fair-release-key" {
		t.Fatalf("authorities %v: want the release key alone", auths)
	}
	atts := asList(dig(auths[0], "attestations"))
	if len(atts) != 1 || dig(atts[0], "predicateType") != "https://slsa.dev/provenance/v0.2" {
		t.Fatalf("attestations %v", atts)
	}
	cue, _ := dig(atts[0], "policy", "data").(string)
	for _, want := range []string{"generator_container_slsa3", "rformer/FAIR-app@refs/tags/v", `entryPoint: ".github/workflows/release.yml"`} {
		if !strings.Contains(cue, want) {
			t.Errorf("provenance policy lacks %s", want)
		}
	}
	pc := named(fleetDocs(t, "addons"), "HelmRelease", "policy-controller")
	if dig(pc, "spec", "values", "webhook", "failurePolicy") != "Fail" || dig(pc, "spec", "values", "webhook", "configData", "no-match-policy") != "deny" {
		t.Errorf("the policy-controller does not fail closed: %v", dig(pc, "spec", "values"))
	}
}

var semverRE = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// TestAddonsPinned: every chart by exact version, every image by digest.
func TestAddonsPinned(t *testing.T) {
	for _, d := range fleetDocs(t, "addons") {
		if d["kind"] != "HelmRelease" {
			continue
		}
		name := dig(d, "metadata", "name")
		if v, _ := dig(d, "spec", "chart", "spec", "version").(string); !semverRE.MatchString(v) {
			t.Errorf("%s: chart version %q", name, v)
		}
		b, _ := yaml.Marshal(dig(d, "spec", "values"))
		vals := string(b)
		repos := regexp.MustCompile(`repository: (\S+)`).FindAllString(vals, -1)
		pins := regexp.MustCompile(`(@|version: |digest: )sha256:[0-9a-f]{64}`).FindAllString(vals, -1)
		if len(repos) == 0 || len(pins) != len(repos) {
			t.Errorf("%s: %d images, %d digests:\n%s", name, len(repos), len(pins), vals)
		}
	}
}

func TestRenderRefuses(t *testing.T) {
	base := Options{Release: "v1.0.0", Deploy: filepath.Join(root, "deploy/k8s")}
	bad := images()
	bad["iam"] = "ghcr.io/rformer/fair-iam:v1.0.0"
	missing := images()
	delete(missing, "risk")
	for name, imgs := range map[string]map[string]string{"tag": bad, "missing": missing, "none": nil} {
		o := base
		o.Images = imgs
		if err := Render(o, filepath.Join(t.TempDir(), "a")); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}
