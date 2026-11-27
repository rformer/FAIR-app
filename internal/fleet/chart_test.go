package fleet

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"helm.sh/helm/v4/pkg/chart/common"
	chartutil "helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/engine"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"

	yaml "go.yaml.in/yaml/v3"
)

func chartImages() map[string]string {
	m := images()
	for _, c := range []string{OpenBaoComponent, FairctlComponent} {
		m[c] = "ghcr.io/rformer/fair-" + c + "@sha256:" + strings.Repeat("1", 64)
	}
	return m
}

func renderChart(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "chart")
	err := RenderChart(ChartOptions{Options: Options{Release: "v0.0.0-test", Images: chartImages(), Deploy: filepath.Join(root, "deploy/k8s"),
		Keys: filepath.Join(root, "deploy/k8s/keys")}, Hooks: filepath.Join(root, "deploy/k8s/hooks"), ManifestDigest: strings.Repeat("a", 64)}, out)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// objects keys decoded objects by kind, namespace and name; values are
// normalized through JSON so both renderers' numbers compare equal.
type objects map[string]map[string]any

func objKey(o map[string]any) string {
	ns, _ := dig(o, "metadata", "namespace").(string)
	name, _ := dig(o, "metadata", "name").(string)
	return fmt.Sprintf("%v/%s/%s", o["kind"], ns, name)
}

func addObjects(t *testing.T, into objects, text, from string) {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(text))
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			if err.Error() == "EOF" {
				return
			}
			t.Fatalf("%s: %v", from, err)
		}
		if d == nil {
			continue
		}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var n map[string]any
		if err := json.Unmarshal(b, &n); err != nil {
			t.Fatal(err)
		}
		k := objKey(n)
		if _, dup := into[k]; dup {
			t.Fatalf("%s: %s twice", from, k)
		}
		into[k] = n
	}
}

// helmRender renders the chart with the Helm SDK's engine, as helm install
// would (values coalesced with values.yaml and checked against the schema).
func helmRender(dir string, vals map[string]any) (objects, map[string]string, error) {
	ch, err := loader.LoadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	rv, err := chartutil.ToRenderValues(ch, vals, common.ReleaseOptions{Name: "fair", Namespace: "fair-platform", IsInstall: true}, nil)
	if err != nil {
		return nil, nil, err
	}
	out, err := engine.Render(ch, rv)
	if err != nil {
		return nil, nil, err
	}
	return nil, out, nil
}

func chartObjects(t *testing.T, dir string, vals map[string]any) objects {
	t.Helper()
	_, out, err := helmRender(dir, vals)
	if err != nil {
		t.Fatal(err)
	}
	objs := objects{}
	names := make([]string, 0, len(out))
	for n := range out {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if strings.HasSuffix(n, "NOTES.txt") {
			continue
		}
		addObjects(t, objs, out[n], n)
	}
	return objs
}

// stripHelm removes the chart's Helm annotations (hooks, resource policy):
// the one difference from the fleet's objects.
func stripHelm(o map[string]any) map[string]string {
	md, _ := o["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	got := map[string]string{}
	for k, v := range ann {
		if strings.HasPrefix(k, "helm.sh/") {
			got[k], _ = v.(string)
			delete(ann, k)
		}
	}
	if ann != nil && len(ann) == 0 {
		delete(md, "annotations")
	}
	return got
}

func readEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- the repository's own files
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	env := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		env[k] = v
	}
	return env
}

func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		sub, ok := m[p].(map[string]any)
		if !ok {
			sub = map[string]any{}
			m[p] = sub
		}
		m = sub
	}
	m[parts[len(parts)-1]] = v
}

func getPath(m map[string]any, path string) any {
	var v any = m
	for _, p := range strings.Split(path, ".") {
		v = dig(v, p)
	}
	return v
}

// exampleValues are the chart's values for the example instance's
// variables (deploy/fleet/instances/example/instance.env); the mode is the
// chart's (SaaS runs the fleet artifact itself).
func exampleValues(t *testing.T) (map[string]any, map[string]string) {
	t.Helper()
	env := readEnv(t, filepath.Join(root, "deploy/fleet/instances/example/instance.env"))
	env[ModeVariable] = "self-hosted"
	vals := map[string]any{}
	for v, p := range ChartVariables {
		if env[v] == "" {
			t.Fatalf("instance.env has no %s", v)
		}
		setPath(vals, p, env[v])
	}
	for name, p := range ChartEnv {
		if v, ok := env[name]; ok {
			setPath(vals, p, v)
		}
	}
	return vals, env
}

// kustomizeObjects builds kustomization directories as Flux does
// (kustomize, then the post-build variables, strict).
func kustomizeObjects(t *testing.T, env map[string]string, dirs ...string) objects {
	t.Helper()
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	objs := objects{}
	for _, d := range dirs {
		m, err := k.Run(filesys.MakeFsOnDisk(), d)
		if err != nil {
			t.Fatalf("kustomize %s: %v", d, err)
		}
		y, err := m.AsYaml()
		if err != nil {
			t.Fatal(err)
		}
		text := varRE.ReplaceAllStringFunc(string(y), func(s string) string {
			v, ok := env[varRE.FindStringSubmatch(s)[1]]
			if !ok {
				t.Errorf("%s: no value for %s", d, s)
			}
			return v
		})
		addObjects(t, objs, text, d)
	}
	return objs
}

// applyStoreEnv gives the fleet's objects the chart's store and size
// settings: in SaaS the fleet's patches (deploy/fleet/flux/release.yaml)
// set them, not the artifact.
func applyStoreEnv(objs objects, vals map[string]any) {
	for _, o := range objs {
		for _, cs := range []string{"containers", "initContainers"} {
			list, _ := dig(o, "spec", "template", "spec", cs).([]any)
			for _, c := range list {
				env, _ := dig(c, "env").([]any)
				for _, e := range env {
					em, _ := e.(map[string]any)
					name, _ := em["name"].(string)
					if p, ok := ChartEnv[name]; ok {
						if v := getPath(vals, p); v != nil {
							em["value"] = v
						} else if d, ok := defaultValue(p); ok {
							em["value"] = d
						}
					}
				}
			}
		}
	}
}

var chartDefaults map[string]any

func defaultValue(p string) (any, bool) {
	v := getPath(chartDefaults, p)
	return v, v != nil
}

func loadDefaults(t *testing.T, chart string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(chart, "values.yaml")) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	chartDefaults = map[string]any{}
	if err := yaml.Unmarshal(b, &chartDefaults); err != nil {
		t.Fatal(err)
	}
}

// hookKeys are the chart-only hook objects of deploy/k8s/hooks.
func hookKeys(t *testing.T) map[string]bool {
	t.Helper()
	srcs, _ := filepath.Glob(filepath.Join(root, "deploy/k8s/hooks/*.yaml"))
	keys := map[string]bool{}
	for _, s := range srcs {
		ds, err := readDocs(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			keys[fmt.Sprintf("%s/%s/%s", d.kind, d.namespace, d.name)] = true
		}
	}
	return keys
}

func compareObjects(t *testing.T, label string, chart, fleet objects, extra map[string]bool) {
	t.Helper()
	for k, f := range fleet {
		c, ok := chart[k]
		if !ok {
			t.Errorf("%s: the chart lacks %s", label, k)
			continue
		}
		c = cloneJSON(c)
		stripHelm(c)
		if !reflect.DeepEqual(c, f) {
			var diffs []string
			diff(f, c, k, &diffs)
			t.Errorf("%s: %s differs from the fleet's:\n%s", label, k, strings.Join(diffs, "\n"))
		}
	}
	for k := range chart {
		if _, ok := fleet[k]; !ok && !extra[k] {
			t.Errorf("%s: the chart has %s, which the fleet artifact lacks", label, k)
		}
	}
}

func cloneJSON(o map[string]any) map[string]any {
	b, _ := json.Marshal(o)
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	return c
}

// TestChartMatchesFleet (F-014 T-06, AC-03; design §3.2): the chart,
// rendered by the Helm SDK's engine for the example instance's variables,
// holds exactly the fleet artifact's objects (built by kustomize with the
// same variables, as Flux applies them): the same hardening, images by the
// same digests, the same key mounts. The only differences are the ones the
// design names: the self-hosted Ingress and the chart's hooks are added,
// the SaaS key store and Collector stay in the fleet, Helm's hook and
// resource-policy annotations, and the mode and store settings the SaaS
// patches set (given the chart's values on the fleet side). With the
// OpenBao key store the chart equals the same objects with the OpenBao
// Agent patches applied by kustomize.
func TestChartMatchesFleet(t *testing.T) {
	art := filepath.Join(t.TempDir(), "artifact")
	l, err := LoadThirdParty(filepath.Join(root, "deploy/third-party-images.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Render(Options{Release: "v0.0.0-test", Images: images(), Deploy: filepath.Join(root, "deploy/k8s"),
		Keys: filepath.Join(root, "deploy/k8s/keys"), Mirror: l.Mirror(mirrorPrefix)}, art); err != nil {
		t.Fatal(err)
	}
	chart := renderChart(t)
	loadDefaults(t, chart)
	vals, env := exampleValues(t)

	extra := hookKeys(t)
	extra["Ingress/fair-platform/gateway"] = true // the fleet's entry is the load balancer's (ExcludedKinds)

	steps := []string{filepath.Join(art, DirNamespaces), filepath.Join(art, DirMigrate), filepath.Join(art, DirPlatform)}
	fleetObjs := kustomizeObjects(t, env, steps...)
	applyStoreEnv(fleetObjs, vals)
	chartObjs := chartObjects(t, chart, vals)
	compareObjects(t, "kubernetes-secrets", chartObjs, fleetObjs, extra)

	// Hooks: preflight first, then the migration; namespaces are kept.
	for k, want := range map[string]map[string]string{
		"Job/fair-platform/fair-preflight":               {"helm.sh/hook": "pre-install,pre-upgrade", "helm.sh/hook-weight": "-10"},
		"Job/fair-platform/iam-migrate":                  {"helm.sh/hook": "pre-install,pre-upgrade", "helm.sh/hook-weight": "0"},
		"ServiceAccount/fair-platform/iam":               {"helm.sh/hook": "pre-install,pre-upgrade", "helm.sh/hook-weight": "-5"},
		"NetworkPolicy/fair-platform/iam-migrate-egress": {"helm.sh/hook": "pre-install,pre-upgrade", "helm.sh/hook-weight": "-5"},
		"ClusterRole//fair-preflight":                    {"helm.sh/hook": "pre-install,pre-upgrade", "helm.sh/hook-weight": "-15"},
		"Namespace//fair-platform":                       {"helm.sh/resource-policy": "keep"},
		"NetworkPolicy/fair-platform/default-deny":       {"helm.sh/resource-policy": "keep"},
	} {
		o, ok := chartObjs[k]
		if !ok {
			t.Errorf("the chart lacks %s", k)
			continue
		}
		got := stripHelm(cloneJSON(o))
		for a, v := range want {
			if got[a] != v {
				t.Errorf("%s: %s = %q, want %q", k, a, got[a], v)
			}
		}
	}
	pre := chartObjs["Job/fair-platform/fair-preflight"]
	c0 := dig(pre, "spec", "template", "spec", "containers").([]any)[0]
	if img := dig(c0, "image"); img != chartImages()[FairctlComponent] || !reflect.DeepEqual(dig(c0, "command"), []any{"fairctl", "preflight", "-in-cluster"}) {
		t.Errorf("preflight hook: %v %v", img, dig(c0, "command"))
	}
	for p, want := range map[string]any{"runAsNonRoot": true, "runAsUser": float64(65532)} {
		if got := dig(pre, "spec", "template", "spec", "securityContext", p); got != want {
			t.Errorf("preflight hook: securityContext.%s = %v", p, got)
		}
	}
	if dig(c0, "securityContext", "readOnlyRootFilesystem") != true || dig(c0, "securityContext", "allowPrivilegeEscalation") != false ||
		!reflect.DeepEqual(dig(c0, "securityContext", "capabilities", "drop"), []any{"ALL"}) {
		t.Errorf("preflight hook container: %v", dig(c0, "securityContext"))
	}
	if dig(chartObjs["Job/fair-platform/iam-migrate"], "spec", "ttlSecondsAfterFinished") != nil {
		t.Error("the migration hook keeps ttlSecondsAfterFinished")
	}

	// OpenBao: the fleet's platform with deploy/k8s/keys/openbao applied by
	// kustomize in place of the Secret mounts.
	ob := openBaoKustomization(t, filepath.Join(art, DirPlatform))
	obFleet := kustomizeObjects(t, env, filepath.Join(art, DirNamespaces), filepath.Join(art, DirMigrate), ob)
	applyStoreEnv(obFleet, vals)
	obVals := cloneJSON(vals)
	setPath(obVals, "keyStore.kind", KeyStoreOpenBao)
	compareObjects(t, "openbao", chartObjects(t, chart, obVals), obFleet, extra)
}

// openBaoKustomization copies the fleet's platform directory with the
// OpenBao Agent patches (agent image: the release's OpenBao) and objects,
// and the agent's ConfigMap generator, in place of the Secret mounts.
func openBaoKustomization(t *testing.T, platform string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "openbao")
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o750); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(platform, "*.yaml"))
	var res []string
	for _, f := range files {
		if filepath.Base(f) == "kustomization.yaml" {
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- a test directory
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), b, 0o600); err != nil { // #nosec G703 -- a test directory
			t.Fatal(err)
		}
		res = append(res, filepath.Base(f))
	}
	src := filepath.Join(root, "deploy/k8s/keys/openbao")
	ds, err := readDocs(filepath.Join(src, "sidecars.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	agentRE := regexp.MustCompile(`quay\.io/openbao/openbao:\S+@sha256:[0-9a-f]{64}`)
	var patches []any
	var others []string
	for _, d := range ds {
		text := agentRE.ReplaceAllString(d.text, chartImages()[OpenBaoComponent])
		if d.kind == "Deployment" {
			p := "keys/" + d.name + ".yaml"
			if err := os.WriteFile(filepath.Join(dir, p), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			patches = append(patches, map[string]any{"path": p, "target": map[string]any{"kind": "Deployment", "name": d.name}})
			continue
		}
		others = append(others, text)
	}
	if err := os.WriteFile(filepath.Join(dir, "openbao-objects.yaml"), []byte(strings.Join(others, "---\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	res = append(res, "openbao-objects.yaml")
	var k struct {
		Namespace          string           `yaml:"namespace"`
		ConfigMapGenerator []map[string]any `yaml:"configMapGenerator"`
		GeneratorOptions   map[string]any   `yaml:"generatorOptions"`
	}
	b, err := os.ReadFile(filepath.Join(src, "kustomization.yaml")) // #nosec G304 -- the repository's own files
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &k); err != nil {
		t.Fatal(err)
	}
	for _, g := range k.ConfigMapGenerator {
		g["namespace"] = k.Namespace // the generator's own namespace: a kustomization-wide one would move every object
		for _, f := range g["files"].([]any) {
			c, err := os.ReadFile(filepath.Join(src, f.(string))) // #nosec G304 -- the repository's own files
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, f.(string)), []byte(strings.ReplaceAll(string(c), "\r\n", "\n")), 0o600); err != nil { // #nosec G703 -- the repository's own file names
				t.Fatal(err)
			}
		}
	}
	kust := map[string]any{"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization", "resources": res,
		"patches": patches, "configMapGenerator": k.ConfigMapGenerator, "generatorOptions": k.GeneratorOptions}
	out, err := yaml.Marshal(kust)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kustomization.yaml"), out, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// diff lists the paths where two decoded objects differ; list items with a
// name are addressed by it.
func diff(a, b any, path string, out *[]string) {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			*out = append(*out, path+" (structure)")
			return
		}
		keys := map[string]bool{}
		for k := range av {
			keys[k] = true
		}
		for k := range bv {
			keys[k] = true
		}
		for k := range keys {
			_, ina := av[k]
			_, inb := bv[k]
			if !ina || !inb {
				*out = append(*out, path+"."+k+" (structure)")
				continue
			}
			diff(av[k], bv[k], path+"."+k, out)
		}
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			*out = append(*out, path+" (structure)")
			return
		}
		for i := range av {
			el := "[" + strconv.Itoa(i) + "]"
			if n, ok := dig(av[i], "name").(string); ok && n == dig(bv[i], "name") {
				el = "[name=" + n + "]"
			}
			diff(av[i], bv[i], path+el, out)
		}
	default:
		if !reflect.DeepEqual(a, b) {
			*out = append(*out, path)
		}
	}
}

// schemaLeaves lists the schema's leaf values by path, failing on any
// object that is not closed and any leaf that is not narrowed.
func schemaLeaves(t *testing.T, s map[string]any, path string, leaves map[string]map[string]any) {
	t.Helper()
	if s["type"] != "object" {
		switch s["type"] {
		case "string":
			if s["pattern"] == nil && s["enum"] == nil {
				t.Errorf("%s: a string without a pattern or enum", path)
			}
		case "integer":
			if s["minimum"] == nil || s["maximum"] == nil {
				t.Errorf("%s: an unbounded integer", path)
			}
		case "boolean":
		default:
			t.Errorf("%s: type %v", path, s["type"])
		}
		leaves[path] = s
		return
	}
	if s["additionalProperties"] != false {
		t.Errorf("%s: not closed (additionalProperties: %v)", path, s["additionalProperties"])
	}
	props, _ := s["properties"].(map[string]any)
	var req []string
	for _, r := range s["required"].([]any) {
		req = append(req, r.(string))
	}
	for k, v := range props {
		if forbiddenValueRE.MatchString(k) {
			t.Errorf("%s.%s: a value named like a security field", path, k)
		}
		if !slices.Contains(req, k) {
			t.Errorf("%s.%s is not required (a null would remove it)", path, k)
		}
		schemaLeaves(t, v.(map[string]any), strings.TrimPrefix(path+"."+k, "."), leaves)
	}
}

var forbiddenValueRE = regexp.MustCompile(`(?i)security|capabilit|privileg|root|seccomp|apparmor|selinux|runas|fsgroup|liveness|readiness|startup|rbac|role|rule|policy|serviceaccount|token|automount|tls|cert|secret|password|key$|tag|digest|hostnetwork|hostpath|hostpid|volume|command|args|resources|limit`)

// The value-driven fields: every difference between two renders with
// different values must be one of these placeholders (design §3.2).
var allowedDiffs = []*regexp.Regexp{
	regexp.MustCompile(`^Deployment/[^|]+\|\.spec\.replicas$`),
	regexp.MustCompile(`^(Deployment|DaemonSet|Job)/[^|]+\|\.spec\.template\.spec\.(containers|initContainers)\[name=[^\]]+\]\.image$`),
	regexp.MustCompile(`^(Deployment|DaemonSet|Job)/[^|]+\|\.spec\.template\.spec\.containers\[name=[^\]]+\]\.env\[name=(PGHOST|FAIR_PUBLIC_ORIGIN|FAIR_TRUSTED_PROXIES|FAIR_NOTIFY_BASE_URL|FAIR_INGRESS_ENDPOINTS|FAIR_DEPLOYMENT_MODE|FAIR_AUDIT_STORE_(BUCKET|ENDPOINT|REGION)|FAIR_REPORT_STORE_(BUCKET|ENDPOINT|REGION)|FAIR_AUDIT_STORAGE_QUOTA)\]\.value$`),
	regexp.MustCompile(`^NetworkPolicy/[^|]+\|\.spec\.(ingress|egress)\[[0-9]+\]\.(from|to)\[[0-9]+\]\.ipBlock\.cidr$`),
	regexp.MustCompile(`^Ingress/[^|]+\|\.spec\.(rules\[[0-9]+\]\.host|tls\[[0-9]+\]\.hosts\[[0-9]+\])$`),
}

// otherValues are valid values unlike every example value.
func otherValues(t *testing.T, leaves map[string]map[string]any) map[string]any {
	t.Helper()
	v := map[string]any{}
	fixed := map[string]any{
		"global.registry":        "registry.customer.example:5000/mirror/fair",
		"mode":                   "air-gapped",
		"database.host":          "pg.customer.example",
		"platform.host":          "fair.customer.example",
		"ingress.host":           "ingress.customer.example",
		"ingress.cidr":           "192.168.10.0/24",
		"apiServer.cidr":         "172.20.0.1/32",
		"stores.audit.bucket":    "customer-audit",
		"stores.audit.endpoint":  "s3.customer.example:9000",
		"stores.audit.region":    "local",
		"stores.report.bucket":   "customer-reports",
		"stores.report.endpoint": "s3.customer.example:9000",
		"stores.report.region":   "local",
		"audit.storageQuota":     "2TiB",
		"keyStore.kind":          KeyStoreSecrets,
		"scanner.enabled":        true,
		"fipsProbe.enabled":      true,
	}
	for p, s := range leaves {
		switch {
		case fixed[p] != nil:
			setPath(v, p, fixed[p])
		case s["type"] == "integer":
			setPath(v, p, 3)
		default:
			t.Fatalf("no other value for %s", p)
		}
	}
	return v
}

// TestChartValuesSchema (F-014 T-06, AC-03; design §3.2): the values
// schema is closed and narrow, the templates read values only as the
// placeholders they fill, and no security-relevant field is value-driven:
// two renders with every value changed differ only in the placeholders'
// fields, the switches remove whole files of objects, and the key store
// changes only the Deployments its patch sets cover.
func TestChartValuesSchema(t *testing.T) {
	chart := renderChart(t)
	b, err := os.ReadFile(filepath.Join(chart, "values.schema.json")) // #nosec G304 -- a test directory
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	leaves := map[string]map[string]any{}
	schemaLeaves(t, schema, "", leaves)

	// The schema refuses unknown values, tags, open CIDRs, SaaS, empty
	// placeholders and anything that could break out of a quoted scalar.
	vals, _ := exampleValues(t)
	if _, _, err := helmRender(chart, vals); err != nil {
		t.Fatalf("example values: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown top-level":   func(m map[string]any) { m["securityContext"] = map[string]any{"privileged": true} },
		"unknown nested":      func(m map[string]any) { setPath(m, "database.port", "5432") },
		"unknown leaf object": func(m map[string]any) { setPath(m, "global.imageTag", "latest") },
		"tag":                 func(m map[string]any) { setPath(m, "global.registry", "ghcr.io/rformer:latest") },
		"digest":              func(m map[string]any) { setPath(m, "global.registry", "evil.example/x@sha256:00") },
		"open cidr":           func(m map[string]any) { setPath(m, "ingress.cidr", "0.0.0.0/0") },
		"saas":                func(m map[string]any) { setPath(m, "mode", "saas") },
		"empty host":          func(m map[string]any) { setPath(m, "database.host", "") },
		"null host":           func(m map[string]any) { setPath(m, "database.host", nil) },
		"quote":               func(m map[string]any) { setPath(m, "platform.host", `x"y`) },
		"newline":             func(m map[string]any) { setPath(m, "platform.host", "x\ny: z") },
		"template":            func(m map[string]any) { setPath(m, "database.host", "{{ .Release.Name }}") },
		"key store":           func(m map[string]any) { setPath(m, "keyStore.kind", "none") },
		"one replica":         func(m map[string]any) { setPath(m, "replicas.gateway", 1) },
		"switch as string":    func(m map[string]any) { setPath(m, "scanner.enabled", "false") },
	} {
		m := cloneJSON(vals)
		mutate(m)
		if _, _, err := helmRender(chart, m); err == nil {
			t.Errorf("%s: the schema accepts %v", name, m)
		}
	}

	// The templates: every action is an escape, a comment, a switch or key
	// store condition, or a placeholder's value at an allowed key; every
	// value is read.
	actionRE := regexp.MustCompile(`\{\{-?\s*(.*?)\s*-?\}\}`)
	refRE := regexp.MustCompile(`\.Values\.([A-Za-z0-9.]+)`)
	condRE := regexp.MustCompile(`^if (\.Values\.(scanner|fipsProbe)\.enabled|eq \.Values\.keyStore\.kind "(kubernetes-secrets|openbao)"|and( \((\.Values\.(scanner|fipsProbe)\.enabled|eq \.Values\.keyStore\.kind "(kubernetes-secrets|openbao)")\))+)$`)
	lineRE := regexp.MustCompile(`(^|[\s{,\[-])(value|image|cidr|host|replicas): \{\{ |hosts: \[\{\{ `)
	exprRE := regexp.MustCompile(`^(\.Values\.[A-Za-z0-9.]+|print( (\.Values\.[A-Za-z0-9.]+|"[^"{}]*"))+) \| toJson$`)
	read := map[string]bool{}
	err = filepath.WalkDir(filepath.Join(chart, "templates"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, "NOTES.txt") {
			return err
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- a test directory
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			for _, m := range actionRE.FindAllStringSubmatch(line, -1) {
				a := m[1]
				switch {
				case a == `"{{"`, strings.HasPrefix(a, "/*"), a == "end":
				case strings.HasPrefix(a, "if "):
					if !condRE.MatchString(a) {
						t.Errorf("%s:%d: condition %q", p, i+1, a)
					}
				case exprRE.MatchString(a):
					if !lineRE.MatchString(line) {
						t.Errorf("%s:%d: a value outside a placeholder: %s", p, i+1, line)
					}
					for _, r := range refRE.FindAllStringSubmatch(a, -1) {
						s, ok := leaves[r[1]]
						if !ok {
							t.Errorf("%s:%d: %s is not a value of the schema", p, i+1, r[1])
						} else if s["type"] == "boolean" || r[1] == "keyStore.kind" {
							t.Errorf("%s:%d: switch %s used as a value", p, i+1, r[1])
						}
						read[r[1]] = true
					}
				default:
					t.Errorf("%s:%d: action %q", p, i+1, a)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for p, s := range leaves {
		if !read[p] && s["type"] != "boolean" && p != "keyStore.kind" {
			t.Errorf("value %s fills no placeholder", p)
		}
	}

	// Two renders with every value changed differ only in the
	// placeholders' fields; images keep their digests.
	a, bo := chartObjects(t, chart, vals), chartObjects(t, chart, otherValues(t, leaves))
	if len(a) != len(bo) {
		t.Fatalf("other values change the objects: %d, %d", len(a), len(bo))
	}
	changed := map[string]bool{}
	for k, o := range a {
		var diffs []string
		diff(o, bo[k], "", &diffs)
		for _, d := range diffs {
			p := k[:strings.Index(k, "/")] + "/" + k[strings.Index(k, "/")+1:] + "|" + d
			ok := false
			for _, re := range allowedDiffs {
				ok = ok || re.MatchString(p)
			}
			if !ok {
				t.Errorf("a value reaches %s", p)
			}
			changed[strings.SplitN(p, "|", 2)[1]] = true
		}
		for _, cs := range []string{"containers", "initContainers"} {
			ca, _ := dig(o, "spec", "template", "spec", cs).([]any)
			cb, _ := dig(bo[k], "spec", "template", "spec", cs).([]any)
			for i := range ca {
				ia, _ := dig(ca[i], "image").(string)
				ib, _ := dig(cb[i], "image").(string)
				_, da, _ := strings.Cut(ia, "@")
				_, db, _ := strings.Cut(ib, "@")
				if da == "" || da != db || !strings.HasPrefix(ib, "registry.customer.example:5000/mirror/fair/") {
					t.Errorf("%s: image %s became %s", k, ia, ib)
				}
			}
		}
	}
	if len(changed) == 0 {
		t.Error("no value changed anything")
	}

	// The switches remove whole files of objects (never a namespace or its
	// default deny) and change nothing else.
	for file, sw := range ChartSwitches {
		ds, err := readDocs(filepath.Join(root, "deploy/k8s", file))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{}
		for _, d := range ds {
			if d.kind != "Namespace" && (d.kind != "NetworkPolicy" || d.name != "default-deny") && !slices.Contains(ExcludedKinds, d.kind) {
				want[fmt.Sprintf("%s/%s/%s", d.kind, d.namespace, d.name)] = true
			}
		}
		m := cloneJSON(vals)
		setPath(m, sw, false)
		off := chartObjects(t, chart, m)
		for k, o := range a {
			switch _, kept := off[k]; {
			case want[k] && kept:
				t.Errorf("%s off keeps %s", sw, k)
			case !want[k] && !kept:
				t.Errorf("%s off removes %s", sw, k)
			case kept && !reflect.DeepEqual(o, off[k]):
				t.Errorf("%s off changes %s", sw, k)
			}
		}
	}

	// The key store changes only the Deployments its patch sets cover, and
	// adds the OpenBao objects.
	m := cloneJSON(vals)
	setPath(m, "keyStore.kind", KeyStoreOpenBao)
	ob := chartObjects(t, chart, m)
	mounts, err := readDocs(filepath.Join(root, "deploy/k8s/keys/secret-mounts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	patched := map[string]bool{}
	for _, d := range mounts {
		patched["Deployment/fair-platform/"+d.name] = true
	}
	for k, o := range ob {
		if x, ok := a[k]; !ok {
			if !strings.HasPrefix(k, "ConfigMap/fair-platform/fair-openbao-agent") && !strings.HasPrefix(k, "NetworkPolicy/fair-platform/engine-egress-openbao") {
				t.Errorf("openbao adds %s", k)
			}
		} else if !reflect.DeepEqual(o, x) && !patched[k] {
			t.Errorf("openbao changes %s", k)
		}
	}
	for k := range patched {
		if reflect.DeepEqual(a[k], ob[k]) {
			t.Errorf("openbao does not change %s", k)
		}
	}
}

// TestChartFiles: Chart.yaml names the release and its manifest's digest,
// NOTES.txt is plain text, and the chart refuses images the release lacks.
func TestChartFiles(t *testing.T) {
	chart := renderChart(t)
	ch, err := loader.LoadDir(chart)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Metadata.Name != ChartName || ch.Metadata.Version != "0.0.0-test" || ch.Metadata.AppVersion != "v0.0.0-test" || ch.Metadata.KubeVersion != MinKubeVersion ||
		ch.Metadata.Annotations["fair-platform.io/release-manifest-sha256"] != strings.Repeat("a", 64) {
		t.Errorf("Chart.yaml: %+v", ch.Metadata)
	}
	if err := ch.Validate(); err != nil {
		t.Error(err)
	}
	_, out, err := helmRender(chart, func() map[string]any { v, _ := exampleValues(t); return v }())
	if err != nil {
		t.Fatal(err)
	}
	n := out["fair-platform/templates/NOTES.txt"]
	if !strings.Contains(n, "fairctl") || strings.ContainsAny(n, "\x1b\r") || !strings.Contains(n, "v0.0.0-test") {
		t.Errorf("NOTES.txt: %q", n)
	}
	for _, c := range []string{OpenBaoComponent, FairctlComponent} {
		imgs := chartImages()
		delete(imgs, c)
		err := RenderChart(ChartOptions{Options: Options{Release: "v0.0.0-test", Images: imgs, Deploy: filepath.Join(root, "deploy/k8s"),
			Keys: filepath.Join(root, "deploy/k8s/keys")}, Hooks: filepath.Join(root, "deploy/k8s/hooks")}, filepath.Join(t.TempDir(), "c"))
		if err == nil || !strings.Contains(err.Error(), c) {
			t.Errorf("without the %s image: %v", c, err)
		}
	}
	if err := RenderChart(ChartOptions{Options: Options{Release: "latest", Images: chartImages(), Deploy: filepath.Join(root, "deploy/k8s"),
		Keys: filepath.Join(root, "deploy/k8s/keys")}}, filepath.Join(t.TempDir(), "c")); err == nil {
		t.Error("a release that is not a version renders")
	}
}
