package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/checks"
	"github.com/rformer/fair-app/internal/scanner/kube"

	yaml "go.yaml.in/yaml/v3"
)

// F-014 T-08 (F-014-AC-01, AC-03; design §3.3, D-OQ2, D-OQ12): the bundled
// dependencies of deploy/bundled as chart options.

const identityHost = "id.fair.example"

// allBundled is vals with every bundled dependency on.
func allBundled(vals map[string]any) map[string]any {
	m := cloneJSON(vals)
	for _, b := range Bundled {
		setPath(m, b.Value+".bundled", true)
	}
	setPath(m, "keycloak.host", identityHost)
	return m
}

// withBundled is vals with one dependency on (and what it needs).
func withBundled(vals map[string]any, b BundledDependency) map[string]any {
	m := cloneJSON(vals)
	setPath(m, b.Value+".bundled", true)
	if b.Value == "keycloak" {
		setPath(m, "postgres.bundled", true)
		setPath(m, "keycloak.host", identityHost)
	}
	return m
}

// bundledKeys are the objects a bundled directory holds (its resources and
// generated ConfigMaps), by objKey.
func bundledKeys(t *testing.T, b BundledDependency) map[string]bool {
	t.Helper()
	dir := filepath.Join(root, "deploy/bundled", b.Dir)
	kb, err := os.ReadFile(filepath.Join(dir, "kustomization.yaml")) // #nosec G304 -- the repository's own files
	if err != nil {
		t.Fatal(err)
	}
	var k bundledKustomization
	if err := yaml.Unmarshal(kb, &k); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, r := range k.Resources {
		ds, err := readDocs(filepath.Join(dir, r))
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			keys[fmt.Sprintf("%s/%s/%s", d.kind, d.namespace, d.name)] = true
		}
	}
	for _, g := range k.ConfigMapGenerator {
		keys["ConfigMap/"+g.Namespace+"/"+g.Name] = true
	}
	return keys
}

var secretEnvRE = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential)`)

// TestBundledManifests (F-014 T-08; design §3.3): every bundled dependency
// is one chart switch that adds exactly its directory's objects and
// changes nothing else; its workloads carry the platform's hardening
// (non-root, read-only root filesystem, capabilities dropped, seccomp,
// no privilege escalation, no host access, limits, probes, no
// ServiceAccount token but where an operator needs one); every namespace
// enforces restricted pod security and denies by default, with an explicit
// policy for every workload and no rule open to everything; no Role or
// ClusterRole grants a cluster-wide write (the chart holds no cluster-scoped
// RBAC; fairctl's cluster-scoped residue only reads); no credential is in
// a manifest; and every listener is configured for TLS 1.2 or later,
// without the features that run outside the FIPS module.
func TestBundledManifests(t *testing.T) {
	// The directories are exactly Bundled's, each a kustomization of every
	// file in it.
	entries, err := os.ReadDir(filepath.Join(root, "deploy/bundled"))
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		} else if e.Name() != "sources.json" {
			t.Errorf("deploy/bundled/%s: not a dependency directory", e.Name())
		}
	}
	var want []string
	for _, b := range Bundled {
		want = append(want, b.Dir)
	}
	sort.Strings(want)
	if !slices.Equal(dirs, want) {
		t.Errorf("deploy/bundled holds %v, want %v", dirs, want)
	}
	for _, b := range Bundled {
		dir := filepath.Join(root, "deploy/bundled", b.Dir)
		kb, err := os.ReadFile(filepath.Join(dir, "kustomization.yaml")) // #nosec G304 -- the repository's own files
		if err != nil {
			t.Fatal(err)
		}
		var k bundledKustomization
		if err := yaml.Unmarshal(kb, &k); err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
		var got []string
		for _, f := range files {
			if filepath.Base(f) != "kustomization.yaml" {
				got = append(got, filepath.Base(f))
			}
		}
		if !slices.Equal(slices.Sorted(slices.Values(k.Resources)), got) {
			t.Errorf("%s: resources %v, files %v", b.Dir, k.Resources, got)
		}
	}

	chart := renderChart(t)
	vals, _ := exampleValues(t)
	base := chartObjects(t, chart, vals)

	// One switch, one directory's objects, nothing else changed.
	for _, b := range Bundled {
		on := chartObjects(t, chart, withBundled(vals, b))
		want := bundledKeys(t, b)
		if b.Value == "keycloak" {
			maps.Copy(want, bundledKeys(t, Bundled[0]))
		}
		for k, o := range on {
			switch x, inBase := base[k]; {
			case inBase && !want[k] && !mapsEqual(o, x):
				t.Errorf("%s.bundled changes %s", b.Value, k)
			case inBase && want[k]:
				t.Errorf("%s.bundled: %s is also the platform's", b.Value, k)
			case !inBase && !want[k]:
				t.Errorf("%s.bundled adds %s, not in deploy/bundled/%s", b.Value, k, b.Dir)
			}
		}
		for k := range want {
			if _, ok := on[k]; !ok {
				t.Errorf("%s.bundled lacks %s", b.Value, k)
			}
		}
	}

	all := chartObjects(t, chart, allBundled(vals))
	bundled := objects{}
	for k, o := range all {
		if _, ok := base[k]; !ok {
			bundled[k] = o
		}
	}

	// Namespaces: restricted, default deny, kept on uninstall.
	namespaces := map[string]bool{}
	for k, o := range bundled {
		if o["kind"] != "Namespace" {
			continue
		}
		name := dig(o, "metadata", "name").(string)
		namespaces[name] = true
		if dig(o, "metadata", "labels", "pod-security.kubernetes.io/enforce") != "restricted" {
			t.Errorf("%s does not enforce restricted pod security", k)
		}
		if dig(o, "metadata", "annotations", "helm.sh/resource-policy") != "keep" {
			t.Errorf("%s is not kept on uninstall", k)
		}
	}
	for _, ns := range []string{"fair-data", "fair-objects", "fair-identity", "openbao"} {
		if !namespaces[ns] {
			t.Errorf("no bundled namespace %s", ns)
		}
	}
	policies := map[string][]map[string]any{}
	for _, o := range all {
		if o["kind"] == "NetworkPolicy" {
			ns := dig(o, "metadata", "namespace").(string)
			policies[ns] = append(policies[ns], o)
		}
	}
	isDefaultDeny := func(p map[string]any) bool {
		types, _ := dig(p, "spec", "policyTypes").([]any)
		sel, _ := dig(p, "spec", "podSelector").(map[string]any)
		return len(sel) == 0 && slices.Contains(types, any("Ingress")) && slices.Contains(types, any("Egress")) &&
			dig(p, "spec", "ingress") == nil && dig(p, "spec", "egress") == nil
	}
	for ns := range namespaces {
		if !slices.ContainsFunc(policies[ns], isDefaultDeny) {
			t.Errorf("namespace %s has no default-deny policy", ns)
		}
	}

	// Workloads.
	tokenNeeded := map[string]bool{"Deployment/fair-data/cnpg-controller-manager": true} // drives the Kubernetes API
	for k, o := range bundled {
		switch o["kind"] {
		case "Deployment", "StatefulSet", "DaemonSet", "Job":
		default:
			continue
		}
		spec, _ := dig(o, "spec", "template", "spec").(map[string]any)
		labels, _ := dig(o, "spec", "template", "metadata", "labels").(map[string]any)
		ns := dig(o, "metadata", "namespace").(string)
		if dig(spec, "securityContext", "runAsNonRoot") != true || dig(spec, "securityContext", "seccompProfile", "type") != "RuntimeDefault" {
			t.Errorf("%s: pod security context %v", k, dig(spec, "securityContext"))
		}
		if uid, ok := dig(spec, "securityContext", "runAsUser").(float64); !ok || uid == 0 {
			t.Errorf("%s: runAsUser %v", k, dig(spec, "securityContext", "runAsUser"))
		}
		for _, f := range []string{"hostNetwork", "hostPID", "hostIPC"} {
			if spec[f] == true {
				t.Errorf("%s: %s", k, f)
			}
		}
		vols, _ := spec["volumes"].([]any)
		for _, v := range vols {
			if dig(v, "hostPath") != nil {
				t.Errorf("%s: hostPath volume %v", k, dig(v, "name"))
			}
		}
		if auto := spec["automountServiceAccountToken"]; auto != false && (!tokenNeeded[k] || auto != true) {
			t.Errorf("%s: automountServiceAccountToken %v", k, auto)
		}
		ctrs, _ := spec["containers"].([]any)
		inits, _ := spec["initContainers"].([]any)
		for _, c := range append(slices.Clone(ctrs), inits...) {
			name := dig(c, "name")
			sc := dig(c, "securityContext")
			if dig(sc, "allowPrivilegeEscalation") != false || dig(sc, "readOnlyRootFilesystem") != true || dig(sc, "privileged") == true ||
				!slices.Equal(anyStrings(dig(sc, "capabilities", "drop")), []string{"ALL"}) || dig(sc, "capabilities", "add") != nil {
				t.Errorf("%s/%v: security context %v", k, name, sc)
			}
			if dig(c, "resources", "limits", "memory") == nil {
				t.Errorf("%s/%v: no memory limit", k, name)
			}
			if dig(c, "livenessProbe") == nil || dig(c, "readinessProbe") == nil {
				t.Errorf("%s/%v: liveness and readiness probes required", k, name)
			}
			if img, _ := dig(c, "image").(string); !strings.Contains(img, "@sha256:") {
				t.Errorf("%s/%v: image %s not by digest", k, name, img)
			}
			envs, _ := dig(c, "env").([]any)
			for _, e := range envs {
				n, _ := dig(e, "name").(string)
				if secretEnvRE.MatchString(n) && !strings.HasSuffix(n, "_FILE") && dig(e, "valueFrom", "secretKeyRef") == nil {
					t.Errorf("%s/%v: %s is not from a Secret", k, name, n)
				}
			}
		}
		// An explicit policy for the workload.
		selected := slices.ContainsFunc(policies[ns], func(p map[string]any) bool {
			if isDefaultDeny(p) {
				return false
			}
			ml, _ := dig(p, "spec", "podSelector", "matchLabels").(map[string]any)
			for lk, lv := range ml {
				if labels[lk] != lv {
					return false
				}
			}
			return len(ml) > 0
		})
		if !selected {
			t.Errorf("%s: no explicit NetworkPolicy", k)
		}
	}

	// Policies: no ingress rule from everywhere, no open address range.
	for k, o := range bundled {
		if o["kind"] != "NetworkPolicy" {
			continue
		}
		ing, _ := dig(o, "spec", "ingress").([]any)
		for i, r := range ing {
			if from, _ := dig(r, "from").([]any); len(from) == 0 {
				t.Errorf("%s: ingress rule %d admits every source", k, i)
			}
		}
		b, _ := json.Marshal(o)
		if strings.Contains(string(b), `"0.0.0.0/0"`) || strings.Contains(string(b), `"::/0"`) {
			t.Errorf("%s: an open address range", k)
		}
	}

	// RBAC: Roles only, read or namespaced writes; no wildcard, no
	// escalation; bindings to a Role of their namespace.
	for k, o := range bundled {
		switch o["kind"] {
		case "ClusterRole", "ClusterRoleBinding":
			t.Errorf("%s: the chart holds cluster-scoped RBAC", k)
		case "Role":
			checkRules(t, k, o, false)
		case "RoleBinding":
			ns := dig(o, "metadata", "namespace")
			if dig(o, "roleRef", "kind") != "Role" {
				t.Errorf("%s binds a %v", k, dig(o, "roleRef", "kind"))
			}
			subs, _ := dig(o, "subjects").([]any)
			for _, s := range subs {
				if dig(s, "namespace") != ns {
					t.Errorf("%s: subject %v outside %v", k, s, ns)
				}
			}
		case "Secret":
			t.Errorf("%s: a Secret in the chart (credentials are fairctl's)", k)
		}
	}
	residue, err := readDocs(filepath.Join(root, "deploy/bundled/postgres/cluster/cluster-scoped.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range residue {
		k := d.kind + "/" + d.name
		j, _ := json.Marshal(d.obj)
		var o map[string]any
		_ = json.Unmarshal(j, &o)
		switch d.kind {
		case "ClusterRole":
			checkRules(t, k, o, true)
		case "ClusterRoleBinding":
			if !slices.ContainsFunc(residue, func(x doc) bool { return x.kind == "ClusterRole" && x.name == dig(o, "roleRef", "name") }) {
				t.Errorf("%s binds %v, not a residue ClusterRole", k, dig(o, "roleRef", "name"))
			}
		case "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration":
			hooks, _ := o["webhooks"].([]any)
			for _, h := range hooks {
				if dig(h, "failurePolicy") != "Fail" || dig(h, "clientConfig", "service", "namespace") != "fair-data" ||
					dig(h, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "fair-data" {
					t.Errorf("%s: webhook %v", k, dig(h, "name"))
				}
			}
		default:
			t.Errorf("%s: unexpected cluster-scoped residue", k)
		}
	}

	// TLS 1.2 or later everywhere, no FIPS-module exclusions configured.
	cm := func(ns, name, key string) string {
		s, _ := dig(bundled["ConfigMap/"+ns+"/"+name], "data", key).(string)
		if s == "" {
			t.Errorf("ConfigMap %s/%s has no %s", ns, name, key)
		}
		return s
	}
	envOf := func(k, ctr string) map[string]any {
		out := map[string]any{}
		cs, _ := dig(bundled[k], "spec", "template", "spec", "containers").([]any)
		for _, c := range cs {
			if dig(c, "name") != ctr {
				continue
			}
			es, _ := dig(c, "env").([]any)
			for _, e := range es {
				if v, ok := dig(e, "value").(string); ok {
					out[dig(e, "name").(string)] = v
				} else {
					out[dig(e, "name").(string)] = dig(e, "valueFrom")
				}
			}
		}
		return out
	}
	nats := cm("fair-platform", "nats-config", "nats.conf")
	for _, s := range []string{`min_version: "1.2"`, "handshake_first", "verify: true", "https: 0.0.0.0:8222", "cert_file: /etc/nats/tls/tls.crt"} {
		if !strings.Contains(nats, s) {
			t.Errorf("nats.conf lacks %q", s)
		}
	}
	if strings.Count(nats, `min_version: "1.2"`) != 2 {
		t.Error("nats.conf: TLS 1.2 floor on clients and routes")
	}
	if regexp.MustCompile(`(?m)^\s*(http|http_port|password|users|authorization|auth_callout|leafnodes|gateway|websocket|mqtt)\s*[:{=]`).MatchString(nats) {
		t.Error("nats.conf: a plain listener, a password or an auth callout")
	}
	bao := cm("openbao", "openbao-config", "openbao.hcl")
	for _, s := range []string{`tls_min_version = "tls12"`, "ui           = false", `tls_cert_file   = "/openbao/tls/tls.crt"`} {
		if !strings.Contains(bao, s) {
			t.Errorf("openbao.hcl lacks %q", s)
		}
	}
	if regexp.MustCompile(`tls_disable\s*=\s*(true|1|"true")|seal\s+"|pgp_keys`).MatchString(bao) {
		t.Error("openbao.hcl: TLS off, a seal outside D-OQ9's or PGP keys")
	}
	db := bundled["Cluster/fair-data/fair-db"]
	if dig(db, "spec", "postgresql", "parameters", "ssl_min_protocol_version") != "TLSv1.2" || dig(db, "spec", "postgresUID") != float64(65532) ||
		dig(db, "spec", "postgresGID") != float64(65532) || dig(db, "spec", "certificates", "serverTLSSecret") == nil ||
		!strings.HasPrefix(fmt.Sprint(dig(db, "spec", "imageName")), DefaultRegistry+"/fair-postgres@sha256:") {
		t.Errorf("Cluster fair-db: %v", dig(db, "spec"))
	}
	if hba := anyStrings(dig(db, "spec", "postgresql", "pg_hba")); len(hba) < 2 || hba[0] != "hostnossl all all 0.0.0.0/0 reject" || hba[1] != "hostnossl all all ::/0 reject" {
		t.Errorf("Cluster fair-db: pg_hba %v does not refuse plain connections first", hba)
	}
	op := envOf("Deployment/fair-data/cnpg-controller-manager", "manager")
	opImg := dig(dig(bundled["Deployment/fair-data/cnpg-controller-manager"], "spec", "template", "spec", "containers").([]any)[0], "image")
	if op["WATCH_NAMESPACE"] != "fair-data" || op["MANAGE_WEBHOOK_CONFIGURATIONS"] != "false" || op["WEBHOOK_CERT_DIR"] == nil ||
		op["OPERATOR_IMAGE_NAME"] != opImg || !strings.HasPrefix(fmt.Sprint(opImg), DefaultRegistry+"/mirror/cloudnative-pg@sha256:") {
		t.Errorf("CloudNativePG operator: env %v, image %v", op, opImg)
	}
	vgw := bundled["Deployment/fair-objects/versitygw"]
	vc := dig(vgw, "spec", "template", "spec", "containers").([]any)[0]
	if args := anyStrings(dig(vc, "args")); !slices.Contains(args, "posix") || !slices.Contains(args, "--iam-dir") ||
		slices.ContainsFunc(args, func(a string) bool { return slices.Contains([]string{"s3", "azure", "scoutfs", "plugin"}, a) }) {
		t.Errorf("versitygw args %v", args)
	}
	var subPaths []string
	for _, m := range dig(vc, "volumeMounts").([]any) {
		if dig(m, "name") == "data" {
			subPaths = append(subPaths, fmt.Sprint(dig(m, "subPath")))
		}
	}
	if !slices.Equal(subPaths, []string{"data", "versions", "iam"}) {
		t.Errorf("versitygw volume subPaths %v", subPaths)
	}
	kc := envOf("Deployment/fair-identity/keycloak", "keycloak")
	if kc["KC_HTTP_ENABLED"] != "false" || kc["KC_HTTPS_PROTOCOLS"] != "TLSv1.3,TLSv1.2" || kc["KC_HOSTNAME"] != "https://"+identityHost ||
		!strings.Contains(fmt.Sprint(kc["KC_DB_URL"]), "sslmode=verify-full") {
		t.Errorf("keycloak env %v", kc)
	}
	realm, err := os.ReadFile(filepath.Join(root, "deploy/keycloak/fair-realm.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cm("fair-identity", "keycloak-realm", "fair-realm.json") != strings.ReplaceAll(string(realm), "\r\n", "\n") {
		t.Error("the realm ConfigMap is not deploy/keycloak/fair-realm.json")
	}
	col, err := os.ReadFile(filepath.Join(root, "deploy/observability/collector-selfhosted.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c := cm("fair-platform", "otelcol-selfhosted", "config.yaml"); c != strings.ReplaceAll(string(col), "\r\n", "\n") || strings.Count(c, `min_version: "1.2"`) != 2 {
		t.Error("the Collector's ConfigMap is not deploy/observability's self-hosted configuration with TLS 1.2")
	}

	// The mirrored third parties of deploy/bundled/sources.json are those of
	// deploy/third-party-images.json, with the same publisher identity.
	var src struct {
		Sources []struct {
			Kind, Image string
			Identity    string `json:"certificate_identity"`
			Issuer      string `json:"certificate_oidc_issuer"`
		} `json:"sources"`
	}
	sb, err := os.ReadFile(filepath.Join(root, "deploy/bundled/sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(sb, &src); err != nil {
		t.Fatal(err)
	}
	l, err := LoadThirdParty(filepath.Join(root, "deploy/third-party-images.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range src.Sources {
		if s.Kind != "mirror" {
			continue
		}
		if !slices.ContainsFunc(l.Images, func(i ThirdParty) bool {
			return i.Image == s.Image && i.Identity == s.Identity && i.Issuer == s.Issuer
		}) {
			t.Errorf("mirrored source %s is not in deploy/third-party-images.json as pinned", s.Image)
		}
	}

	// The renderer refuses a cluster-scoped object in a bundled directory
	// and a mirror outside the registry the chart re-roots.
	bad := t.TempDir()
	if err := os.CopyFS(bad, os.DirFS(filepath.Join(root, "deploy/bundled"))); err != nil {
		t.Fatal(err)
	}
	crb := "\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: { name: x }\nrules: [{ apiGroups: [\"\"], resources: [secrets], verbs: [get] }]\n"
	f := filepath.Join(bad, "nats", "nats.yaml")
	b, _ := os.ReadFile(f)                                            // #nosec G304 -- a test directory
	if err := os.WriteFile(f, append(b, crb...), 0o600); err != nil { // #nosec G703 -- a test directory
		t.Fatal(err)
	}
	opts := ChartOptions{Options: Options{Release: "v0.0.0-test", Images: chartImages(), Deploy: filepath.Join(root, "deploy/k8s"),
		Keys: filepath.Join(root, "deploy/k8s/keys"), Mirror: chartMirror(t)}, Bundled: bad}
	if err := RenderChart(opts, filepath.Join(t.TempDir(), "c")); err == nil || !strings.Contains(err.Error(), "cluster-scoped") {
		t.Errorf("a ClusterRole in deploy/bundled: %v", err)
	}
	opts.Bundled = filepath.Join(root, "deploy/bundled")
	opts.Mirror = map[string]string{"x": "registry.example/mirror/x@sha256:" + strings.Repeat("0", 64)}
	if err := RenderChart(opts, filepath.Join(t.TempDir(), "c")); err == nil {
		t.Error("a mirror outside the chart's registry renders")
	}
}

// checkRules: no wildcard, no escalation verbs; cluster-scoped roles read
// only.
func checkRules(t *testing.T, k string, o map[string]any, clusterScoped bool) {
	t.Helper()
	rules, _ := o["rules"].([]any)
	for i, r := range rules {
		all := append(append(anyStrings(dig(r, "apiGroups")), anyStrings(dig(r, "resources"))...), anyStrings(dig(r, "verbs"))...)
		if slices.Contains(all, "*") {
			t.Errorf("%s: rule %d has a wildcard", k, i)
		}
		for _, v := range anyStrings(dig(r, "verbs")) {
			if slices.Contains([]string{"escalate", "bind", "impersonate"}, v) || clusterScoped && !slices.Contains([]string{"get", "list", "watch"}, v) {
				t.Errorf("%s: rule %d grants %s", k, i, v)
			}
		}
	}
}

func anyStrings(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

func mapsEqual(a, b map[string]any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// --- F-015's checks over each bundled render ---------------------------------

// renderReader serves a rendered chart as a cluster (the scanner fixtures'
// reader, F-015 T-28).
type renderReader struct{ objs map[string][]kube.Object }

func (r *renderReader) List(_ context.Context, res kube.Resource, ns string) ([]kube.Object, string, error) {
	if res.Plural == "externalsecrets" {
		return nil, "", kube.ErrNotFound // no External Secrets operator self-hosted
	}
	var out []kube.Object
	for _, o := range r.objs[res.Plural] {
		if !res.Namespaced || ns == "" || o.Metadata.Namespace == ns {
			out = append(out, o)
		}
	}
	return out, "1", nil
}

func (r *renderReader) Watch(ctx context.Context, _ kube.Resource, _, _ string, _ func(kube.Event) error) error {
	<-ctx.Done()
	return nil
}

func (r *renderReader) add(t *testing.T, o map[string]any) {
	t.Helper()
	plural := map[string]string{
		"Namespace": "namespaces", "Node": "nodes", "Pod": "pods", "Service": "services", "ServiceAccount": "serviceaccounts",
		"NetworkPolicy": "networkpolicies", "Role": "roles", "RoleBinding": "rolebindings", "ClusterRole": "clusterroles",
		"ClusterRoleBinding": "clusterrolebindings", "StorageClass": "storageclasses", "PersistentVolumeClaim": "persistentvolumeclaims",
		"ValidatingAdmissionPolicy": "validatingadmissionpolicies", "ValidatingWebhookConfiguration": "validatingwebhookconfigurations",
	}[fmt.Sprint(o["kind"])]
	if plural == "" {
		return // what the checks do not read
	}
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var ko kube.Object
	if err := json.Unmarshal(raw, &ko); err != nil {
		t.Fatal(err)
	}
	ko.Raw = raw
	r.objs[plural] = append(r.objs[plural], ko)
}

// cluster turns a render into what a cluster serves once it is applied:
// workloads as running pods of their templates, claims of StatefulSets and
// Clusters, plus a compliant cluster (an attested FIPS node, an encrypted
// default StorageClass, a signature-verifying admission policy) and, with
// the bundled PostgreSQL, fairctl's cluster-scoped residue.
func cluster(t *testing.T, objs objects) *renderReader {
	t.Helper()
	r := &renderReader{objs: map[string][]kube.Object{}}
	for _, k := range slices.Sorted(maps.Keys(objs)) {
		o := cloneJSON(objs[k])
		if dig(o, "metadata", "annotations", "helm.sh/hook") != nil {
			continue // hooks run before the release and are gone
		}
		ns, _ := dig(o, "metadata", "namespace").(string)
		name, _ := dig(o, "metadata", "name").(string)
		switch o["kind"] {
		case "Deployment", "StatefulSet":
			tmpl, _ := dig(o, "spec", "template").(map[string]any)
			labels, _ := dig(tmpl, "metadata", "labels").(map[string]any)
			owner := map[string]any{"kind": o["kind"], "name": name}
			pod := name + "-0"
			if o["kind"] == "Deployment" {
				labels["pod-template-hash"] = "5f6d7c8b9"
				owner = map[string]any{"kind": "ReplicaSet", "name": name + "-5f6d7c8b9"}
				pod = name + "-5f6d7c8b9-ref00"
			}
			spec, _ := tmpl["spec"].(map[string]any)
			status := map[string]any{}
			for _, cs := range []string{"containers", "initContainers"} {
				list, _ := spec[cs].([]any)
				var st []any
				for _, c := range list {
					st = append(st, map[string]any{"name": dig(c, "name"), "image": dig(c, "image"), "imageID": dig(c, "image")})
				}
				status[map[string]string{"containers": "containerStatuses", "initContainers": "initContainerStatuses"}[cs]] = st
			}
			r.add(t, map[string]any{"apiVersion": "v1", "kind": "Pod",
				"metadata": map[string]any{"name": pod, "namespace": ns, "labels": labels, "ownerReferences": []any{owner}},
				"spec":     spec, "status": status})
			vcts, _ := dig(o, "spec", "volumeClaimTemplates").([]any)
			for _, v := range vcts {
				r.add(t, map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim",
					"metadata": map[string]any{"name": fmt.Sprintf("%v-%s-0", dig(v, "metadata", "name"), name), "namespace": ns}, "spec": dig(v, "spec")})
			}
		case "Cluster":
			r.add(t, map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim",
				"metadata": map[string]any{"name": name + "-1", "namespace": ns}, "spec": map[string]any{"accessModes": []any{"ReadWriteOnce"}}})
		default:
			r.add(t, o)
		}
	}
	if _, ok := objs["Cluster/fair-data/fair-db"]; ok {
		ds, err := readDocs(filepath.Join(root, "deploy/bundled/postgres/cluster/cluster-scoped.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			r.add(t, cloneJSON(d.obj))
		}
	}
	r.add(t, map[string]any{"apiVersion": "v1", "kind": "Node", "metadata": map[string]any{"name": "node-0", "labels": map[string]any{checks.LabelFIPS: "attested"}}})
	r.add(t, map[string]any{"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", "provisioner": "example.com/csi",
		"metadata": map[string]any{"name": "encrypted", "annotations": map[string]any{
			"storageclass.kubernetes.io/is-default-class": "true", checks.AnnotationEncrypted: "true"}}})
	r.add(t, map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
		"metadata": map[string]any{"name": "image-signatures", "annotations": map[string]any{checks.AnnotationVerifiesSignatures: "true"}},
		"spec":     map[string]any{"failurePolicy": "Fail"}})
	return r
}

// goodTLS serves TLS 1.2+ with a certificate valid for a year: the
// rendered Services' endpoints (their TLS configuration is
// TestBundledManifests').
func goodTLS(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "endpoint"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_ = c.(*tls.Conn).HandshakeContext(context.Background())
				_ = c.Close()
			}()
		}
	}()
	return lis.Addr().String()
}

// releaseManifest signs a release manifest for a render: its images (the
// release's and the mirrored copies) and the RBAC of deploy/k8s plus, with
// the bundled PostgreSQL, the operator's Role and fairctl's residue.
func releaseManifest(t *testing.T, objs objects) (string, *ecdsa.PublicKey) {
	t.Helper()
	dirs := []string{filepath.Join(root, "deploy/k8s")}
	if _, ok := objs["Cluster/fair-data/fair-db"]; ok {
		dirs = append(dirs, filepath.Join(root, "deploy/bundled/postgres"), filepath.Join(root, "deploy/bundled/postgres/cluster"))
	}
	rbac, err := releasemanifest.RBACFromDir(dirs...)
	if err != nil {
		t.Fatal(err)
	}
	m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: "0.0.0-test", RBAC: rbac, Images: chartImages()}
	m.EngineValidation = &releasemanifest.EngineValidation{Image: m.Images[releasemanifest.EngineComponent], SuiteVersion: "1",
		EngineVersion: "1", Architecture: "amd64", Passed: true, RunAtUnixMS: 1, RecordSHA256: strings.Repeat("0", 64)}
	for _, to := range chartMirror(t) {
		m.Images["mirror-"+strings.SplitN(strings.TrimPrefix(to, DefaultRegistry+"/mirror/"), "@", 2)[0]] = to
	}
	b, err := releasemanifest.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, err := profilepkg.Sign(key, b)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "release-manifest.json")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file+".sig", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	return file, &key.PublicKey
}

// TestBundledChecks (F-014 T-08, AC-03; F-015 T-28): F-015's deployment
// checks, the scanner's catalog, find nothing in the chart rendered with
// each bundled dependency and with all of them, applied to a compliant
// cluster, over the platform's and every bundled namespace.
func TestBundledChecks(t *testing.T) {
	chart := renderChart(t)
	vals, _ := exampleValues(t)
	configs := map[string]map[string]any{"none": vals, "all": allBundled(vals)}
	for _, b := range Bundled {
		configs[b.Value] = withBundled(vals, b)
	}
	tlsAddr := goodTLS(t)
	for _, name := range slices.Sorted(maps.Keys(configs)) {
		t.Run(name, func(t *testing.T) {
			objs := chartObjects(t, chart, configs[name])
			r := cluster(t, objs)
			var scope scanner.Scope
			scope.ProbeNamespace = "fair-fips-probe"
			for _, o := range r.objs["namespaces"] {
				if o.Metadata.Name != scope.ProbeNamespace {
					scope.Namespaces = append(scope.Namespaces, o.Metadata.Name)
				}
			}
			sort.Strings(scope.Namespaces)
			manifest, pub := releaseManifest(t, objs)
			cfg := checks.Config{ReleaseManifest: manifest, ReleaseKey: pub, Dial: func(ctx context.Context, addr string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(addr)
				if !strings.HasSuffix(host, ".svc") {
					return nil, fmt.Errorf("no route to %s", addr)
				}
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", tlsAddr)
			}}
			for _, c := range checks.Catalog(cfg) {
				res, err := c.Run(context.Background(), r, scope)
				if err != nil {
					t.Fatalf("%s: %v", c.ID(), err)
				}
				for _, f := range res.Findings {
					t.Errorf("%s: %s %s %s", c.ID(), f.Severity, f.Subject, f.DetailJSON)
				}
			}
			if name == "all" && len(scope.Namespaces) < 5 {
				t.Errorf("scope %v: the bundled namespaces are missing", scope.Namespaces)
			}
		})
	}
}
