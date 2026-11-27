package fleet

// F-014 T-06 (F-014-AC-01, AC-03, AC-04; design §3.2; ADR-019): the
// fair-platform Helm chart, a second output of the fleet render. RenderChart
// shares build (loading deploy/k8s, image substitution, the key-mount
// patches) with Render and writes the rendered objects as the chart's
// templates. Only these become values:
//
//   - each placeholder of Variables the chart's objects use (ChartVariables),
//     and the store and size settings the SaaS patches of
//     deploy/fleet/flux/release.yaml set (ChartEnv), each as one quoted
//     value at the place the reference manifest names;
//   - the registry prefix of the release's images (global.registry), never a
//     tag: every image is named by the release's digest;
//   - the replica counts of the Deployments the reference runs with two or
//     more replicas;
//   - the key store, selecting one of two patch sets merged in at render
//     time: Kubernetes Secrets (deploy/k8s/keys/secret-mounts.yaml) or
//     OpenBao Agent sidecars (deploy/k8s/keys/openbao); the SaaS External
//     Secrets stay in the fleet artifact only;
//   - the scanner and fips-probe switches (whole files of objects);
//   - the bundled dependencies (F-014 T-08; design §3.3): one switch
//     <dependency>.bundled per directory of deploy/bundled (Bundled), each
//     including every object of that directory and nothing else, and the
//     bundled Keycloak's public host (keycloak.host).
//
// values.schema.json is closed (additionalProperties: false everywhere) and
// every value is a pattern-checked string, an enum, a bounded integer or a
// switch, so no value reaches a security context, a capability, a probe,
// RBAC, an image tag or any field but the placeholder it fills
// (TestChartValuesSchema). TestChartMatchesFleet holds the chart's objects
// equal to the fleet artifact's for the same variables.
//
// Hooks: the in-cluster preflight (deploy/k8s/hooks, weight -10) and the
// iam-migrate Job with its ServiceAccount and egress policy (weight 0 and
// -5) run before every install and upgrade. Namespaces are kept on
// uninstall (helm.sh/resource-policy: keep): they hold the customer's data.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Chart names and choices.
const (
	ChartName        = "fair-platform"
	DefaultRegistry  = "ghcr.io/rformer"
	KeyStoreSecrets  = "kubernetes-secrets" // #nosec G101 -- a key store's name, not a credential
	KeyStoreOpenBao  = "openbao"
	OpenBaoComponent = "openbao" // the release's OpenBao image (the agent sidecars)
	FairctlComponent = "fairctl" // the hooks' image
	// MinKubeVersion: the OpenBao Agent runs as a native sidecar.
	MinKubeVersion = ">=1.29.0-0"
)

// ChartVariables maps the fleet variables the chart's objects use to their
// values. FAIR_INSTANCE and FAIR_REGION are the SaaS key store's only.
var ChartVariables = map[string]string{
	"FAIR_DB_HOST":        "database.host",
	"FAIR_PLATFORM_HOST":  "platform.host",
	"FAIR_INGRESS_HOST":   "ingress.host",
	"FAIR_INGRESS_CIDR":   "ingress.cidr",
	"FAIR_APISERVER_CIDR": "apiServer.cidr",
	ModeVariable:          "mode",
	"FAIR_IDENTITY_HOST":  "keycloak.host",
}

// BundledVariables are the placeholders only deploy/bundled uses (the
// fleet runs no bundled dependency), each a chart variable.
var BundledVariables = map[string]string{
	"REPLACE_WITH_IDENTITY_HOST": "FAIR_IDENTITY_HOST",
}

// BundledDependency is one bundled dependency (F-014 T-08; design §3.3,
// ADR-005's table): a directory of deploy/bundled, a kustomization whose
// resources and generated ConfigMaps the switch <Value>.bundled includes.
type BundledDependency struct {
	Dir, Value, Doc string
}

// Bundled are the chart's bundled dependencies. Each is off by default
// (brought); none holds a cluster-scoped object but its namespace
// (RenderChart refuses one): what the CloudNativePG operator needs at
// cluster scope is fairctl's (deploy/bundled/postgres/cluster).
var Bundled = []BundledDependency{
	{"postgres", "postgres", "Run the bundled PostgreSQL 16 (CloudNativePG, operator namespace-scoped in fair-data; set database.host to fair-db-rw.fair-data.svc). fairctl installs the operator's CRDs and cluster-scoped reads first."},
	{"nats", "nats", "Run the bundled NATS JetStream (three servers in fair-platform, TLS)."},
	{"object-store", "objectStore", "Run the bundled object store, versitygw (fair-objects, one replica, software WORM: ADR-020); set stores.*.endpoint to versitygw.fair-objects.svc:443."},
	{"keycloak", "keycloak", "Run the bundled Keycloak with the FAIR realm (fair-identity); needs postgres.bundled and keycloak.host."},
	{"openbao", "openbao", "Run the bundled OpenBao (namespace openbao, raft, TLS), the key store of keyStore.kind openbao."},
	{"collector", "collector", "Run the bundled OpenTelemetry Collector with the self-hosted configuration (fair-platform; nothing leaves the installation)."},
}

// ChartEnv maps environment variables whose value is the instance's (the
// SaaS patches set them) to their values; the reference's literal, when it
// is not a placeholder, is the default.
var ChartEnv = map[string]string{
	"FAIR_AUDIT_STORE_BUCKET":    "stores.audit.bucket",
	"FAIR_AUDIT_STORE_ENDPOINT":  "stores.audit.endpoint",
	"FAIR_AUDIT_STORE_REGION":    "stores.audit.region",
	"FAIR_REPORT_STORE_BUCKET":   "stores.report.bucket",
	"FAIR_REPORT_STORE_ENDPOINT": "stores.report.endpoint",
	"FAIR_REPORT_STORE_REGION":   "stores.report.region",
	"FAIR_AUDIT_STORAGE_QUOTA":   "audit.storageQuota",
}

// ChartSwitches are the deploy/k8s files whose objects (but namespaces) a
// switch includes.
var ChartSwitches = map[string]string{
	"posture-scanner.yaml": "scanner.enabled",
	"fips-probe.yaml":      "fipsProbe.enabled",
}

// Value kinds: each value's schema.
const (
	kindHost     = "host"
	kindCIDR     = "cidr"
	kindHostPort = "host-port"
	kindBucket   = "bucket"
	kindRegion   = "region"
	kindSize     = "size"
	kindRegistry = "registry"
	kindMode     = "mode"
	kindKeyStore = "key-store"
	kindSwitch   = "switch"
	kindReplicas = "replicas"
	kindOptHost  = "optional-host" // a host, or "" while its dependency is not bundled
)

const (
	hostPattern = `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*`
	octet       = `(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`
)

// valueSchemas: no value can hold a quote, a space, a brace or a newline.
// A CIDR is IPv4 with a prefix of 8 to 32 bits: it fills one ipBlock the
// reference names and cannot open a rule to every address.
var valueSchemas = map[string]map[string]any{
	kindHost:     {"type": "string", "maxLength": 253, "pattern": "^" + hostPattern + "$"},
	kindOptHost:  {"type": "string", "maxLength": 253, "pattern": "^(" + hostPattern + ")?$"},
	kindCIDR:     {"type": "string", "pattern": `^(` + octet + `\.){3}` + octet + `/([89]|[12][0-9]|3[0-2])$`},
	kindHostPort: {"type": "string", "maxLength": 259, "pattern": "^" + hostPattern + `:[1-9][0-9]{0,4}$`},
	kindBucket:   {"type": "string", "pattern": `^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`},
	kindRegion:   {"type": "string", "pattern": `^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`},
	kindSize:     {"type": "string", "pattern": `^[1-9][0-9]{0,5}(GiB|TiB)$`},
	kindRegistry: {"type": "string", "maxLength": 255, "pattern": "^" + hostPattern + `(:[1-9][0-9]{0,4})?(/[a-z0-9]([a-z0-9._-]{0,126}[a-z0-9])?)*$`},
	kindMode:     {"type": "string", "enum": []any{"self-hosted", "air-gapped"}},
	kindKeyStore: {"type": "string", "enum": []any{KeyStoreSecrets, KeyStoreOpenBao}},
	kindSwitch:   {"type": "boolean"},
	kindReplicas: {"type": "integer", "minimum": 2, "maximum": 20},
}

// chartValue is one value of the chart.
type chartValue struct {
	path, kind, doc string
	def             any
}

// staticValues are the chart's values but the replica counts.
var staticValues = []chartValue{
	{"global.registry", kindRegistry, "Registry and path the release's images are pulled from (a mirror in air-gapped installs). Images are always named by the release's signed digest, never by a tag.", DefaultRegistry},
	{"mode", kindMode, "Deployment mode (ADR-005): self-hosted or air-gapped. SaaS instances run the fleet artifact, not this chart.", "self-hosted"},
	{"keyStore.kind", kindKeyStore, "Where the services' keys come from: kubernetes-secrets (Secrets fair-<service>-<dir>, mounted read-only) or openbao (OpenBao Agent sidecars). fairctl generates the keys into it.", KeyStoreSecrets},
	{"database.host", kindHost, "PostgreSQL host name (TLS verify-full).", ""},
	{"platform.host", kindHost, "The platform's public host name (the gateway's Ingress, links in notifications).", ""},
	{"ingress.host", kindHost, "The ingress the scanner probes for TLS.", ""},
	{"ingress.cidr", kindCIDR, "Address range of the ingress controller or load balancer (the gateway's ingress rule and trusted proxies).", ""},
	{"apiServer.cidr", kindCIDR, "Address range of the Kubernetes API server endpoints (the scanner's and the preflight's egress).", ""},
	{"stores.audit.bucket", kindBucket, "The audit store's bucket (versioning and compliance-mode Object Lock).", ""},
	{"stores.audit.endpoint", kindHostPort, "The audit store's S3 endpoint, host:port (TLS).", ""},
	{"stores.audit.region", kindRegion, "The audit store's region.", nil},
	{"stores.report.bucket", kindBucket, "The report store's bucket (versioned).", ""},
	{"stores.report.endpoint", kindHostPort, "The report store's S3 endpoint, host:port (TLS).", ""},
	{"stores.report.region", kindRegion, "The report store's region.", nil},
	{"audit.storageQuota", kindSize, "Storage the audit trail may use in the database (FAIR_AUDIT_STORAGE_QUOTA; sizing guide).", nil},
	{"scanner.enabled", kindSwitch, "Run posture-scanner: only when the administrator granted it Kubernetes access (consent, F-015 T-30).", true},
	{"fipsProbe.enabled", kindSwitch, "Run fips-probe on every node (node FIPS evidence by probe; off when nodes are attested by label).", true},
	{"keycloak.host", kindOptHost, "The bundled Keycloak's public host name (its own origin, not the platform's); required with keycloak.bundled.", ""},
}

// chartValues are the static values and a switch per bundled dependency.
func chartValues() []chartValue {
	vs := slices.Clone(staticValues)
	for _, b := range Bundled {
		vs = append(vs, chartValue{b.Value + ".bundled", kindSwitch, b.Doc, false})
	}
	return vs
}

// bundledRules are the schema's conditions between values: the bundled
// Keycloak keeps its database in the bundled PostgreSQL and needs its host.
func bundledRules() []any {
	on := func(dep string) map[string]any {
		return map[string]any{"properties": map[string]any{dep: map[string]any{"properties": map[string]any{"bundled": map[string]any{"const": true}}}}}
	}
	then := on("postgres")
	then["properties"].(map[string]any)["keycloak"] = map[string]any{"properties": map[string]any{"host": map[string]any{"minLength": 1}}}
	return []any{map[string]any{"if": on("keycloak"), "then": then}}
}

// ChartOptions are RenderChart's inputs.
type ChartOptions struct {
	Options               // Observability is not used: the chart has no SaaS Collector
	Hooks          string // deploy/k8s/hooks: the chart-only hook objects ("" for none)
	ManifestDigest string // SHA-256 of the signed release-manifest.json ("" for none)
	// Bundled is deploy/bundled ("" for none): the bundled dependencies'
	// directories (Bundled). Their third-party images must be in
	// Options.Mirror, mirrored under DefaultRegistry.
	Bundled string
}

// ManifestDigest is the SHA-256 of a release manifest file, for
// ChartOptions.ManifestDigest.
func ManifestDigest(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- release-pipeline input
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// chartDoc is one object of the chart: its template file, the conditions it
// is rendered under, and its YAML.
type chartDoc struct {
	file  string
	conds []string
	node  *yaml.Node
}

var chartVersionRE = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)

// RenderChart writes the fair-platform chart into out (created; must not
// exist).
func RenderChart(o ChartOptions, out string) error {
	if err := checkOptions(o.Options, out); err != nil {
		return err
	}
	if !chartVersionRE.MatchString(o.Release) {
		return fmt.Errorf("fleet: release %q is not a semantic version (vX.Y.Z)", o.Release)
	}
	opts := o.Options
	opts.Observability = ""
	a, err := build(opts, true)
	if err != nil {
		return err
	}
	patches := map[string]map[string]*yaml.Node{KeyStoreSecrets: {}, KeyStoreOpenBao: {}}
	var docs []chartDoc
	for _, f := range a.files {
		for _, d := range f.docs {
			n, err := parseNode(d.text)
			if err != nil {
				return fmt.Errorf("%s/%s: %w", f.dir, f.name, err)
			}
			switch f.dir {
			case DirSecrets, DirObservability:
				// The SaaS key store and Collector are the fleet's only.
			case DirNamespaces:
				// Never switched: a namespace and its default deny stay
				// whichever workloads run in it.
				setAnnotation(n, "helm.sh/resource-policy", "keep")
				docs = append(docs, chartDoc{"namespaces.yaml", nil, n})
			case DirMigrate:
				weight := "-5" // the Job's ServiceAccount and egress first
				if mapGet(n.Content[0], "kind").Value == "Job" {
					weight = "0"
				}
				setAnnotation(n, "helm.sh/hook", "pre-install,pre-upgrade")
				setAnnotation(n, "helm.sh/hook-weight", weight)
				setAnnotation(n, "helm.sh/hook-delete-policy", "before-hook-creation")
				docs = append(docs, chartDoc{"hooks/" + strings.TrimSuffix(f.name, ".yaml") + "-migrate.yaml", nil, n})
			case DirPlatform:
				if name, ok := strings.CutPrefix(filepath.ToSlash(f.name), "keys/"); ok {
					patches[KeyStoreSecrets][strings.TrimSuffix(name, ".yaml")] = n
					continue
				}
				docs = append(docs, chartDoc{f.name, switchConds(d.source), n})
			}
		}
	}
	extra, err := openBaoSet(o, patches[KeyStoreOpenBao])
	if err != nil {
		return err
	}
	docs = append(docs, extra...)
	if o.Hooks != "" {
		hooks, err := readHooks(o)
		if err != nil {
			return err
		}
		docs = append(docs, hooks...)
	}
	if o.Bundled != "" {
		bundled, err := readBundled(o)
		if err != nil {
			return err
		}
		docs = append(docs, bundled...)
	}

	// The key stores: each patched Deployment once per store, its patch
	// merged in.
	var expanded []chartDoc
	for _, d := range docs {
		top := d.node.Content[0]
		name := mapGet(mapGet(top, "metadata"), "name")
		if mapGet(top, "kind").Value != "Deployment" || name == nil {
			expanded = append(expanded, d)
			continue
		}
		sp, op := patches[KeyStoreSecrets][name.Value], patches[KeyStoreOpenBao][name.Value]
		if sp == nil && op == nil {
			expanded = append(expanded, d)
			continue
		}
		if sp == nil || op == nil {
			return fmt.Errorf("fleet: Deployment %s has key mounts for one key store only", name.Value)
		}
		for _, ks := range []struct {
			kind  string
			patch *yaml.Node
		}{{KeyStoreSecrets, sp}, {KeyStoreOpenBao, op}} {
			n := copyNode(d.node)
			if err := mergeNode(n.Content[0], ks.patch.Content[0], ""); err != nil {
				return fmt.Errorf("fleet: Deployment %s, %s key mounts: %w", name.Value, ks.kind, err)
			}
			expanded = append(expanded, chartDoc{d.file, append(slices.Clone(d.conds), keyStoreCond(ks.kind)), n})
		}
	}

	t := &templater{defaults: map[string]any{}, replicas: map[string]int{}}
	files := map[string][]string{}
	var order []string
	for _, d := range expanded {
		text, err := t.template(d.node)
		if err != nil {
			return fmt.Errorf("fleet: %s: %w", d.file, err)
		}
		if _, ok := files[d.file]; !ok {
			order = append(order, d.file)
		}
		files[d.file] = append(files[d.file], wrap(d.conds, text))
	}
	for _, v := range chartValues() {
		if v.kind != kindSwitch && v.kind != kindKeyStore && !t.used[v.path] {
			return fmt.Errorf("fleet: chart value %s fills no placeholder of the release", v.path)
		}
	}
	values, schema := t.values()
	return writeChart(o, out, order, files, values, schema)
}

// switchConds are the switch conditions of a deploy/k8s file's objects.
func switchConds(source string) []string {
	if v, ok := ChartSwitches[source]; ok {
		return []string{".Values." + v}
	}
	return nil
}

func keyStoreCond(kind string) string {
	return fmt.Sprintf("eq .Values.keyStore.kind %q", kind)
}

// wrap renders a document under its conditions.
func wrap(conds []string, text string) string {
	switch len(conds) {
	case 0:
		return "---\n" + text
	case 1:
		return "---\n{{- if " + conds[0] + " }}\n" + text + "{{- end }}\n"
	default:
		parts := make([]string, len(conds))
		for i, c := range conds {
			parts[i] = "(" + c + ")"
		}
		return "---\n{{- if and " + strings.Join(parts, " ") + " }}\n" + text + "{{- end }}\n"
	}
}

var openBaoImageRE = regexp.MustCompile(`(?m)^(\s*(?:-\s*)?image:\s*)quay\.io/openbao/openbao:[^\s@]+@sha256:[0-9a-f]{64}\s*$`)

// openBaoSet reads the OpenBao key store: sidecar patches of the release's
// Deployments, its other objects and the agent's ConfigMap
// (keys/openbao/kustomization.yaml's generator). The agent runs the
// release's OpenBao image (built from source with the FIPS module, F-014
// T-07), never the upstream one.
func openBaoSet(o ChartOptions, patches map[string]*yaml.Node) ([]chartDoc, error) {
	dir := filepath.Join(o.Keys, "openbao")
	if o.Keys == "" {
		return nil, errors.New("fleet: the chart needs the key store manifests (-keys)")
	}
	ds, err := readDocs(filepath.Join(dir, "sidecars.yaml"))
	if err != nil {
		return nil, err
	}
	agent, ok := o.Images[OpenBaoComponent]
	if !ok {
		return nil, fmt.Errorf("fleet: no %s image for the OpenBao Agent sidecars", OpenBaoComponent)
	}
	var docs []chartDoc
	for _, d := range ds {
		text := openBaoImageRE.ReplaceAllString(d.text, "${1}"+agent)
		text, err := substitute(text, o.Images)
		if err == nil {
			text, err = mirrorImages(text, o.Images, o.Mirror)
		}
		if err != nil {
			return nil, fmt.Errorf("keys/openbao/sidecars.yaml: %w", err)
		}
		n, err := parseNode(text)
		if err != nil {
			return nil, err
		}
		if d.kind == "Deployment" {
			patches[d.name] = n
			continue
		}
		docs = append(docs, chartDoc{"keys-openbao.yaml", []string{keyStoreCond(KeyStoreOpenBao)}, n})
	}
	b, err := os.ReadFile(filepath.Join(dir, "kustomization.yaml")) // #nosec G304 -- the repository's own files
	if err != nil {
		return nil, err
	}
	var k struct {
		Namespace          string `yaml:"namespace"`
		ConfigMapGenerator []struct {
			Name  string   `yaml:"name"`
			Files []string `yaml:"files"`
		} `yaml:"configMapGenerator"`
	}
	if err := yaml.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("keys/openbao/kustomization.yaml: %w", err)
	}
	for _, g := range k.ConfigMapGenerator {
		data := map[string]any{}
		for _, f := range g.Files {
			c, err := os.ReadFile(filepath.Join(dir, f)) // #nosec G304 -- the repository's own files
			if err != nil {
				return nil, err
			}
			data[f] = strings.ReplaceAll(string(c), "\r\n", "\n")
		}
		cm := map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": g.Name, "namespace": k.Namespace},
			"data":       data,
		}
		var n yaml.Node
		if err := n.Encode(cm); err != nil {
			return nil, err
		}
		n.HeadComment = "Generated from deploy/k8s/keys/openbao (its configMapGenerator)."
		docs = append(docs, chartDoc{"keys-openbao.yaml", []string{keyStoreCond(KeyStoreOpenBao)}, &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{&n}}})
	}
	return docs, nil
}

// readHooks reads the chart-only hook objects; each must be a Helm hook.
func readHooks(o ChartOptions) ([]chartDoc, error) {
	srcs, err := filepath.Glob(filepath.Join(o.Hooks, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(srcs)
	var docs []chartDoc
	for _, src := range srcs {
		ds, err := readDocs(src)
		if err != nil {
			return nil, err
		}
		for _, d := range ds {
			if _, ok := dig(d.obj, "metadata", "annotations", "helm.sh/hook").(string); !ok {
				return nil, fmt.Errorf("%s: %s %s is not a Helm hook", src, d.kind, d.name)
			}
			text, err := substitute(d.text, o.Images)
			if err == nil {
				text, err = mirrorImages(text, o.Images, o.Mirror)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", src, err)
			}
			n, err := parseNode(text)
			if err != nil {
				return nil, err
			}
			docs = append(docs, chartDoc{"hooks/" + filepath.Base(src), nil, n})
		}
	}
	return docs, nil
}

// bundledKustomization is what RenderChart reads of a bundled dependency's
// kustomization.yaml (the same file `kubectl kustomize` builds, so the
// directory validates on its own: scripts/fleet-check.sh).
type bundledKustomization struct {
	Resources          []string `yaml:"resources"`
	ConfigMapGenerator []struct {
		Name      string   `yaml:"name"`
		Namespace string   `yaml:"namespace"`
		Files     []string `yaml:"files"`
	} `yaml:"configMapGenerator"`
}

// bundledClusterScoped are the cluster-scoped kinds a bundled directory may
// hold.
var bundledClusterScoped = []string{"Namespace"}

// readBundled reads every bundled dependency's objects, each under its
// switch. Namespaces are kept on uninstall (they hold the dependencies'
// data); any other cluster-scoped object is refused (the platform holds no
// cluster-wide rights; fairctl installs what an operator needs there).
func readBundled(o ChartOptions) ([]chartDoc, error) {
	for c, to := range o.Mirror {
		if !strings.HasPrefix(to, DefaultRegistry+"/") {
			return nil, fmt.Errorf("fleet: the chart's copy of %s must be under %s (global.registry): %s", c, DefaultRegistry, to)
		}
	}
	var docs []chartDoc
	for _, b := range Bundled {
		dir := filepath.Join(o.Bundled, b.Dir)
		kb, err := os.ReadFile(filepath.Join(dir, "kustomization.yaml")) // #nosec G304 -- the repository's own files
		if err != nil {
			return nil, err
		}
		var k bundledKustomization
		if err := yaml.Unmarshal(kb, &k); err != nil {
			return nil, fmt.Errorf("%s/kustomization.yaml: %w", dir, err)
		}
		file := "bundled-" + b.Dir + ".yaml"
		cond := []string{".Values." + b.Value + ".bundled"}
		for _, r := range k.Resources {
			ds, err := readDocs(filepath.Join(dir, filepath.FromSlash(r)))
			if err != nil {
				return nil, err
			}
			for _, d := range ds {
				if d.namespace == "" && !slices.Contains(bundledClusterScoped, d.kind) {
					return nil, fmt.Errorf("%s/%s: %s %s is cluster-scoped: the chart holds no cluster-scoped object of a bundled dependency", b.Dir, r, d.kind, d.name)
				}
				text, err := substitute(d.text, o.Images)
				if err == nil {
					text, err = mirrorImages(text, o.Images, o.Mirror)
				}
				if err != nil {
					return nil, fmt.Errorf("%s/%s: %w", b.Dir, r, err)
				}
				n, err := parseNode(text)
				if err != nil {
					return nil, fmt.Errorf("%s/%s: %w", b.Dir, r, err)
				}
				if d.kind == "Namespace" {
					setAnnotation(n, "helm.sh/resource-policy", "keep")
				}
				docs = append(docs, chartDoc{file, cond, n})
			}
		}
		for _, g := range k.ConfigMapGenerator {
			data := map[string]any{}
			for _, f := range g.Files {
				key, src, ok := strings.Cut(f, "=")
				if !ok {
					key, src = filepath.Base(f), f
				}
				c, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(src))) // #nosec G304 -- the repository's own files
				if err != nil {
					return nil, err
				}
				data[key] = strings.ReplaceAll(string(c), "\r\n", "\n")
			}
			cm := map[string]any{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata":   map[string]any{"name": g.Name, "namespace": g.Namespace},
				"data":       data,
			}
			var n yaml.Node
			if err := n.Encode(cm); err != nil {
				return nil, err
			}
			n.HeadComment = "Generated from deploy/bundled/" + b.Dir + " (its configMapGenerator)."
			docs = append(docs, chartDoc{file, cond, &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{&n}}})
		}
	}
	return docs, nil
}

func parseNode(text string) (*yaml.Node, error) {
	if strings.Contains(text, tokenPrefix) {
		return nil, fmt.Errorf("the text holds %s", tokenPrefix)
	}
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(text), &n); err != nil {
		return nil, err
	}
	if n.Kind != yaml.DocumentNode || len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode || mapGet(n.Content[0], "kind") == nil {
		return nil, errors.New("not a Kubernetes object")
	}
	return &n, nil
}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func copyNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, x := range n.Content {
		c.Content[i] = copyNode(x)
	}
	return &c
}

func setAnnotation(doc *yaml.Node, key, value string) {
	md := mapGet(doc.Content[0], "metadata")
	ann := mapGet(md, "annotations")
	if ann == nil {
		ann = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		md.Content = append(md.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "annotations"}, ann)
	}
	v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: yaml.DoubleQuotedStyle}
	if old := mapGet(ann, key); old != nil {
		*old = *v
		return
	}
	ann.Content = append(ann.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

// mergeKeys are the strategic-merge keys of the lists the key-mount patches
// touch (Kubernetes' patchMergeKey for each); a patch with another list is
// refused rather than merged differently from kustomize.
var mergeKeys = map[string]string{
	"containers":     "name",
	"initContainers": "name",
	"env":            "name",
	"volumes":        "name",
	"volumeMounts":   "mountPath",
}

// mergeNode merges a strategic-merge patch into dst as kustomize does for
// the key-mount patches: maps by key, the lists of mergeKeys by their key
// (patch-only items appended in order), scalars replaced.
func mergeNode(dst, src *yaml.Node, field string) error {
	switch {
	case src.Kind == yaml.MappingNode && dst.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(src.Content); i += 2 {
			k, v := src.Content[i], src.Content[i+1]
			if strings.HasPrefix(k.Value, "$") {
				return fmt.Errorf("patch directive %s is not supported", k.Value)
			}
			if dv := mapGet(dst, k.Value); dv != nil {
				if err := mergeNode(dv, v, k.Value); err != nil {
					return fmt.Errorf("%s: %w", k.Value, err)
				}
				continue
			}
			dst.Content = append(dst.Content, copyNode(k), copyNode(v))
		}
	case src.Kind == yaml.SequenceNode && dst.Kind == yaml.SequenceNode:
		key, ok := mergeKeys[field]
		if !ok {
			return fmt.Errorf("list %s has no merge key", field)
		}
		// kustomize's order: the patch's items first (merged with the
		// list's item of the same key), then the list's other items.
		var merged []*yaml.Node
		taken := map[*yaml.Node]bool{}
		for _, item := range src.Content {
			kv := mapGet(item, key)
			if kv == nil {
				return fmt.Errorf("an item of %s has no %s", field, key)
			}
			var match *yaml.Node
			for _, d := range dst.Content {
				if dk := mapGet(d, key); dk != nil && dk.Value == kv.Value {
					match = d
					break
				}
			}
			if match == nil {
				merged = append(merged, copyNode(item))
				continue
			}
			if err := mergeNode(match, item, ""); err != nil {
				return err
			}
			merged = append(merged, match)
			taken[match] = true
		}
		for _, d := range dst.Content {
			if !taken[d] {
				merged = append(merged, d)
			}
		}
		dst.Content = merged
	case src.Kind == yaml.ScalarNode && dst.Kind == yaml.ScalarNode:
		*dst = *copyNode(src)
	default:
		return fmt.Errorf("%s: a patch of a different shape", field)
	}
	return nil
}

// tokenPrefix marks a templated scalar between encoding and writing.
const tokenPrefix = "FAIRCHARTEXPR" // #nosec G101 -- a marker, not a credential

var (
	chartVarRE    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	releaseImgRE  = regexp.MustCompile(`^` + regexp.QuoteMeta(DefaultRegistry) + `/([a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64})$`)
	tokenRE       = regexp.MustCompile(tokenPrefix + `([0-9]{4})X`)
	camelRE       = regexp.MustCompile(`-([a-z0-9])`)
	escapeBraceRE = regexp.MustCompile(`\{\{`)
)

// templater turns objects into template text, collecting the values used.
type templater struct {
	exprs    []string
	used     map[string]bool
	defaults map[string]any // value path -> the reference's literal
	replicas map[string]int // replicas.<key> -> the reference's count
}

func (t *templater) token(expr string, paths ...string) string {
	if t.used == nil {
		t.used = map[string]bool{}
	}
	for _, p := range paths {
		t.used[p] = true
	}
	t.exprs = append(t.exprs, expr)
	return fmt.Sprintf("%s%04dX", tokenPrefix, len(t.exprs)-1)
}

func setToken(n *yaml.Node, tok string) {
	n.Value, n.Tag, n.Style = tok, "!!str", 0
}

// template returns a document's template text.
func (t *templater) template(doc *yaml.Node) (string, error) {
	top := doc.Content[0]
	kind := mapGet(top, "kind").Value
	name := ""
	if n := mapGet(mapGet(top, "metadata"), "name"); n != nil {
		name = n.Value
	}
	if err := t.walk(top, kind, name, nil); err != nil {
		return "", fmt.Errorf("%s %s: %w", kind, name, err)
	}
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	text := escapeBraceRE.ReplaceAllString(b.String(), `{{ "{{" }}`)
	return tokenRE.ReplaceAllStringFunc(text, func(m string) string {
		i, _ := strconv.Atoi(tokenRE.FindStringSubmatch(m)[1])
		return t.exprs[i]
	}), nil
}

func (t *templater) walk(n *yaml.Node, kind, name string, path []string) error {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i].Value, n.Content[i+1]
			p := append(slices.Clone(path), k)
			switch {
			case k == "env" && v.Kind == yaml.SequenceNode:
				for _, item := range v.Content {
					if err := t.env(item, p); err != nil {
						return err
					}
				}
				continue
			case kind == "ConfigMap" && len(path) == 0 && k == "data":
				// Configuration files (the agents', the bundled servers',
				// the realm, the Collector's) are literal: their ${...} are
				// the software's own expansions, never values.
				if err := literal(v, p); err != nil {
					return err
				}
				continue
			case (k == "image" || kind == "Cluster" && k == "imageName") && v.Kind == yaml.ScalarNode:
				if err := t.image(v); err != nil {
					return err
				}
				continue
			case kind == "Deployment" && slices.Equal(p, []string{"spec", "replicas"}):
				r, err := strconv.Atoi(v.Value)
				if err != nil {
					return fmt.Errorf("replicas %q", v.Value)
				}
				if r >= 2 {
					key := camelRE.ReplaceAllStringFunc(name, func(s string) string { return strings.ToUpper(s[1:]) })
					t.replicas[key] = r
					setToken(v, t.token("{{ .Values.replicas."+key+" | toJson }}", "replicas."+key))
				}
				continue
			}
			if err := t.walk(v, kind, name, p); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if err := t.walk(c, kind, name, path); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		return t.scalar(n, path)
	}
	return nil
}

// image templates a release image (or a mirrored copy) under
// global.registry, by its digest.
func (t *templater) image(v *yaml.Node) error {
	m := releaseImgRE.FindStringSubmatch(v.Value)
	if m == nil {
		return fmt.Errorf("image %s is not the release's (%s/…@sha256:…)", v.Value, DefaultRegistry)
	}
	setToken(v, t.token(fmt.Sprintf("{{ print .Values.global.registry %q | toJson }}", "/"+m[1]), "global.registry"))
	return nil
}

// literal refuses a placeholder anywhere under n.
func literal(n *yaml.Node, path []string) error {
	if n.Kind == yaml.ScalarNode && strings.Contains(n.Value, "REPLACE_WITH_") {
		return fmt.Errorf("%s: placeholder in a literal configuration", strings.Join(path, "."))
	}
	for _, c := range n.Content {
		if err := literal(c, path); err != nil {
			return err
		}
	}
	return nil
}

// env templates an environment variable: one of ChartEnv by its name, an
// image (the CloudNativePG operator names its own for the pods it makes)
// as images are, any other through its variables.
func (t *templater) env(item *yaml.Node, path []string) error {
	nm, v := mapGet(item, "name"), mapGet(item, "value")
	if nm == nil || v == nil || v.Kind != yaml.ScalarNode {
		return t.walk(item, "", "", path)
	}
	if releaseImgRE.MatchString(v.Value) {
		return t.image(v)
	}
	p, ok := ChartEnv[nm.Value]
	if !ok {
		return t.scalar(v, append(path, nm.Value))
	}
	if !strings.Contains(v.Value, "REPLACE_WITH_") && !strings.Contains(v.Value, "${") {
		if d, seen := t.defaults[p]; seen && d != v.Value {
			return fmt.Errorf("%s has two reference values (%v, %s)", nm.Value, d, v.Value)
		}
		t.defaults[p] = v.Value
	}
	setToken(v, t.token("{{ .Values."+p+" | toJson }}", p))
	return nil
}

func (t *templater) scalar(n *yaml.Node, path []string) error {
	if !strings.Contains(n.Value, "${") {
		if strings.Contains(n.Value, "REPLACE_WITH_") {
			return fmt.Errorf("%s: placeholder %s has no chart value", strings.Join(path, "."), n.Value)
		}
		return nil
	}
	var parts, paths []string
	last := 0
	for _, l := range chartVarRE.FindAllStringSubmatchIndex(n.Value, -1) {
		if l[0] > last {
			parts = append(parts, strconv.Quote(n.Value[last:l[0]]))
		}
		v := n.Value[l[2]:l[3]]
		p, ok := ChartVariables[v]
		if !ok {
			return fmt.Errorf("%s: variable %s has no chart value", strings.Join(path, "."), v)
		}
		parts = append(parts, ".Values."+p)
		paths = append(paths, p)
		last = l[1]
	}
	if last < len(n.Value) {
		parts = append(parts, strconv.Quote(n.Value[last:]))
	}
	expr := "{{ " + parts[0] + " | toJson }}"
	if len(parts) > 1 {
		expr = "{{ print " + strings.Join(parts, " ") + " | toJson }}"
	}
	setToken(n, t.token(expr, paths...))
	return nil
}

// values returns the chart's default values and its closed schema.
func (t *templater) values() (map[string]any, map[string]any) {
	vs := t.valueList()
	values := map[string]any{}
	schema := closedObject("FAIR Risk Platform chart values (F-014 design §3.2)")
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	for _, v := range vs {
		parts := strings.Split(v.path, ".")
		m, s := values, schema
		for _, p := range parts[:len(parts)-1] {
			if _, ok := m[p]; !ok {
				m[p] = map[string]any{}
				props := s["properties"].(map[string]any)
				props[p] = closedObject("")
				s["required"] = append(s["required"].([]string), p)
			}
			m = m[p].(map[string]any)
			s = s["properties"].(map[string]any)[p].(map[string]any)
		}
		leaf := parts[len(parts)-1]
		m[leaf] = v.def
		ls := map[string]any{"description": v.doc}
		for k, x := range valueSchemas[v.kind] {
			ls[k] = x
		}
		s["properties"].(map[string]any)[leaf] = ls
		s["required"] = append(s["required"].([]string), leaf)
	}
	schema["allOf"] = bundledRules()
	return values, schema
}

// valueList is every value of the chart, with its default.
func (t *templater) valueList() []chartValue {
	var vs []chartValue
	for _, v := range chartValues() {
		if v.def == nil {
			v.def = t.defaults[v.path]
			if v.def == nil {
				v.def = ""
			}
		}
		vs = append(vs, v)
	}
	keys := make([]string, 0, len(t.replicas))
	for k := range t.replicas {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs = append(vs, chartValue{"replicas." + k, kindReplicas, "Replicas of the " + k + " Deployment.", t.replicas[k]})
	}
	return vs
}

func closedObject(desc string) map[string]any {
	o := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{}, "required": []string{}}
	if desc != "" {
		o["description"] = desc
	}
	return o
}

const notes = `The FAIR Risk Platform {{ .Chart.AppVersion }} is installed in the
namespaces fair-platform and fair-fips-probe.

This chart holds the platform's workloads with the reference hardening of
the release. It does not create credentials, database roles or install
decisions: fairctl provisions them (generated keys in the key store, the
database roles, buckets, streams and the install-time records) and then
installs this chart. Without them the services refuse to start; their logs
name what is missing.

Before every install and upgrade the chart's hooks ran the in-cluster
preflight (fairctl preflight -in-cluster) and the schema migrations
(iam migrate). A failed preflight leaves its Job for inspection:
  kubectl logs job/fair-preflight -n fair-platform

Check the installation with:
  fairctl report
The namespaces are kept on helm uninstall; they hold the platform's data.
See the installation guide in the release's documentation (docs/install/).
`

type chartMeta struct {
	APIVersion  string            `yaml:"apiVersion"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Type        string            `yaml:"type"`
	Version     string            `yaml:"version"`
	AppVersion  string            `yaml:"appVersion"`
	KubeVersion string            `yaml:"kubeVersion"`
	Annotations map[string]string `yaml:"annotations"`
}

func writeChart(o ChartOptions, out string, order []string, files map[string][]string, values, schema map[string]any) error {
	meta := chartMeta{
		APIVersion:  "v2",
		Name:        ChartName,
		Description: "The FAIR Risk Platform, rendered from the release's reference manifests (installed by fairctl).",
		Type:        "application",
		Version:     strings.TrimPrefix(o.Release, "v"),
		AppVersion:  o.Release,
		KubeVersion: MinKubeVersion,
		Annotations: map[string]string{"fair-platform.io/release": o.Release},
	}
	if o.ManifestDigest != "" {
		meta.Annotations["fair-platform.io/release-manifest-sha256"] = o.ManifestDigest
	}
	mb, err := yaml.Marshal(meta)
	if err != nil {
		return err
	}
	vb, err := valuesYAML(values)
	if err != nil {
		return err
	}
	sb, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}
	write := map[string]string{
		"Chart.yaml":          "# Generated by releasegen chart (internal/fleet RenderChart). Do not edit.\n" + string(mb),
		"values.yaml":         string(vb),
		"values.schema.json":  string(sb) + "\n",
		"templates/NOTES.txt": notes,
	}
	header := fmt.Sprintf("{{- /* Generated by releasegen chart from the %s reference manifests (internal/fleet RenderChart). Do not edit. */ -}}\n", o.Release)
	for _, f := range order {
		write["templates/"+f] = header + strings.Join(files[f], "")
	}
	for name, text := range write {
		p := filepath.Join(out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- a public release artifact
			return err
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil { // #nosec G306 -- a public release artifact
			return err
		}
	}
	return nil
}

// valuesYAML writes the defaults with each value's description.
func valuesYAML(values map[string]any) ([]byte, error) {
	docs := map[string]string{}
	for _, v := range chartValues() {
		docs[v.path] = v.doc
	}
	var node func(m map[string]any, prefix string) *yaml.Node
	node = func(m map[string]any, prefix string) *yaml.Node {
		n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			path := strings.TrimPrefix(prefix+"."+k, ".")
			kn := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k, HeadComment: docs[path]}
			var vn *yaml.Node
			if sub, ok := m[k].(map[string]any); ok {
				vn = node(sub, path)
			} else {
				vn = &yaml.Node{}
				if err := vn.Encode(m[k]); err != nil {
					panic(err) // scalars only
				}
			}
			n.Content = append(n.Content, kn, vn)
		}
		return n
	}
	var b strings.Builder
	b.WriteString("# The fair-platform chart's values (values.schema.json is closed: no other\n# value is accepted). Empty strings must be set; fairctl sets every value\n# from the install decisions.\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(node(values, "")); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}
