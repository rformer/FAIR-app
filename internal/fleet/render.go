// Package fleet renders a release's platform manifests as the per-release
// OCI artifact Flux reconciles (F-012 T-15, F-012-AC-18; design §3.6;
// ADR-016). The release pipeline runs `releasegen fleet`, pushes the
// directory with `flux push artifact` and signs it like the images;
// deploy/fleet holds the Flux objects that consume it.
//
// The artifact has one directory per reconciliation step, each a
// kustomization, applied in this order by deploy/fleet/flux/release.yaml:
//
//	namespaces/     every Namespace and each namespace's default-deny policy
//	secrets/        the SaaS key store's ExternalSecrets and the services'
//	                certificates (deploy/k8s/keys/saas)
//	migrate/        the iam migration Job, its ServiceAccount and egress
//	platform/       every other object of deploy/k8s, with the key mounts of
//	                deploy/k8s/keys/secret-mounts.yaml as patches
//	observability/  the Collector and its log agent (deploy/observability)
//	release.json    the release and its images
//
// Images named ghcr.io/rformer/fair-<component>:REPLACE_WITH_DIGEST become
// the release's images by digest; the engine digest placeholder becomes the
// engine's digest. Instance values that have one meaning everywhere become
// Flux post-build variables (Variables), filled from the instance's
// fair-instance ConfigMap; the rest are set by the SaaS patches of
// deploy/fleet/flux/release.yaml.
package fleet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Directories of the artifact, in reconciliation order.
const (
	DirNamespaces    = "namespaces"
	DirSecrets       = "secrets"
	DirMigrate       = "migrate"
	DirPlatform      = "platform"
	DirObservability = "observability"
)

// Dirs are the artifact's directories in reconciliation order.
var Dirs = []string{DirNamespaces, DirSecrets, DirMigrate, DirPlatform, DirObservability}

// Excluded are deploy/k8s files that are not part of a running instance:
// the emergency break-glass Job is run by an operator, by hand (F-001 T-35).
var Excluded = []string{"breakglass-emergency.yaml"}

// Variables maps the reference manifests' instance placeholders to the
// Flux post-build variables of the instance (deploy/fleet/instances).
var Variables = map[string]string{
	"REPLACE_WITH_INSTANCE":       "FAIR_INSTANCE",
	"REPLACE_WITH_REGION":         "FAIR_REGION",
	"REPLACE_WITH_DB_HOST":        "FAIR_DB_HOST",
	"REPLACE_WITH_PLATFORM_HOST":  "FAIR_PLATFORM_HOST",
	"REPLACE_WITH_APISERVER_CIDR": "FAIR_APISERVER_CIDR",
	"REPLACE_WITH_INGRESS_CIDR":   "FAIR_INGRESS_CIDR",
	"REPLACE_WITH_INGRESS_HOST":   "FAIR_INGRESS_HOST",
}

// Collector is a Collector configuration rendered as a ConfigMap of the
// observability directory.
type Collector struct{ Name, Namespace string }

// Collectors maps files of deploy/observability to their ConfigMaps.
var Collectors = map[string]Collector{
	"collector-saas.yaml":       {"otelcol-saas", "fair-platform"},
	"collector-saas-agent.yaml": {"otelcol-agent", ObservabilityNamespace},
}

// ObservabilityWorkloads is the file in deploy/observability holding the
// Collector's Kubernetes objects.
const ObservabilityWorkloads = "k8s-saas.yaml"

// ObservabilityNamespace is the Collector's namespace.
const ObservabilityNamespace = "fair-observability"

// Options are the renderer's inputs.
type Options struct {
	Release       string            // the release version (vX.Y.Z)
	Images        map[string]string // component -> repository@sha256:<digest>
	Deploy        string            // deploy/k8s
	Keys          string            // deploy/k8s/keys
	Observability string            // deploy/observability ("" for none)
}

// Release is release.json.
type Release struct {
	Format  string            `json:"format"`
	Release string            `json:"release"`
	Images  map[string]string `json:"images"`
}

// Format is release.json's format.
const Format = "fair.fleet-release.v1"

var (
	imageRE       = regexp.MustCompile(`ghcr\.io/rformer/fair-([a-z0-9-]+):REPLACE_WITH_DIGEST`)
	placeholderRE = regexp.MustCompile(`REPLACE_WITH_[A-Z_]+`)
	digestRE      = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)
	ttlRE         = regexp.MustCompile(`(?m)^\s*ttlSecondsAfterFinished:.*\n`)
	// A placeholder in a flow mapping ("{ name: X, value: REPLACE_WITH_Y }")
	// is quoted first: a plain scalar there cannot hold the variable's braces.
	flowRE = regexp.MustCompile(`(:[ \t]+)([^\s,{}\[\]"']*REPLACE_WITH_[A-Z_]+[^\s,{}\[\]"']*)([ \t]*[,}])`)
	modeRE = regexp.MustCompile(`(name: FAIR_DEPLOYMENT_MODE, value: )[a-z-]+`)
)

// ModeVariable is the deployment mode's variable: the reference manifests'
// FAIR_DEPLOYMENT_MODE values are the instance's (saas for the fleet).
const ModeVariable = "FAIR_DEPLOYMENT_MODE"

// doc is one YAML document of a source file: its text (comments kept) and
// what it is.
type doc struct {
	text      string
	kind      string
	name      string
	namespace string
	obj       map[string]any
}

// Render writes the artifact into out (created; must not exist).
func Render(o Options, out string) error {
	if o.Release == "" {
		return errors.New("fleet: a release version is required")
	}
	if len(o.Images) == 0 {
		return errors.New("fleet: no images")
	}
	for c, ref := range o.Images {
		if !digestRE.MatchString(ref) {
			return fmt.Errorf("fleet: image %s is not repository@sha256:<digest>: %q", c, ref)
		}
	}
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("fleet: %s exists", out)
	}
	files := map[string][]string{} // dir -> its files
	type file struct{ dir, name, text string }
	var outFiles []file
	var namespaces []string
	add := func(dir, name string, docs []string) {
		if len(docs) == 0 {
			return
		}
		outFiles = append(outFiles, file{dir, name, strings.Join(docs, "---\n")})
		files[dir] = append(files[dir], name)
	}

	// deploy/k8s: namespaces, migrate, platform.
	srcs, err := filepath.Glob(filepath.Join(o.Deploy, "*.yaml"))
	if err != nil {
		return err
	}
	sort.Strings(srcs)
	var deployments []string
	for _, src := range srcs {
		base := filepath.Base(src)
		if slices.Contains(Excluded, base) {
			continue
		}
		ds, err := readDocs(src)
		if err != nil {
			return err
		}
		migrateSA, migrateApps := migrationParts(ds)
		var plat, mig []string
		for _, d := range ds {
			switch {
			case d.kind == "Namespace", d.kind == "NetworkPolicy" && d.name == "default-deny":
				namespaces = append(namespaces, d.text)
			case d.kind == "Job" && strings.HasSuffix(d.name, "-migrate"):
				mig = append(mig, ttlRE.ReplaceAllString(d.text, ""))
			case d.kind == "ServiceAccount" && migrateSA[d.namespace+"/"+d.name]:
				mig = append(mig, d.text)
			case d.kind == "NetworkPolicy" && migrateApps[podSelectorName(d.obj)]:
				mig = append(mig, d.text)
			default:
				if d.kind == "Deployment" {
					deployments = append(deployments, d.name)
				}
				plat = append(plat, d.text)
			}
		}
		add(DirMigrate, base, mig)
		add(DirPlatform, base, plat)
	}
	if len(files[DirMigrate]) == 0 {
		return fmt.Errorf("fleet: %s has no migration Job (*-migrate)", o.Deploy)
	}

	// deploy/k8s/keys: the SaaS store's objects, and the key mounts as
	// patches of the Deployments the release has.
	var patches []string
	if o.Keys != "" {
		saas, err := filepath.Glob(filepath.Join(o.Keys, "saas", "*.yaml"))
		if err != nil {
			return err
		}
		sort.Strings(saas)
		for _, src := range saas {
			ds, err := readDocs(src)
			if err != nil {
				return err
			}
			var texts []string
			for _, d := range ds {
				if d.kind == "Namespace" {
					namespaces = append(namespaces, d.text)
					continue
				}
				texts = append(texts, d.text)
			}
			add(DirSecrets, filepath.Base(src), texts)
		}
		mounts := filepath.Join(o.Keys, "secret-mounts.yaml")
		if _, err := os.Stat(mounts); err == nil {
			ds, err := readDocs(mounts)
			if err != nil {
				return err
			}
			for _, d := range ds {
				if d.kind != "Deployment" || !slices.Contains(deployments, d.name) {
					continue
				}
				add(DirPlatform, filepath.Join("keys", d.name+".yaml"), []string{d.text})
				patches = append(patches, d.name)
			}
		}
	}

	// deploy/observability: the Collector.
	if o.Observability != "" {
		w := filepath.Join(o.Observability, ObservabilityWorkloads)
		ds, err := readDocs(w)
		if err != nil {
			return err
		}
		var texts []string
		for _, d := range ds {
			if d.kind == "Namespace" || d.kind == "NetworkPolicy" && d.name == "default-deny" {
				namespaces = append(namespaces, d.text)
				continue
			}
			texts = append(texts, d.text)
		}
		names := make([]string, 0, len(Collectors))
		for f := range Collectors {
			names = append(names, f)
		}
		sort.Strings(names)
		for _, f := range names {
			b, err := os.ReadFile(filepath.Join(o.Observability, f)) // #nosec G304 -- the repository's own files
			if err != nil {
				return err
			}
			cm, err := configMap(Collectors[f].Name, Collectors[f].Namespace, string(b))
			if err != nil {
				return err
			}
			texts = append(texts, cm)
		}
		add(DirObservability, ObservabilityWorkloads, texts)
	}
	add(DirNamespaces, "namespaces.yaml", namespaces)

	// Substitute, then check nothing unknown is left.
	for i := range outFiles {
		t, err := substitute(outFiles[i].text, o.Images)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", outFiles[i].dir, outFiles[i].name, err)
		}
		outFiles[i].text = t
	}

	if err := os.MkdirAll(out, 0o755); err != nil { // #nosec G301 -- a public release artifact
		return err
	}
	for _, f := range outFiles {
		p := filepath.Join(out, f.dir, f.name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- a public release artifact
			return err
		}
		if err := os.WriteFile(p, []byte(f.text), 0o644); err != nil { // #nosec G306 -- a public release artifact
			return err
		}
	}
	for _, dir := range Dirs {
		if len(files[dir]) == 0 {
			continue
		}
		if err := writeKustomization(filepath.Join(out, dir), files[dir], patchesFor(dir, patches)); err != nil {
			return err
		}
	}
	rel, err := json.MarshalIndent(Release{Format: Format, Release: o.Release, Images: o.Images}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "release.json"), append(rel, '\n'), 0o644) // #nosec G306 -- a public release artifact
}

func patchesFor(dir string, deployments []string) []string {
	if dir != DirPlatform {
		return nil
	}
	return deployments
}

// substitute replaces image and instance placeholders. Non-comment
// placeholders left are the SaaS patches' (deploy/fleet/flux/release.yaml).
func substitute(text string, images map[string]string) (string, error) {
	var errs []error
	text = imageRE.ReplaceAllStringFunc(text, func(m string) string {
		c := imageRE.FindStringSubmatch(m)[1]
		ref, ok := images[c]
		if !ok {
			errs = append(errs, fmt.Errorf("no image for component %s", c))
			return m
		}
		return ref
	})
	if strings.Contains(text, "REPLACE_WITH_ENGINE_DIGEST") {
		ref, ok := images["engine"]
		if !ok {
			errs = append(errs, errors.New("no engine image for REPLACE_WITH_ENGINE_DIGEST"))
		} else {
			_, d, _ := strings.Cut(ref, "@")
			text = strings.ReplaceAll(text, "REPLACE_WITH_ENGINE_DIGEST", d)
		}
	}
	text = flowRE.ReplaceAllString(text, `${1}"${2}"${3}`)
	text = modeRE.ReplaceAllString(text, `${1}"$${`+ModeVariable+`}"`)
	text = placeholderRE.ReplaceAllStringFunc(text, func(m string) string {
		if v, ok := Variables[m]; ok {
			return "${" + v + "}"
		}
		return m
	})
	return text, errors.Join(errs...)
}

// migrationParts names the ServiceAccounts and app names of a file's
// migration Jobs.
func migrationParts(ds []doc) (sas, apps map[string]bool) {
	sas, apps = map[string]bool{}, map[string]bool{}
	for _, d := range ds {
		if d.kind != "Job" || !strings.HasSuffix(d.name, "-migrate") {
			continue
		}
		if sa, _ := dig(d.obj, "spec", "template", "spec", "serviceAccountName").(string); sa != "" {
			sas[d.namespace+"/"+sa] = true
		}
		if n, _ := dig(d.obj, "spec", "template", "metadata", "labels", "app.kubernetes.io/name").(string); n != "" {
			apps[n] = true
		}
	}
	return sas, apps
}

func podSelectorName(o map[string]any) string {
	n, _ := dig(o, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name").(string)
	return n
}

func dig(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

var sepRE = regexp.MustCompile(`(?m)^---[ \t]*$\n?`)

// readDocs splits a file into its documents, keeping each one's text with
// the comments above it; comment-only chunks are dropped.
func readDocs(path string) ([]doc, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the repository's own files
	if err != nil {
		return nil, err
	}
	src := strings.ReplaceAll(string(b), "\r\n", "\n")
	var out []doc
	for _, chunk := range sepRE.Split(src, -1) {
		var obj map[string]any
		if err := yaml.Unmarshal([]byte(chunk), &obj); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if obj == nil {
			continue
		}
		if !strings.HasSuffix(chunk, "\n") {
			chunk += "\n"
		}
		kind, _ := obj["kind"].(string)
		name, _ := dig(obj, "metadata", "name").(string)
		ns, _ := dig(obj, "metadata", "namespace").(string)
		out = append(out, doc{text: chunk, kind: kind, name: name, namespace: ns, obj: obj})
	}
	return out, nil
}

// configMap holds a Collector configuration. Flux's post-build
// substitution is off for it: the Collector expands ${env:...} itself.
func configMap(name, namespace, config string) (string, error) {
	cm := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"labels":    map[string]any{"app.kubernetes.io/part-of": "fair-platform"},
			"annotations": map[string]any{
				"kustomize.toolkit.fluxcd.io/substitute": "disabled",
			},
		},
		"data": map[string]any{"config.yaml": strings.ReplaceAll(config, "\r\n", "\n")},
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cm); err != nil {
		return "", err
	}
	return "# Rendered from deploy/observability by releasegen fleet.\n" + buf.String(), nil
}

func writeKustomization(dir string, resources, patches []string) error {
	var res []string
	for _, r := range resources {
		if !strings.HasPrefix(filepath.ToSlash(r), "keys/") {
			res = append(res, filepath.ToSlash(r))
		}
	}
	sort.Strings(res)
	k := map[string]any{
		"apiVersion": "kustomize.config.k8s.io/v1beta1",
		"kind":       "Kustomization",
		"resources":  res,
	}
	if len(patches) > 0 {
		sort.Strings(patches)
		var ps []any
		for _, d := range patches {
			ps = append(ps, map[string]any{
				"path":   "keys/" + d + ".yaml",
				"target": map[string]any{"kind": "Deployment", "name": d},
			})
		}
		k["patches"] = ps
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(k); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "kustomization.yaml"), buf.Bytes(), 0o644) // #nosec G306 -- a public release artifact
}
