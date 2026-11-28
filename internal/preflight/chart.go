package preflight

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"helm.sh/helm/v4/pkg/chart/common"
	chartutil "helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/engine"

	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/objreader"
)

// ErrValues means the values do not satisfy the chart's schema.
var ErrValues = errors.New("preflight: the chart refuses the values")

// RenderChart renders the release's chart (a directory or a packaged .tgz)
// with values, as `helm install` would, into its objects (hooks included:
// objreader.Applied drops them). The Helm SDK is linked into the tools only
// (ADR-019; TestSDKLinkedOnlyIntoTools).
func RenderChart(path string, values map[string]any, upgrade bool) ([]map[string]any, error) {
	ch, err := loader.Load(path)
	if err != nil {
		return nil, fmt.Errorf("preflight: the chart: %w", err)
	}
	vals, err := chartutil.CoalesceValues(ch, values)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrValues, err)
	}
	if err := chartutil.ValidateAgainstSchema(ch, vals); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrValues, err)
	}
	rv, err := chartutil.ToRenderValuesWithSchemaValidation(ch, values,
		common.ReleaseOptions{Name: "fair", Namespace: "fair-platform", IsInstall: !upgrade, IsUpgrade: upgrade}, nil, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrValues, err)
	}
	files, err := engine.Render(ch, rv)
	if err != nil {
		return nil, fmt.Errorf("preflight: rendering the chart: %w", err)
	}
	var out []map[string]any
	seen := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if strings.HasSuffix(name, "NOTES.txt") {
			continue
		}
		docs, err := objreader.DecodeYAMLString(files[name])
		if err != nil {
			return nil, fmt.Errorf("preflight: %s: %w", name, err)
		}
		for _, d := range docs {
			k := objreader.Key(d)
			if seen[k] {
				return nil, fmt.Errorf("preflight: %s rendered twice", k)
			}
			seen[k] = true
			out = append(out, d)
		}
	}
	return out, nil
}

// Scanner defaults (cmd/posture-scanner).
const (
	DefaultPlatformNamespace = "fair-platform"
	DefaultProbeNamespace    = "fair-fips-probe"
)

// Settings are the drift scanner's settings as the rendered release gives
// them to posture-scanner (its Deployment's environment), so the preflight
// evaluates the checks exactly as the installed scanner will.
type Settings struct {
	Scope            scanner.Scope
	PSADefault       string
	IngressEndpoints []string
}

// ScannerSettings reads the settings from the rendered posture-scanner
// Deployment; without one (the scanner switched off), the scanner's
// defaults.
func ScannerSettings(objs []map[string]any) Settings {
	env := map[string]string{}
	for _, o := range objs {
		md, _ := o["metadata"].(map[string]any)
		if o["kind"] != "Deployment" || md["name"] != "posture-scanner" {
			continue
		}
		spec, _ := dig(o, "spec", "template", "spec").(map[string]any)
		cs, _ := spec["containers"].([]any)
		for _, c := range cs {
			es, _ := dig(c, "env").([]any)
			for _, e := range es {
				n, _ := dig(e, "name").(string)
				v, _ := dig(e, "value").(string)
				env[n] = v
			}
		}
	}
	s := Settings{Scope: scanner.Scope{Namespaces: list(env["FAIR_PLATFORM_NAMESPACES"]), ProbeNamespace: env["FAIR_FIPS_PROBE_NAMESPACE"]},
		PSADefault: env["FAIR_PSA_DEFAULT"], IngressEndpoints: list(env["FAIR_INGRESS_ENDPOINTS"])}
	if len(s.Scope.Namespaces) == 0 {
		s.Scope.Namespaces = []string{DefaultPlatformNamespace}
	}
	if s.Scope.ProbeNamespace == "" {
		s.Scope.ProbeNamespace = DefaultProbeNamespace
	}
	return s
}

func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// PackageManifest returns the release manifest the checks compare with: the
// verified release manifest itself. Its signed mirrors section (F-014 design
// §3.17, T-10) is what makes a bundled dependency's mirrored image the
// release's; the package manifest adds no images of its own.
func PackageManifest(m *releasemanifest.Manifest, _ *releaseverify.PackageManifest) (*releasemanifest.Manifest, error) {
	out := *m
	return &out, out.Validate()
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
