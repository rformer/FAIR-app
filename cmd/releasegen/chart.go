package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"helm.sh/helm/v4/pkg/chart/v2/loader"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"

	"github.com/rformer/fair-app/internal/fleet"
)

// chart writes the fair-platform Helm chart (F-014 T-06, design §3.2):
//
//	releasegen chart -release VERSION -images FILE -out DIR [-deploy deploy/k8s]
//	    [-keys deploy/k8s/keys] [-hooks deploy/k8s/hooks] [-manifest FILE]
//	    [-bundled deploy/bundled] [-third-party deploy/third-party-images.json]
//	    [-package DIR] [-registry REPO]
//
// images FILE is the release's {"component": "repository@sha256:<digest>"}
// and must hold the OpenBao (agent sidecars) and fairctl (hooks) images;
// -manifest names the signed release-manifest.json whose SHA-256 Chart.yaml
// records; -bundled adds the bundled dependencies (F-014 T-08), whose
// images FILE must hold too (postgres, nats, versitygw, keycloak, openbao),
// and whose third-party images are named by their mirrored copies under
// <registry>/mirror (-registry: the release repository, default
// fleet.DefaultRegistry; a dry run's is ghcr.io/<owner>/test); -package also writes fair-platform-<version>.tgz into DIR. The
// Helm SDK only loads, checks and packages the chart here (ADR-019);
// signing and the OCI push are the release's chart job (T-10).
func chart(args []string) error {
	fs := flag.NewFlagSet("chart", flag.ExitOnError)
	release := fs.String("release", "", "release version (vX.Y.Z)")
	images := fs.String("images", "", "JSON file: component -> repository@sha256:<digest>")
	deploy := fs.String("deploy", "deploy/k8s", "reference manifests")
	keys := fs.String("keys", "deploy/k8s/keys", "key store manifests")
	hooks := fs.String("hooks", "deploy/k8s/hooks", "the chart's hook objects")
	manifest := fs.String("manifest", "", "the signed release-manifest.json (\"\": none)")
	bundled := fs.String("bundled", "deploy/bundled", "the bundled dependencies (\"\": none)")
	third := fs.String("third-party", "deploy/third-party-images.json", "third-party images, named by their copies under "+fleet.DefaultRegistry+"/mirror (\"\": none)")
	pkg := fs.String("package", "", "also write the packaged chart (.tgz) into this directory")
	registry := fs.String("registry", fleet.DefaultRegistry, "the release repository the images are named in (global.registry's default)")
	out := fs.String("out", "", "output directory (must not exist)")
	_ = fs.Parse(args)
	if *out == "" || *images == "" {
		return errors.New("chart: -images and -out are required")
	}
	b, err := os.ReadFile(*images) // #nosec G304 G703 -- release-pipeline operator input
	if err != nil {
		return err
	}
	var imgs map[string]string
	if err := json.Unmarshal(b, &imgs); err != nil {
		return fmt.Errorf("%s: %w", *images, err)
	}
	o := fleet.ChartOptions{Options: fleet.Options{Release: *release, Images: imgs, Deploy: *deploy, Keys: *keys}, Hooks: *hooks, Bundled: *bundled, Registry: *registry}
	if *third != "" {
		l, err := fleet.LoadThirdParty(*third)
		if err != nil {
			return err
		}
		o.Mirror = l.Mirror(strings.TrimSuffix(*registry, "/") + "/mirror")
	}
	if *manifest != "" {
		if o.ManifestDigest, err = fleet.ManifestDigest(*manifest); err != nil {
			return err
		}
	}
	if err := fleet.RenderChart(o, *out); err != nil {
		return err
	}
	c, err := loader.LoadDir(*out)
	if err != nil {
		return fmt.Errorf("chart: the rendered chart does not load: %w", err)
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("chart: %w", err)
	}
	if *pkg != "" {
		if err := os.MkdirAll(*pkg, 0o755); err != nil { // #nosec G301 -- a public release artifact
			return err
		}
		p, err := chartutil.Save(c, *pkg)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "chart:", p)
	}
	return nil
}
