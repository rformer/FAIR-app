package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/rformer/fair-app/internal/chartgate"
	"github.com/rformer/fair-app/internal/fleet"
	"github.com/rformer/fair-app/internal/profilegen"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
)

// F-014 T-09 (AC-02, AC-03; design §3.17): the chart and package rows of
// the release checklist.
//
//	-chart DIR|TGZ      the fair-platform chart (releasegen chart): every
//	                    option combination rendered, F-015's checks over each
//	                    on the compliant cluster, images and RBAC equal to
//	                    -manifest (the release manifest, unsigned in the
//	                    pipeline: its signature is release-sign.yml's)
//	-package DIR|TAR    the air-gap package (releasegen package, T-10):
//	                    verified offline with -key, then its chart as -chart
//	                    against the package's own signed release manifest
//	-key FILE           the pinned release public key (PEM), for -package
//	-layout PATH        the package's OCI image layout (relative; "": images/<component>/)
//	-third-party FILE   the release's third-party images (mirrored copies)
//	-bundled DIR        deploy/bundled: what fairctl applies at cluster scope
//	                    for each bundled dependency

// gateInputs are the flags.
type gateInputs struct {
	chart, pkg, key, layout, thirdParty, bundled, manifest string
}

// chartRows are the four rows of one chart's gate.
var chartRows = []struct{ area, name string }{
	{chartgate.AreaRender, "every option combination the schema allows renders"},
	{chartgate.AreaChecks, "F-015's deployment checks find nothing in any combination"},
	{chartgate.AreaImages, "every image is by digest and the release's"},
	{chartgate.AreaRBAC, "every RBAC object equals the release manifest's (hooks and fairctl's included)"},
}

func chartChecks(ctx context.Context, in gateInputs) []profilegen.Check {
	var out []profilegen.Check
	base, berr := gateOptions(in)
	switch {
	case in.chart == "":
		out = append(out, profilegen.Check{Name: "Chart release gate", OK: true, Detail: "skipped (no -chart; the release pipeline's chart job passes it)"})
	case berr != nil:
		out = append(out, profilegen.Check{Name: "Chart release gate", Detail: berr.Error()})
	default:
		if r, err := runChart(ctx, base, in); err != nil {
			out = append(out, profilegen.Check{Name: "Chart release gate", Detail: err.Error()})
		} else {
			out = append(out, rows("Chart", r)...)
		}
	}
	switch {
	case in.pkg == "":
		out = append(out, profilegen.Check{Name: "Air-gap package release gate", OK: true, Detail: "skipped (no -package; the release pipeline's package job passes it)"})
	case berr != nil:
		out = append(out, profilegen.Check{Name: "Air-gap package release gate", Detail: berr.Error()})
	default:
		out = append(out, packageChecks(ctx, in, base)...)
	}
	return out
}

func runChart(ctx context.Context, o chartgate.Options, in gateInputs) (*chartgate.Report, error) {
	m, err := readManifest(in.manifest)
	if err != nil {
		return nil, err
	}
	o.Chart, o.Manifest = in.chart, m
	return chartgate.Check(ctx, o)
}

func packageChecks(ctx context.Context, in gateInputs, base chartgate.Options) []profilegen.Check {
	const name = "The air-gap package verifies against the release manifest"
	if in.key == "" {
		return []profilegen.Check{{Name: name, Detail: "-package needs the pinned release key (-key)"}}
	}
	key, err := releaseverify.LoadPublicKey(in.key)
	if err != nil {
		return []profilegen.Check{{Name: name, Detail: err.Error()}}
	}
	r, err := chartgate.CheckPackage(ctx, chartgate.PackageOptions{Path: in.pkg, Key: key, Layout: in.layout, Chart: base})
	if err != nil {
		return []profilegen.Check{{Name: name, Detail: err.Error()}}
	}
	if r.Refusal != nil {
		return []profilegen.Check{{Name: name, Detail: r.Refusal.Reason + " " + r.Refusal.Subject + ": " + r.Refusal.Detail}}
	}
	out := []profilegen.Check{{Name: name, OK: true, Detail: fmt.Sprintf("release %s verified offline with the release key: %d steps, %d images", r.Verify.Release, len(r.Verify.Steps), len(r.Verify.Images))}}
	return append(out, rows("Package chart", r.Chart)...)
}

func rows(label string, r *chartgate.Report) []profilegen.Check {
	var out []profilegen.Check
	for _, row := range chartRows {
		out = append(out, profilegen.Check{Name: label + ": " + row.name, OK: !r.Failed(row.area), Detail: r.Summary(row.area)})
	}
	return out
}

func gateOptions(in gateInputs) (chartgate.Options, error) {
	var o chartgate.Options
	if in.chart == "" && in.pkg == "" {
		return o, nil
	}
	l, err := fleet.LoadThirdParty(in.thirdParty)
	if err != nil {
		return o, err
	}
	o.ThirdParty = l
	if o.Residue, err = fleet.BundledResidue(in.bundled); err != nil {
		return o, err
	}
	return o, nil
}

// readManifest reads the pipeline's (unsigned) release manifest strictly.
func readManifest(path string) (*releasemanifest.Manifest, error) {
	if path == "" {
		return nil, errors.New("-chart needs the release manifest (-manifest)")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- release-pipeline operator input
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m releasemanifest.Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, m.Validate()
}
