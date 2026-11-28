package chartgate

import (
	"archive/tar"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/rformer/fair-app/internal/airgap"
	"github.com/rformer/fair-app/internal/fleet"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
)

// The air-gap package gate (`release-check -package`; design §3.1,
// §3.17): the package verifies offline with the pinned release key as
// fairctl verify does (internal/releaseverify: the release manifest,
// SHA256SUMS, package-manifest.json naming every file and every image,
// each image's signature and attestations), and its chart passes Check
// against the package's own release manifest, every image any combination
// runs listed by the package.
//
// What T-10's `releasegen package` produces for this gate (internal/airgap):
// the package directory (or `fair-<version>-airgap.tar` holding it, one top
// directory) with the verification kit of internal/releaseverify, the
// images in its Zarf package's OCI layout (read by airgap.Layout; or the
// layout PackageOptions.Layout names, or images/<component>/), every
// mirrored third-party copy the release manifest's mirrors name among
// package-manifest.json's images, and the chart the Zarf package holds also
// as a file of the package: ChartFile(version) in any directory
// (chart/), listed by package-manifest.json.

// ChartFile is the packaged chart's file name for a release (Helm's
// <name>-<version>.tgz, the version without "v").
func ChartFile(release string) string {
	return fleet.ChartName + "-" + strings.TrimPrefix(release, "v") + ".tgz"
}

// Reasons the package itself is refused.
const (
	ReasonPackageVerify = "package_not_verified" // releaseverify refused the package
	ReasonPackageChart  = "package_chart"        // the package holds no (or more than one) chart
)

// AreaPackage is the package row of the release-check report.
const AreaPackage = "package"

// PackageOptions configure CheckPackage.
type PackageOptions struct {
	// Path is the package directory or its .tar.
	Path string
	// Key is the pinned release public key.
	Key *ecdsa.PublicKey
	// Layout is the OCI layout of the package's images, relative to the
	// package directory or absolute ("": its Zarf package's layout, or
	// images/<component>/ when it has none).
	Layout string
	// Chart are the chart gate's options but Chart, Manifest and
	// PackageImages, which come from the package.
	Chart Options
}

// PackageReport is CheckPackage's outcome.
type PackageReport struct {
	Verify *releaseverify.Report `json:"verify"`
	// Refusal is set when the package cannot be checked further (its
	// verification failed or it holds no chart).
	Refusal *Failure `json:"refusal,omitempty"`
	Chart   *Report  `json:"chart,omitempty"`
}

// Failed reports whether the package or its chart failed.
func (r *PackageReport) Failed() bool {
	return r.Refusal != nil || r.Chart == nil || r.Chart.Failed()
}

// CheckPackage verifies the package and runs Check over its chart. It
// returns an error only when the package cannot be read.
func CheckPackage(ctx context.Context, o PackageOptions) (*PackageReport, error) {
	dir := o.Path
	if st, err := os.Stat(dir); err != nil {
		return nil, err
	} else if !st.IsDir() {
		tmp, err := os.MkdirTemp("", "fair-package-")
		if err != nil {
			return nil, err
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		if dir, err = extract(o.Path, tmp); err != nil {
			return nil, err
		}
	}
	rep := &PackageReport{}
	layout := o.Layout
	switch {
	case layout != "" && filepath.IsAbs(layout):
	case layout != "":
		layout = filepath.Join(dir, filepath.FromSlash(layout))
	default:
		// The images of a package T-10 builds: Zarf's layout, read from its
		// Zarf package once that is checked against the signed package
		// manifest (D-OQ4: the images are in the package once). When it
		// cannot be read, releaseverify reports why.
		if l, cleanup, err := airgap.Layout(dir, o.Key, ""); err == nil {
			defer cleanup()
			layout = l
		}
	}
	vr := releaseverify.Verify(dir, releaseverify.Options{Key: o.Key, Package: true, Provenance: releaseverify.ReleasePolicy(), Layout: layout})
	rep.Verify = vr
	if err := vr.Err(); err != nil {
		rep.Refusal = &Failure{Area: AreaPackage, Reason: ReasonPackageVerify, Subject: vr.Refusal.Subject, Detail: err.Error(), Combinations: 0, Example: "the package"}
		return rep, nil
	}
	m, err := releasemanifest.Load(o.Key, filepath.Join(dir, releaseverify.ReleaseManifestFile))
	if err != nil {
		return nil, err // verified just now: unreadable only if the directory changed
	}
	b, err := os.ReadFile(filepath.Join(dir, releaseverify.PackageManifestFile)) // #nosec G304 -- the package being checked
	if err != nil {
		return nil, err
	}
	pm, err := releaseverify.DecodePackageManifest(b)
	if err != nil {
		return nil, err
	}
	var charts []string
	for _, f := range pm.Files {
		if path.Base(f.Path) == ChartFile(m.Release) {
			charts = append(charts, f.Path)
		}
	}
	if len(charts) != 1 {
		rep.Refusal = &Failure{Area: AreaPackage, Reason: ReasonPackageChart, Subject: ChartFile(m.Release),
			Detail: fmt.Sprintf("package-manifest.json lists %d files named %s, want one", len(charts), ChartFile(m.Release)), Example: "the package"}
		return rep, nil
	}
	co := o.Chart
	co.Chart = filepath.Join(dir, filepath.FromSlash(charts[0]))
	co.Manifest = m
	co.PackageImages = map[string]bool{}
	for _, i := range pm.Images {
		co.PackageImages[i.Image] = true
	}
	if rep.Chart, err = Check(ctx, co); err != nil {
		return nil, err
	}
	return rep, nil
}

// Limits of a package tarball's extraction.
const (
	maxEntries = 1 << 16
	maxBytes   = 64 << 30
)

// extract unpacks a package tarball (regular files and directories, paths
// inside the target only) and returns the package directory: the
// tarball's one top directory, or the target when the files are at its
// top.
func extract(file, into string) (string, error) {
	f, err := os.Open(file) // #nosec G304 -- the operator's package
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	tops := map[string]bool{}
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("%s: %w", file, err)
		}
		if n >= maxEntries {
			return "", fmt.Errorf("%s: more than %d entries", file, maxEntries)
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." {
			continue
		}
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, `\`) {
			return "", fmt.Errorf("%s: entry %q is outside the package", file, h.Name)
		}
		top, _, _ := strings.Cut(name, "/")
		tops[top] = true
		dst := filepath.Join(into, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o750); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if total += h.Size; h.Size < 0 || total > maxBytes {
				return "", fmt.Errorf("%s: larger than %d bytes", file, int64(maxBytes))
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
				return "", err
			}
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- path checked above
			if err != nil {
				return "", err
			}
			_, cerr := io.CopyN(out, tr, h.Size)
			if err := errors.Join(cerr, out.Close()); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("%s: entry %q is not a file or directory", file, h.Name)
		}
	}
	if len(tops) == 1 {
		for t := range tops {
			if st, err := os.Stat(filepath.Join(into, t)); err == nil && st.IsDir() {
				return filepath.Join(into, t), nil
			}
		}
	}
	return into, nil
}
