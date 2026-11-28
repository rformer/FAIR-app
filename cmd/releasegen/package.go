package main

// F-014 T-10 (F-014-AC-01, AC-02, AC-04; design §3.1, D-OQ4): the air-gap
// package and the chart's OCI push.
//
//	releasegen package zarf -manifest FILE -chart TGZ [-arch amd64] -out DIR
//	    writes DIR/zarf.yaml (zarf.dev/v1beta1) and the chart beside it:
//	    the input of `zarf package create DIR`, which pulls every image of
//	    the release manifest and its mirrors with their signatures (and the
//	    release's attestations) into Zarf's OCI layout.
//	releasegen package build -release V -release-dir DIR -chart TGZ -zarf FILE
//	    -notes DIR -source-date EPOCH -minor-first-released YYYY-MM-DD
//	    [-upgrade-from v1,v2] [-tools DIR] [-root .] -out DIR
//	    assembles the package directory around the signed Zarf package
//	    (internal/airgap): the verification kit, chart/, tools/, content/,
//	    compliance/, docs/, notes/, platforms.json, and an unsigned
//	    package-manifest.json and SHA256SUMS for `releasegen sign -any`.
//	releasegen push-chart -chart TGZ -repository oci://REPO [-source-date EPOCH] -out FILE
//	    pushes the packaged chart to REPO/<name>:<version> with the Helm
//	    SDK's OCI client (credentials: Helm's, then Docker's) and writes
//	    {"ref", "digest"} to FILE for signing (cosign sign).

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/registry"

	"github.com/rformer/fair-app/internal/airgap"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
)

func packageCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: releasegen package zarf | build (see the command documentation)")
	}
	switch args[0] {
	case "zarf":
		return packageZarf(args[1:])
	case "build":
		return packageBuild(args[1:])
	}
	return fmt.Errorf("package: unknown command %q", args[0])
}

func packageZarf(args []string) error {
	fs := flag.NewFlagSet("package zarf", flag.ExitOnError)
	manifest := fs.String("manifest", "", "the release manifest (release-manifest.json)")
	chart := fs.String("chart", "", "the packaged chart (fair-platform-<v>.tgz)")
	arch := fs.String("arch", "amd64", "the package's architecture")
	out := fs.String("out", "", "output directory (must not exist)")
	_ = fs.Parse(args)
	if *manifest == "" || *chart == "" || *out == "" {
		return errors.New("package zarf: -manifest, -chart and -out are required")
	}
	b, err := os.ReadFile(*manifest) // #nosec G304 G703 -- release-pipeline input
	if err != nil {
		return err
	}
	var m releasemanifest.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("%s: %w", *manifest, err)
	}
	cfg, err := airgap.ZarfConfig(&m, filepath.Base(*chart), *arch)
	if err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("package zarf: %s exists", *out)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil { // #nosec G301 -- a public release artifact
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "zarf.yaml"), cfg, 0o644); err != nil { // #nosec G306 G703 -- a public release artifact
		return err
	}
	return copyFile(*chart, filepath.Join(*out, filepath.Base(*chart)))
}

var dateRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

func packageBuild(args []string) error {
	fs := flag.NewFlagSet("package build", flag.ExitOnError)
	release := fs.String("release", "", "release version")
	releaseDir := fs.String("release-dir", "", "the signed release's files")
	tools := fs.String("tools", "", "further binaries for tools/ (releasegen-*)")
	chart := fs.String("chart", "", "the packaged chart")
	zarf := fs.String("zarf", "", "the signed Zarf package")
	notes := fs.String("notes", "", "release notes of the upgrade window (<release>.md)")
	root := fs.String("root", ".", "the repository root")
	sourceDate := fs.String("source-date", os.Getenv("SOURCE_DATE_EPOCH"), "the release commit's time, seconds since the epoch")
	minor := fs.String("minor-first-released", "", "the day the release's minor line was first released (YYYY-MM-DD)")
	upgrade := fs.String("upgrade-from", "", "comma-separated releases this one upgrades from")
	out := fs.String("out", "", "the package directory (must not exist)")
	_ = fs.Parse(args)
	secs, err := strconv.ParseInt(*sourceDate, 10, 64)
	if err != nil || secs <= 0 {
		return errors.New("package build: -source-date (or SOURCE_DATE_EPOCH) must be the commit time")
	}
	if !dateRE.MatchString(*minor) {
		return errors.New("package build: -minor-first-released must be YYYY-MM-DD")
	}
	var from []string
	for _, v := range strings.Split(*upgrade, ",") {
		if v = strings.TrimSpace(v); v != "" {
			from = append(from, v)
		}
	}
	pm, err := airgap.Build(airgap.BuildOptions{
		Release: *release, ReleaseDir: *releaseDir, Tools: *tools, Chart: *chart, Zarf: *zarf, Notes: *notes, Root: *root,
		SourceDate: time.Unix(secs, 0), MinorFirstReleased: *minor, UpgradeFrom: from, Out: *out,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "package %s: %d files, %d images in %s\n", pm.Release, len(pm.Files), len(pm.Images), *out)
	return nil
}

func pushChart(args []string) error {
	fs := flag.NewFlagSet("push-chart", flag.ExitOnError)
	chart := fs.String("chart", "", "the packaged chart (.tgz)")
	repo := fs.String("repository", "", "oci://<registry>/<path> the chart is pushed under")
	sourceDate := fs.String("source-date", os.Getenv("SOURCE_DATE_EPOCH"), "creation time, seconds since the epoch (the commit time)")
	out := fs.String("out", "", "JSON file: {ref, digest}")
	_ = fs.Parse(args)
	if *chart == "" || *out == "" || !strings.HasPrefix(*repo, "oci://") {
		return errors.New("push-chart: -chart, -repository oci://… and -out are required")
	}
	data, err := os.ReadFile(*chart) // #nosec G304 G703 -- release-pipeline input
	if err != nil {
		return err
	}
	ch, err := loader.LoadArchive(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("push-chart: %w", err)
	}
	ref := strings.TrimSuffix(strings.TrimPrefix(*repo, "oci://"), "/") + "/" + ch.Metadata.Name + ":" + ch.Metadata.Version
	c, err := registry.NewClient(registry.ClientOptWriter(io.Discard))
	if err != nil {
		return err
	}
	var opts []registry.PushOption
	if secs, err := strconv.ParseInt(*sourceDate, 10, 64); err == nil && secs > 0 {
		opts = append(opts, registry.PushOptCreationTime(time.Unix(secs, 0).UTC().Format(time.RFC3339)))
	}
	res, err := c.Push(data, ref, opts...)
	if err != nil {
		return fmt.Errorf("push-chart: %w", err)
	}
	repoOnly := ref[:strings.LastIndex(ref, ":")]
	b, err := profilepkg.Encode(map[string]string{"ref": repoOnly + "@" + res.Manifest.Digest, "digest": res.Manifest.Digest, "tag": ref})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "push-chart:", repoOnly+"@"+res.Manifest.Digest)
	return os.WriteFile(*out, b, 0o644) // #nosec G306 G703 -- a public release artifact
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src) // #nosec G304 G703 -- release-pipeline input
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644) // #nosec G306 G703 -- a public release artifact
}
