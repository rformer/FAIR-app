package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/chartgate"
	"github.com/rformer/fair-app/internal/installer"
	"github.com/rformer/fair-app/internal/preflight"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/releaseverify"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/checks"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

// preflightOutput is `fairctl preflight -output json`
// (docs/formats/fairctl-preflight.schema.json).
type preflightOutput struct {
	Command string            `json:"command"`
	RunID   string            `json:"run_id"`
	Digest  string            `json:"digest"`
	Report  *preflight.Report `json:"report"`
}

// preflightTimeout bounds a whole run (design §3.7: at most 5 minutes).
const preflightTimeout = 5 * time.Minute

// dialCluster connects to the cluster (tests replace it).
var dialCluster = func(o kube.KubeconfigOptions) (scanner.Reader, error) {
	cfg, err := kube.FromKubeconfig(o)
	if err != nil {
		return nil, err
	}
	return kube.New(cfg)
}

// preflightCmd runs the preflight alone (T-13; AC-15, AC-18, AC-21; design
// §3.7): it verifies the package with the pinned key, renders its chart
// with the decisions' values, and runs every check over the cluster read
// through the administrator's kubeconfig with the release applied, read
// only and installing nothing. Exit 0 passed (overrides included), 1
// refused, 2 usage or invalid input, 4 the cluster unreachable. Overrides
// come from the decisions; their recording as deployment exceptions is
// install's (T-16, T-18).
func preflightCmd(e *env, args []string) int {
	const name = "preflight"
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	o := outputFlags(fs)
	clusterFlags(fs)
	decisionsFlag(fs)
	pkgFlag(fs)
	keyFile := fs.String("key", "", "the pinned release public key (PEM), obtained apart from the package")
	inCluster := fs.Bool("in-cluster", false, "run inside the cluster (the chart's hook)")
	mode := fs.String("mode", "", "the deployment mode to check for (saas: no overrides)")
	out, code, ok := parse(e, name, fs, o, args)
	if !ok {
		return code
	}
	if fs.NArg() != 0 {
		return out.Fail(name, exitUsage, installer.CodeUsage, "usage: fairctl preflight "+argsOf(name))
	}
	var d *installer.Decisions
	if p := fs.Lookup("decisions").Value.String(); p != "" {
		if d, code, ok = loadDecisions(out, name, p); !ok {
			return code
		}
	}
	if *inCluster {
		return out.Fail(name, exitUsage, installer.CodeNotAvailable, "preflight -in-cluster is not yet available in this build")
	}
	pkg := fs.Lookup("package").Value.String()
	for flagName, v := range map[string]string{"decisions": fs.Lookup("decisions").Value.String(), "package": pkg, "key": *keyFile} {
		if v == "" {
			return out.Fail(name, exitUsage, installer.CodeUsage, fmt.Sprintf("-%s is required\nusage: fairctl preflight %s", flagName, argsOf(name)))
		}
	}
	switch *mode {
	case "":
		*mode = d.Mode
	case preflight.ModeSaaS:
	default:
		return out.Fail(name, exitUsage, installer.CodeUsage, "-mode must be saas")
	}
	key, err := releaseverify.LoadPublicKey(*keyFile)
	if err != nil {
		return out.Fail(name, exitUsage, installer.CodeUsage, "-key: "+err.Error())
	}
	if st, err := os.Stat(pkg); err != nil || !st.IsDir() {
		return out.Fail(name, exitUsage, installer.CodeUsage, pkg+" is not a package directory")
	}

	// The release: verified before anything reads the cluster (a release
	// that does not verify is on the hard floor, AC-19).
	vr := releaseverify.Verify(pkg, releaseverify.Options{Key: key, Package: true, Provenance: releaseverify.ReleasePolicy()})
	if err := vr.Err(); err != nil {
		return out.Fail(name, exitRefused, installer.CodeRefused, "the package does not verify: "+err.Error())
	}
	m, err := releasemanifest.Load(key, filepath.Join(pkg, releaseverify.ReleaseManifestFile))
	if err != nil {
		return out.Fail(name, exitRefused, installer.CodeRefused, "the release manifest: "+err.Error())
	}
	b, err := os.ReadFile(filepath.Join(pkg, releaseverify.PackageManifestFile)) // #nosec G304 -- the verified package
	if err != nil {
		return out.Fail(name, exitRefused, installer.CodeRefused, "the package manifest: "+err.Error())
	}
	pm, err := releaseverify.DecodePackageManifest(b)
	if err != nil {
		return out.Fail(name, exitRefused, installer.CodeRefused, "the package manifest: "+err.Error())
	}
	var chart string
	for _, f := range pm.Files {
		if path.Base(f.Path) == chartgate.ChartFile(m.Release) {
			if chart != "" {
				return out.Fail(name, exitRefused, installer.CodeRefused, "the package holds more than one chart")
			}
			chart = filepath.Join(pkg, filepath.FromSlash(f.Path))
		}
	}
	if chart == "" {
		return out.Fail(name, exitRefused, installer.CodeRefused, "the package holds no chart "+chartgate.ChartFile(m.Release))
	}
	manifest, err := preflight.PackageManifest(m, pm)
	if err != nil {
		return out.Fail(name, exitRefused, installer.CodeRefused, err.Error())
	}
	objs, err := preflight.RenderChart(chart, installer.ChartValues(d), false)
	if errors.Is(err, preflight.ErrValues) {
		return out.Fail(name, exitUsage, installer.CodeInvalidDecisions, "the decisions do not give the chart's values: "+err.Error())
	} else if err != nil {
		return out.Fail(name, exitRefused, installer.CodeRefused, err.Error())
	}

	ko := kube.KubeconfigOptions{Context: fs.Lookup("context").Value.String(), UserAgent: "fairctl", Paths: kube.KubeconfigPaths(e.getenv)}
	if p := fs.Lookup("kubeconfig").Value.String(); p != "" {
		ko.Paths = []string{p}
	}
	live, err := dialCluster(ko)
	if err != nil {
		return out.Fail(name, exitUsage, installer.CodeUsage, "kubeconfig: "+err.Error())
	}
	s := preflight.ScannerSettings(objs)
	var overrides []preflight.Override
	for _, ov := range d.Overrides {
		overrides = append(overrides, preflight.Override{Check: ov.Check, Subject: ov.Subject, Reason: ov.Reason})
	}
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	rep, err := preflight.Run(ctx, preflight.Options{Live: live, Objects: objs, Scope: s.Scope,
		Config:  checks.Config{Manifest: manifest, PSADefault: s.PSADefault, IngressEndpoints: s.IngressEndpoints},
		Release: m.Release, Purpose: preflight.PurposeCheck, Mode: *mode, Profile: d.Profile, Overrides: overrides})
	if errors.Is(err, preflight.ErrUnreachable) {
		return out.Fail(name, installer.ExitUnreachable, installer.CodeUnreachable, err.Error())
	} else if err != nil {
		return out.Fail(name, exitUsage, installer.CodeUsage, err.Error())
	}
	id, err := preflight.NewRunID()
	if err != nil {
		return out.Fail(name, exitUsage, installer.CodeUsage, err.Error())
	}
	rec, err := rep.Record(id)
	if err != nil {
		return out.Fail(name, exitRefused, installer.CodeRefused, err.Error())
	}
	if out.JSON {
		if err := out.Document(preflightOutput{Command: name, RunID: rec.RunID, Digest: rec.Digest, Report: rep}); err != nil {
			say(e.stderr, "fairctl preflight: %v\n", err)
		}
	} else {
		writePreflight(out, rep, rec)
	}
	if rep.Result == preflight.Refused {
		return exitRefused
	}
	return exitOK
}

// writePreflight prints a report as plain lines, one fact per line.
func writePreflight(out *installer.Output, r *preflight.Report, rec *preflight.Record) {
	out.Fact("release", r.Release)
	out.Fact("purpose", r.Purpose)
	out.Fact("mode", r.Mode)
	if r.Profile != "" {
		out.Fact("profile", r.Profile)
	}
	for _, c := range r.Checks {
		switch c.Result {
		case preflight.ResultNotApplicable:
			out.Line("skip: %s (not in mode %s)", c.ID, r.Mode)
			continue
		case preflight.ResultPassed:
			out.Result(true, "%s: %s", c.ID, c.Title)
			continue
		case preflight.ResultError:
			out.Result(false, "%s: %s: could not run: %s", c.ID, c.Title, c.Error)
			continue
		}
		for _, f := range c.Findings {
			mark := ""
			switch {
			case f.Overridden:
				mark = " (overridden)"
			case f.HardFloor:
				mark = " (hard floor: no override)"
			}
			out.Result(f.Overridden, "%s: %s [%s]%s", c.ID, f.Subject, f.Severity, mark)
			out.Line("  found: %s", string(f.Detail))
			out.Line("  controls: %s", strings.Join(f.Controls, ", "))
			out.Line("  remediation: %s", f.Remediation)
		}
	}
	for _, o := range r.Overrides {
		if o.Applied {
			out.Line("override: %s %s: applied (%s)", o.Check, o.Subject, o.Reason)
		} else {
			out.Line("override: %s %s: not applied: %s", o.Check, o.Subject, o.Refusal)
		}
	}
	out.Fact("result", r.Result)
	out.Fact("run", rec.RunID)
	out.Fact("digest", rec.Digest)
}
