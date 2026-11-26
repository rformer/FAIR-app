// Command evidence exports the change evidence of F-012-AC-26 (F-012 T-17,
// design §3.8): for a period, and optionally one instance, every merged
// pull request with its approvers (never its author) and required checks,
// every release with its signatures and the release pipeline's signing,
// provenance and verification jobs, every rollout of a release to an
// instance (Flux's events) and every infrastructure apply with its
// environment approvals; every gap is a finding (internal/changeevidence;
// format docs/formats/fair-change-evidence-v1.md).
//
//	evidence -repo OWNER/NAME [-fleet-repo OWNER/NAME] -from DATE -to DATE [-instance ID]
//	         -token-file FILE [-api URL] -release-pub cosign.pub
//	         [-checks infra/github/variables.tf] [-release-jobs build,provenance,...]
//	         [-flux-events DIR] [-release TAG]... [-first-base COMMIT]
//	         (-key FILE | -unsigned) -out DIR
//
// DATEs are days (UTC); -to is inclusive. It writes DIR/change-evidence.json
// and DIR/change-evidence.csv, each with a detached signature (.sig: the
// releasegen format, ECDSA P-256 over SHA-256, base64 DER) made with the
// evidence key in a PEM file (-key). An evidence key in AWS KMS signs them
// with "releasegen sign -any -kms KEY -region REGION -in FILE" after an
// -unsigned export: the AWS SDK stays linked into releasegen alone
// (ADR-018). Check a file with "releasegen verify -any -pub <evidence public
// key> -in FILE". It only
// reads GitHub (a token from -token-file, never from the environment) and
// the Flux events copied from the evidence bucket. Exit 0 when written
// (findings are listed on stderr and in the files), 1 on an error.
package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/changeevidence"
	"github.com/rformer/fair-app/internal/cicheck"
	"github.com/rformer/fair-app/internal/profilepkg"
)

func main() {
	if err := run(context.Background(), os.Args[1:], nil, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "evidence:", err)
		os.Exit(1)
	}
}

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// run is the command; doer replaces the HTTP client in tests.
func run(ctx context.Context, args []string, doer changeevidence.Doer, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", "", "the platform repository, OWNER/NAME")
	fleetRepo := fs.String("fleet-repo", "", "the fleet repository, OWNER/NAME")
	branch := fs.String("branch", "main", "the protected branch")
	from := fs.String("from", "", "first day (YYYY-MM-DD, UTC)")
	to := fs.String("to", "", "last day, inclusive (YYYY-MM-DD, UTC)")
	instance := fs.String("instance", "", "only this instance's deployments and applies, and what they ran")
	tokenFile := fs.String("token-file", "", "file holding a GitHub token that may read the repositories")
	api := fs.String("api", "https://api.github.com", "the GitHub API")
	pubFile := fs.String("release-pub", "", "the release public key (cosign.pub)")
	checksFile := fs.String("checks", "infra/github/variables.tf", "the required checks (infra/github/variables.tf)")
	jobs := fs.String("release-jobs", strings.Join(changeevidence.DefaultReleaseJobs, ","), "release workflow jobs that must succeed")
	fluxDir := fs.String("flux-events", "", "Flux's events, as copied from the evidence bucket (\"\": none)")
	firstBase := fs.String("first-base", "", "the commit the first release's changes are counted from")
	keyFile := fs.String("key", "", "evidence signing key (PEM)")
	unsigned := fs.Bool("unsigned", false, "write no signatures (to sign with releasegen sign -any -kms)")
	out := fs.String("out", "", "output directory")
	var releases list
	fs.Var(&releases, "release", "also include this release (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	if *out == "" || *pubFile == "" {
		return errors.New("-out and -release-pub are required")
	}
	if (*keyFile == "") == !*unsigned {
		return errors.New("exactly one of -key and -unsigned")
	}
	start, err := day(*from)
	if err != nil {
		return fmt.Errorf("-from: %w", err)
	}
	end, err := day(*to)
	if err != nil {
		return fmt.Errorf("-to: %w", err)
	}
	pub, err := profilepkg.LoadPublicKey(*pubFile)
	if err != nil {
		return fmt.Errorf("-release-pub: %w", err)
	}
	var key *ecdsa.PrivateKey
	if *keyFile != "" {
		if key, err = profilepkg.LoadPrivateKey(*keyFile); err != nil {
			return fmt.Errorf("-key: %w", err)
		}
	}
	var checks []string
	if *checksFile != "" {
		if checks, err = cicheck.RequiredChecks(*checksFile); err != nil {
			return fmt.Errorf("-checks: %w", err)
		}
		if len(checks) == 0 {
			return fmt.Errorf("-checks: %s lists no required checks", *checksFile)
		}
	}
	var events []changeevidence.FluxEvent
	if *fluxDir != "" {
		if events, err = changeevidence.LoadFluxEvents(*fluxDir); err != nil {
			return err
		}
	}
	gh, err := changeevidence.NewGitHub(*api, *tokenFile, doer)
	if err != nil {
		return err
	}
	rep, err := changeevidence.Collect(ctx, gh, changeevidence.Options{
		Repository: *repo, FleetRepository: *fleetRepo, Branch: *branch,
		From: start, To: end.AddDate(0, 0, 1), Instance: *instance,
		Releases: releases, FirstBase: *firstBase, RequiredChecks: checks,
		ReleaseJobs: splitList(*jobs), ReleaseKey: pub, FluxEvents: events,
	})
	if err != nil {
		return err
	}
	j, err := rep.JSON()
	if err != nil {
		return err
	}
	c, err := rep.CSV()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		b    []byte
	}{{"change-evidence.json", j}, {"change-evidence.csv", c}} {
		p, b := filepath.Join(*out, f.name), f.b
		if key == nil {
			if err := os.WriteFile(p, b, 0o600); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stderr, "unsigned: releasegen sign -any -kms KEY -region REGION -in %s\n", p)
			continue
		}
		sig, err := profilepkg.Sign(key, b)
		if err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(p+".sig", sig, 0o600); err != nil {
			return err
		}
	}
	summary(stderr, rep)
	return nil
}

func day(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("a day (YYYY-MM-DD) is required")
	}
	return time.Parse(time.DateOnly, s)
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func summary(w io.Writer, r *changeevidence.Report) {
	_, _ = fmt.Fprintf(w, "change evidence %s to %s: %d pull requests, %d releases, %d deployments, %d applies, %d findings\n",
		r.From, r.To, len(r.PullRequests), len(r.Releases), len(r.Deployments), len(r.Applies), len(r.Findings))
	n := map[string]int{}
	for _, f := range r.Findings {
		n[f.Code]++
	}
	codes := make([]string, 0, len(n))
	for c := range n {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	for _, c := range codes {
		_, _ = fmt.Fprintf(w, "  %s: %d\n", c, n[c])
	}
}
