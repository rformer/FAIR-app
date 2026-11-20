package main

// F-012 T-07 (F-012-AC-11, AC-12; design §3.4): the release pipeline's
// commands.
//
//	releasegen notes -from REF -to REF [-prs FILE] -out FILE
//	    the release notes (internal/releasenotes); -prs is JSON
//	    [{"number", "title", "url"}] of the security-labelled pull requests.
//	releasegen profiles (-key FILE | -kms KEY -region R) [-dir profiles/packages] -out DIR
//	    the profile packages and their manifest, each signed with the
//	    release key, checked against the key's public half.
//	releasegen component-definition -version V -source-date EPOCH -out FILE
//	    the OSCAL component definition from compliance/statements (every
//	    feature's file, checked as the tests check it).

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/compliance"
	"github.com/rformer/fair-app/internal/profilegen"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasenotes"
)

func notes(args []string) error {
	fs := flag.NewFlagSet("notes", flag.ExitOnError)
	from := fs.String("from", "", "previous release ref (the first release: git's empty tree)")
	to := fs.String("to", "", "this release's ref")
	prs := fs.String("prs", "", "JSON file of security-labelled pull requests")
	out := fs.String("out", "", "output file (Markdown)")
	_ = fs.Parse(args)
	if *from == "" || *to == "" || *out == "" {
		return errors.New("notes: -from, -to and -out are required")
	}
	var sec []releasenotes.PR
	if *prs != "" {
		b, err := os.ReadFile(*prs) // #nosec G304 G703 -- release-pipeline input
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &sec); err != nil {
			return fmt.Errorf("%s: %w", *prs, err)
		}
	}
	n, err := releasenotes.Build(releasenotes.Git{Dir: "."}, *from, *to, sec)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, n.Markdown(), 0o644) // #nosec G306 G703 -- a public release artifact
}

// signer is the release key: a PEM file or the KMS key.
func signer(keyFile, kmsKey, region string) (func([]byte) ([]byte, error), *ecdsa.PublicKey, error) {
	if (keyFile == "") == (kmsKey == "") {
		return nil, nil, errors.New("exactly one of -key and -kms")
	}
	if kmsKey != "" {
		s, err := kmsSigner(kmsKey, region)
		if err != nil {
			return nil, nil, err
		}
		return func(b []byte) ([]byte, error) { return s.Sign(context.Background(), b) }, s.Public(), nil
	}
	k, err := profilepkg.LoadPrivateKey(keyFile)
	if err != nil {
		return nil, nil, err
	}
	return func(b []byte) ([]byte, error) { return profilepkg.Sign(k, b) }, &k.PublicKey, nil
}

func profiles(args []string) error {
	fs := flag.NewFlagSet("profiles", flag.ExitOnError)
	keyFile := fs.String("key", "", "release signing key (PEM)")
	kmsKey := fs.String("kms", "", "release key in AWS KMS")
	region := fs.String("region", "", "AWS region of the KMS key")
	dir := fs.String("dir", "profiles/packages", "the built profile packages")
	out := fs.String("out", "", "output directory")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("profiles: -out is required")
	}
	sign, pub, err := signer(*keyFile, *kmsKey, *region)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".json") {
			b, err := os.ReadFile(filepath.Join(*dir, e.Name())) // #nosec G304 -- the repository's packages
			if err != nil {
				return err
			}
			files[e.Name()] = b
		}
	}
	sigs, err := profilepkg.SignReleaseWith(sign, profilegen.ManifestFile, files)
	if err != nil {
		return err
	}
	for n, b := range sigs {
		files[n] = b
	}
	if _, err := profilepkg.VerifyRelease(pub, profilegen.ManifestFile, files); err != nil {
		return fmt.Errorf("signed profile packages do not verify: %w", err)
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(*out, n), files[n], 0o644); err != nil { // #nosec G306 G703 -- public release artifacts
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "signed %d profile package files\n", len(sigs))
	return nil
}

func componentDefinition(args []string) error {
	fs := flag.NewFlagSet("component-definition", flag.ExitOnError)
	version := fs.String("version", "", "release version")
	sourceDate := fs.String("source-date", os.Getenv("SOURCE_DATE_EPOCH"), "last-modified time, seconds since the epoch (the commit time)")
	dir := fs.String("dir", "compliance/statements", "control implementation statements")
	out := fs.String("out", "", "output file")
	_ = fs.Parse(args)
	if *version == "" || *out == "" {
		return errors.New("component-definition: -version and -out are required")
	}
	secs, err := strconv.ParseInt(*sourceDate, 10, 64)
	if err != nil || secs <= 0 {
		return errors.New("component-definition: -source-date (or SOURCE_DATE_EPOCH) must be the commit time")
	}
	files, err := filepath.Glob(filepath.Join(*dir, "F-*.yaml"))
	if err != nil {
		return err
	}
	slices.Sort(files)
	var all []*compliance.Statements
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- the repository's statements
		if err != nil {
			return err
		}
		s, err := compliance.Load(b)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if err := compliance.Check(s, "."); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		all = append(all, s)
	}
	if len(all) == 0 {
		return fmt.Errorf("component-definition: no statements in %s", *dir)
	}
	b, err := compliance.ComponentDefinition(compliance.PlatformComponentUUID, *version, time.Unix(secs, 0).UTC(), all...)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, b, 0o644) // #nosec G306 G703 -- a public release artifact
}
