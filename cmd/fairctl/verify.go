package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"

	"github.com/rformer/fair-app/internal/releaseverify"
)

// verifyOutput is `fairctl verify -output json`
// (docs/formats/fairctl-verify.schema.json).
type verifyOutput struct {
	Command string `json:"command"`
	*releaseverify.Report
}

// verify checks an air-gap package offline (T-11, AC-07; design §3.5). The
// key is pinned: obtained apart from the package (the release notes and the
// vendor's support site print its fingerprint, docs/security/verify.md),
// and the package's own cosign.pub must equal it. Everything the release
// promises is required: the package manifest, and provenance from the
// release workflow.
func verify(e *env, args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	keyFile := fs.String("key", "", "the pinned release public key (PEM), obtained apart from the package")
	out := outputFlags(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if err := out.check(); err != nil {
		say(e.stderr, "fairctl verify: %v\n", err)
		return exitUsage
	}
	if *keyFile == "" || fs.NArg() != 1 {
		say(e.stderr, "usage: fairctl verify -key FILE [-output text|json] [-color] PACKAGE\n")
		return exitUsage
	}
	key, err := releaseverify.LoadPublicKey(*keyFile)
	if err != nil {
		say(e.stderr, "fairctl verify: -key: %v\n", err)
		return exitUsage
	}
	dir := fs.Arg(0)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		say(e.stderr, "fairctl verify: %s is not a package directory\n", dir)
		return exitUsage
	}
	rep := releaseverify.Verify(dir, releaseverify.Options{
		Key:        key,
		Package:    true,
		Provenance: releaseverify.ReleasePolicy(),
	})
	if out.format == "json" {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(verifyOutput{Command: "verify", Report: rep}); err != nil {
			say(e.stderr, "fairctl verify: %v\n", err)
		}
	} else {
		rep.WriteText(e.stdout, e.stderr, out.colored(e))
	}
	if !rep.Verified {
		return exitRefused
	}
	return exitOK
}
