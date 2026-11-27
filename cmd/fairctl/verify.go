package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/rformer/fair-app/internal/installer"
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
	keyFile := fs.String("key", "", "the pinned release public key (PEM), obtained apart from the package")
	o := outputFlags(fs)
	out, code, ok := parse(e, "verify", fs, o, args)
	if !ok {
		return code
	}
	if *keyFile == "" || fs.NArg() != 1 {
		return out.Fail("verify", exitUsage, installer.CodeUsage, "usage: fairctl verify -key FILE [-output text|json] [-color] PACKAGE")
	}
	key, err := releaseverify.LoadPublicKey(*keyFile)
	if err != nil {
		return out.Fail("verify", exitUsage, installer.CodeUsage, "-key: "+err.Error())
	}
	dir := fs.Arg(0)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return out.Fail("verify", exitUsage, installer.CodeUsage, dir+" is not a package directory")
	}
	rep := releaseverify.Verify(dir, releaseverify.Options{
		Key:        key,
		Package:    true,
		Provenance: releaseverify.ReleasePolicy(),
	})
	if out.JSON {
		if err := out.Document(verifyOutput{Command: "verify", Report: rep}); err != nil {
			say(e.stderr, "fairctl verify: %v\n", err)
		}
	} else {
		// The report names files from the package: written plain, made
		// printable line by line, then coloured.
		var stdout, stderr bytes.Buffer
		rep.WriteText(&stdout, &stderr, false)
		writePrintable(e.stdout, stdout.String(), out.Color)
		writePrintable(e.stderr, stderr.String(), out.Color)
	}
	if !rep.Verified {
		return exitRefused
	}
	return exitOK
}

// writePrintable writes text's lines made printable, with the "ok" and
// "FAIL" marks coloured when color is set.
func writePrintable(w io.Writer, text string, color bool) {
	for _, l := range strings.SplitAfter(text, "\n") {
		if l == "" {
			continue
		}
		l = installer.Printable(strings.TrimSuffix(l, "\n")) + "\n"
		if color {
			for _, m := range []struct{ mark, sgr string }{{"ok", "32"}, {"FAIL", "31"}} {
				if strings.HasPrefix(l, m.mark+" - ") {
					l = "\x1b[" + m.sgr + "m" + m.mark + "\x1b[0m" + l[len(m.mark):]
				}
			}
		}
		_, _ = io.WriteString(w, l)
	}
}
