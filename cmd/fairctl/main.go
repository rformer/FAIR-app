// Command fairctl is the FAIR installer (F-014; design §3.4, §6.2;
// ADR-019). It verifies a release offline, and (from T-12 on) runs
// preflight, installs, upgrades, backs up, restores and decommissions.
//
//	fairctl verify -key FILE [-output text|json] [-color] PACKAGE
//	    verifies the air-gap package directory PACKAGE with the pinned
//	    release key FILE (internal/releaseverify): the release manifest,
//	    SHA256SUMS, package-manifest.json, every image's signature, SBOM and
//	    SLSA provenance, offline, with the standard library alone.
//	fairctl version
//
// Output (design §3.4, AC-54): plain lines, one fact per line; no colour
// unless -color, and never with NO_COLOR set; no cursor movement. -output
// json prints one JSON document (docs/formats/fairctl-<command>.schema.json).
// Exit codes: 0 done, 1 refused (verification or a check failed), 2 usage
// or unreadable input, 3 interrupted (resumable), 4 environment unreachable.
package main

import (
	"crypto/fips140"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes (design §3.4). T-12 adds 3 (interrupted, resumable) and 4
// (environment unreachable) with the commands that return them.
const (
	exitOK      = 0
	exitRefused = 1
	exitUsage   = 2
)

// env is what a command reads and writes besides its arguments.
type env struct {
	stdout, stderr io.Writer
	getenv         func(string) string
}

// command is one fairctl command. T-12 adds the rest of design §6.2's set.
type command struct {
	name, args, summary string
	run                 func(e *env, args []string) int
}

var commands = []command{
	{"verify", "-key FILE [-output text|json] [-color] PACKAGE", "verify a release package offline with the pinned release key", verify},
	{"version", "", "print the version", printVersion},
}

func main() {
	os.Exit(run(os.Args[1:], &env{stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv}))
}

func run(args []string, e *env) int {
	if len(args) == 0 {
		say(e.stderr, "%s", usage())
		return exitUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		say(e.stdout, "%s", usage())
		return exitOK
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(e, args[1:])
		}
	}
	say(e.stderr, "fairctl: unknown command %q\n%s", args[0], usage())
	return exitUsage
}

func usage() string {
	var b strings.Builder
	b.WriteString("usage:\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "  fairctl %s %s\n      %s\n", c.name, c.args, c.summary)
	}
	return b.String()
}

func printVersion(e *env, args []string) int {
	if len(args) > 0 {
		say(e.stderr, "usage: fairctl version\n")
		return exitUsage
	}
	say(e.stdout, "fairctl %s (FIPS 140 module: %v)\n", version, fips140.Enabled())
	return exitOK
}

// output holds the flags every command takes (design §6.2).
type output struct {
	format string
	color  bool
}

func outputFlags(fs *flag.FlagSet) *output {
	o := &output{}
	fs.StringVar(&o.format, "output", "text", "output format: text or json")
	fs.BoolVar(&o.color, "color", false, "colour the text output (never with NO_COLOR set)")
	return o
}

func (o *output) check() error {
	if o.format != "text" && o.format != "json" {
		return fmt.Errorf("-output must be text or json, not %q", o.format)
	}
	return nil
}

// colored reports whether text output may use colour.
func (o *output) colored(e *env) bool { return o.color && e.getenv("NO_COLOR") == "" }

// say writes output; a failed write changes nothing, the exit code carries
// the result.
func say(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
