// Command fairctl is the FAIR installer (F-014; design §3.4, §6.2;
// ADR-019): it verifies a release offline, runs preflight, installs,
// upgrades, rolls back, backs up, restores, installs licences, uninstalls
// and decommissions. Every command of design §6.2 is in the command table;
// one this build does not yet implement says so and exits 2, never
// pretending to succeed (T-12 holds the command set; preflight comes with
// T-13 to T-16, credentials T-17, install T-18, backup and restore T-24 and
// T-26, licences T-20 and T-21, upgrade and rollback T-28, uninstall and
// decommissioning T-30).
//
// Output (design §3.4, AC-54; internal/installer.Output): plain lines, one
// fact per line; no colour unless -color, and never with NO_COLOR set; no
// cursor movement or spinners; prompts end with the accepted answers.
// -output json prints one JSON document per command
// (docs/formats/fairctl-<command>.schema.json; failures before a result
// exists: fairctl-error.schema.json). Exit codes: 0 done, 1 refused
// (verification or a check failed), 2 usage, invalid input or a command not
// in this build, 3 interrupted (resumable), 4 environment unreachable.
package main

import (
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/rformer/fair-app/internal/installer"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes (design §3.4).
const (
	exitOK      = installer.ExitOK
	exitRefused = installer.ExitRefused
	exitUsage   = installer.ExitUsage
)

// env is what a command reads and writes besides its arguments. The
// commands that run steps (T-18 on) add the interrupt context (exit 3) and
// standard input for the prompts.
type env struct {
	stdout, stderr io.Writer
	getenv         func(string) string
}

// command is one fairctl command. name may be two words ("install
// remove"); the longest name matching the arguments runs.
type command struct {
	name, args, summary string
	run                 func(e *env, args []string) int
}

// commands is the command table (set in init: the commands read it for
// their usage lines).
var commands []command

func init() {
	commands = []command{
		{"verify", "-key FILE [-output text|json] [-color] PACKAGE", "verify a release package offline with the pinned release key", verify},
		planned("registry load", "-package DIR -registry HOST[/PATH]", "load the package's images into a private registry",
			spec{required: []string{"package", "registry"}, flags: pkgFlag, more: registryFlag}),
		{"preflight", "-decisions FILE -package DIR -key FILE [-mode saas] [-in-cluster]", "check the cluster read-only against the release, installing nothing", preflightCmd},
		planned("install", "-package DIR (-decisions FILE | -interactive) [-override CHECK:SUBJECT=REASON] [-resume]", "install the platform",
			spec{required: []string{"package"}, oneOf: []string{"decisions", "interactive"}, flags: clusterFlags, more: func(fs *flag.FlagSet) {
				decisionsFlag(fs)
				pkgFlag(fs)
				fs.Bool("interactive", false, "ask for each decision")
				fs.Var(&multi{}, "override", "proceed past a failed check: CHECK:SUBJECT=REASON (repeatable; never the hard floor)")
				fs.Bool("resume", false, "continue from the first step not done")
				fs.String("log", installer.LogFile, "the install log")
			}}),
		planned("install remove", "", "remove what an unfinished install created", spec{flags: clusterFlags}),
		planned("status", "", "show the installation's state and steps", spec{flags: clusterFlags}),
		planned("report", "", "print the install report", spec{flags: clusterFlags}),
		planned("license install", "FILE", "install a licence file", spec{flags: clusterFlags, args: 1}),
		planned("license show", "", "show the licence's state", spec{flags: clusterFlags}),
		planned("upgrade", "-package DIR [-override CHECK:SUBJECT=REASON]", "upgrade to the package's release",
			spec{required: []string{"package"}, flags: clusterFlags, more: func(fs *flag.FlagSet) {
				pkgFlag(fs)
				fs.Var(&multi{}, "override", "proceed past a failed check: CHECK:SUBJECT=REASON (repeatable)")
			}}),
		planned("rollback", "", "roll back to the previous release's images", spec{flags: clusterFlags}),
		planned("backup run", "[-to DIR]", "take a backup now", spec{flags: clusterFlags, more: func(fs *flag.FlagSet) { fs.String("to", "", "write the backup set to DIR") }}),
		planned("backup schedule", "", "show or set the backup schedule", spec{flags: clusterFlags}),
		planned("backup list", "", "list backup sets", spec{flags: clusterFlags}),
		planned("backup verify", "ID", "verify a backup set", spec{flags: clusterFlags, args: 1}),
		planned("backup keys", "-to DIR", "export the backup and key-escrow keys", spec{required: []string{"to"}, flags: clusterFlags,
			more: func(fs *flag.FlagSet) { fs.String("to", "", "the directory to write the keys to") }}),
		planned("restore", "-backup ID [-target-time T] [-new-cluster]", "restore a backup set",
			spec{required: []string{"backup"}, flags: clusterFlags, more: func(fs *flag.FlagSet) {
				fs.String("backup", "", "the backup set")
				fs.String("target-time", "", "restore to this time (RFC 3339)")
				fs.Bool("new-cluster", false, "restore into a new cluster")
			}}),
		planned("restore verify", "", "verify a restore before the installation opens", spec{flags: clusterFlags}),
		planned("uninstall", "", "remove the platform, keeping its data", spec{flags: clusterFlags}),
		planned("decommission export", "", "export what retention requires before destruction", spec{flags: clusterFlags}),
		planned("decommission destroy", "-installation ID -confirm ID", "destroy the installation's data and keys",
			spec{required: []string{"installation", "confirm"}, flags: clusterFlags, more: func(fs *flag.FlagSet) {
				fs.String("installation", "", "the installation identifier")
				fs.String("confirm", "", "the installation identifier again")
			}}),
		planned("decommission record", "", "write the signed decommissioning record", spec{flags: clusterFlags}),
		{"version", "[-output text|json]", "print the version", printVersion},
	}
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
	if c, rest := lookup(args); c != nil {
		return c.run(e, rest)
	}
	out := &installer.Output{Stdout: e.stdout, Stderr: e.stderr, JSON: wantsJSON(args)}
	name := args[0]
	if groups := subcommands(name); len(groups) > 0 {
		sub := ""
		if len(args) > 1 {
			sub = " " + args[1]
		}
		return out.Fail(name, exitUsage, installer.CodeUsage, fmt.Sprintf("unknown command %q: one of %s", name+sub, strings.Join(groups, ", ")))
	}
	if !out.JSON {
		say(e.stderr, "fairctl: unknown command %q\n%s", installer.Printable(name), usage())
		return exitUsage
	}
	return out.Fail(name, exitUsage, installer.CodeUsage, fmt.Sprintf("unknown command %q", name))
}

// lookup returns the command the arguments name and the rest.
func lookup(args []string) (*command, []string) {
	var best *command
	words := 0
	for i := range commands {
		w := strings.Fields(commands[i].name)
		if len(w) <= len(args) && slices.Equal(w, args[:len(w)]) && len(w) > words {
			best, words = &commands[i], len(w)
		}
	}
	if best == nil {
		return nil, nil
	}
	return best, args[words:]
}

// subcommands lists the two-word commands under a first word.
func subcommands(first string) []string {
	var out []string
	for _, c := range commands {
		if w := strings.Fields(c.name); len(w) == 2 && w[0] == first {
			out = append(out, c.name)
		}
	}
	return out
}

func usage() string {
	var b strings.Builder
	b.WriteString("usage:\n")
	for _, c := range commands {
		line := "  fairctl " + c.name
		if c.args != "" {
			line += " " + c.args
		}
		fmt.Fprintf(&b, "%s\n      %s\n", line, c.summary)
	}
	b.WriteString("every command takes -output text|json and -color (never with NO_COLOR set)\nexit codes:\n")
	for _, c := range installer.ExitCodes() {
		fmt.Fprintf(&b, "  %s\n", c)
	}
	return b.String()
}

// versionOutput is `fairctl version -output json`
// (docs/formats/fairctl-version.schema.json).
type versionOutput struct {
	Command string `json:"command"`
	Version string `json:"version"`
	FIPS140 bool   `json:"fips140"`
}

func printVersion(e *env, args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	o := outputFlags(fs)
	out, code, ok := parse(e, "version", fs, o, args)
	if !ok {
		return code
	}
	if fs.NArg() > 0 {
		return out.Fail("version", exitUsage, installer.CodeUsage, "usage: fairctl version [-output text|json]")
	}
	if out.JSON {
		_ = out.Document(versionOutput{Command: "version", Version: version, FIPS140: fips140.Enabled()})
		return exitOK
	}
	out.Line("fairctl %s (FIPS 140 module: %v)", version, fips140.Enabled())
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

// parse parses a command's flags (errors through the output layer, so that
// -output json gets its document) and returns the Output; ok false with the
// exit code when the command must stop (-h prints the flags and exits 0).
func parse(e *env, name string, fs *flag.FlagSet, o *output, args []string) (*installer.Output, int, bool) {
	fs.SetOutput(io.Discard)
	out := &installer.Output{Stdout: e.stdout, Stderr: e.stderr, JSON: wantsJSON(args)}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(e.stdout)
			say(e.stdout, "usage: fairctl %s %s\n", name, argsOf(name))
			fs.PrintDefaults()
			return out, exitOK, false
		}
		return out, out.Fail(name, exitUsage, installer.CodeUsage, err.Error()), false
	}
	out.JSON = o.format == "json"
	if err := o.check(); err != nil {
		return out, out.Fail(name, exitUsage, installer.CodeUsage, err.Error()), false
	}
	out.Color = o.colored(e)
	return out, 0, true
}

func argsOf(name string) string {
	for _, c := range commands {
		if c.name == name {
			return c.args
		}
	}
	return ""
}

// wantsJSON reports whether the raw arguments ask for JSON output (for
// errors found before the flags are parsed).
func wantsJSON(args []string) bool {
	for i, a := range args {
		switch strings.TrimLeft(a, "-") {
		case "output=json":
			return true
		case "output":
			if strings.HasPrefix(a, "-") && i+1 < len(args) && args[i+1] == "json" {
				return true
			}
		}
	}
	return false
}

// say writes output; a failed write changes nothing, the exit code carries
// the result.
func say(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
