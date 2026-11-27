package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/rformer/fair-app/internal/installer"
)

// spec is a command's command line: its flags, the ones it requires, a set
// of which exactly one is required, and its positional arguments.
type spec struct {
	flags    func(fs *flag.FlagSet) // shared flags (the cluster's)
	more     func(fs *flag.FlagSet) // the command's own
	required []string
	oneOf    []string
	args     int
}

// planned is a command of design §6.2 whose body a later task implements.
// It parses and checks its command line as the finished command will (so
// usage errors are real), reads and checks the decisions file when one is
// named (a file with a secret is refused before anything runs, AC-14),
// then says it is not available in this build and exits 2.
func planned(name, args, summary string, s spec) command {
	return command{name: name, args: args, summary: summary, run: func(e *env, argv []string) int {
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		o := outputFlags(fs)
		if s.flags != nil {
			s.flags(fs)
		}
		if s.more != nil {
			s.more(fs)
		}
		out, code, ok := parse(e, name, fs, o, argv)
		if !ok {
			return code
		}
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		for _, r := range s.required {
			if !set[r] {
				return out.Fail(name, exitUsage, installer.CodeUsage, fmt.Sprintf("-%s is required\nusage: fairctl %s %s", r, name, args))
			}
		}
		if len(s.oneOf) > 0 {
			n := 0
			for _, f := range s.oneOf {
				if set[f] {
					n++
				}
			}
			if n != 1 {
				return out.Fail(name, exitUsage, installer.CodeUsage, fmt.Sprintf("one of -%s is required\nusage: fairctl %s %s", strings.Join(s.oneOf, ", -"), name, args))
			}
		}
		if fs.NArg() != s.args {
			return out.Fail(name, exitUsage, installer.CodeUsage, fmt.Sprintf("usage: fairctl %s %s", name, args))
		}
		if name == "decommission destroy" && fs.Lookup("confirm").Value.String() != fs.Lookup("installation").Value.String() {
			return out.Fail(name, exitUsage, installer.CodeUsage, "-confirm must repeat -installation")
		}
		if f := fs.Lookup("decisions"); f != nil && set["decisions"] {
			if _, err := installer.LoadDecisions(f.Value.String()); err != nil {
				var de *installer.DecisionsError
				if errors.As(err, &de) {
					msg := "the decisions file is refused"
					if de.Secret {
						msg = "the decisions file is refused: it holds a value that looks secret (give credentials as file paths); nothing was run"
					}
					return out.Fail(name, exitUsage, installer.CodeInvalidDecisions, msg, de.Problems...)
				}
				return out.Fail(name, exitUsage, installer.CodeInvalidDecisions, "decisions: "+err.Error())
			}
		}
		return out.Fail(name, exitUsage, installer.CodeNotAvailable, fmt.Sprintf("%s is not yet available in this build", name))
	}}
}

// clusterFlags are the flags of every command that reaches the cluster.
func clusterFlags(fs *flag.FlagSet) {
	fs.String("kubeconfig", "", "the kubeconfig (default: KUBECONFIG, else ~/.kube/config)")
	fs.String("context", "", "the kubeconfig context (default: its current-context)")
}

func decisionsFlag(fs *flag.FlagSet) {
	fs.String("decisions", "", "the decisions file (fair.install-decisions.v1)")
}

func pkgFlag(fs *flag.FlagSet) { fs.String("package", "", "the release package directory") }

func registryFlag(fs *flag.FlagSet) { fs.String("registry", "", "the private registry") }

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }
