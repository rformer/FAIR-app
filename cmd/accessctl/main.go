// Command accessctl applies and expires just-in-time operator access to the
// SaaS instances (F-012 T-18, F-012-AC-27, design §3.9; internal/accessctl,
// docs/operations/access.md). It runs in the fleet repository's access
// workflow, as fair-access-controller in the operations account.
//
//	accessctl check  [-dir access] [-base DIR]        check the directory (and, against the base, that merged requests only gain revocations)
//	accessctl grant  [-dir access] [-record FILE] ID... grant requests inside their window
//	accessctl revoke [-dir access] [-record FILE] -reason TEXT ID
//	accessctl expire [-dir access] [-record FILE]      remove everything no active request backs
//	accessctl list   [-dir access] [-json]             show FAIR assignments and access entries
//
// grant, revoke, expire and list call AWS with credentials from the web
// identity token file only (AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE).
// Each change is written to stdout as a JSON line, and appended to -record.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rformer/fair-app/internal/accessctl"
)

// clients builds the controller's AWS side (a fake in tests).
type clients func(accessctl.ControllerConfig) (accessctl.SSOAdmin, accessctl.Accounts, error)

func realClients(cfg accessctl.ControllerConfig) (accessctl.SSOAdmin, accessctl.Accounts, error) {
	c, err := accessctl.NewClients(cfg)
	if err != nil {
		return nil, nil, err
	}
	return c.SSO, c.Accounts, nil
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, realClients, time.Now))
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: accessctl check|grant|revoke|expire|list [flags] [ID...] (docs/operations/access.md)")
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, mk clients, now func() time.Time) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("accessctl "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "access", "the access directory")
	var base, record, reason *string
	var asJSON *bool
	switch cmd {
	case "check":
		base = fs.String("base", "", "the access directory this one changes (the pull request's base)")
	case "grant", "expire":
		record = fs.String("record", "", "append the records to this file too")
	case "revoke":
		record = fs.String("record", "", "append the records to this file too")
		reason = fs.String("reason", "", "why the access ends now")
	case "list":
		asJSON = fs.Bool("json", false, "JSON lines instead of a table")
	default:
		usage(stderr)
		return 2
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintln(stderr, "accessctl "+cmd+":", err)
		return 1
	}
	d, err := accessctl.Load(*dir)
	if err != nil {
		return fail(err)
	}
	switch cmd {
	case "check":
		if fs.NArg() != 0 {
			usage(stderr)
			return 2
		}
		if *base != "" {
			b, err := accessctl.Load(*base)
			if err != nil {
				return fail(fmt.Errorf("the base: %w", err))
			}
			if err := accessctl.CheckChanges(b, d); err != nil {
				return fail(err)
			}
		}
		_, _ = fmt.Fprintf(stdout, "%d requests, %d operators, %d instances: ok\n", len(d.Requests), len(d.Operators), len(d.Instances))
		return 0
	case "grant":
		if fs.NArg() == 0 {
			usage(stderr)
			return 2
		}
	case "revoke":
		if fs.NArg() != 1 || strings.TrimSpace(*reason) == "" {
			_, _ = fmt.Fprintln(stderr, "accessctl revoke: one request id and -reason")
			return 2
		}
	case "expire":
		if fs.NArg() != 0 {
			usage(stderr)
			return 2
		}
	}

	sso, accounts, err := mk(d.Controller)
	if err != nil {
		return fail(err)
	}
	out := stdout
	if record != nil && *record != "" {
		f, err := os.OpenFile(*record, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 G703 -- the workflow's own record file
		if err != nil {
			return fail(err)
		}
		defer func() { _ = f.Close() }()
		out = io.MultiWriter(stdout, f)
	}
	c := &accessctl.Controller{Dir: d, SSO: sso, Accounts: accounts, Records: out, Now: now}
	switch cmd {
	case "grant":
		err = c.Grant(ctx, fs.Args()...)
	case "revoke":
		err = c.Revoke(ctx, fs.Arg(0), *reason)
	case "expire":
		err = c.Expire(ctx)
	case "list":
		var gs []accessctl.Grant
		gs, err = c.List(ctx)
		err = errors.Join(err, printGrants(stdout, gs, *asJSON))
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

func printGrants(w io.Writer, gs []accessctl.Grant, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		for _, g := range gs {
			if err := enc.Encode(g); err != nil {
				return err
			}
		}
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "INSTANCE\tACCOUNT\tROLE\tPRINCIPAL\tOPERATOR\tREQUEST\tEXPIRES")
	for _, g := range gs {
		req, inst := g.Request, g.Instance
		if !g.Backed {
			req = "(none: expire removes it)"
		}
		if inst == "" {
			inst = "(not an instance)"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", inst, g.Account, g.Role, g.Principal, g.Operator, req, g.Expires)
	}
	return tw.Flush()
}
