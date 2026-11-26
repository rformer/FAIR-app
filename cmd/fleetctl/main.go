// Command fleetctl rolls releases through the SaaS fleet (F-012 T-16,
// F-012-AC-20, AC-21; design §3.6; docs/operations/fleet.md). It reads a
// checkout of the fleet repository and writes every pin change as a local
// branch for a pull request; it never pushes.
//
//	fleetctl status      -repo DIR [-json] [health flags]
//	    each instance's pin, what Flux reconciled, its health now
//	fleetctl promote     -repo DIR -release vX.Y.Z (-digest sha256:… | -fleet-json FILE) [-ring R] [-base REV] [health flags]
//	    the next ring (or R): gates on the earlier ring, then one branch per instance
//	fleetctl merge-check -repo DIR -branch B [-base REV] [health flags]
//	    exit 0 when B may merge now (window and gates; rollbacks at once)
//	fleetctl rollback    -repo DIR (-instance ID[,ID…] | -ring R) [-base REV]
//	    one branch per instance pinning its previous release
//
// Health flags: -credentials DIR (DIR/<instance>/token, ca.crt for the
// instance's API server), -prometheus URL, -prometheus-token FILE,
// -prometheus-ca FILE, -readyz-ca FILE.
//
// Exit status: 0 done, 1 error, 3 stopped by a gate (the pipeline alerts).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rformer/fair-app/internal/fleetctl"
)

// env is what run needs from outside: tests replace the health sources and
// the clock.
type env struct {
	stdout, stderr io.Writer
	now            func() time.Time
	sources        func(fleetctl.Live) fleetctl.Sources
}

func main() {
	e := env{stdout: os.Stdout, stderr: os.Stderr, now: time.Now,
		sources: func(l fleetctl.Live) fleetctl.Sources { return l }}
	os.Exit(run(context.Background(), os.Args[1:], e))
}

const usage = "usage: fleetctl status|promote|merge-check|rollback -repo DIR … (see docs/operations/fleet.md)"

func run(ctx context.Context, args []string, e env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(e.stderr, usage)
		return 1
	}
	var err error
	switch args[0] {
	case "status":
		err = status(ctx, args[1:], e)
	case "promote":
		err = promote(ctx, args[1:], e)
	case "merge-check":
		err = mergeCheck(ctx, args[1:], e)
	case "rollback":
		err = rollback(ctx, args[1:], e)
	default:
		err = errors.New(usage)
	}
	if err == nil {
		return 0
	}
	_, _ = fmt.Fprintln(e.stderr, "fleetctl:", err)
	var se *fleetctl.StopError
	if errors.As(err, &se) {
		return 3
	}
	return 1
}

type common struct {
	fs   *flag.FlagSet
	repo *string
	base *string
	live fleetctl.Live
}

func newFlags(name string, e env, health bool) *common {
	c := &common{fs: flag.NewFlagSet(name, flag.ContinueOnError)}
	c.fs.SetOutput(e.stderr)
	c.repo = c.fs.String("repo", "", "the fleet repository checkout")
	c.base = c.fs.String("base", "HEAD", "the revision the branches start from")
	if health {
		c.fs.StringVar(&c.live.Credentials, "credentials", "", "DIR/<instance>/token and ca.crt for each instance's API server")
		c.fs.StringVar(&c.live.Prometheus, "prometheus", "", "the operations account's Prometheus query URL (https)")
		c.fs.StringVar(&c.live.PromToken, "prometheus-token", "", "a bearer token file for Prometheus")
		c.fs.StringVar(&c.live.PromCA, "prometheus-ca", "", "the CA file for Prometheus")
		c.fs.StringVar(&c.live.ReadyCA, "readyz-ca", "", "the CA file for the readiness URLs")
	}
	return c
}

func (c *common) parse(args []string) error {
	if err := c.fs.Parse(args); err != nil {
		return err
	}
	if c.fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", c.fs.Arg(0))
	}
	if *c.repo == "" {
		return errors.New("-repo is required")
	}
	return nil
}

// load reads the fleet at the base revision, so what is checked is what
// the branches start from.
func (c *common) load(ctx context.Context, rev string) (fleetctl.Git, string, *fleetctl.Fleet, error) {
	g := fleetctl.Git{Dir: *c.repo}
	commit, err := g.Resolve(ctx, rev)
	if err != nil {
		return g, "", nil, err
	}
	f, err := fleetctl.Load(g.Tree(ctx, commit))
	return g, commit, f, err
}

func status(ctx context.Context, args []string, e env) error {
	c := newFlags("status", e, true)
	asJSON := c.fs.Bool("json", false, "JSON lines instead of a table")
	if err := c.parse(args); err != nil {
		return err
	}
	f, err := fleetctl.Load(fleetctl.FSTree{FS: os.DirFS(*c.repo)})
	if err != nil {
		return err
	}
	rows := f.Status(ctx, e.sources(c.live), e.now())
	if *asJSON {
		enc := json.NewEncoder(e.stdout)
		for _, r := range rows {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}
	w := tabwriter.NewWriter(e.stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "INSTANCE\tRING\tPINNED\tRECONCILED\tHEALTH\tWINDOW")
	for _, r := range rows {
		h := "healthy"
		if !r.Healthy {
			h = r.Problem
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Instance, r.Ring, r.Pinned, dash(r.Reconciled), h, r.Window)
	}
	return w.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

var fleetRefRE = regexp.MustCompile(`^[^@\s]+/fair-manifests@(sha256:[0-9a-f]{64})$`)

func promote(ctx context.Context, args []string, e env) error {
	c := newFlags("promote", e, true)
	release := c.fs.String("release", "", "the release tag, vX.Y.Z")
	digest := c.fs.String("digest", "", "the fleet artifact's digest, sha256:…")
	fleetJSON := c.fs.String("fleet-json", "", "the release's fleet.json (its release reference names the digest)")
	ring := c.fs.String("ring", "", "the ring to promote (default: the first not on the release)")
	if err := c.parse(args); err != nil {
		return err
	}
	rel := fleetctl.Pin{Tag: *release, Digest: *digest}
	if *fleetJSON != "" {
		d, err := digestFromFleetJSON(*fleetJSON)
		if err != nil {
			return err
		}
		if rel.Digest != "" && rel.Digest != d {
			return fmt.Errorf("-digest %s is not fleet.json's %s", rel.Digest, d)
		}
		rel.Digest = d
	}
	g, base, f, err := c.load(ctx, *c.base)
	if err != nil {
		return err
	}
	plan, err := f.Promote(ctx, e.sources(c.live), e.now(), rel, *ring)
	if err != nil {
		return err
	}
	if plan.Ring == "" {
		_, _ = fmt.Fprintf(e.stdout, "every instance is pinned to %s\n", rel)
		return nil
	}
	if len(plan.Gated) > 0 {
		_, _ = fmt.Fprintf(e.stdout, "gates passed: %s\n", strings.Join(plan.Gated, ", "))
	}
	return write(ctx, e, g, base, plan)
}

func digestFromFleetJSON(name string) (string, error) {
	b, err := os.ReadFile(name) // #nosec G304 -- the operator's release file
	if err != nil {
		return "", err
	}
	var v struct {
		Release string `json:"release"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	m := fleetRefRE.FindStringSubmatch(v.Release)
	if m == nil {
		return "", fmt.Errorf("%s: release %q is not <repository>/fair-manifests@sha256:…", name, v.Release)
	}
	return m[1], nil
}

func write(ctx context.Context, e env, g fleetctl.Git, base string, plan fleetctl.Plan) error {
	for _, s := range plan.Skipped {
		_, _ = fmt.Fprintf(e.stdout, "%s: already pinned\n", s)
	}
	if len(plan.Changes) == 0 {
		_, _ = fmt.Fprintln(e.stdout, "nothing to change")
		return nil
	}
	if err := g.Branches(ctx, base, plan.Changes); err != nil {
		return err
	}
	for _, ch := range plan.Changes {
		_, _ = fmt.Fprintf(e.stdout, "%s: branch %s (push it and open a pull request)\n", ch.Instance, ch.Branch)
	}
	return nil
}

func mergeCheck(ctx context.Context, args []string, e env) error {
	c := newFlags("merge-check", e, true)
	branch := c.fs.String("branch", "", "the pull request's branch")
	if err := c.parse(args); err != nil {
		return err
	}
	if *branch == "" {
		return errors.New("-branch is required")
	}
	_, _, base, err := c.load(ctx, *c.base)
	if err != nil {
		return err
	}
	_, _, head, err := c.load(ctx, *branch)
	if err != nil {
		return err
	}
	msg, err := fleetctl.MergeCheck(ctx, e.sources(c.live), e.now(), base, head)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(e.stdout, msg)
	return nil
}

func rollback(ctx context.Context, args []string, e env) error {
	c := newFlags("rollback", e, false)
	instances := c.fs.String("instance", "", "instances to roll back, comma-separated")
	ring := c.fs.String("ring", "", "roll back every instance of this ring")
	if err := c.parse(args); err != nil {
		return err
	}
	if (*instances == "") == (*ring == "") {
		return errors.New("give -instance or -ring")
	}
	var ids []string
	if *instances != "" {
		ids = strings.Split(*instances, ",")
	}
	g, base, f, err := c.load(ctx, *c.base)
	if err != nil {
		return err
	}
	plan, err := f.Rollback(ids, *ring)
	if err != nil {
		return err
	}
	return write(ctx, e, g, base, plan)
}
