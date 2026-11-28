// Package preflight is the installer's preflight (F-014 T-13; AC-15, AC-18,
// AC-21; design §3.7): before an install or upgrade, and alone for a
// security team's review, it checks the target cluster and reports every
// failure with the check, the subject, what was found, the affected
// controls, the remediation and whether it is on the hard floor.
//
// One rule, two moments (AC-18). The checks F-015's drift scanner runs are
// run here by the same code: checks.Catalog, the scanner's own functions,
// never a copy. Before install the release's objects do not exist, so the
// catalog reads objreader.Overlay(live, applied): the administrator's
// read-only view of the cluster with the release's rendered objects served
// as if applied (objreader.Applied: workloads as running pods of their
// templates, hooks gone). After install the scanner reads the applied
// objects themselves, so both evaluate the same objects by the same rule;
// TestPreflightMatchesDrift holds the two equal over every distribution
// fixture of internal/scanner/checks/testdata, pass and fail.
//
// Read-only (AC-21). The live reader is internal/scanner/kube's client,
// which issues only GET requests (list and watch) and refuses Secrets;
// preflight writes nothing anywhere. Its report, fair.preflight-report.v1
// (docs/formats/fair-preflight-report-v1.md), is recorded in
// install.preflight once the database exists (Record: run id, release,
// purpose, times, result, the report and its digest; never a secret).
//
// The registry (Checks) lists every check with its metadata: the drift
// checks from checks.Metas() and the preflight-only cluster and dependency
// checks of design §3.7 (T-14, T-15 register them with register). Each
// classifies its findings for the hard floor (HardFloor, AC-19): a finding
// on the floor is never overridden; any other failed finding passes only
// on an override naming its check and subject with a reason (design §3.8;
// recording overrides as deployment exceptions is T-16), and SaaS takes no
// override at all.
package preflight

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/checks"
	"github.com/rformer/fair-app/internal/scanner/kube"
	"github.com/rformer/fair-app/internal/scanner/objreader"
)

// Sources of a check.
const (
	SourceDrift     = "drift"     // F-015's deployment check catalog, also run by the drift scanner
	SourcePreflight = "preflight" // preflight only (design §3.7: cluster and dependency checks)
)

// Deployment modes (ADR-005).
const (
	ModeSaaS       = "saas"
	ModeSelfHosted = "self-hosted"
	ModeAirGapped  = "air-gapped"
)

// Modes are the deployment modes.
var Modes = []string{ModeSaaS, ModeSelfHosted, ModeAirGapped}

// Purposes of a run.
const (
	PurposeCheck   = "check"   // fairctl preflight alone
	PurposeInstall = "install" // fairctl install's step 3
	PurposeUpgrade = "upgrade" // fairctl upgrade
)

// Check is a registry entry.
type Check struct {
	ID          string
	Title       string
	Controls    []string
	Remediation string
	// Anchor is the check's section in the preflight documentation
	// (AC-52; TestPreflightChecksDocumented).
	Anchor string
	Source string   // SourceDrift or SourcePreflight
	Modes  []string // the modes it runs in; nil: every mode

	// floor classifies a finding for the hard floor (nil: never on it).
	floor func(f Finding, c Context) bool
	// run is a preflight-only check's body (nil for drift checks, which
	// run through checks.Catalog).
	run func(ctx context.Context, in Input) (scanner.Result, error)
}

// AppliesTo reports whether the check runs in a mode.
func (c Check) AppliesTo(mode string) bool {
	return len(c.Modes) == 0 || slices.Contains(c.Modes, mode)
}

// Input is what a preflight-only check reads (T-14, T-15 extend it with
// the decisions and the dependency connections).
type Input struct {
	Reader scanner.Reader // the overlay: the live cluster with the release applied
	Scope  scanner.Scope
	Mode   string
}

// only are the preflight-only checks, in registration order.
var only []Check

// register adds a preflight-only check (T-14, T-15). An identifier may be
// registered once and never equal a drift check's.
func register(c Check) {
	if c.run == nil || c.ID == "" {
		panic("preflight: a preflight-only check needs an identifier and a body")
	}
	for _, m := range checks.Metas() {
		if m.ID == c.ID {
			panic("preflight: " + c.ID + " is a drift check")
		}
	}
	for _, o := range only {
		if o.ID == c.ID {
			panic("preflight: " + c.ID + " registered twice")
		}
	}
	c.Source = SourcePreflight
	if c.Anchor == "" {
		c.Anchor = c.ID
	}
	only = append(only, c)
}

// Checks is the registry: every drift check (checks.Metas(), in the
// catalog's order) and then the preflight-only checks.
func Checks() []Check {
	var out []Check
	for _, m := range checks.Metas() {
		out = append(out, Check{ID: m.ID, Title: m.Title, Controls: slices.Clone(m.Controls), Remediation: m.Remediation,
			Anchor: m.ID, Source: SourceDrift, floor: driftFloor[m.ID]})
	}
	for _, c := range only {
		c.Controls = slices.Clone(c.Controls)
		c.Modes = slices.Clone(c.Modes)
		out = append(out, c)
	}
	return out
}

// Override names a failed finding to proceed past (design §3.8).
type Override struct {
	Check   string `json:"check"`
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

// Options configure Run.
type Options struct {
	// Live reads the target cluster (read-only: kube.Client).
	Live scanner.Reader
	// Objects are the release's rendered objects (the chart with the
	// decisions' values), applied over Live as the cluster will serve them
	// (objreader.Applied). None: the cluster as it runs.
	Objects []map[string]any
	// Config is the drift checks' configuration, as the installed scanner
	// will have it (ScannerSettings): the verified release manifest, the
	// attested pod security default, the ingress endpoints.
	Config checks.Config
	// Scope is the scanner's scope (ScannerSettings).
	Scope scanner.Scope
	// Release names the release; Purpose is PurposeCheck, PurposeInstall
	// or PurposeUpgrade; Mode a deployment mode; Profile the posture
	// profile (the FIPS hard floor follows its family).
	Release, Purpose, Mode, Profile string
	// Overrides name failed findings to proceed past.
	Overrides []Override
	// Timeout bounds each check (default 2 minutes, the scanner's).
	Timeout time.Duration
	Now     func() time.Time
}

// ErrUnreachable means the cluster could not be reached (fairctl exits 4).
var ErrUnreachable = errors.New("preflight: the cluster is unreachable")

// Run runs every check that applies to the mode and returns the report.
// It returns an error only for invalid options or an unreachable cluster:
// a check that cannot run is a failed check in the report (never passed).
func Run(ctx context.Context, o Options) (*Report, error) {
	if o.Live == nil {
		return nil, errors.New("preflight: no cluster reader")
	}
	if !slices.Contains(Modes, o.Mode) {
		return nil, fmt.Errorf("preflight: mode %q is not one of %s", o.Mode, strings.Join(Modes, ", "))
	}
	if !slices.Contains([]string{PurposeCheck, PurposeInstall, PurposeUpgrade}, o.Purpose) {
		return nil, fmt.Errorf("preflight: purpose %q", o.Purpose)
	}
	if o.Release == "" {
		return nil, errors.New("preflight: no release")
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	rep := &Report{Format: Format, Release: o.Release, Purpose: o.Purpose, Mode: o.Mode, Profile: o.Profile, Started: stamp(now())}

	// The cluster first: unreachable is not a failed check.
	if _, _, err := o.Live.List(ctx, kube.Namespaces, ""); err != nil && !errors.Is(err, kube.ErrForbidden) && !errors.Is(err, kube.ErrNotFound) {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	set := objreader.New()
	applied, err := objreader.Applied(o.Objects)
	if err != nil {
		return nil, err
	}
	for _, obj := range applied {
		if _, err := set.Add(obj); err != nil {
			return nil, fmt.Errorf("preflight: the release's objects: %w", err)
		}
	}
	reader := objreader.Overlay(o.Live, set)

	drift := map[string]scanner.Check{}
	for _, c := range checks.Catalog(o.Config) {
		drift[c.ID()] = c
	}
	reg := Checks()
	results := make([]CheckResult, len(reg))
	var wg sync.WaitGroup
	for i, c := range reg {
		results[i] = CheckResult{ID: c.ID, Title: c.Title, Source: c.Source, Controls: c.Controls}
		if !c.AppliesTo(o.Mode) {
			results[i].Result = ResultNotApplicable
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			var res scanner.Result
			var err error
			if c.run != nil {
				res, err = c.run(cctx, Input{Reader: reader, Scope: o.Scope, Mode: o.Mode})
			} else if d, ok := drift[c.ID]; ok {
				res, err = d.Run(cctx, reader, o.Scope)
			} else {
				err = errors.New("not in the deployment check catalog")
			}
			results[i].fill(c, res, err, Context{Mode: o.Mode, Profile: o.Profile})
		}()
	}
	wg.Wait()
	rep.Checks = results
	rep.applyOverrides(o.Overrides)
	rep.Finished = stamp(now())
	return rep, nil
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
