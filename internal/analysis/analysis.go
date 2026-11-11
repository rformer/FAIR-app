// Package analysis runs simulations in the risk service (F-005 design §1,
// §6.1, §6.3): it records runs in schema analysis, queues them as River
// jobs in schema risk_river, calls the engine (through engine-gate) and
// stores results with their audit events.
//
//   - Request builds the scenario version's input bundle under the
//     analyst's DB context, and inserts the run (analysis.request_run, with
//     the bundle as analysis.run_input) and its job in the request's
//     transaction. The SQL records analysis.run_requested.
//   - The worker (River kind analysis.simulate) starts the run, reads its
//     bundle and inputs with the attempt token, checks the engine (Info:
//     validation passed), streams Simulate, reports progress at most once a
//     second (stopping when the run is cancelled), checks the results'
//     shapes, computes the results digest (Digest) and stores everything
//     with analysis.finish_run in one transaction.
//   - The engine unreachable or the stream broken: retried (3 attempts),
//     then failed engine_unavailable; a model error (invalid_bundle,
//     engine_not_validated, invalid_results, ...) fails at once. A worker
//     that dies leaves the job to River's rescuer, which starts again (the
//     results are deterministic). No partial results are stored.
package analysis

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/rformer/fair-app/internal/risk"
	"github.com/rformer/fair-app/internal/risk/model"
)

// River for analysis (design §4.1): schema risk_river (migrations 0101,
// 0102; app_rw), queue analysis.
const (
	RiverSchema  = "risk_river"
	Queue        = "analysis"
	Attempts     = 3
	RunTimeout   = 2 * time.Hour
	ProgressGap  = time.Second
	MaxBundle    = 8 << 20 // analysis.run_input's bound
	MaxSetsInRun = 20      // analysis.run's bound
)

// SimulateArgs is the simulate job: run RunID.
type SimulateArgs struct {
	RunID string `json:"run_id"`
}

// Kind implements river.JobArgs.
func (SimulateArgs) Kind() string { return "analysis.simulate" }

// InsertOpts implements river.JobArgsWithInsertOpts.
func (SimulateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: Queue, MaxAttempts: Attempts}
}

// RunRequest is what an analyst asks for (design §5).
type RunRequest struct {
	ScenarioID  string
	Version     int64
	ControlSets []string // empty: every set of the version, the current one first
	Iterations  int      // 0: the default
	Seed        *uint64  // nil: random
	Reproduces  string   // a run id, for a reproduction (T-12)
}

// Limits are F-005's settings (design §7), read per request.
type Limits struct {
	IterationsDefault, IterationsMin, IterationsMax, MaxActive int
}

// Requested is a queued run.
type Requested struct {
	ID           string
	BundleDigest string
	Seed         uint64
	Iterations   int
	ControlSets  []string
}

// ErrControlSet: a control set the version does not have, or not the
// current one first.
var ErrControlSet = errors.New("analysis: control sets")

// Request queues a run in tx (under the caller's DB context). The caller
// has checked analysis.run at the scenario's BU. Database refusals are
// returned as they are (PF024 with a hint: archived, iterations,
// too_many_runs, bundle_changed).
func Request(ctx context.Context, tx pgx.Tx, ins func(context.Context, pgx.Tx, SimulateArgs) error, in RunRequest, lim Limits) (Requested, error) {
	b, err := risk.LoadScenarioBundle(ctx, tx, in.ScenarioID, in.Version)
	if err != nil {
		return Requested{}, err
	}
	sets, err := controlSets(ctx, tx, in.ScenarioID, in.Version, in.ControlSets)
	if err != nil {
		return Requested{}, err
	}
	iters := in.Iterations
	if iters == 0 {
		iters = lim.IterationsDefault
	}
	var seed uint64
	if in.Seed != nil {
		seed = *in.Seed
	} else {
		var buf [8]byte
		_, _ = rand.Read(buf[:]) // crypto/rand.Read never fails
		seed = binary.BigEndian.Uint64(buf[:])
	}
	var reproduces any
	if in.Reproduces != "" {
		reproduces = in.Reproduces
	}
	var id string
	err = tx.QueryRow(ctx, "SELECT analysis.request_run($1, $2, $3, $4::numeric, $5, $6, $7, $8, $9, $10)::text",
		in.ScenarioID, in.Version, b.Canonical, strconv.FormatUint(seed, 10), iters, sets, reproduces,
		lim.IterationsMin, lim.IterationsMax, lim.MaxActive).Scan(&id)
	if err != nil {
		return Requested{}, err
	}
	if err := ins(ctx, tx, SimulateArgs{RunID: id}); err != nil {
		return Requested{}, fmt.Errorf("analysis: queue the run: %w", err)
	}
	return Requested{ID: id, BundleDigest: b.Digest, Seed: seed, Iterations: iters, ControlSets: sets}, nil
}

// controlSets are the requested sets, checked against the version's: the
// current set first, each once; every set when none is named.
func controlSets(ctx context.Context, tx pgx.Tx, id string, version int64, want []string) ([]string, error) {
	var doc []byte
	if err := tx.QueryRow(ctx, "SELECT document FROM risk.scenario_version WHERE scenario_id = $1 AND version = $2", id, version).Scan(&doc); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, risk.ErrNoVersion
		}
		return nil, err
	}
	d, problems := model.Validate(model.KindScenario, doc)
	if len(problems) > 0 {
		return nil, fmt.Errorf("analysis: the stored version does not validate: %v", problems)
	}
	sc := d.Value.(*model.Scenario)
	var current string
	var all []string
	for _, cs := range sc.ControlSets {
		if cs.Current {
			current = cs.Name
		}
	}
	all = append(all, current)
	for _, cs := range sc.ControlSets {
		if !cs.Current {
			all = append(all, cs.Name)
		}
	}
	if len(want) == 0 {
		return all, nil
	}
	if want[0] != current {
		return nil, fmt.Errorf("%w: the current set %q comes first", ErrControlSet, current)
	}
	seen := map[string]bool{}
	for _, s := range want {
		if !slices.Contains(all, s) {
			return nil, fmt.Errorf("%w: the version has no control set %q", ErrControlSet, s)
		}
		if seen[s] {
			return nil, fmt.Errorf("%w: %q is named twice", ErrControlSet, s)
		}
		seen[s] = true
	}
	if len(want) > MaxSetsInRun {
		return nil, fmt.Errorf("%w: at most %d control sets", ErrControlSet, MaxSetsInRun)
	}
	return want, nil
}
