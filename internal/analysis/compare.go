package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// F-006 T-02 (F-006-AC-10, AC-11, AC-13, AC-20; design §3.2): comparisons
// of two to six succeeded results, read under the caller's RLS in one
// snapshot, all or nothing.

// Comparison limits (design §9).
const (
	CompareMin = 2
	CompareMax = 6
)

// Comparison errors: ErrHidden for any item the caller cannot see or that
// does not exist (one answer whichever item, AC-13), ErrNotSucceeded for a
// visible one without results, ErrCompareItems for a malformed request.
var (
	ErrHidden       = errors.New("analysis: not found")
	ErrNotSucceeded = errors.New("analysis: not succeeded")
	ErrCompareItems = errors.New("analysis: comparison items")
)

// SamplingNoise is stated on a comparison whose items come from more than
// one run or aggregate (AC-11).
const SamplingNoise = "These results come from separate runs, which draw separate random numbers: differences between them " +
	"include sampling noise. Control sets of one run share their random numbers, so their differences come from the controls."

// Item is one result of a comparison: a run's control set, or an aggregate.
type Item struct {
	Kind string // run or aggregate
	ID   string
	Set  string // a run's control set
}

func (i Item) String() string {
	if i.Kind == "aggregate" {
		return "aggregate:" + i.ID
	}
	return "run:" + i.ID + ":" + i.Set
}

var itemRE = regexp.MustCompile(`^(?:run:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):(.+)|aggregate:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))$`)

// ParseItems reads the request's `item` values in order: `run:<id>:<set>`
// (the set name is the rest of the value, which the query string carries
// percent-encoded) or `aggregate:<id>`; 2 to 6, no duplicates.
func ParseItems(values []string) ([]Item, error) {
	if len(values) < CompareMin || len(values) > CompareMax {
		return nil, fmt.Errorf("%w: compare %d to %d items", ErrCompareItems, CompareMin, CompareMax)
	}
	out := make([]Item, 0, len(values))
	seen := map[Item]bool{}
	for _, v := range values {
		m := itemRE.FindStringSubmatch(v)
		if m == nil || len(m[2]) > 200 {
			return nil, fmt.Errorf("%w: an item is run:<id>:<control set> or aggregate:<id>", ErrCompareItems)
		}
		it := Item{Kind: "run", ID: m[1], Set: m[2]}
		if m[3] != "" {
			it = Item{Kind: "aggregate", ID: m[3]}
		}
		if seen[it] {
			return nil, fmt.Errorf("%w: %s is named twice", ErrCompareItems, it)
		}
		seen[it] = true
		out = append(out, it)
	}
	return out, nil
}

// compared is an item as read.
type compared struct {
	item                                      Item
	bu, state, seed, label                    string
	scenario, scenarioName, aggregateName     *string
	version                                   *int64
	iterations                                int64
	engineVersion, architecture, resultDigest *string
	sets                                      []string
	summary                                   map[string]any
}

// Compare reads the items in tx (the caller's context, one snapshot) and
// builds the comparison: every item's facts, ALE summary and curve, its
// differences from the first, which inputs differ, and whether sampling
// noise is part of the differences. Any unseen item is ErrHidden, before
// anything else is checked, so no answer depends on which item is hidden.
func Compare(ctx context.Context, tx pgx.Tx, items []Item) (map[string]any, error) {
	got := make([]*compared, len(items))
	for i, it := range items {
		c := &compared{item: it}
		var err error
		if it.Kind == "run" {
			err = tx.QueryRow(ctx, `SELECT r.bu_id::text, r.state, r.seed::text, r.scenario_id::text, s.name, r.scenario_version, r.iterations,
				r.engine_version, r.architecture, r.result_digest, r.control_sets
				FROM analysis.run r LEFT JOIN risk.scenario s ON s.id = r.scenario_id WHERE r.id = $1`, it.ID).
				Scan(&c.bu, &c.state, &c.seed, &c.scenario, &c.scenarioName, &c.version, &c.iterations, &c.engineVersion, &c.architecture, &c.resultDigest, &c.sets)
		} else {
			err = tx.QueryRow(ctx, `SELECT a.bu_id::text, a.state, a.seed::text, a.name, a.iterations, a.engine_version, a.architecture, a.result_digest
				FROM analysis.aggregate a WHERE a.id = $1`, it.ID).
				Scan(&c.bu, &c.state, &c.seed, &c.aggregateName, &c.iterations, &c.engineVersion, &c.architecture, &c.resultDigest)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrHidden
		}
		if err != nil {
			return nil, err
		}
		got[i] = c
	}
	for _, c := range got {
		if c.item.Kind == "run" && !slices.Contains(c.sets, c.item.Set) {
			return nil, fmt.Errorf("%w: %q is not a control set of run %s", ErrCompareItems, c.item.Set, c.item.ID)
		}
	}
	for _, c := range got {
		if c.state != "succeeded" {
			return nil, ErrNotSucceeded
		}
	}
	for _, c := range got {
		var raw []byte
		var err error
		if c.item.Kind == "run" {
			err = tx.QueryRow(ctx, "SELECT summary FROM analysis.result WHERE run_id = $1 AND control_set = $2", c.item.ID, c.item.Set).Scan(&raw)
		} else {
			err = tx.QueryRow(ctx, "SELECT summary FROM analysis.aggregate WHERE id = $1", c.item.ID).Scan(&raw)
		}
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &c.summary); err != nil {
			return nil, err
		}
	}
	return build(got), nil
}

var comparedPercentiles = []string{"p50", "p90", "p95", "p99"}

func build(got []*compared) map[string]any {
	base := ale(got[0].summary)
	out := make([]map[string]any, len(got))
	for i, c := range got {
		m := map[string]any{
			"kind": c.item.Kind, "id": c.item.ID, "bu_id": c.bu, "seed": c.seed, "iterations": c.iterations, "result_digest": c.resultDigest,
			"engine": map[string]any{"version": c.engineVersion, "architecture": c.architecture},
			"ale":    c.summary["ale"], "curve": c.summary["curve"], "differences": nil,
		}
		if c.item.Kind == "run" {
			m["control_set"], m["scenario_id"], m["scenario_version"], m["scenario_name"] = c.item.Set, c.scenario, c.version, c.scenarioName
			m["label"] = fmt.Sprintf("%s v%d · %s", deref(c.scenarioName, "Scenario"), *c.version, c.item.Set)
		} else {
			m["aggregate_name"] = c.aggregateName
			m["label"] = deref(c.aggregateName, "Aggregate")
		}
		if i > 0 {
			m["differences"] = differences(ale(c.summary), base)
		}
		out[i] = m
	}
	sources := map[string]bool{}
	for _, c := range got {
		sources[c.item.Kind+":"+c.item.ID] = true
	}
	noise := len(sources) > 1
	res := map[string]any{"items": out, "unlike": unlike(got), "sampling_noise": noise, "statement": nil}
	if noise {
		res["statement"] = SamplingNoise
	}
	return res
}

func deref(s *string, or string) string {
	if s == nil || *s == "" {
		return or
	}
	return *s
}

// ale is a summary's ALE: mean and percentiles as numbers (absent ones
// missing).
func ale(summary map[string]any) map[string]float64 {
	out := map[string]float64{}
	a, _ := summary["ale"].(map[string]any)
	if v, ok := a["mean"].(float64); ok {
		out["mean"] = v
	}
	ps, _ := a["percentiles"].(map[string]any)
	for _, p := range comparedPercentiles {
		if v, ok := ps[p].(float64); ok {
			out[p] = v
		}
	}
	return out
}

// differences are x − base as amounts and as shares of base (null where
// base is 0 or either value is missing).
func differences(x, base map[string]float64) map[string]any {
	one := func(k string) any {
		a, ok1 := x[k]
		b, ok2 := base[k]
		if !ok1 || !ok2 {
			return nil
		}
		d := map[string]any{"amount": a - b, "share": nil}
		if b != 0 {
			d["share"] = (a - b) / b
		}
		return d
	}
	ps := map[string]any{}
	for _, p := range comparedPercentiles {
		ps[p] = one(p)
	}
	return map[string]any{"mean": one("mean"), "percentiles": ps}
}

// unlike lists the inputs that differ among the items (AC-11); an
// aggregate has no scenario or version, which differs from a run's.
func unlike(got []*compared) []string {
	fields := []struct {
		name string
		of   func(*compared) string
	}{
		{"scenario", func(c *compared) string { return deref(c.scenario, "") }},
		{"scenario_version", func(c *compared) string {
			if c.version == nil {
				return ""
			}
			return fmt.Sprint(*c.version)
		}},
		{"iterations", func(c *compared) string { return fmt.Sprint(c.iterations) }},
		{"seed", func(c *compared) string { return c.seed }},
		{"engine_version", func(c *compared) string { return deref(c.engineVersion, "") }},
		{"architecture", func(c *compared) string { return deref(c.architecture, "") }},
	}
	out := []string{}
	for _, f := range fields {
		for _, c := range got[1:] {
			if f.of(c) != f.of(got[0]) {
				out = append(out, f.name)
				break
			}
		}
	}
	return out
}

// IsCompareItems reports a malformed comparison request and its message.
func IsCompareItems(err error) (string, bool) {
	if !errors.Is(err, ErrCompareItems) {
		return "", false
	}
	return strings.TrimPrefix(err.Error(), ErrCompareItems.Error()+": "), true
}
