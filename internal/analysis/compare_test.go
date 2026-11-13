package analysis

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// F-006 T-02 (AC-10, AC-11; design §3.2): items, differences, unlike.

const (
	idA = "11111111-1111-4111-8111-111111111111"
	idB = "22222222-2222-4222-8222-222222222222"
)

func TestParseItems(t *testing.T) {
	got, err := ParseItems([]string{"run:" + idA + ":Current", "aggregate:" + idB, "run:" + idA + ":With: MFA & SSO"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Item{{"run", idA, "Current"}, {"aggregate", idB, ""}, {"run", idA, "With: MFA & SSO"}}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	for name, v := range map[string][]string{
		"one":         {"aggregate:" + idA},
		"seven":       {"aggregate:" + idA, "aggregate:" + idB, "run:" + idA + ":a", "run:" + idA + ":b", "run:" + idA + ":c", "run:" + idA + ":d", "run:" + idA + ":e"},
		"twice":       {"run:" + idA + ":Current", "run:" + idA + ":Current"},
		"no set":      {"run:" + idA, "aggregate:" + idB},
		"empty set":   {"run:" + idA + ":", "aggregate:" + idB},
		"other kind":  {"scenario:" + idA, "aggregate:" + idB},
		"upper uuid":  {"aggregate:" + strings.ToUpper("abcdef01-1111-4111-8111-111111111111"), "aggregate:" + idB},
		"long set":    {"run:" + idA + ":" + strings.Repeat("x", 201), "aggregate:" + idB},
		"agg and set": {"aggregate:" + idA + ":Current", "aggregate:" + idB},
	} {
		if _, err := ParseItems(v); !errors.Is(err, ErrCompareItems) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if msg, ok := IsCompareItems(func() error { _, err := ParseItems(nil); return err }()); !ok || msg != "compare 2 to 6 items" {
		t.Errorf("message %q", msg)
	}
}

func TestComparisonBuild(t *testing.T) {
	s := func(v string) *string { return &v }
	n := func(v int64) *int64 { return &v }
	sum := func(mean, p50 float64) map[string]any {
		return map[string]any{"ale": map[string]any{"mean": mean, "percentiles": map[string]any{"p50": p50, "p90": 0.0}}, "curve": map[string]any{}}
	}
	run := func(id, set, scenario string, version int64, seed string, engine string, mean, p50 float64) *compared {
		return &compared{item: Item{"run", id, set}, bu: "bu", seed: seed, scenario: s(scenario), scenarioName: s("Ransomware"), version: n(version),
			iterations: 1000, engineVersion: s(engine), architecture: s("amd64"), resultDigest: s("d"), summary: sum(mean, p50)}
	}

	// Two sets of one run: no sampling noise, nothing unlike.
	out := build([]*compared{run(idA, "Current", "s", 1, "7", "0.1.0", 100, 50), run(idA, "MFA", "s", 1, "7", "0.1.0", 80, 0)})
	if out["sampling_noise"] != false || out["statement"] != nil || len(out["unlike"].([]string)) != 0 {
		t.Fatalf("one run: %v", out)
	}
	items := out["items"].([]map[string]any)
	if items[0]["differences"] != nil || items[0]["label"] != "Ransomware v1 · Current" {
		t.Errorf("base: %v", items[0])
	}
	d := items[1]["differences"].(map[string]any)
	if m := d["mean"].(map[string]any); m["amount"] != -20.0 || m["share"] != -0.2 {
		t.Errorf("mean difference %v", m)
	}
	ps := d["percentiles"].(map[string]any)
	if p := ps["p50"].(map[string]any); p["amount"] != -50.0 || p["share"] != -1.0 {
		t.Errorf("p50 %v", p)
	}
	if p := ps["p90"].(map[string]any); p["amount"] != 0.0 || p["share"] != nil {
		t.Errorf("p90 over a zero base %v", p)
	}
	if ps["p95"] != nil {
		t.Errorf("a missing percentile %v", ps["p95"])
	}

	// Another scenario, version, seed and engine, and an aggregate.
	agg := &compared{item: Item{"aggregate", idB, ""}, bu: "bu", seed: "7", aggregateName: s("Portfolio"), iterations: 1000,
		engineVersion: s("0.1.0"), architecture: s("amd64"), resultDigest: s("d"), summary: sum(1, 1)}
	out = build([]*compared{run(idA, "Current", "s", 1, "7", "0.1.0", 1, 1), run(idB, "Current", "t", 2, "8", "0.2.0", 1, 1), agg})
	if u := out["unlike"].([]string); !slices.Equal(u, []string{"scenario", "scenario_version", "seed", "engine_version"}) {
		t.Errorf("unlike %v", u)
	}
	if out["sampling_noise"] != true || out["statement"] != SamplingNoise {
		t.Errorf("noise %v", out)
	}
	if l := out["items"].([]map[string]any)[2]["label"]; l != "Portfolio" {
		t.Errorf("aggregate label %v", l)
	}
	// The same scenario at another version lists only the version.
	out = build([]*compared{run(idA, "Current", "s", 1, "7", "0.1.0", 1, 1), run(idB, "Current", "s", 2, "7", "0.1.0", 1, 1)})
	if u := out["unlike"].([]string); !slices.Equal(u, []string{"scenario_version"}) {
		t.Errorf("versions %v", u)
	}
}
