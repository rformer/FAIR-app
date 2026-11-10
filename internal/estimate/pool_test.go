package estimate_test

import (
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/rformer/fair-app/internal/estimate"
)

func ans(name, lo, ml, hi, conf, class string, rate *string) estimate.Answer {
	return estimate.Answer{Estimator: name, Name: name, Revision: 1, Min: lo, ML: ml, Max: hi, Confidence: conf, Class: class, RangeRate: rate, AsOf: "2026-11-10"}
}

func s(v string) *string { return &v }

// F-004 T-08 (AC-16, AC-17; design §3.4): pools are exact, rounded to 12
// places, ordered and deterministic; weights follow the calibration class.
func TestPool(t *testing.T) {
	a := ans("a", "2", "5", "10", "0.9", "calibrated", s("0.9"))
	b := ans("b", "4", "7", "12", "0.9", "not_measured", nil)
	c := ans("c", "1", "2", "4", "0.9", "overconfident", s("0.6"))
	for _, x := range []struct {
		name, method string
		answers      []estimate.Answer
		want         estimate.Pooled
	}{
		{"single", estimate.MethodSingle, []estimate.Answer{ans("x", "1", "2", "3", "0.8", "calibrated", nil)},
			estimate.Pooled{Min: "1", ML: "2", Max: "3", Confidence: "0.8", Weights: []string{"1"}}},
		{"equal of two", estimate.MethodEqual, []estimate.Answer{a, b}, estimate.Pooled{Min: "3", ML: "6", Max: "11", Confidence: "0.9", Weights: []string{"1", "1"}}},
		{"equal of three: thirds", estimate.MethodEqual, []estimate.Answer{a, b, c},
			estimate.Pooled{Min: "2.333333333333", ML: "4.666666666667", Max: "8.666666666667", Confidence: "0.9", Weights: []string{"1", "1", "1"}}},
		// Weights 1, 0.5 and max(0.1, 1 − 2.5·0.3) = 0.25.
		{"calibration", estimate.MethodCalibration, []estimate.Answer{a, b, c},
			estimate.Pooled{Min: "2.428571428571", ML: "5.142857142857", Max: "9.714285714286", Confidence: "0.9", Weights: []string{"1", "0.5", "0.25"}}},
	} {
		got, err := estimate.Pool(x.method, x.answers, "0.9")
		if err != nil {
			t.Errorf("%s: %v", x.name, err)
			continue
		}
		if got.Min != x.want.Min || got.ML != x.want.ML || got.Max != x.want.Max || got.Confidence != x.want.Confidence || !slices.Equal(got.Weights, x.want.Weights) {
			t.Errorf("%s: %+v, want %+v", x.name, got, x.want)
		}
		again, _ := estimate.Pool(x.method, x.answers, "0.9")
		if !slices.Equal(again.Weights, got.Weights) || again.Min != got.Min || again.Max != got.Max {
			t.Errorf("%s: not deterministic", x.name)
		}
	}
	// Weights by class: calibrated 1, not measured 0.5, the floor 0.1.
	for _, w := range []struct {
		class string
		rate  *string
		want  string
	}{
		{"calibrated", s("0.85"), "1"}, {"not_measured", nil, "1/2"}, {"underconfident", s("1"), "3/4"},
		{"overconfident", s("0.5"), "1/10"}, {"overconfident", s("0.2"), "1/10"}, {"overconfident", nil, "1/2"},
	} {
		if got := estimate.CalibrationWeight(w.class, w.rate); got.Cmp(mustRat(w.want)) != 0 {
			t.Errorf("%s %v: weight %s, want %s", w.class, w.rate, got.RatString(), w.want)
		}
	}
	// Refused pools.
	for name, c := range map[string]struct {
		method  string
		answers []estimate.Answer
	}{
		"no answers":         {estimate.MethodEqual, nil},
		"single of two":      {estimate.MethodSingle, []estimate.Answer{a, b}},
		"another confidence": {estimate.MethodEqual, []estimate.Answer{a, ans("d", "1", "2", "3", "0.8", "calibrated", nil)}},
		"unknown method":     {"median", []estimate.Answer{a}},
		"own is not a pool":  {estimate.MethodOwn, []estimate.Answer{a}},
	} {
		if _, err := estimate.Pool(c.method, c.answers, "0.9"); !errors.Is(err, estimate.ErrPool) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func mustRat(s string) *big.Rat { r, _ := new(big.Rat).SetString(s); return r }

// Property: a pool of ordered answers is ordered and lies within them.
func TestPoolOrdered(t *testing.T) {
	vals := []string{"0", "0.1", "1", "2.5", "7", "13", "1000", "123456.789"}
	for i := 0; i < len(vals); i++ {
		for j := i; j < len(vals); j++ {
			for k := j; k < len(vals); k++ {
				x := ans("x", vals[i], vals[j], vals[k], "0.9", "calibrated", nil)
				y := ans("y", vals[0], vals[j], vals[len(vals)-1], "0.9", "overconfident", s("0.7"))
				p, err := estimate.Pool(estimate.MethodCalibration, []estimate.Answer{x, y}, "0.9")
				if err != nil {
					t.Fatal(err)
				}
				lo, ml, hi := mustRat(p.Min), mustRat(p.ML), mustRat(p.Max)
				if lo.Cmp(ml) > 0 || ml.Cmp(hi) > 0 || lo.Cmp(mustRat(vals[0])) < 0 || hi.Cmp(mustRat(vals[len(vals)-1])) > 0 {
					t.Fatalf("pool of %v and %v: %+v", x, y, p)
				}
			}
		}
	}
}
