// Package chart draws F-010's report charts as PDF vector graphics (ADR-015):
// loss exceedance curves, histograms and horizontal bars, on the report
// writer's Canvas. The scales port web/src/charts/scale.ts and are held
// equal to it by shared vectors (testdata/scales.json); the series styles
// follow ADR-014's light theme, a colour paired with a dash pattern and a
// marker, so series differ by more than colour.
package chart

import (
	"math"
	"strconv"
)

// Scale maps values in Domain to positions in Range.
type Scale struct {
	Log    bool
	Domain [2]float64
	Range  [2]float64
	l0, k  float64
}

// Linear is a linear scale; a domain of one value is widened by one unit
// either side.
func Linear(domain, rng [2]float64) Scale {
	d0, d1 := domain[0], domain[1]
	if d0 == d1 {
		d0, d1 = d0-1, d1+1
	}
	return Scale{Domain: [2]float64{d0, d1}, Range: rng, k: (rng[1] - rng[0]) / (d1 - d0)}
}

// LogScale is a logarithmic scale over positive values; a domain of one
// value is widened by a factor of ten either side. ok is false for a domain
// that is not positive.
func LogScale(domain, rng [2]float64) (Scale, bool) {
	d0, d1 := domain[0], domain[1]
	if !(d0 > 0) || !(d1 > 0) {
		return Scale{}, false
	}
	if d0 == d1 {
		d0, d1 = d0/10, d1*10
	}
	l0 := math.Log(d0)
	return Scale{Log: true, Domain: [2]float64{d0, d1}, Range: rng, l0: l0, k: (rng[1] - rng[0]) / (math.Log(d1) - l0)}, true
}

// Map is the position of v, clamped to the domain.
func (s Scale) Map(v float64) float64 {
	d0, d1 := s.Domain[0], s.Domain[1]
	v = math.Min(math.Max(v, math.Min(d0, d1)), math.Max(d0, d1))
	if s.Log {
		return s.Range[0] + (math.Log(v)-s.l0)*s.k
	}
	return s.Range[0] + (v-d0)*s.k
}

// Ticks are about count tick values within the domain.
func (s Scale) Ticks(count int) []float64 {
	if s.Log {
		return LogTicks(s.Domain[0], s.Domain[1], count)
	}
	return LinearTicks(s.Domain[0], s.Domain[1], count)
}

// NiceStep is the "nice" step (1, 2 or 5 times a power of ten) giving about
// count ticks.
func NiceStep(span float64, count int) float64 {
	raw := math.Abs(span) / float64(max(count, 1))
	if !(raw > 0) || math.IsInf(raw, 0) {
		return 1
	}
	p := math.Pow(10, math.Floor(math.Log10(raw)))
	m := raw / p
	switch {
	case m <= 1:
		return p
	case m <= 2:
		return 2 * p
	case m <= 5:
		return 5 * p
	}
	return 10 * p
}

// LinearTicks are the multiples of the nice step within [d0, d1].
func LinearTicks(d0, d1 float64, count int) []float64 {
	lo, hi := math.Min(d0, d1), math.Max(d0, d1)
	step := NiceStep(hi-lo, count)
	var out []float64
	for i := math.Ceil(lo / step); i*step <= hi+step*1e-9; i++ {
		out = append(out, round(i*step, step))
		if len(out) > 100 {
			break
		}
	}
	return out
}

// LogTicks are the powers of ten within [d0, d1] (every other one when there
// are many); 2 and 5 times them when there are fewer than two.
func LogTicks(d0, d1 float64, count int) []float64 {
	e0 := int(math.Ceil(math.Log10(d0) - 1e-12))
	e1 := int(math.Floor(math.Log10(d1) + 1e-12))
	if e1-e0+1 >= 2 {
		every := max(1, int(math.Ceil(float64(e1-e0)/float64(max(count, 1)))))
		var out []float64
		for e := e0; e <= e1; e++ {
			if (e-e0)%every == 0 {
				out = append(out, math.Pow(10, float64(e)))
			}
		}
		return out
	}
	var out []float64
	for e := int(math.Floor(math.Log10(d0))); e <= int(math.Ceil(math.Log10(d1))); e++ {
		for _, m := range []float64{1, 2, 5} {
			v := m * math.Pow(10, float64(e))
			if v >= d0*(1-1e-12) && v <= d1*(1+1e-12) {
				out = append(out, v)
			}
		}
	}
	if len(out) >= 2 {
		return out
	}
	return []float64{d0, d1}
}

// round is JavaScript's Number(v.toFixed(digits)) for the step's digits.
func round(v, step float64) float64 {
	digits := max(0, int(-math.Floor(math.Log10(step)))+1)
	f, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'f', min(digits, 20), 64), 64)
	return f
}
