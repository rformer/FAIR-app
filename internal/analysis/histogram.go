package analysis

import (
	"encoding/binary"
	"errors"
	"math"
	"sort"
)

// F-006 T-01 (F-006-AC-02, AC-07, AC-09; design §3.1): histograms of a
// stored per-year series, computed on request (runs are immutable; nothing
// is stored).

// HistogramBins is the number of bins of every histogram (design §9).
const HistogramBins = 60

// Histogram scales.
const (
	ScaleLog    = "log"
	ScaleLinear = "linear"
)

// ErrSeries is a stored series of the wrong length.
var ErrSeries = errors.New("analysis: the stored series has the wrong length")

// Histogram is the binned series. Edges has len(Counts)+1 values; a value
// falls in the bin whose lower edge is the largest edge at or below it, and
// the last bin includes its upper edge. Years outside the bins are counted
// apart: Zero (no loss, or for a difference no change) and, for a
// difference, BothNone (neither set lost anything). With nothing to bin,
// Edges and Counts are empty.
type Histogram struct {
	Scale     string    `json:"scale"`
	N         int       `json:"n"`
	Zero      int       `json:"zero"`
	ZeroShare float64   `json:"zero_share"`
	BothNone  *int      `json:"both_none,omitempty"`
	Edges     []float64 `json:"edges"`
	Counts    []int     `json:"counts"`
}

// Floats decodes a stored series (float64 little-endian, design §4.1).
func Floats(b []byte, n int) ([]float64, error) {
	if len(b) != 8*n {
		return nil, ErrSeries
	}
	out := make([]float64, n)
	for i := range out {
		out[i] = math.Float64frombits(binary.LittleEndian.Uint64(b[8*i:]))
	}
	return out, nil
}

// LossHistogram bins the years with a positive loss; years with no loss
// are Zero (AC-02). Log edges run in equal ratios from the smallest
// positive loss to the largest, linear edges in equal steps from 0 to the
// largest. Any scale but linear is log (the API refuses others first).
func LossHistogram(v []float64, scale string) Histogram {
	if scale != ScaleLinear {
		scale = ScaleLog
	}
	h := Histogram{Scale: scale, N: len(v), Edges: []float64{}, Counts: []int{}}
	lo, hi := math.Inf(1), 0.0
	for _, x := range v {
		if x > 0 {
			lo, hi = min(lo, x), max(hi, x)
		} else {
			h.Zero++
		}
	}
	h.ZeroShare = share(h.Zero, h.N)
	if hi == 0 {
		return h
	}
	switch {
	case lo == hi:
		h.Edges = []float64{lo, hi}
	case scale == ScaleLinear:
		h.Edges = linearEdges(0, hi)
	default:
		h.Edges = logEdges(lo, hi)
	}
	h.Counts = make([]int, len(h.Edges)-1)
	for _, x := range v {
		if x > 0 {
			h.Counts[bin(h.Edges, x)]++
		}
	}
	return h
}

// DifferenceHistogram bins the per-year difference v[i] − base[i] (AC-09;
// meaningful year by year because a run's control sets share their random
// numbers) in linear bins over its non-zero range; years with no
// difference are Zero, and BothNone counts the years where neither lost
// anything. A negative difference is a reduction.
func DifferenceHistogram(v, base []float64) Histogram {
	h := Histogram{Scale: ScaleLinear, N: len(v), Edges: []float64{}, Counts: []int{}}
	both := 0
	h.BothNone = &both
	lo, hi := math.Inf(1), math.Inf(-1)
	d := make([]float64, len(v))
	for i := range v {
		d[i] = v[i] - base[i]
		if v[i] == 0 && base[i] == 0 {
			both++
		}
		if d[i] == 0 {
			h.Zero++
			continue
		}
		lo, hi = min(lo, d[i]), max(hi, d[i])
	}
	h.ZeroShare = share(h.Zero, h.N)
	if h.Zero == h.N {
		return h
	}
	if lo == hi {
		h.Edges = []float64{lo, hi}
	} else {
		h.Edges = linearEdges(lo, hi)
	}
	h.Counts = make([]int, len(h.Edges)-1)
	for _, x := range d {
		if x != 0 {
			h.Counts[bin(h.Edges, x)]++
		}
	}
	return h
}

func share(k, n int) float64 {
	if n == 0 {
		return 0
	}
	return float64(k) / float64(n)
}

func linearEdges(lo, hi float64) []float64 {
	e := make([]float64, HistogramBins+1)
	step := (hi - lo) / HistogramBins
	for i := range e {
		e[i] = lo + float64(i)*step
	}
	e[0], e[HistogramBins] = lo, hi
	return e
}

func logEdges(lo, hi float64) []float64 {
	e := make([]float64, HistogramBins+1)
	a, b := math.Log(lo), math.Log(hi)
	for i := range e {
		e[i] = math.Exp(a + float64(i)*(b-a)/HistogramBins)
	}
	e[0], e[HistogramBins] = lo, hi
	return e
}

// bin is the bin of x in [edges[0], edges[len-1]]: the largest edge at or
// below x, the last bin closed.
func bin(edges []float64, x float64) int {
	i := sort.SearchFloat64s(edges, x) // first edge >= x
	if i < len(edges) && edges[i] == x {
		return min(i, len(edges)-2)
	}
	return max(i-1, 0)
}
