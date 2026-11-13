package analysis

import (
	"encoding/binary"
	"math"
	"slices"
	"testing"
)

// F-006 T-01 (AC-02, AC-07, AC-09; design §3.1): the binning rules.

func sum(c []int) int {
	n := 0
	for _, x := range c {
		n += x
	}
	return n
}

func TestLossHistogramLog(t *testing.T) {
	v := []float64{0, 0, 1, 10, 100, 1000, 1000, 0}
	h := LossHistogram(v, ScaleLog)
	if h.Scale != ScaleLog || h.N != 8 || h.Zero != 3 || h.ZeroShare != 3.0/8 {
		t.Fatalf("header %+v", h)
	}
	if len(h.Edges) != HistogramBins+1 || len(h.Counts) != HistogramBins || h.Edges[0] != 1 || h.Edges[HistogramBins] != 1000 {
		t.Fatalf("edges %v", h.Edges)
	}
	if !slices.IsSorted(h.Edges) {
		t.Fatal("edges not increasing")
	}
	// Log-equal: 10 is a third of the way, 100 two thirds.
	if h.Counts[0] != 1 || h.Counts[20] != 1 || h.Counts[40] != 1 || h.Counts[59] != 2 || sum(h.Counts) != 5 {
		t.Fatalf("counts %v", h.Counts)
	}
	for i := 1; i < len(h.Edges); i++ {
		if r := h.Edges[i] / h.Edges[i-1]; math.Abs(r-math.Pow(1000, 1.0/60)) > 1e-9 {
			t.Fatalf("ratio %v at %d", r, i)
		}
	}
}

func TestLossHistogramLinear(t *testing.T) {
	v := []float64{0, 6, 60, 120, 119.999}
	h := LossHistogram(v, ScaleLinear)
	if h.Edges[0] != 0 || h.Edges[60] != 120 || h.Zero != 1 {
		t.Fatalf("%+v", h)
	}
	// 6 is exactly the lower edge of bin 3; 60 of bin 30; 120 is the last bin's closed upper edge.
	if h.Counts[3] != 1 || h.Counts[30] != 1 || h.Counts[59] != 2 || sum(h.Counts) != 4 {
		t.Fatalf("counts %v", h.Counts)
	}
	if LossHistogram(v, "other").Scale != ScaleLog {
		t.Fatal("an unknown scale is not log")
	}
}

func TestLossHistogramDegenerate(t *testing.T) {
	h := LossHistogram([]float64{0, 0}, ScaleLog)
	if h.Zero != 2 || h.ZeroShare != 1 || len(h.Edges) != 0 || len(h.Counts) != 0 {
		t.Fatalf("all zero %+v", h)
	}
	h = LossHistogram([]float64{2.5, 2.5, 0}, ScaleLog)
	if !slices.Equal(h.Edges, []float64{2.5, 2.5}) || !slices.Equal(h.Counts, []int{2}) || h.Zero != 1 {
		t.Fatalf("one value %+v", h)
	}
	h = LossHistogram(nil, ScaleLinear)
	if h.N != 0 || h.ZeroShare != 0 || h.Edges == nil || h.Counts == nil {
		t.Fatalf("empty %+v", h)
	}
}

func TestDifferenceHistogram(t *testing.T) {
	base := []float64{0, 0, 10, 10, 10, 10}
	v := []float64{0, 4, 10, 4, 0, 16}
	h := DifferenceHistogram(v, base)
	if h.Scale != ScaleLinear || h.Zero != 2 || *h.BothNone != 1 || h.N != 6 {
		t.Fatalf("header %+v", h)
	}
	if h.Edges[0] != -10 || h.Edges[60] != 6 {
		t.Fatalf("edges %v", h.Edges)
	}
	// -10, -6, 4, 6: a reduction is negative.
	if h.Counts[0] != 1 || h.Counts[59] != 1 || sum(h.Counts) != 4 {
		t.Fatalf("counts %v", h.Counts)
	}
	same := DifferenceHistogram([]float64{1, 0}, []float64{1, 0})
	if same.Zero != 2 || *same.BothNone != 1 || len(same.Counts) != 0 {
		t.Fatalf("identical %+v", same)
	}
	one := DifferenceHistogram([]float64{3, 5}, []float64{1, 3})
	if !slices.Equal(one.Edges, []float64{2, 2}) || !slices.Equal(one.Counts, []int{2}) {
		t.Fatalf("one value %+v", one)
	}
}

func TestFloats(t *testing.T) {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, math.Float64bits(1.25))
	binary.LittleEndian.PutUint64(b[8:], math.Float64bits(-3))
	got, err := Floats(b, 2)
	if err != nil || !slices.Equal(got, []float64{1.25, -3}) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := Floats(b, 3); err != ErrSeries {
		t.Fatalf("wrong length: %v", err)
	}
}
