package estimate_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/estimate"
)

func hits(n, k int) []bool {
	out := make([]bool, n)
	for i := 0; i < k; i++ {
		out[i] = true
	}
	return out
}

// F-004 T-09 (AC-23; design §3.6): the tolerance band's edges.
func TestBand(t *testing.T) {
	for n, want := range map[int][2]int{10: {7, 10}, 20: {16, 20}, 100: {85, 95}} {
		if got := estimate.Band(n); got != want {
			t.Errorf("band(%d) = %v, want %v", n, got, want)
		}
	}
	// The band always holds the expected count and widens with n.
	prev := 0
	for n := 1; n <= 500; n++ {
		b := estimate.Band(n)
		mean := 0.9 * float64(n)
		if float64(b[0]) > mean || float64(b[1]) < mean-1 || b[0] < 0 || b[1] > n || b[1]-b[0] < prev-1 {
			t.Fatalf("band(%d) = %v", n, b)
		}
		prev = b[1] - b[0]
	}
}

// Classes for ranges and binary answers, the minimum, and the overall class.
func TestScore(t *testing.T) {
	bin := func(conf string, correct, wrong int) []estimate.BinaryAnswer {
		var out []estimate.BinaryAnswer
		for i := 0; i < correct; i++ {
			out = append(out, estimate.BinaryAnswer{Confidence: conf, Correct: true})
		}
		for i := 0; i < wrong; i++ {
			out = append(out, estimate.BinaryAnswer{Confidence: conf, Correct: false})
		}
		return out
	}
	for _, c := range []struct {
		name                string
		ranges              []bool
		binary              []estimate.BinaryAnswer
		class, rc, bc, rate string
	}{
		{"nothing yet", nil, nil, "not_measured", "not_measured", "not_measured", ""},
		{"too few ranges", hits(19, 10), nil, "not_measured", "not_measured", "not_measured", "0.5263"},
		{"calibrated at the band's foot", hits(20, 16), nil, "calibrated", "calibrated", "not_measured", "0.8"},
		{"overconfident just below it", hits(20, 15), nil, "overconfident", "overconfident", "not_measured", "0.75"},
		{"every range held", hits(20, 20), nil, "calibrated", "calibrated", "not_measured", "1"},
		{"underconfident at 100", hits(100, 100), nil, "underconfident", "underconfident", "not_measured", "1"},
		{"binary only, calibrated", nil, bin("0.7", 14, 6), "calibrated", "not_measured", "calibrated", ""},
		{"binary only, overconfident", nil, bin("0.9", 10, 10), "overconfident", "not_measured", "overconfident", ""},
		{"binary only, underconfident", nil, bin("0.5", 18, 2), "underconfident", "not_measured", "underconfident", ""},
		{"certain and once wrong", nil, bin("1", 19, 1), "overconfident", "not_measured", "overconfident", ""},
		{"ranges decide over binary", hits(20, 18), bin("0.9", 10, 10), "calibrated", "calibrated", "overconfident", "0.9"},
	} {
		s := estimate.ScoreOf(c.ranges, c.binary, 20)
		if s.Class != c.class || s.Ranges.Class != c.rc || s.Binary.Class != c.bc || s.Ranges.Rate != c.rate {
			t.Errorf("%s: %+v", c.name, s)
		}
	}
	// The Brier score and the stored shape (estimate.save_answer reads class
	// and ranges.rate).
	s := estimate.ScoreOf(hits(20, 18), bin("0.8", 8, 2), 20)
	if s.Binary.Brier != "0.16" || s.Binary.Expected != "8" || s.Binary.Z != "0" {
		t.Fatalf("binary figures: %+v", s.Binary)
	}
	b, _ := json.Marshal(s)
	for _, want := range []string{`"class":"calibrated"`, `"ranges":{"n":20,"hits":18,"rate":"0.9","band":[16,20],"class":"calibrated"}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON %s lacks %s", b, want)
		}
	}
}

// Properties: perfect answers are calibrated or underconfident, never
// overconfident; missing every range is overconfident once measured.
func TestScoreProperties(t *testing.T) {
	for n := 20; n <= 200; n += 7 {
		if s := estimate.ScoreOf(hits(n, n), nil, 20); s.Class == "overconfident" {
			t.Fatalf("every range held, n=%d: %+v", n, s)
		}
		if s := estimate.ScoreOf(hits(n, 0), nil, 20); s.Class != "overconfident" {
			t.Fatalf("every range missed, n=%d: %+v", n, s)
		}
		if s := estimate.ScoreOf(hits(n, (9*n+5)/10), nil, 20); s.Class != "calibrated" {
			t.Fatalf("90%% held, n=%d: %+v", n, s)
		}
	}
}
