package estimate

import (
	"math"
	"math/big"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// Calibration classes (design §3.6).
const (
	ClassCalibrated     = "calibrated"
	ClassOverconfident  = "overconfident"
	ClassUnderconfident = "underconfident"
	ClassNotMeasured    = "not_measured"
)

// RangeTarget is the confidence of range questions: a calibrated person's
// 90% ranges contain the truth 90% of the time.
const RangeTarget = 0.9

// bandTail is each tail of the tolerance band: a central 90% interval.
const bandTail = 0.05

// zLimit is the binary test's two-sided 90% limit.
const zLimit = 1.6448536269514722

// BinaryAnswer is one true-or-false answer: the confidence (0.5 to 1) that
// the chosen answer is right, and whether it was.
type BinaryAnswer struct {
	Confidence float64
	Correct    bool
}

// RangeScore is the range part of a score.
type RangeScore struct {
	N     int    `json:"n"`
	Hits  int    `json:"hits"`
	Rate  string `json:"rate,omitempty"` // hits / n, 4 places
	Band  [2]int `json:"band"`           // the central 90% interval of hits for n calibrated answers
	Class string `json:"class"`
}

// BinaryScore is the binary part of a score.
type BinaryScore struct {
	N        int    `json:"n"`
	Correct  int    `json:"correct"`
	Expected string `json:"expected,omitempty"` // Σ confidence, 4 places
	Z        string `json:"z,omitempty"`        // (correct − expected) / σ, 4 places
	Brier    string `json:"brier,omitempty"`    // Σ (confidence − correct)² / n, 4 places
	Class    string `json:"class"`
}

// Score is a person's calibration over a window (design §3.6), stored as
// estimate.score's JSON: the class is the range class when ranges are
// measured, otherwise the binary class, otherwise not measured.
type Score struct {
	Class  string      `json:"class"`
	Ranges RangeScore  `json:"ranges"`
	Binary BinaryScore `json:"binary"`
}

// Band is the central 90% interval [lo, hi] of hits among n answers of a
// perfectly calibrated person: P(K < lo) ≤ 5% and P(K > hi) ≤ 5% for K ~
// Binomial(n, 0.9).
func Band(n int) [2]int {
	if n <= 0 {
		return [2]int{0, 0}
	}
	cdf := 0.0
	lo, hi := -1, -1
	for k := 0; k <= n; k++ {
		cdf += binomPMF(n, k, RangeTarget)
		if lo < 0 && cdf > bandTail {
			lo = k
		}
		if hi < 0 && cdf >= 1-bandTail {
			hi = k
			break
		}
	}
	if hi < 0 {
		hi = n
	}
	return [2]int{lo, hi}
}

func binomPMF(n, k int, p float64) float64 {
	lc, _ := math.Lgamma(float64(n + 1))
	lk, _ := math.Lgamma(float64(k + 1))
	lnk, _ := math.Lgamma(float64(n - k + 1))
	return math.Exp(lc - lk - lnk + float64(k)*math.Log(p) + float64(n-k)*math.Log1p(-p))
}

func places(r *big.Rat, n int) string {
	d, _ := canon.Decimal(r.FloatString(n))
	return d
}

func placesF(x float64, n int) string {
	r := new(big.Rat)
	r.SetFloat64(x)
	return places(r, n)
}

// ScoreOf scores range answers (whether each range held the truth) and
// binary answers, each part measured only with at least minAnswers answers
// (design §3.6).
func ScoreOf(ranges []bool, binary []BinaryAnswer, minAnswers int) Score {
	var s Score
	s.Ranges.N = len(ranges)
	for _, hit := range ranges {
		if hit {
			s.Ranges.Hits++
		}
	}
	s.Ranges.Band = Band(s.Ranges.N)
	s.Ranges.Class = ClassNotMeasured
	if s.Ranges.N > 0 {
		s.Ranges.Rate = places(big.NewRat(int64(s.Ranges.Hits), int64(s.Ranges.N)), 4)
	}
	if s.Ranges.N >= minAnswers && s.Ranges.N > 0 {
		switch {
		case s.Ranges.Hits < s.Ranges.Band[0]:
			s.Ranges.Class = ClassOverconfident
		case s.Ranges.Hits > s.Ranges.Band[1]:
			s.Ranges.Class = ClassUnderconfident
		default:
			s.Ranges.Class = ClassCalibrated
		}
	}

	s.Binary.N = len(binary)
	s.Binary.Class = ClassNotMeasured
	var mu, varSum, brier float64
	for _, b := range binary {
		y := 0.0
		if b.Correct {
			y = 1
			s.Binary.Correct++
		}
		mu += b.Confidence
		varSum += b.Confidence * (1 - b.Confidence)
		brier += (b.Confidence - y) * (b.Confidence - y)
	}
	if s.Binary.N > 0 {
		s.Binary.Expected = placesF(mu, 4)
		s.Binary.Brier = placesF(brier/float64(s.Binary.N), 4)
		diff := float64(s.Binary.Correct) - mu
		var z float64
		switch {
		case varSum > 0:
			z = diff / math.Sqrt(varSum)
			s.Binary.Z = placesF(z, 4)
		case diff < 0:
			z = math.Inf(-1) // certain of every answer, and wrong at least once
		}
		if s.Binary.N >= minAnswers {
			switch {
			case z < -zLimit:
				s.Binary.Class = ClassOverconfident
			case z > zLimit:
				s.Binary.Class = ClassUnderconfident
			default:
				s.Binary.Class = ClassCalibrated
			}
		}
	}

	switch {
	case s.Ranges.Class != ClassNotMeasured:
		s.Class = s.Ranges.Class
	case s.Binary.Class != ClassNotMeasured:
		s.Class = s.Binary.Class
	default:
		s.Class = ClassNotMeasured
	}
	return s
}
