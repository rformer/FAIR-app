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

// The scoring is exact (integers and decimals), so that the database's
// estimate.compute_score gives the same score, digit for digit (F-004
// T-10): the database scores, this is the reference it is tested against.

// zLimit2 is the square of the binary test's two-sided 90% limit (1.6449),
// as a decimal: |z| > 1.6449 exactly when z² > 2.70569601.
var zLimit2 = big.NewRat(270569601, 100000000)

// BinaryAnswer is one true-or-false answer: the confidence (a decimal from
// 0.5 to 1) that the chosen answer is right, and whether it was.
type BinaryAnswer struct {
	Confidence string
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
// Binomial(n, 0.9). Exactly: with Sₖ = Σᵢ≤ₖ C(n, i)·9ⁱ, P(K ≤ k) = Sₖ / 10ⁿ,
// lo is the least k with 20·Sₖ > 10ⁿ and hi the least with 20·Sₖ ≥ 19·10ⁿ.
func Band(n int) [2]int {
	if n <= 0 {
		return [2]int{0, 0}
	}
	total := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	low := total
	high := new(big.Int).Mul(total, big.NewInt(19))
	term := big.NewInt(1) // C(n, k)·9ᵏ
	sum := new(big.Int)
	twenty := big.NewInt(20)
	lo, hi := -1, n
	for k := 0; k <= n; k++ {
		sum.Add(sum, term)
		s20 := new(big.Int).Mul(sum, twenty)
		if lo < 0 && s20.Cmp(low) > 0 {
			lo = k
		}
		if s20.Cmp(high) >= 0 {
			hi = k
			break
		}
		// C(n, k+1)·9^(k+1) = C(n, k)·9ᵏ · 9·(n−k)/(k+1), exact.
		term.Mul(term, big.NewInt(int64(9*(n-k))))
		term.Quo(term, big.NewInt(int64(k+1)))
	}
	return [2]int{lo, hi}
}

func places(r *big.Rat, n int) string {
	d, _ := canon.Decimal(r.FloatString(n))
	return d
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
	mu, varSum, brier := new(big.Rat), new(big.Rat), new(big.Rat)
	one := big.NewRat(1, 1)
	for _, b := range binary {
		c, err := rat(b.Confidence)
		if err != nil {
			continue
		}
		y := new(big.Rat)
		if b.Correct {
			y = one
			s.Binary.Correct++
		}
		mu.Add(mu, c)
		varSum.Add(varSum, new(big.Rat).Mul(c, new(big.Rat).Sub(one, c)))
		d := new(big.Rat).Sub(c, y)
		brier.Add(brier, d.Mul(d, d))
	}
	if s.Binary.N > 0 {
		s.Binary.Expected = places(mu, 4)
		s.Binary.Brier = places(new(big.Rat).Quo(brier, big.NewRat(int64(s.Binary.N), 1)), 4)
		diff := new(big.Rat).Sub(big.NewRat(int64(s.Binary.Correct), 1), mu)
		// z² = diff² / σ²; the sign of z is diff's.
		outside := false
		if varSum.Sign() > 0 {
			z2 := new(big.Rat).Quo(new(big.Rat).Mul(diff, diff), varSum)
			outside = z2.Cmp(zLimit2) > 0
			df, _ := diff.Float64()
			vf, _ := varSum.Float64()
			s.Binary.Z = places(new(big.Rat).SetFloat64(math.Round(df/math.Sqrt(vf)*1e4)/1e4), 4)
		} else {
			outside = diff.Sign() != 0 // certain of every answer: any miss is decisive
		}
		if s.Binary.N >= minAnswers {
			switch {
			case outside && diff.Sign() < 0:
				s.Binary.Class = ClassOverconfident
			case outside && diff.Sign() > 0:
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
