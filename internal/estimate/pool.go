package estimate

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// Methods of accepting answers (design §3.4).
const (
	MethodSingle      = "single"      // one answer as given
	MethodEqual       = "equal"       // the average of the answers
	MethodCalibration = "calibration" // the average weighted by each estimator's calibration
	MethodOwn         = "own"         // the analyst's own estimate, informed by the answers
)

// Answer is one estimator's submitted answer, as a pool uses it.
type Answer struct {
	Estimator  string
	Name       string
	Revision   int64
	Min        string // canonical decimals
	ML         string
	Max        string
	Confidence string
	Class      string  // calibration class at the time
	RangeRate  *string // range hit rate at the time, if measured
	AsOf       string  // the calibration's date (YYYY-MM-DD)
}

// Pooled is a pool's result: the estimate's numbers, and each answer's
// weight as recorded in the provenance (design §3.5).
type Pooled struct {
	Min, ML, Max, Confidence string
	Weights                  []string
}

// Decimals: a pool is exact over the decimals, then rounded to 12 places,
// halves away from zero (as PostgreSQL's round(numeric, 12)), and written
// canonically, so that the database can re-compute it digit for digit.
const poolPlaces = 12

func rat(s string) (*big.Rat, error) {
	d, err := canon.Decimal(s)
	if err != nil {
		return nil, err
	}
	r, _ := new(big.Rat).SetString(d)
	return r, nil
}

func decimal(r *big.Rat) string {
	d, _ := canon.Decimal(r.FloatString(poolPlaces))
	return d
}

// CalibrationWeight is an estimator's weight in a calibration-weighted
// pool (design §3.4): 1 when calibrated, 0.5 when not yet measured, and
// max(0.1, 1 − 2.5·|rate − 0.9|) when over- or underconfident.
func CalibrationWeight(class string, rate *string) *big.Rat {
	switch class {
	case "calibrated":
		return big.NewRat(1, 1)
	case "not_measured":
		return big.NewRat(1, 2)
	}
	if rate == nil {
		return big.NewRat(1, 2)
	}
	r, err := rat(*rate)
	if err != nil {
		return big.NewRat(1, 2)
	}
	d := new(big.Rat).Sub(r, big.NewRat(9, 10))
	d.Abs(d)
	w := new(big.Rat).Sub(big.NewRat(1, 1), d.Mul(d, big.NewRat(5, 2)))
	if w.Cmp(big.NewRat(1, 10)) < 0 {
		return big.NewRat(1, 10)
	}
	return w
}

// ErrPool is returned for a pool that cannot be made: no answers, more
// than one for single, or answers at another confidence than the request's.
var ErrPool = errors.New("estimate: pool")

// Pool combines answers by a method at the request's confidence (design
// §3.4). Single takes one answer as given, at its own confidence; the pools
// take answers at the request's confidence and give
// round(Σ wᵢ·vᵢ / Σ wᵢ) for the minimum, the most likely value and the
// maximum, with every wᵢ 1 (equal) or the calibration weight. Weights are
// recorded as they are, not normalised.
func Pool(method string, answers []Answer, confidence string) (Pooled, error) {
	if len(answers) == 0 {
		return Pooled{}, fmt.Errorf("%w: no answers", ErrPool)
	}
	switch method {
	case MethodSingle:
		if len(answers) != 1 {
			return Pooled{}, fmt.Errorf("%w: the single method takes one answer", ErrPool)
		}
		a := answers[0]
		return Pooled{Min: a.Min, ML: a.ML, Max: a.Max, Confidence: a.Confidence, Weights: []string{"1"}}, nil
	case MethodEqual, MethodCalibration:
	default:
		return Pooled{}, fmt.Errorf("%w: unknown method %q", ErrPool, method)
	}
	want, err := rat(confidence)
	if err != nil {
		return Pooled{}, fmt.Errorf("%w: confidence: %v", ErrPool, err)
	}
	sum := new(big.Rat)
	totals := [3]*big.Rat{new(big.Rat), new(big.Rat), new(big.Rat)}
	out := Pooled{Confidence: decimal(want)}
	for _, a := range answers {
		c, err := rat(a.Confidence)
		if err != nil || c.Cmp(want) != 0 {
			return Pooled{}, fmt.Errorf("%w: %s answered at another confidence; use it alone", ErrPool, a.Name)
		}
		w := big.NewRat(1, 1)
		if method == MethodCalibration {
			// The recorded weight is what the pool uses, so that it can be
			// re-computed from the provenance alone.
			w, _ = rat(decimal(CalibrationWeight(a.Class, a.RangeRate)))
		}
		sum.Add(sum, w)
		out.Weights = append(out.Weights, decimal(w))
		for i, s := range []string{a.Min, a.ML, a.Max} {
			v, err := rat(s)
			if err != nil {
				return Pooled{}, fmt.Errorf("%w: %v", ErrPool, err)
			}
			totals[i].Add(totals[i], new(big.Rat).Mul(w, v))
		}
	}
	vals := make([]string, 3)
	for i := range totals {
		vals[i] = decimal(totals[i].Quo(totals[i], sum))
	}
	out.Min, out.ML, out.Max = vals[0], vals[1], vals[2]
	return out, nil
}
