package estimate

import (
	"fmt"
	"math"
	"math/big"

	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model"
)

// Range is the numbers of an estimate being entered: canonical or JSON
// decimal strings.
type Range struct {
	Min        string `json:"min"`
	ML         string `json:"ml"`
	Max        string `json:"max"`
	Confidence string `json:"confidence"`
}

// Warning is advice about an estimate; it never refuses one (F-004 AC-12).
type Warning struct {
	Code    string `json:"code"`
	Pointer string `json:"pointer,omitempty"` // in the estimate: "/min", "/ml", "/max", "/confidence", or "" for the range
	Message string `json:"message"`
}

// Warning codes (design §3.7).
const (
	WarnMLAtBound       = "ml_at_bound"
	WarnNarrow          = "narrow_range"
	WarnWide            = "wide_range"
	WarnCertain         = "reaches_certainty"
	WarnOtherConfidence = "other_confidence"
)

// rats parses a range; an error names the first value that is not a
// decimal or the order that is broken.
func rats(r Range) (lo, ml, hi, c *big.Rat, err error) {
	parse := func(name, s string) (*big.Rat, error) {
		d, err := canon.Decimal(s)
		if err != nil {
			return nil, fmt.Errorf("/%s: %w", name, err)
		}
		x, _ := new(big.Rat).SetString(d)
		return x, nil
	}
	if lo, err = parse("min", r.Min); err != nil {
		return
	}
	if ml, err = parse("ml", r.ML); err != nil {
		return
	}
	if hi, err = parse("max", r.Max); err != nil {
		return
	}
	if c, err = parse("confidence", r.Confidence); err != nil {
		return
	}
	if lo.Cmp(ml) > 0 || ml.Cmp(hi) > 0 {
		err = fmt.Errorf(": must be ordered: min ≤ ml ≤ max")
	}
	return
}

// Warnings advises on an estimate in a unit (design §3.7). requested is the
// confidence a request asked for ("" when there is none). The error is a
// value that is not a decimal or a range out of order: those the editor
// refuses on its own.
func Warnings(unit string, r Range, requested string) ([]Warning, error) {
	lo, ml, hi, c, err := rats(r)
	if err != nil {
		return nil, err
	}
	var out []Warning
	add := func(code, ptr, msg string) { out = append(out, Warning{code, ptr, msg}) }
	if lo.Cmp(hi) != 0 && (lo.Cmp(ml) == 0 || ml.Cmp(hi) == 0) {
		add(WarnMLAtBound, "/ml", "The most likely value is at a bound of the range: is anything on the other side of it really impossible?")
	}
	switch unit {
	case model.UnitEventsPerYear, model.UnitCurrency:
		if lo.Sign() > 0 {
			ratio := new(big.Rat).Quo(hi, lo)
			switch {
			case ratio.Cmp(big.NewRat(11, 10)) < 0:
				add(WarnNarrow, "", "The maximum is less than 1.1 times the minimum: few people know a frequency or a loss that precisely.")
			case ratio.Cmp(big.NewRat(1000, 1)) > 0:
				add(WarnWide, "", "The maximum is more than 1,000 times the minimum: can you narrow it with what you know?")
			}
		}
	case model.UnitProbability, model.UnitFraction:
		if new(big.Rat).Sub(hi, lo).Cmp(big.NewRat(2, 100)) < 0 {
			add(WarnNarrow, "", "The range is narrower than 0.02: few people know a probability that precisely.")
		}
		if unit == model.UnitProbability && (lo.Sign() == 0 || hi.Cmp(big.NewRat(1, 1)) == 0) {
			add(WarnCertain, "", "The range reaches 0 or 1: is the event really impossible, or certain?")
		}
	case model.UnitPercentile:
		w := new(big.Rat).Sub(hi, lo)
		switch {
		case w.Cmp(big.NewRat(2, 1)) < 0:
			add(WarnNarrow, "", "The range spans less than 2 percentiles: few people know a capability or a strength that precisely.")
		case w.Cmp(big.NewRat(90, 1)) > 0:
			add(WarnWide, "", "The range spans more than 90 percentiles: can you narrow it with what you know?")
		}
	}
	if requested != "" {
		if q, err := canon.Decimal(requested); err == nil {
			if want, _ := new(big.Rat).SetString(q); want.Cmp(c) != 0 {
				add(WarnOtherConfidence, "/confidence", fmt.Sprintf("The request asks for %s%% confidence; this estimate states %s%%.", percent(want), percent(c)))
			}
		}
	}
	return out, nil
}

func percent(r *big.Rat) string {
	p := new(big.Rat).Mul(r, big.NewRat(100, 1))
	d, _ := canon.Decimal(p.FloatString(6))
	return d
}

// Bet is the equivalent-bet prompt for a range at its confidence (F-004
// AC-11).
func Bet(r Range) string {
	_, _, _, c, err := rats(r)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("Would you rather win a prize if the true value is between %s and %s, or by spinning a wheel that wins %s%% of the time? "+
		"If you would rather spin the wheel, your range is too narrow; if you would rather bet on your range, it may be too wide. "+
		"At the right range you would not mind which.", r.Min, r.Max, percent(c))
}

// Preview is an illustrative curve for a range: a Beta-PERT density through
// minimum, most likely and maximum, as points. It is for the eye only; the
// simulation chooses its own distributions (F-005).
type Preview struct {
	Shape  string       `json:"shape"` // "beta_pert", or "point" for a range of one value
	Points [][2]float64 `json:"points"`
}

// PreviewOf draws n+1 points of the range's Beta-PERT density.
func PreviewOf(r Range, n int) (Preview, error) {
	lo, ml, hi, _, err := rats(r)
	if err != nil {
		return Preview{}, err
	}
	a, _ := lo.Float64()
	m, _ := ml.Float64()
	b, _ := hi.Float64()
	if b <= a {
		return Preview{Shape: "point", Points: [][2]float64{{a, 1}}}, nil
	}
	alpha := 1 + 4*(m-a)/(b-a)
	beta := 1 + 4*(b-m)/(b-a)
	lb, _ := math.Lgamma(alpha)
	lc, _ := math.Lgamma(beta)
	ld, _ := math.Lgamma(alpha + beta)
	norm := ld - lb - lc
	pts := make([][2]float64, 0, n+1)
	for i := 0; i <= n; i++ {
		x := float64(i) / float64(n)
		var y float64
		if (x > 0 || alpha == 1) && (x < 1 || beta == 1) {
			y = math.Exp(norm+(alpha-1)*math.Log(math.Max(x, 1e-300))+(beta-1)*math.Log(math.Max(1-x, 1e-300))) / (b - a)
		}
		pts = append(pts, [2]float64{a + x*(b-a), y})
	}
	return Preview{Shape: "beta_pert", Points: pts}, nil
}
