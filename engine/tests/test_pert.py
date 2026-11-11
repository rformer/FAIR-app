"""F-005 T-05 (AC-07; design §3.1): confidence-honouring Beta-PERT and its sampling."""

from __future__ import annotations

import itertools

import numpy as np
import pytest
from scipy.special import betainc

import fairsim  # noqa: F401  (pins NumPy's dispatch first)
from fairsim import pert, rng

CONFIDENCES = (0.5, 0.8, 0.9, 0.95, 0.99)
MODES = (0.0, 0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99, 1.0)
# (unit, lo, hi): interior ranges, ranges at a domain edge, tiny and huge scales.
RANGES = (
    ("currency", 1_000.0, 50_000.0),
    ("currency", 2.5e8, 4e9),
    ("currency", 1e6, 1e6 + 1),
    ("events_per_year", 0.1, 4.0),
    ("events_per_year", 0.0, 4.0),
    ("events_per_year", 1e-4, 2e-3),
    ("probability", 0.05, 0.6),
    ("probability", 0.3, 1.0),
    ("probability", 0.0, 1.0),
    ("fraction", 0.1, 0.5),
    ("percentile", 20.0, 80.0),
    ("percentile", 1.0, 99.0),
)


def _held(f: pert.Fit) -> float:
    """How far the fit misses its stated probabilities."""
    w = f.b - f.a
    fl = float(betainc(f.alpha, f.beta, (f.lo - f.a) / w))
    fh = float(betainc(f.alpha, f.beta, (f.hi - f.a) / w))
    if f.fallback is None:
        return max(abs(fl - (1 - f.confidence) / 2), abs(fh - (1 + f.confidence) / 2))
    return abs(fh - fl - f.confidence)


@pytest.mark.parametrize(("unit", "lo", "hi"), RANGES)
def test_fits_hold_the_stated_confidence(unit: str, lo: float, hi: float) -> None:
    d0, d1 = pert.DOMAINS[unit]
    for mf, c in itertools.product(MODES, CONFIDENCES):
        ml = lo + mf * (hi - lo)
        f = pert.fit(lo, ml, hi, c, unit)
        assert d0 <= f.a <= f.lo
        assert f.hi <= f.b <= d1
        mode = f.a + (f.alpha - 1) / (f.alpha + f.beta - 2) * (f.b - f.a)
        assert mode == pytest.approx(ml, rel=1e-9, abs=1e-9 * (hi - lo))
        if f.fallback == pert.BOUNDS:
            assert (f.a, f.b) == (lo, hi)
        else:
            assert _held(f) <= 1e-9, (unit, lo, ml, hi, c, f)
        if f.fallback == pert.DOMAIN_LOW:
            assert f.a == d0
        if f.fallback == pert.DOMAIN_HIGH:
            assert f.b == d1


def test_interior_estimates_fit_without_fallback() -> None:
    for (lo, hi), mf, c in itertools.product(((1_000.0, 60_000.0), (0.5, 4.0)), MODES, CONFIDENCES):
        f = pert.fit(lo, lo + mf * (hi - lo), hi, c, "currency")
        assert f.fallback is None or f.fallback == pert.DOMAIN_LOW
        if f.fallback is None:
            assert f.a < lo
            assert f.b > hi
    f = pert.fit("10000", "25000", "100000", "0.9", "currency")
    assert f.fallback is None
    assert _held(f) <= 1e-12


def test_point() -> None:
    f = pert.fit(5, 5, 5, 0.9, "events_per_year")
    assert f.fallback == pert.POINT
    d = pert.Distribution.of(f)
    assert np.all(d.ppf([1e-9, 0.5, 1 - 1e-9]) == 5.0)
    assert np.all(d.quantile([0.05, 0.95]) == 5.0)
    assert list(d.cdf([4.9, 5.0, 5.1])) == [0.0, 1.0, 1.0]


def test_domain_low() -> None:
    # A minimum of zero events: the lower bound cannot move below it.
    f = pert.fit(0, 1, 4, 0.9, "events_per_year")
    assert f.fallback == pert.DOMAIN_LOW
    assert f.a == 0.0
    assert f.b > 4
    assert _held(f) <= 1e-12
    # Close to the edge: the solution would cross it.
    f = pert.fit(0.01, 0.02, 4, 0.9, "events_per_year")
    assert f.fallback == pert.DOMAIN_LOW
    assert f.a == 0.0


def test_domain_high() -> None:
    f = pert.fit(0.7, 0.9, 1.0, 0.8, "probability")
    assert f.fallback == pert.DOMAIN_HIGH
    assert f.b == 1.0
    assert f.a < 0.7
    assert _held(f) <= 1e-12


def test_bounds() -> None:
    # Both bounds at the domain.
    f = pert.fit(0, 0.3, 1, 0.9, "probability")
    assert f.fallback == pert.BOUNDS
    assert (f.a, f.b) == (0.0, 1.0)
    assert (f.alpha, f.beta) == pytest.approx((2.2, 3.8))
    # A wide 50% interval: the PERT holding it leaves the domain on both sides.
    f = pert.fit(20, 50, 80, 0.5, "percentile")
    assert f.fallback == pert.BOUNDS
    assert (f.a, f.b) == (20.0, 80.0)
    # The upper bound at the domain and no lower bound inside it holds c.
    f = pert.fit(0.3, 0.3, 1, 0.5, "probability")
    assert f.fallback == pert.BOUNDS


def test_fit_is_deterministic() -> None:
    a = pert.fit("1000", "4000", "90000", "0.9", "currency")
    b = pert.fit(1000.0, 4000.0, 90000.0, 0.9, "currency")
    assert a == b


@pytest.mark.parametrize(
    "args",
    [
        (2, 1, 3, 0.9, "currency"),
        (1, 4, 3, 0.9, "currency"),
        (-1, 0, 1, 0.9, "currency"),
        (0, 0.5, 1.5, 0.9, "probability"),
        (0, 50, 101, 0.9, "percentile"),
        (0, 1, 2, 1, "currency"),
        (0, 1, 2, 0, "currency"),
        (0, 1, 2, 0.9, "dollars"),
        (0, 1, "inf", 0.9, "currency"),
    ],
)
def test_invalid_estimates_are_refused(args: tuple[object, ...]) -> None:
    with pytest.raises(pert.EstimateError):
        pert.fit(*args)  # type: ignore[arg-type]


TABLE_CASES = (
    ("currency", 1_000, 1_000, 50_000, 0.9),
    ("currency", 1_000, 5_000, 50_000, 0.9),
    ("events_per_year", 0.1, 0.5, 4, 0.99),
    ("events_per_year", 0, 0, 4, 0.9),
    ("percentile", 20, 79, 80, 0.5),
    ("fraction", 0.1, 0.12, 0.5, 0.95),
    ("probability", 0.7, 0.9, 1.0, 0.8),
)


@pytest.mark.parametrize(("unit", "lo", "ml", "hi", "c"), TABLE_CASES)
def test_table_error_against_the_exact_inverse(unit: str, lo: float, ml: float, hi: float, c: float) -> None:
    f = pert.fit(lo, ml, hi, c, unit)
    d = pert.Distribution.of(f)
    n = pert.TABLE_SIZE * 5
    u = np.concatenate([(np.arange(n) + 0.5) / n, [2.0**-53, 1e-12, 1e-9, 1e-6, 1 - 1e-6, 1 - 1e-9, 1 - 2.0**-53]])
    err = np.max(np.abs(d.ppf(u) - d.quantile(u))) / (f.b - f.a)
    assert err <= pert.TABLE_TOLERANCE
    assert 0 < d.exact_cells < pert.TABLE_SIZE // 100


def test_sampling_matches_the_distribution() -> None:
    f = pert.fit(1_000, 5_000, 50_000, 0.9, "currency")
    d = pert.Distribution.of(f)
    x = d.ppf(rng.uniforms(42, rng.fnv1a32("/primary/productivity"), np.arange(400_000)))
    assert np.all((x >= f.a) & (x <= f.b))
    inside = np.mean((x >= 1_000) & (x <= 50_000))
    assert inside == pytest.approx(0.9, abs=0.003)
    mean = f.a + f.alpha / (f.alpha + f.beta) * (f.b - f.a)
    assert x.mean() == pytest.approx(mean, rel=0.005)
    assert d.cdf(d.quantile([0.05, 0.5, 0.95])) == pytest.approx([0.05, 0.5, 0.95], abs=1e-12)


def test_sampling_is_independent_of_chunking() -> None:
    d = pert.Distribution.of(pert.fit(0.1, 0.5, 4, 0.9, "events_per_year"))
    u = rng.uniforms(9, 9, np.arange(50_000))
    whole = d.ppf(u)
    assert np.array_equal(whole, np.concatenate([d.ppf(u[j : j + 3_333]) for j in range(0, 50_000, 3_333)]))
    assert np.array_equal(whole, pert.Distribution.of(pert.fit(0.1, 0.5, 4, 0.9, "events_per_year")).ppf(u))
