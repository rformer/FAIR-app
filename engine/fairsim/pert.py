"""Confidence-honouring Beta-PERT estimates (F-005 design §3.1; AC-07).

An estimate gives ``lo ≤ ml ≤ hi`` at confidence ``c`` in a unit with a
domain. ``fit`` finds the Beta-PERT (λ = 4) with its mode at ``ml`` whose
central ``c`` interval is ``[lo, hi]``: true bounds ``a ≤ lo`` and
``b ≥ hi`` with ``F(lo) = (1 − c)/2`` and ``F(hi) = (1 + c)/2``, inside the
domain. When there is none it applies the documented fallbacks, in order:

``point``
    ``lo = hi``: the quantity is the constant ``lo``.
``domain_low`` / ``domain_high``
    The solution would put ``a`` below the domain (``b`` above it): that
    bound is fixed at the domain's edge and the other is solved so the
    interval holds ``c`` in total.
``bounds``
    No solution, or both bounds at the domain: a plain Beta-PERT on
    ``[lo, hi]``.

``Distribution`` samples by inverse CDF from a quantile table at 2¹⁶ + 1
equally spaced probabilities, interpolated linearly. Where the quantile
function bends too sharply for interpolation to stay within the table's
tolerance (the tails, where the density goes to zero), the table marks the
cell and those draws use the exact inverse, so every draw is within
``TABLE_TOLERANCE`` of the range of ``scipy.special.betaincinv``.

All arithmetic is deterministic for the same inputs on the same
architecture (AC-17).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Final

import numpy as np
from numpy.typing import ArrayLike, NDArray
from scipy.special import betainc, betaincinv

LAMBDA: Final = 4.0

INF: Final = math.inf

# The domain of each unit (F-003 design §3.2).
DOMAINS: Final[dict[str, tuple[float, float]]] = {
    "events_per_year": (0.0, INF),
    "currency": (0.0, INF),
    "probability": (0.0, 1.0),
    "fraction": (0.0, 1.0),
    "percentile": (0.0, 100.0),
}

POINT: Final = "point"
DOMAIN_LOW: Final = "domain_low"
DOMAIN_HIGH: Final = "domain_high"
BOUNDS: Final = "bounds"
FALLBACKS: Final = (POINT, DOMAIN_LOW, DOMAIN_HIGH, BOUNDS)

MAX_ITERATIONS: Final = 200
# The solution's residual on the two probabilities.
TOLERANCE: Final = 1e-12

TABLE_BITS: Final = 16
TABLE_SIZE: Final = 1 << TABLE_BITS
# Every sampled value is within this fraction of the range of the exact
# inverse (design §3.1, validation §8).
TABLE_TOLERANCE: Final = 1e-6
# A cell is interpolated only when its midpoint error is below this: a
# margin under TABLE_TOLERANCE for the error away from the midpoint.
_CELL_TOLERANCE: Final = TABLE_TOLERANCE / 8


class EstimateError(ValueError):
    """The estimate is not a valid range for its unit."""


@dataclass(frozen=True)
class Fit:
    """A fitted estimate: the Beta-PERT on ``[a, b]`` with shapes ``alpha``, ``beta``.

    For ``point`` the quantity is the constant ``a`` (``= b``).
    """

    lo: float
    ml: float
    hi: float
    confidence: float
    unit: str
    a: float
    b: float
    alpha: float
    beta: float
    fallback: str | None
    iterations: int = 0

    @property
    def constant(self) -> bool:
        return self.fallback == POINT


def _number(x: str | float | int | Decimal) -> float:
    v = float(x)  # decimal strings convert correctly rounded
    if not math.isfinite(v):
        raise EstimateError(f"{x!r} is not a finite number")
    return v


def fit(
    lo: str | float | Decimal,
    ml: str | float | Decimal,
    hi: str | float | Decimal,
    confidence: str | float | Decimal,
    unit: str,
) -> Fit:
    """The Beta-PERT for an estimate, or its fallback (design §3.1)."""
    lo_, ml_, hi_, c = _number(lo), _number(ml), _number(hi), _number(confidence)
    if unit not in DOMAINS:
        raise EstimateError(f"unknown unit {unit!r}")
    d0, d1 = DOMAINS[unit]
    if not lo_ <= ml_ <= hi_:
        raise EstimateError("the estimate must be ordered: min ≤ ml ≤ max")
    if lo_ < d0 or hi_ > d1:
        raise EstimateError(f"the estimate must lie within [{d0}, {d1}] for {unit}")
    if not 0.0 < c < 1.0:
        raise EstimateError("the confidence must be between 0 and 1, exclusive")

    if lo_ == hi_:
        return Fit(lo_, ml_, hi_, c, unit, lo_, lo_, 1.0, 1.0, POINT)
    s, t, fallback, n = _extensions((ml_ - lo_) / (hi_ - lo_), c, (lo_ - d0) / (hi_ - lo_), (d1 - hi_) / (hi_ - lo_))
    return _fit(lo_, ml_, hi_, c, unit, s=s, t=t, fallback=fallback, n=n)


def _extensions(m: float, c: float, smax: float, tmax: float) -> tuple[float, float, str | None, int]:
    """The extensions below ``lo`` and above ``hi`` (in units of ``hi − lo``) and the fallback.

    ``m`` is the mode's place in ``[lo, hi]``; ``smax`` and ``tmax`` are the
    room the domain leaves on each side.
    """
    if smax == 0.0 and tmax == 0.0:
        return 0.0, 0.0, BOUNDS, 0
    if smax > 0.0 and tmax > 0.0:
        solved = _solve2(m, c)
        if solved is None:
            return 0.0, 0.0, BOUNDS, MAX_ITERATIONS
        s, t, n = solved
        low_out, high_out = s > smax, t > tmax
        if not (low_out or high_out):
            return s, t, None, n
    else:
        low_out, high_out = smax == 0.0, tmax == 0.0
    # Fix the bound that left the domain at its edge and solve the other;
    # when both left it, the low side first. No solution inside the domain
    # means both bounds would be at it: plain PERT on the estimate's bounds.
    if low_out and (t1 := _solve1(m, c, smax, tmax, free="t")) is not None:
        return smax, t1[0], DOMAIN_LOW, t1[1]
    if high_out and (s1 := _solve1(m, c, smax, tmax, free="s")) is not None:
        return s1[0], tmax, DOMAIN_HIGH, s1[1]
    return 0.0, 0.0, BOUNDS, 0


def _shapes(m: float, s: float, t: float) -> tuple[float, float, float]:
    """α, β and the width of the PERT on ``[−s, 1 + t]`` with mode ``m`` (normalized)."""
    w = 1.0 + s + t
    return 1.0 + LAMBDA * (m + s) / w, 1.0 + LAMBDA * (1.0 + t - m) / w, w


def _cdf2(m: float, s: float, t: float) -> tuple[float, float]:
    """``F(lo)`` and ``F(hi)`` of the normalized PERT (``lo = 0``, ``hi = 1``)."""
    al, be, w = _shapes(m, s, t)
    return float(betainc(al, be, s / w)), float(betainc(al, be, (1.0 + s) / w))


def _fit(lo: float, ml: float, hi: float, c: float, unit: str, *, s: float, t: float, fallback: str | None, n: int) -> Fit:
    span = hi - lo
    m = (ml - lo) / span
    al, be, _ = _shapes(m, s, t)
    d0, d1 = DOMAINS[unit]
    a = d0 if fallback == DOMAIN_LOW else lo - s * span
    b = d1 if fallback == DOMAIN_HIGH else hi + t * span
    return Fit(lo, ml, hi, c, unit, max(a, d0), min(b, d1), al, be, fallback, n)


def _initial(c: float) -> float:
    """Each side's extension for the symmetric PERT (α = β = 3) holding ``c``."""
    z = float(betaincinv(3.0, 3.0, (1.0 + c) / 2.0))
    return (1.0 / (2.0 * z - 1.0) - 1.0) / 2.0


def _solve2(m: float, c: float) -> tuple[float, float, int] | None:
    """Both extensions ``(s, t)`` for ``F(0) = (1 − c)/2``, ``F(1) = (1 + c)/2``.

    Damped Newton on ``(log s, log t)`` with a central-difference Jacobian;
    each step is halved (bisection on the step) until the residual falls.
    """
    pl, ph = (1.0 - c) / 2.0, (1.0 + c) / 2.0

    def residual(x: tuple[float, float]) -> tuple[float, float]:
        fl, fh = _cdf2(m, math.exp(x[0]), math.exp(x[1]))
        return fl - pl, fh - ph

    s0 = _initial(c)
    x = (math.log(s0), math.log(s0))
    r = residual(x)
    h = 1e-6
    n = 0
    for n in range(1, MAX_ITERATIONS + 1):
        norm = max(abs(r[0]), abs(r[1]))
        if norm <= TOLERANCE / 100:
            return math.exp(x[0]), math.exp(x[1]), n
        ra, rb = residual((x[0] + h, x[1])), residual((x[0] - h, x[1]))
        rc, rd = residual((x[0], x[1] + h)), residual((x[0], x[1] - h))
        j00, j10 = (ra[0] - rb[0]) / (2 * h), (ra[1] - rb[1]) / (2 * h)
        j01, j11 = (rc[0] - rd[0]) / (2 * h), (rc[1] - rd[1]) / (2 * h)
        det = j00 * j11 - j01 * j10
        if det == 0.0 or not math.isfinite(det):
            break
        d0 = -(j11 * r[0] - j01 * r[1]) / det
        d1 = -(-j10 * r[0] + j00 * r[1]) / det
        big = max(abs(d0), abs(d1))
        if big > 2.0:  # at most a factor e² per step
            d0, d1 = 2.0 * d0 / big, 2.0 * d1 / big
        lam = 1.0
        for _ in range(60):
            y = (x[0] + lam * d0, x[1] + lam * d1)
            ry = residual(y)
            if max(abs(ry[0]), abs(ry[1])) < norm:
                break
            lam /= 2.0
        else:
            break
        if max(abs(lam * d0), abs(lam * d1)) < 1e-15:
            x, r = y, ry
            break
        x, r = y, ry
    if max(abs(r[0]), abs(r[1])) <= TOLERANCE:
        return math.exp(x[0]), math.exp(x[1]), n
    return None


def _solve1(m: float, c: float, smax: float, tmax: float, free: str) -> tuple[float, int] | None:
    """One extension, the other fixed at the domain's edge, so the interval holds ``c``.

    Bisection on the free extension in ``[0, its maximum]``. The interval's
    mass is ``1 − F(lo)`` (or ``F(hi)``) with the free side at the
    estimate's bound and falls toward 0 as that side widens.
    """

    def g(v: float) -> float:
        s, t = (smax, v) if free == "t" else (v, tmax)
        fl, fh = _cdf2(m, s, t)
        return fh - fl - c

    lo_v, g_lo = 0.0, g(0.0)
    if g_lo <= 0.0:
        return (0.0, 0) if abs(g_lo) <= TOLERANCE else None
    vmax = tmax if free == "t" else smax
    n = 0
    if math.isfinite(vmax):
        hi_v = vmax
        if g(hi_v) > 0.0:
            return None
    else:
        hi_v = 1.0
        while g(hi_v) > 0.0:
            n += 1
            if n > MAX_ITERATIONS:
                return None
            lo_v, hi_v = hi_v, hi_v * 2.0
    best, best_g = hi_v, abs(g(hi_v))
    while n < MAX_ITERATIONS:
        n += 1
        mid = (lo_v + hi_v) / 2.0
        if mid in (lo_v, hi_v):
            break
        gm = g(mid)
        if abs(gm) < best_g:
            best, best_g = mid, abs(gm)
        if gm == 0.0:
            break
        if gm > 0.0:
            lo_v = mid
        else:
            hi_v = mid
    return (best, n) if best_g <= TOLERANCE else None


@dataclass(frozen=True, eq=False)
class Distribution:
    """A fitted estimate's distribution, sampled by inverse CDF (design §3.1)."""

    fit: Fit
    _z: NDArray[np.float64] = field(repr=False)
    _exact: NDArray[np.bool_] = field(repr=False)

    @classmethod
    def of(cls, f: Fit) -> Distribution:
        if f.constant:
            return cls(f, np.zeros(1), np.zeros(1, dtype=np.bool_))
        p = np.arange(TABLE_SIZE + 1, dtype=np.float64) / TABLE_SIZE
        z = np.asarray(betaincinv(f.alpha, f.beta, p), dtype=np.float64)
        z[0], z[-1] = 0.0, 1.0
        mid = np.asarray(betaincinv(f.alpha, f.beta, (np.arange(TABLE_SIZE, dtype=np.float64) + 0.5) / TABLE_SIZE), dtype=np.float64)
        exact = np.abs((z[:-1] + z[1:]) / 2.0 - mid) > _CELL_TOLERANCE
        return cls(f, z, exact)

    @property
    def exact_cells(self) -> int:
        """The table cells sampled by the exact inverse."""
        return int(self._exact.sum())

    def _scale(self, z: NDArray[np.float64]) -> NDArray[np.float64]:
        f = self.fit
        out: NDArray[np.float64] = np.clip(f.a + (f.b - f.a) * z, f.a, f.b)
        return out

    def ppf(self, u: ArrayLike) -> NDArray[np.float64]:
        """The values at uniforms ``u`` in (0, 1): the table, or the exact inverse in marked cells."""
        uu = np.asarray(u, dtype=np.float64)
        if self.fit.constant:
            return np.full(uu.shape, self.fit.a)
        x = uu * TABLE_SIZE
        j = np.minimum(np.floor(x).astype(np.int64), TABLE_SIZE - 1)
        frac = x - j
        z = self._z[j] + frac * (self._z[j + 1] - self._z[j])
        exact = self._exact[j]
        if exact.any():
            z[exact] = betaincinv(self.fit.alpha, self.fit.beta, uu[exact])
        return self._scale(z)

    def quantile(self, p: ArrayLike) -> NDArray[np.float64]:
        """The exact quantiles (``betaincinv``), for percentiles of an input."""
        pp = np.asarray(p, dtype=np.float64)
        if self.fit.constant:
            return np.full(pp.shape, self.fit.a)
        return self._scale(np.asarray(betaincinv(self.fit.alpha, self.fit.beta, pp), dtype=np.float64))

    def cdf(self, x: ArrayLike) -> NDArray[np.float64]:
        """``F(x)``; for a constant, the step at it."""
        xx = np.asarray(x, dtype=np.float64)
        f = self.fit
        if f.constant:
            return (xx >= f.a).astype(np.float64)
        z = np.clip((xx - f.a) / (f.b - f.a), 0.0, 1.0)
        out: NDArray[np.float64] = np.asarray(betainc(f.alpha, f.beta, z), dtype=np.float64)
        return out
