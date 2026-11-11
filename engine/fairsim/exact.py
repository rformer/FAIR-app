"""Exact sums of float64 arrays, independent of order and chunking.

``ExactSum`` keeps the exact sum of everything added, as integers per
binary exponent, and rounds once at the end, so its value is what
``math.fsum`` gives over all the values together, whatever the order or
the chunks they arrived in (F-005-AC-17). Each value's 53-bit significand
is split into two halves summed per exponent; ``np.bincount`` sums them in
float64, which is exact while a call adds fewer than 2²⁶ values.
"""

from __future__ import annotations

import math
from fractions import Fraction

import numpy as np
from numpy.typing import ArrayLike

_HALF = 26
_OFFSET = 1100  # frexp exponents run from -1073 to 1024
_BUCKETS = 2200
_MAX_CALL = 1 << 26


class ExactSum:
    """The exact sum and count of the values added."""

    def __init__(self) -> None:
        self._hi = np.zeros(_BUCKETS, dtype=np.int64)
        self._lo = np.zeros(_BUCKETS, dtype=np.int64)
        self.count = 0

    def add(self, values: ArrayLike) -> None:
        x = np.asarray(values, dtype=np.float64).ravel()
        if not np.all(np.isfinite(x)):
            raise ValueError("only finite values can be summed")
        for start in range(0, x.size, _MAX_CALL):
            part = x[start : start + _MAX_CALL]
            m, e = np.frexp(part)
            mi = np.ldexp(m, 53).astype(np.int64)  # exact: |mi| < 2⁵³
            hi = mi >> _HALF
            lo = mi - (hi << _HALF)
            idx = e.astype(np.int64) + _OFFSET
            self._hi += np.bincount(idx, weights=hi.astype(np.float64), minlength=_BUCKETS).astype(np.int64)
            self._lo += np.bincount(idx, weights=lo.astype(np.float64), minlength=_BUCKETS).astype(np.int64)
        self.count += x.size

    def merge(self, other: ExactSum) -> None:
        """Add another sum's values (exact, so in any order)."""
        self._hi += other._hi
        self._lo += other._lo
        self.count += other.count

    def exact(self) -> Fraction:
        total = Fraction(0)
        for j in np.flatnonzero((self._hi != 0) | (self._lo != 0)):
            v = (int(self._hi[j]) << _HALF) + int(self._lo[j])
            total += Fraction(v) * Fraction(2) ** (int(j) - _OFFSET - 53)
        return total

    def value(self) -> float:
        """The sum, correctly rounded (as ``math.fsum``)."""
        return float(self.exact())

    def mean(self) -> float:
        """The mean, the exact sum over the count, correctly rounded; NaN when empty."""
        if self.count == 0:
            return math.nan
        return float(self.exact() / self.count)


def fsum(values: ArrayLike) -> float:
    """``math.fsum`` of an array, vectorized."""
    s = ExactSum()
    s.add(values)
    return s.value()


def mean(values: ArrayLike) -> float:
    s = ExactSum()
    s.add(values)
    return s.mean()
