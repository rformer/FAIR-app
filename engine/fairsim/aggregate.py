"""Aggregates of runs (F-005 design §3.5; AC-18).

Members are succeeded runs, one control set each, all with the same
iteration count. The aggregate's loss in year ``i`` is
``Σ_m ALE_m[π_m(i)]``, summed in member position order, where ``π_m`` is a
permutation of the iterations drawn from the aggregate's seed and the
member's position (the order of ``u(seed, member:<position>, i)``). Members
therefore never share draws, even when their runs share a seed: they are
combined as independent, which the result states.

The result has the summaries and curve of a run and each member's
contribution: its mean, and its share of the aggregate's 95th-percentile
year (the year whose loss is that order statistic).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

import numpy as np
from numpy.typing import NDArray

from fairsim import exact, results, rng

MIN_MEMBERS: Final = 2
MAX_MEMBERS: Final = 200
SHARE_PERCENTILE: Final = 95

INDEPENDENCE: Final = (
    "Members are combined as independent: each member's years are permuted by the aggregate's seed, "
    "so members never share random numbers; correlations between scenarios are not modelled."
)

F64 = NDArray[np.float64]


class AggregateError(ValueError):
    """The members cannot be aggregated."""


@dataclass(frozen=True)
class Member:
    position: int
    ale: F64
    label: str = ""


def permutation(seed: int, position: int, n: int) -> NDArray[np.int64]:
    """``π_m``: the iterations in the order of the member's uniforms."""
    u = rng.uniforms(seed, rng.fnv1a32(f"member:{position}"), np.arange(n, dtype=np.int64))
    out: NDArray[np.int64] = np.argsort(u, kind="stable").astype(np.int64)
    return out


def aggregate(seed: int, members: Sequence[Member]) -> tuple[dict[str, Any], F64]:
    """The aggregate's summary and its per-year series."""
    if not MIN_MEMBERS <= len(members) <= MAX_MEMBERS:
        raise AggregateError(f"an aggregate has {MIN_MEMBERS} to {MAX_MEMBERS} members")
    ordered = sorted(members, key=lambda m: m.position)
    if len({m.position for m in ordered}) != len(ordered):
        raise AggregateError("two members have the same position")
    n = ordered[0].ale.size
    if n == 0:
        raise AggregateError("members have no iterations")
    for m in ordered:
        if m.ale.shape != (n,):
            raise AggregateError(f"member {m.position} has {m.ale.size} iterations, not {n}")
        if not np.all(np.isfinite(m.ale)):
            raise AggregateError(f"member {m.position} has a value that is not finite")
    shuffled = [m.ale[permutation(seed, m.position, n)] for m in ordered]
    total = np.zeros(n)
    for x in shuffled:
        total = total + x
    ale = results.summarize(total, positive=True)
    k = math.ceil(SHARE_PERCENTILE / 100 * n) - 1  # the inverted_cdf order statistic
    year = int(np.argsort(total, kind="stable")[k])
    contributions = [
        {
            "position": m.position,
            "label": m.label,
            "mean": exact.mean(m.ale),
            "share_of_p95_year": (float(x[year] / total[year]) if total[year] != 0 else None),
        }
        for m, x in zip(ordered, shuffled, strict=True)
    ]
    summary = {
        "independence": INDEPENDENCE,
        "iterations": n,
        "members": len(ordered),
        "ale": ale,
        "curve": results.curve(total, ale["percentiles"]),
        "p95_year": {"loss": float(total[year])},
        "contributions": contributions,
    }
    return summary, total
