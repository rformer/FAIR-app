"""Results of a run (F-005 design §3.4; AC-11 to AC-13), sensitivity apart (T-07).

Per control set, from its per-year arrays: summaries of annualized loss,
loss event frequency and loss per event; the loss exceedance curve; the
breakdown of mean annualized loss; the comparison with the current set
(per-year differences, meaningful because the sets share their random
numbers); and convergence. Means are exact sums over the count, correctly
rounded; percentiles are order statistics (``inverted_cdf``). Undefined
values (a mean of nothing, a relative error of a zero mean) are ``None``.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any, Final

import numpy as np
from numpy.typing import NDArray
from scipy.stats import binom

from fairsim import exact
from fairsim.model import SetSeries, Simulation

PERCENTILES: Final = (1, 5, 10, 25, 50, 75, 90, 95, 99)
COMPARED: Final = (50, 90, 95, 99)
INTERVALS: Final = (50, 90, 95, 99)
CURVE_POINTS: Final = 200
CURVE_FROM: Final = 0.1  # percentile of the positive annual losses
INTERVAL_LEVEL: Final = 0.95

# Stated on every result (AC-10).
INDEPENDENCE: Final = "Every input is sampled independently of every other; correlations between inputs are not modelled."

F64 = NDArray[np.float64]
Summary = dict[str, Any]


def _num(x: float) -> float | None:
    return None if math.isnan(x) else float(x)


def summarize(x: F64, *, positive: bool = False) -> Summary:
    """Mean, standard deviation (two-pass), minimum, maximum and percentiles."""
    n = int(x.size)
    out: Summary = {"n": n}
    if n == 0:
        out |= {"mean": None, "sd": None, "min": None, "max": None, "percentiles": {f"p{p}": None for p in PERCENTILES}}
        if positive:
            out["p_positive"] = None
        return out
    mu = exact.mean(x)
    sd = math.sqrt(exact.fsum((x - mu) ** 2) / (n - 1)) if n > 1 else 0.0
    q = np.percentile(x, PERCENTILES, method="inverted_cdf")
    out |= {
        "mean": mu,
        "sd": sd,
        "min": float(x.min()),
        "max": float(x.max()),
        "percentiles": {f"p{p}": float(v) for p, v in zip(PERCENTILES, q, strict=True)},
    }
    if positive:
        out["p_positive"] = int(np.count_nonzero(x > 0)) / n
    return out


def curve(ale: F64, percentiles: Summary) -> Summary:
    """The loss exceedance curve: ``P(ALE > x)`` at 200 log-spaced losses, and at each percentile."""
    n = ale.size
    srt = np.sort(ale)

    def exceed(v: F64) -> F64:
        out: F64 = (n - np.searchsorted(srt, v, side="right")) / n
        return out

    pos = srt[srt > 0]
    points: list[list[float]] = []
    if pos.size:
        lo = float(np.percentile(pos, CURVE_FROM, method="inverted_cdf"))
        hi = float(pos[-1])
        xs = np.geomspace(lo, hi, CURVE_POINTS) if hi > lo else np.array([hi])
        xs[0], xs[-1] = lo, hi
        points = [[float(a), float(b)] for a, b in zip(xs, exceed(xs), strict=True)]
    at = {k: (None if v is None else float(exceed(np.array([v]))[0])) for k, v in percentiles.items()}
    return {"points": points, "at_percentiles": at}


def convergence(ale: F64, threshold_bp: int) -> Summary:
    """Standard error, relative standard error and distribution-free 95% intervals for percentiles."""
    n = ale.size
    mu = exact.mean(ale)
    sd = math.sqrt(exact.fsum((ale - mu) ** 2) / (n - 1)) if n > 1 else 0.0
    se = sd / math.sqrt(n)
    rse = se / mu if mu != 0 else math.nan
    srt = np.sort(ale)
    intervals: dict[str, list[float]] = {}
    a = (1 - INTERVAL_LEVEL) / 2
    for p in INTERVALS:
        # Order statistics r and s (1-based) with P(X(r) ≤ ξp ≤ X(s)) ≥ 95%.
        r = max(int(binom.ppf(a, n, p / 100)), 1)
        s = min(int(binom.ppf(1 - a, n, p / 100)) + 1, n)
        intervals[f"p{p}"] = [float(srt[r - 1]), float(srt[s - 1])]
    converged = (math.isnan(rse) and sd == 0) or (not math.isnan(rse) and abs(rse) * 10_000 <= threshold_bp)
    return {
        "se": se,
        "rse": _num(rse),
        "threshold_bp": threshold_bp,
        "converged": bool(converged),
        "intervals": intervals,
    }


def breakdown(s: SetSeries) -> Summary:
    """Mean annualized loss split into primary and secondary, by form and by stakeholder group."""
    return {
        "primary": _num(s.primary.mean()),
        "secondary": _num(s.secondary.mean()),
        "forms": {f: _num(v.mean()) for f, v in s.forms.items()},
        "stakeholders": {g: _num(v.mean()) for g, v in s.stakeholders.items()},
    }


def compare(s: SetSeries, current: SetSeries, mine: Summary, theirs: Summary) -> Summary:
    """The set against the current one: differences of mean and percentiles, and the per-year difference."""
    diff = s.ale - current.ale
    return {
        "against": current.name,
        "mean": mine["mean"] - theirs["mean"],
        "percentiles": {f"p{p}": mine["percentiles"][f"p{p}"] - theirs["percentiles"][f"p{p}"] for p in COMPARED},
        "difference": summarize(diff),
    }


def results(sim: Simulation, threshold_bp: int) -> list[tuple[str, Summary]]:
    """Each control set's summary, the current set first."""
    sets: Sequence[SetSeries] = sim.sets
    current = sets[0]
    ales = [summarize(s.ale, positive=True) for s in sets]
    out = []
    for j, s in enumerate(sets):
        summary: Summary = {
            "independence": INDEPENDENCE,
            "iterations": int(s.ale.size),
            "ale": ales[j],
            "lef": summarize(s.lef),
            "loss_per_event": summarize(s.event_losses) | {"events_per_year_sampled": s.events_per_year_sampled},
            "curve": curve(s.ale, ales[j]["percentiles"]),
            "breakdown": breakdown(s),
            "comparison": None if j == 0 else compare(s, current, ales[j], ales[0]),
            "convergence": convergence(s.ale, threshold_bp),
        }
        out.append((s.name, summary))
    return out


def not_converged(summaries: list[tuple[str, Summary]]) -> list[tuple[str, str]]:
    """``(control set, detail)`` for each set whose relative standard error is above the threshold."""
    out = []
    for name, s in summaries:
        c = s["convergence"]
        if not c["converged"]:
            rse = c["rse"]
            detail = "the mean is zero but the losses vary" if rse is None else f"relative standard error {abs(rse) * 10_000:.1f} bp"
            out.append((name, f"{detail}, above {c['threshold_bp']} bp"))
    return out
