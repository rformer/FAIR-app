"""Sensitivity of mean annualized loss to each input (F-005 design §3.4; AC-14).

For each input of a control set (each estimate the scenario uses, and each
control effect the set adds or removes) two measures:

- **Swing**: the change in mean annualized loss when the input is held at
  its 5th and at its 95th percentile, every other input sampled as before
  (same seed, so the same draws), over the first ``min(iterations,
  20,000)`` iterations against the same iterations unheld.
- **Spearman**: the rank correlation between the input's value in each
  year and the year's annualized loss, over all iterations. For an
  event-level input (a form of loss) the value is the year's total of that
  form. Threat capability enters through its CDF and has no yearly value,
  so its correlation is ``None``; so is any input that does not vary.

Inputs are ordered by the absolute swing, largest first, then by name. An
input the set does not use (an effect on a form the scenario does not
have) swings 0.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

import numpy as np
from numpy.typing import NDArray
from scipy.stats import rankdata

from fairsim import bundle as bd
from fairsim import exact, model

SAMPLE: Final = 20_000
LOW: Final = 0.05
HIGH: Final = 0.95

F64 = NDArray[np.float64]


@dataclass(frozen=True, eq=False)
class Item:
    """An input whose sensitivity is measured."""

    input: bd.Input
    kind: str  # estimate | control_effect
    level: str  # year | event | cdf
    effect: bd.Effect | None = None


def items(m: bd.Model, cs: bd.ControlSet) -> list[Item]:
    """The inputs of a control set, once each by name."""
    out: dict[str, Item] = {}
    for x in m.year_inputs():
        out.setdefault(x.name, Item(x, "estimate", "year"))
    if m.threat_capability is not None:
        out.setdefault(m.threat_capability.name, Item(m.threat_capability, "estimate", "cdf"))
    for x in m.event_inputs():
        out.setdefault(x.name, Item(x, "estimate", "event"))
    # A changed effect is listed once, as the set's own (added) effect.
    for e in (*cs.added, *cs.removed):
        out.setdefault(e.input.name, Item(e.input, "control_effect", "year", e))
    return list(out.values())


def spearman(x: F64, y_ranks: F64) -> float | None:
    """Spearman's rank correlation (average ranks for ties); ``None`` when either is constant."""
    rx = rankdata(x, method="average")
    mx, my = exact.mean(rx), exact.mean(y_ranks)
    dx, dy = rx - mx, y_ranks - my
    sxx, syy = exact.fsum(dx * dx), exact.fsum(dy * dy)
    if sxx == 0 or syy == 0:
        return None
    return exact.fsum(dx * dy) / math.sqrt(sxx * syy)


def _year_values(m: bd.Model, seed: int, inp: bd.Input, iterations: int) -> F64:
    run = model._Run(m, seed)  # the model's own draws
    return np.concatenate([run.draw(inp, it) for it in model._chunks(iterations, model.CHUNK)])


def _means(sim: model.Simulation) -> list[float]:
    return [exact.mean(s.ale) for s in sim.sets]


def sensitivity(
    m: bd.Model,
    seed: int,
    iterations: int,
    main: model.Simulation,
    *,
    chunk: int = model.CHUNK,
    progress: model.Progress | None = None,
    runner: model.Runner | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, dict[str, Any]]:
    """Each control set's sensitivity block. ``main`` is the run's simulation, recorded."""
    n = min(iterations, SAMPLE)
    per_set = {cs.name: items(m, cs) for cs in m.sets}
    union: dict[str, Item] = {}
    for its in per_set.values():
        for it in its:
            union.setdefault(it.input.name, it)
    passes = 1 + 2 * len(union)
    total = passes * n * len(m.sets)
    done = 0

    def sim(fixed: Mapping[str, float] | None) -> list[float]:
        nonlocal done
        out = _means(model.simulate(m, seed, n, chunk=chunk, fixed=fixed, events=False, runner=runner, cancelled=cancelled))
        done += n * len(m.sets)
        if progress is not None:
            progress(done, total)
        return out

    base = sim(None)
    lows: dict[str, list[float]] = {}
    highs: dict[str, list[float]] = {}
    for name in sorted(union):
        lows[name] = sim({name: LOW})
        highs[name] = sim({name: HIGH})

    values: dict[str, F64] = {}
    out: dict[str, dict[str, Any]] = {}
    for j, cs in enumerate(m.sets):
        s = main.sets[j]
        ranks = rankdata(s.ale, method="average")
        rows: list[dict[str, Any]] = []
        for it in per_set[cs.name]:
            name = it.input.name
            rho: float | None = None
            if it.level == "year":
                if name not in values:
                    values[name] = _year_values(m, seed, it.input, iterations)
                rho = spearman(values[name], ranks)
            elif it.level == "event" and s.form_totals is not None:
                rho = spearman(s.form_totals[name], ranks)
            d = it.effect.input.dist if it.effect is not None else it.input.dist
            lo, hi = lows[name][j] - base[j], highs[name][j] - base[j]
            rows.append(
                {
                    "input": name,
                    "pointer": it.input.pointer,
                    "kind": it.kind,
                    "control": it.effect.control if it.effect is not None else None,
                    "factor": it.effect.factor if it.effect is not None else None,
                    "low": {"value": float(d.quantile(LOW)), "mean": lows[name][j], "change": lo},
                    "high": {"value": float(d.quantile(HIGH)), "mean": highs[name][j], "change": hi},
                    "swing": abs(hi - lo),
                    "spearman": rho,
                }
            )
        rows.sort(key=lambda r: (-r["swing"], r["input"]))
        out[cs.name] = {"iterations": n, "low": LOW, "high": HIGH, "base_mean": base[j], "inputs": rows}
    return out


def passes(m: bd.Model) -> int:
    """How many sensitivity simulations a run makes (for progress)."""
    names: set[str] = set()
    for cs in m.sets:
        names.update(it.input.name for it in items(m, cs))
    return 1 + 2 * len(names)


def sample(iterations: int) -> int:
    return min(iterations, SAMPLE)
