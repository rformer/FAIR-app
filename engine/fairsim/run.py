"""A run from bundle to results, sensitivity included (F-005 design §3, §6.1): what ``Simulate`` serves."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np
from numpy.typing import NDArray

from fairsim import bundle, model, results, sensitivity
from fairsim.workers import Source, Workers


@dataclass(frozen=True)
class SetResult:
    control_set: str
    summary: results.Summary
    ale: NDArray[np.float64]


@dataclass(frozen=True)
class Run:
    sets: tuple[SetResult, ...]
    warnings: tuple[bundle.RunWarning, ...]


def run(
    raw: bytes | Mapping[str, Any],
    seed: int,
    iterations: int,
    control_sets: Sequence[str],
    convergence_threshold_bp: int,
    *,
    chunk: int = model.CHUNK,
    progress: model.Progress | None = None,
    workers: Workers | None = None,
    runner: model.Runner | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> Run:
    """Simulate a bundle; raises ``bundle.BundleError`` for a bundle that cannot be run.

    ``workers`` runs the chunks in worker processes; ``runner`` (tests)
    replaces how chunks are run. Results are the same either way.
    ``cancelled`` stops the run with ``model.Cancelled``.
    """
    data = raw if isinstance(raw, bytes) else json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    m = bundle.read(data, control_sets)
    if runner is None and workers is not None:
        runner = workers.runner(m, Source(data, tuple(control_sets)))
    main_total = iterations * len(m.sets)
    total = main_total + sensitivity.passes(m) * sensitivity.sample(iterations) * len(m.sets)

    def main_progress(done: int, _: int) -> None:
        if progress is not None:
            progress(done, total)

    def sens_progress(done: int, _: int) -> None:
        if progress is not None:
            progress(main_total + done, total)

    sim = model.simulate(m, seed, iterations, chunk=chunk, progress=main_progress, record=True, runner=runner, cancelled=cancelled)
    sens = sensitivity.sensitivity(m, seed, iterations, sim, chunk=chunk, progress=sens_progress, runner=runner, cancelled=cancelled)
    summaries = results.results(sim, convergence_threshold_bp)
    for name, summary in summaries:
        summary["sensitivity"] = sens[name]
    for s in sim.sets:
        s.form_totals = None
    warnings = list(sim.warnings)
    warnings += [bundle.RunWarning("not_converged", "", name, detail) for name, detail in results.not_converged(summaries)]
    sets = tuple(SetResult(name, summary, s.ale) for (name, summary), s in zip(summaries, sim.sets, strict=True))
    return Run(sets, tuple(dict.fromkeys(warnings)))
