"""F-005 T-08 (AC-15, AC-17; design §3.3): results are identical bit for bit.

The same bundle, seed, iterations and control sets give the same series,
summaries and warnings with 1, 2 or 8 worker processes, whatever order the
chunks run in, and with NumPy's CPU dispatch pinned or at its defaults.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

import numpy as np
import pytest
import scenarios as sc

import fairsim  # noqa: F401  (pins NumPy's dispatch first)
from fairsim import bundle, cpu, model
from fairsim.run import Run, run
from fairsim.server import encode_summary
from fairsim.workers import Workers

N = 24_000
CHUNK = 5_000
SETS = ("Current", "With EDR")


def digest(r: Run) -> str:
    h = hashlib.sha256()
    for s in r.sets:
        h.update(s.control_set.encode())
        h.update(encode_summary(s.summary).encode())
        h.update(np.ascontiguousarray(s.ale, dtype="<f8").tobytes())
    for w in r.warnings:
        h.update(repr(w).encode())
    return h.hexdigest()


@pytest.fixture(scope="module")
def reference() -> str:
    return digest(run(sc.corpus(), 2026, N, SETS, 100, chunk=CHUNK))


@pytest.mark.parametrize("workers", [1, 2, 8])
def test_any_number_of_workers(workers: int, reference: str) -> None:
    with Workers(workers) as w:
        assert digest(run(sc.corpus(), 2026, N, SETS, 100, chunk=CHUNK, workers=w)) == reference


def shuffled(m: bundle.Model, seed: int) -> model.Runner:
    """Runs the chunks in a shuffled order, then yields them in task order."""

    def runner(tasks: Sequence[model.Task]) -> Iterator[model.TaskResult]:
        order = list(range(len(tasks)))
        random.Random(seed).shuffle(order)
        done = {j: model.execute(m, tasks[j]) for j in order}
        return (done[j] for j in range(len(tasks)))

    return runner


@pytest.mark.parametrize("order", [1, 2, 3])
def test_any_chunk_order(order: int, reference: str) -> None:
    raw = json.dumps(sc.corpus(), sort_keys=True, separators=(",", ":")).encode()
    m = bundle.read(raw, SETS)
    assert digest(run(raw, 2026, N, SETS, 100, chunk=CHUNK, runner=shuffled(m, order))) == reference


SCRIPT = """
import hashlib, json, os, sys
sys.path.insert(0, {tests!r})
if {default}:
    import numpy  # NumPy loads first, with its default dispatch
    from numpy._core import _multiarray_umath as u
    on = sorted(f for f in u.__cpu_dispatch__ if u.__cpu_features__.get(f))
    os.environ[{env!r}] = {pin!r}  # so that importing fairsim accepts the process
else:
    on = []
import fairsim, scenarios
from fairsim.run import run
from test_determinism import digest
print(json.dumps({{"digest": digest(run(scenarios.corpus(), 2026, {n}, {sets!r}, 100, chunk={chunk})), "dispatched": on}}))
"""


def _subprocess(default: bool) -> dict[str, object]:
    tests = str(Path(__file__).parent)
    env = {k: v for k, v in os.environ.items() if k != cpu.ENV}
    code = SCRIPT.format(
        tests=tests,
        default=default,
        env=cpu.ENV,
        pin=" ".join(cpu.DISPATCHED.get(cpu.architecture(), ())),
        n=N,
        sets=list(SETS),
        chunk=CHUNK,
    )
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=False, cwd=str(Path(tests).parent))
    assert out.returncode == 0, out.stderr[-2000:]
    result: dict[str, object] = json.loads(out.stdout.strip().splitlines()[-1])
    return result


def test_default_and_pinned_cpu_features(reference: str) -> None:
    if cpu.architecture() not in cpu.DISPATCHED:
        pytest.skip("no pin on this architecture")
    pinned, default = _subprocess(False), _subprocess(True)
    assert pinned["digest"] == reference
    assert default["digest"] == reference, f"results differ with NumPy dispatching {default['dispatched']}"
