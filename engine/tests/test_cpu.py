"""F-005 T-04 (ADR-013): NumPy's CPU dispatch is pinned to the baseline."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

import fairsim
from fairsim import cpu
from fairsim.__main__ import info, main


def test_pinned_before_numpy() -> None:
    arch = cpu.architecture()
    if arch in cpu.DISPATCHED:
        assert set(os.environ[cpu.ENV].split()) == set(cpu.DISPATCHED[arch])
    state = cpu.check()
    assert not any(state.values())


def test_a_different_pin_is_refused() -> None:
    if cpu.architecture() not in cpu.DISPATCHED:
        pytest.skip("no pin on this architecture")
    env = dict(os.environ, **{cpu.ENV: "X86_V4"})
    out = subprocess.run([sys.executable, "-c", "import fairsim"], env=env, capture_output=True, text=True, check=False)
    assert out.returncode != 0
    assert "the engine needs" in out.stderr


def test_info(capsys: pytest.CaptureFixture[str]) -> None:
    got = info()
    assert got["version"] == fairsim.__version__
    assert got["architecture"] in ("amd64", "arm64")
    assert main(["fairsim", "info"]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == fairsim.__version__
    assert main(["fairsim"]) == 2
