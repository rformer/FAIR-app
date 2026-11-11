"""F-005 T-09 (AC-20, AC-21; design §3.6): the validation suite and the startup self-check."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

import fairsim
from fairsim import cpu, pert, validation
from fairsim.__main__ import main


@pytest.fixture(scope="module")
def record() -> dict[str, Any]:
    return validation.suite()


def test_the_suite_passes(record: dict[str, Any]) -> None:
    assert record["passed"], {k: v for k, v in record["detail"].items() if not v["passed"]}
    assert record["suite_version"] == validation.SUITE_VERSION
    assert record["engine_version"] == fairsim.__version__
    assert record["architecture"] == cpu.architecture()
    assert set(record["detail"]) == {
        "philox_vectors",
        "pert_fit",
        "sampler_moments",
        "quantile_table",
        "known_constant",
        "known_poisson",
        "known_reduction",
        "known_vulnerability",
        "convergence_coverage",
        "aggregation",
        "cross_feature",
    }
    json.dumps(record, allow_nan=False)


def test_a_broken_sampler_fails_it(monkeypatch: pytest.MonkeyPatch) -> None:
    ppf = pert.Distribution.ppf

    def skewed(self: pert.Distribution, u: Any) -> Any:
        return ppf(self, np.asarray(u) ** 1.02)

    monkeypatch.setattr(pert.Distribution, "ppf", skewed)
    sampler = validation.check_sampler()
    assert not sampler.passed
    assert not validation.check_table().passed
    assert validation.self_check(None)


def test_a_changed_result_without_a_new_version_fails_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validation, "references", lambda: {fairsim.__version__: {cpu.architecture(): "0" * 64}})
    c = validation.check_cross_feature()
    assert not c.passed
    monkeypatch.setattr(validation, "references", dict)
    assert not validation.check_cross_feature().passed


def test_the_corpus_bundle_is_go_s() -> None:
    b = json.loads(validation.corpus_bundle())
    assert b["format"] == "fair.scenario-input.v1"
    assert [p["pointer"] for p in b["pins"]] == sorted(p["pointer"] for p in b["pins"])


def test_self_check(record: dict[str, Any]) -> None:
    assert validation.self_check(record) == []
    assert validation.self_check(None) == []
    assert validation.self_check(dict(record, self_check_digest="0" * 64)) == [
        "the corpus run differs from the one validated at image build"
    ]
    assert validation.self_check(dict(record, engine_version="9.9.9"))


def test_validate_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, record: dict[str, Any]) -> None:
    out = tmp_path / "v.json"
    monkeypatch.setattr(validation, "suite", lambda: record)
    assert main(["fairsim", "validate", "--out", str(out)]) == 0
    assert json.loads(out.read_text())["passed"]
    failed = dict(record, passed=False, detail=dict(record["detail"], pert_fit={"passed": False}))
    monkeypatch.setattr(validation, "suite", lambda: failed)
    assert main(["fairsim", "validate", "--out", str(out)]) == 1
    assert not json.loads(out.read_text())["passed"]
    assert main(["fairsim", "validate", "--bogus", "x"]) == 2


def test_the_engine_refuses_to_serve_after_a_failed_self_check(tmp_path: Path, record: dict[str, Any]) -> None:
    rec = tmp_path / "validation.json"
    rec.write_text(json.dumps(dict(record, self_check_digest="0" * 64)))
    sock = tmp_path / "e.sock"
    p = subprocess.run(
        [sys.executable, "-m", "fairsim", "serve", "--socket", str(sock), "--workers", "1", "--validation", str(rec)],
        cwd=str(Path(fairsim.__file__).parent.parent),
        env=dict(os.environ),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert p.returncode == 1
    assert "self_check_failed" in p.stderr
    assert not sock.exists()
