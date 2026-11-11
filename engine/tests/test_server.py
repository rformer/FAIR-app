"""F-005 T-08 (AC-02, AC-03; design §2, §6.1): the gRPC server on a Unix socket."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import grpc
import numpy as np
import pytest
import scenarios as sc

import fairsim
from fairsim import aggregate, cpu
from fairsim._proto.fair.engine.v1 import engine_pb2 as pb
from fairsim._proto.fair.engine.v1 import engine_pb2_grpc as pbg
from fairsim.run import run
from fairsim.server import SERIES_VALUES, Engine, encode_summary, load_validation, server
from fairsim.workers import Workers

PASSED = {"suite_version": "1", "passed": True, "run_at_unix_ms": 1_700_000_000_000, "detail": {"checks": 1}}


class Running:
    def __init__(self, engine: Engine, path: str) -> None:
        self.engine = engine
        self.server = server(engine, path)
        self.server.start()
        self.channel = grpc.insecure_channel(f"unix://{path}")
        self.stub = pbg.EngineStub(self.channel)

    def close(self) -> None:
        self.channel.close()
        self.server.stop(grace=None).wait()


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Running]:
    r = Running(Engine(Workers(1), dict(PASSED)), str(tmp_path / "engine.sock"))
    yield r
    r.close()


def request(b: dict[str, Any] | None = None, **kw: Any) -> Any:
    raw = json.dumps(b if b is not None else sc.corpus()).encode()
    args: dict[str, Any] = {
        "bundle": raw,
        "seed": 77,
        "iterations": 6_000,
        "control_sets": ["Current", "With EDR"],
        "convergence_threshold_bp": 100,
        "run_id": "r1",
    }
    args.update(kw)
    return pb.SimulateRequest(**args)


def test_socket_permissions(engine: Running, tmp_path: Path) -> None:
    mode = (tmp_path / "engine.sock").stat().st_mode & 0o777
    assert mode & 0o007 == 0


def test_info(engine: Running, tmp_path: Path) -> None:
    got = engine.stub.Info(pb.InfoRequest())
    assert got.version == fairsim.__version__
    assert got.architecture == cpu.architecture()
    assert got.validation.passed
    assert got.validation.suite_version == "1"
    assert json.loads(got.validation.detail_json) == {"checks": 1}
    missing = load_validation(str(tmp_path / "nope.json"))
    assert not missing["passed"]
    (tmp_path / "v.json").write_text(json.dumps(PASSED))
    assert load_validation(str(tmp_path / "v.json"))["passed"]
    (tmp_path / "v.json").write_text(json.dumps(dict(PASSED, passed="yes")))
    assert not load_validation(str(tmp_path / "v.json"))["passed"]


def test_simulate_streams_what_run_computes(engine: Running) -> None:
    events = list(engine.stub.Simulate(request()))
    kinds = [e.WhichOneof("event") for e in events]
    assert kinds[-1] == "done"
    assert "failure" not in kinds
    progress = [(e.progress.done, e.progress.total) for e in events if e.HasField("progress")]
    assert progress
    assert progress[-1][0] == progress[-1][1]
    assert [d for d, _ in progress] == sorted(d for d, _ in progress)
    assert kinds.index("result") > max(j for j, k in enumerate(kinds) if k == "progress")

    want = run(sc.corpus(), 77, 6_000, ["Current", "With EDR"], 100)
    results = [e.result for e in events if e.HasField("result")]
    assert [r.control_set for r in results] == ["Current", "With EDR"]
    for r, w in zip(results, want.sets, strict=True):
        assert r.summary_json == encode_summary(w.summary)
        chunks = [e.series for e in events if e.HasField("series") and e.series.control_set == w.control_set]
        assert [c.offset for c in chunks] == list(range(0, 6_000, SERIES_VALUES))
        got = np.concatenate([np.frombuffer(c.values, dtype="<f8") for c in chunks])
        assert np.array_equal(got, w.ale)
    done = events[-1].done
    assert [(x.code, x.pointer, x.control_set, x.detail) for x in done.warnings] == [
        (x.code, x.pointer, x.control_set, x.detail) for x in want.warnings
    ]


def test_series_chunks_are_at_most_one_mebibyte(engine: Running) -> None:
    b = sc.bundle(sc.scenario({"level": "lef", "estimate": sc.point("1", "events_per_year")}, {"productivity": sc.point("1", "currency")}))
    events = engine.stub.Simulate(request(b, iterations=300_000, control_sets=["Current"]))
    chunks = [e.series for e in events if e.HasField("series")]
    assert len(chunks) == 3
    assert max(len(c.values) for c in chunks) == 1 << 20


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"iterations": 0}, "iterations"),
        ({"iterations": 2_000_001}, "iterations"),
        ({"control_sets": []}, "control sets"),
        ({"control_sets": ["Current", "Nope"]}, "no control set"),
        ({"convergence_threshold_bp": 0}, "threshold"),
        ({"bundle": b""}, "empty"),
        ({"bundle": b"{not json"}, "not JSON"),
        ({"bundle": b'{"format":"other"}'}, "format"),
    ],
)
def test_invalid_requests_fail(engine: Running, kw: dict[str, Any], match: str) -> None:
    events = list(engine.stub.Simulate(request(**kw)))
    assert len(events) == 1
    assert events[0].failure.code == "invalid_bundle"
    assert match in events[0].failure.detail
    assert engine.engine.active == 0


def _long(engine: Running) -> Any:
    return engine.stub.Simulate(request(iterations=2_000_000, control_sets=["Current"]))


def test_a_cancelled_stream_stops_work(engine: Running) -> None:
    call = _long(engine)
    first = next(call)
    assert first.HasField("progress")
    call.cancel()
    deadline = time.monotonic() + 15
    while engine.engine.active and time.monotonic() < deadline:
        time.sleep(0.05)
    assert engine.engine.active == 0
    assert engine.engine.stats["cancelled"] == 1
    assert engine.engine.stats["succeeded"] == 0


def test_too_many_runs(tmp_path: Path) -> None:
    r = Running(Engine(Workers(1), dict(PASSED), max_runs=1), str(tmp_path / "e.sock"))
    try:
        call = _long(r)
        next(call)
        with pytest.raises(grpc.RpcError) as e:
            list(r.stub.Simulate(request()))
        assert e.value.code() == grpc.StatusCode.RESOURCE_EXHAUSTED
        call.cancel()
    finally:
        r.close()


def _members(n: int) -> list[np.ndarray[Any, np.dtype[np.float64]]]:
    g = np.random.default_rng(3)
    return [g.lognormal(5, 1, n), g.lognormal(6, 1, n)]


def _aggregate_inputs(series: list[np.ndarray[Any, np.dtype[np.float64]]], n: int, step: int = 100_000) -> Iterator[Any]:
    members = [pb.Member(position=j, run_id=f"run{j}", control_set="Current", scenario_name=f"S{j}") for j in range(len(series))]
    yield pb.AggregateInput(header=pb.AggregateHeader(aggregate_id="a1", seed=5, iterations=n, members=members))
    for j, s in enumerate(series):
        for off in range(0, n, step):
            yield pb.AggregateInput(series=pb.MemberChunk(position=j, offset=off, values=s[off : off + step].astype("<f8").tobytes()))


def test_aggregate(engine: Running) -> None:
    n = 250_000
    series = _members(n)
    events = list(engine.stub.Aggregate(_aggregate_inputs(series, n)))
    assert events[-1].HasField("done")
    summary, total = aggregate.aggregate(5, [aggregate.Member(j, s, f"S{j}") for j, s in enumerate(series)])
    result = next(e.result for e in events if e.HasField("result"))
    assert result.summary_json == encode_summary(summary)
    got = np.concatenate([np.frombuffer(e.series.values, dtype="<f8") for e in events if e.HasField("series")])
    assert np.array_equal(got, total)


def test_aggregate_refusals(engine: Running) -> None:
    n = 1_000
    series = _members(n)
    inputs = list(_aggregate_inputs(series, n, step=400))
    for bad, match in [
        (inputs[1:], "header must come first"),
        (inputs[:-1], "fewer than"),
        ([inputs[0], inputs[2], *inputs[1:]], "expected"),
        ([inputs[0], inputs[0]], "only series"),
    ]:
        events = list(engine.stub.Aggregate(iter(bad)))
        assert events[-1].failure.code == "invalid_bundle"
        assert match in events[-1].failure.detail


def test_serve_command(tmp_path: Path) -> None:
    sock = tmp_path / "s.sock"
    env = dict(os.environ)
    p = subprocess.Popen(
        [sys.executable, "-m", "fairsim", "serve", "--socket", str(sock), "--workers", "2", "--validation", str(tmp_path / "none.json")],
        env=env,
        cwd=str(Path(fairsim.__file__).parent.parent),
    )
    try:
        deadline = time.monotonic() + 30
        while not sock.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        with grpc.insecure_channel(f"unix://{sock}") as ch:
            info = pbg.EngineStub(ch).Info(pb.InfoRequest(), timeout=10)
            assert info.version == fairsim.__version__
            assert not info.validation.passed
            events = list(pbg.EngineStub(ch).Simulate(request(iterations=12_000), timeout=120))
            assert events[-1].HasField("done")
        p.send_signal(signal.SIGTERM)
        assert p.wait(timeout=30) == 0
    finally:
        if p.poll() is None:
            p.kill()
