"""The engine's gRPC server on a Unix socket (F-005 design §2, §6.1; ADR-013).

The engine listens only on a Unix socket in its pod; engine-gate
terminates mTLS and forwards to it (ADR-013). ``Engine`` implements the
contract in ``api/proto/fair/engine/v1/engine.proto``:

- ``Info``: version, architecture and the image's validation record.
- ``Simulate``: checks the request, runs it on the worker pool, and streams
  progress (at most every half second, and at the end), then per control
  set its summary and its series in 1 MiB chunks, then ``done`` with the
  warnings. A request or bundle that cannot be run ends with ``failure``
  ``invalid_bundle``; anything else unexpected with ``internal`` (detail
  without internals). Cancelling the call stops the work at the next
  chunk.
- ``Aggregate``: the header, then every member's series in order; the
  aggregate's summary and series, then ``done``.

Summaries travel as JSON with sorted keys whose numbers are the shortest
round-trip decimals (Python's float repr), so the risk service stores and
digests exactly what the engine computed (design §6.3). Nothing about a
bundle's content is logged.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import signal
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Final

import grpc
import numpy as np
from numpy.typing import NDArray

import fairsim
from fairsim import aggregate, bundle, cpu, model
from fairsim._proto.fair.engine.v1 import engine_pb2 as pb
from fairsim._proto.fair.engine.v1 import engine_pb2_grpc as pbg
from fairsim.run import Run, run
from fairsim.workers import Workers

log = logging.getLogger("fairsim")

MAX_BUNDLE: Final = 8 << 20
MAX_MESSAGE: Final = 16 << 20
MAX_ITERATIONS: Final = 2_000_000
MAX_ITERATION_SETS: Final = 20_000_000  # design §4.3
MAX_CONTROL_SETS: Final = 100
SERIES_VALUES: Final = (1 << 20) // 8  # 1 MiB of float64
PROGRESS_EVERY: Final = 0.5  # seconds
VALIDATION_PATH: Final = "/engine/validation.json"


class RequestError(ValueError):
    """The request cannot be run."""


def encode_summary(summary: dict[str, Any]) -> str:
    """JSON with sorted keys and shortest round-trip numbers; NaN and infinities are refused."""
    return json.dumps(summary, sort_keys=True, separators=(",", ":"), allow_nan=False)


def series_chunks(control_set: str, ale: NDArray[np.float64]) -> Iterator[Any]:
    data = np.ascontiguousarray(ale, dtype="<f8")
    for off in range(0, data.size, SERIES_VALUES):
        yield pb.SeriesChunk(control_set=control_set, offset=off, values=data[off : off + SERIES_VALUES].tobytes())


def load_validation(path: str) -> dict[str, Any]:
    """The image's validation record (written at image build, T-09); a missing one has not passed."""
    try:
        rec = json.loads(Path(path).read_text(encoding="utf-8"))
        return {
            "suite_version": str(rec["suite_version"]),
            "passed": rec["passed"] is True,
            "run_at_unix_ms": int(rec["run_at_unix_ms"]),
            "detail": rec.get("detail", {}),
        }
    except (OSError, ValueError, KeyError, TypeError) as e:
        return {
            "suite_version": "",
            "passed": False,
            "run_at_unix_ms": 0,
            "detail": {"error": f"no usable validation record: {type(e).__name__}"},
        }


def check_simulate(req: Any) -> None:
    if not req.bundle:
        raise RequestError("the bundle is empty")
    if len(req.bundle) > MAX_BUNDLE:
        raise RequestError(f"the bundle is larger than {MAX_BUNDLE} bytes")
    if not 1 <= req.iterations <= MAX_ITERATIONS:
        raise RequestError(f"iterations must be between 1 and {MAX_ITERATIONS}")
    sets = list(req.control_sets)
    if not 1 <= len(sets) <= MAX_CONTROL_SETS:
        raise RequestError(f"between 1 and {MAX_CONTROL_SETS} control sets")
    if req.iterations * len(sets) > MAX_ITERATION_SETS:
        raise RequestError(f"iterations × control sets must be at most {MAX_ITERATION_SETS}")
    if not 1 <= req.convergence_threshold_bp <= 10_000:
        raise RequestError("the convergence threshold is between 1 and 10,000 basis points")


def _warning(w: bundle.RunWarning) -> Any:
    return pb.Warning(code=w.code, pointer=w.pointer, control_set=w.control_set, detail=w.detail)


def _failure(code: str, detail: str) -> Any:
    return pb.Failure(code=code, detail=detail[:1000])


class Engine(pbg.EngineServicer):  # type: ignore[misc]
    """The engine service."""

    def __init__(self, workers: Workers, validation: dict[str, Any], max_runs: int = 2) -> None:
        self.workers = workers
        self.validation = validation
        self._slots = threading.BoundedSemaphore(max_runs)
        self._lock = threading.Lock()
        self.active = 0
        self.stats = {"started": 0, "succeeded": 0, "failed": 0, "cancelled": 0}

    def _count(self, key: str, active: int = 0) -> None:
        with self._lock:
            self.stats[key] += 1
            self.active += active

    def Info(self, request: Any, context: Any) -> Any:  # noqa: N802  (gRPC method name)
        v = self.validation
        return pb.EngineInfo(
            version=fairsim.__version__,
            architecture=cpu.architecture(),
            validation=pb.Validation(
                suite_version=v["suite_version"],
                passed=v["passed"],
                run_at_unix_ms=v["run_at_unix_ms"],
                detail_json=json.dumps(v["detail"], sort_keys=True),
            ),
        )

    def Simulate(self, request: Any, context: Any) -> Iterator[Any]:  # noqa: N802
        try:
            check_simulate(request)
        except RequestError as e:
            yield pb.SimulateEvent(failure=_failure("invalid_bundle", str(e)))
            return
        if not self._slots.acquire(blocking=False):
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "the engine is running as many runs as it allows")
        stop = threading.Event()
        context.add_callback(stop.set)
        events: queue.Queue[tuple[str, Any]] = queue.Queue()
        started = time.monotonic()
        self._count("started", 1)

        def work() -> None:
            try:
                r = run(
                    bytes(request.bundle),
                    request.seed,
                    request.iterations,
                    list(request.control_sets),
                    request.convergence_threshold_bp,
                    workers=self.workers,
                    progress=lambda d, t: events.put(("progress", (d, t))),
                    cancelled=stop.is_set,
                )
                events.put(("result", r))
            except model.Cancelled:
                events.put(("cancelled", None))
            except bundle.BundleError as e:
                events.put(("failure", ("invalid_bundle", str(e))))
            except Exception:
                log.exception("run %s failed", request.run_id)
                events.put(("failure", ("internal", "the engine could not compute the run")))

        thread = threading.Thread(target=work, name=f"run-{request.run_id}", daemon=True)
        thread.start()
        outcome = "cancelled"
        try:
            last = 0.0
            while True:
                try:
                    kind, value = events.get(timeout=PROGRESS_EVERY)
                except queue.Empty:
                    if stop.is_set() or not context.is_active():
                        stop.set()
                        break
                    continue
                if kind == "progress":
                    done, total = value
                    now = time.monotonic()
                    if now - last >= PROGRESS_EVERY or done == total:
                        last = now
                        yield pb.SimulateEvent(progress=pb.Progress(done=done, total=total))
                    continue
                if kind == "result":
                    yield from self._results(value)
                    outcome = "succeeded"
                elif kind == "failure":
                    yield pb.SimulateEvent(failure=_failure(*value))
                    outcome = "failed"
                break
        finally:
            stop.set()
            thread.join(timeout=30)
            self._slots.release()
            self._count(outcome, -1)
            log.info(
                json.dumps(
                    {"event": "simulate", "run_id": request.run_id, "outcome": outcome, "seconds": round(time.monotonic() - started, 3)}
                )
            )

    def _results(self, r: Run) -> Iterator[Any]:
        for s in r.sets:
            yield pb.SimulateEvent(result=pb.ControlSetResult(control_set=s.control_set, summary_json=encode_summary(s.summary)))
            for c in series_chunks(s.control_set, s.ale):
                yield pb.SimulateEvent(series=c)
        yield pb.SimulateEvent(done=pb.Done(warnings=[_warning(w) for w in r.warnings]))

    def Aggregate(self, request_iterator: Iterator[Any], context: Any) -> Iterator[Any]:  # noqa: N802
        try:
            header, members = self._read_members(request_iterator)
            summary, total = aggregate.aggregate(header.seed, members)
        except (RequestError, aggregate.AggregateError) as e:
            yield pb.AggregateEvent(failure=_failure("invalid_bundle", str(e)))
            return
        except Exception:
            log.exception("aggregate failed")
            yield pb.AggregateEvent(failure=_failure("internal", "the engine could not compute the aggregate"))
            return
        n = header.iterations
        yield pb.AggregateEvent(progress=pb.Progress(done=n, total=n))
        yield pb.AggregateEvent(result=pb.AggregateResult(summary_json=encode_summary(summary)))
        for c in series_chunks("", total):
            yield pb.AggregateEvent(series=c)
        yield pb.AggregateEvent(done=pb.Done())

    def _read_members(self, inputs: Iterator[Any]) -> tuple[Any, list[aggregate.Member]]:
        first = next(inputs, None)
        if first is None or first.WhichOneof("input") != "header":
            raise RequestError("the header must come first")
        h = first.header
        n = h.iterations
        if not 1 <= n <= MAX_ITERATIONS:
            raise RequestError(f"iterations must be between 1 and {MAX_ITERATIONS}")
        if not aggregate.MIN_MEMBERS <= len(h.members) <= aggregate.MAX_MEMBERS:
            raise RequestError(f"an aggregate has {aggregate.MIN_MEMBERS} to {aggregate.MAX_MEMBERS} members")
        labels = {m.position: m.scenario_name or m.run_id for m in h.members}
        if len(labels) != len(h.members):
            raise RequestError("two members have the same position")
        data = {p: np.empty(n) for p in labels}
        got = dict.fromkeys(labels, 0)
        for msg in inputs:
            if msg.WhichOneof("input") != "series":
                raise RequestError("only series follow the header")
            c = msg.series
            if c.position not in data:
                raise RequestError(f"no member at position {c.position}")
            if c.offset != got[c.position]:
                raise RequestError(f"member {c.position}: chunk at {c.offset}, expected {got[c.position]}")
            if len(c.values) % 8 or len(c.values) > 1 << 20:
                raise RequestError("a chunk holds at most 1 MiB of float64 values")
            k = len(c.values) // 8
            if got[c.position] + k > n:
                raise RequestError(f"member {c.position} has more than {n} values")
            data[c.position][c.offset : c.offset + k] = np.frombuffer(c.values, dtype="<f8")
            got[c.position] += k
        short = [p for p, k in got.items() if k != n]
        if short:
            raise RequestError(f"members {short} have fewer than {n} values")
        return h, [aggregate.Member(p, data[p], labels[p]) for p in sorted(data)]


def server(engine: Engine, socket_path: str, threads: int = 8) -> grpc.Server:
    """A gRPC server for the engine on a Unix socket (not started)."""
    s = grpc.server(
        ThreadPoolExecutor(max_workers=threads),
        options=[("grpc.max_receive_message_length", MAX_MESSAGE), ("grpc.max_send_message_length", MAX_MESSAGE)],
    )
    pbg.add_EngineServicer_to_server(engine, s)
    p = Path(socket_path)
    if p.is_socket():
        p.unlink()
    old = os.umask(0o007)  # owner and group: the gate shares the pod's group
    try:
        if s.add_insecure_port(f"unix://{socket_path}") == 0:
            raise OSError(f"cannot listen on {socket_path}")
    finally:
        os.umask(old)
    return s


def serve(socket_path: str, workers: int, validation_path: str = VALIDATION_PATH) -> int:
    """Run the engine until SIGTERM or SIGINT."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cpu.check()
    pool = Workers(workers)
    engine = Engine(pool, load_validation(validation_path))
    srv = server(engine, socket_path)
    stopped = threading.Event()

    def stop(*_: object) -> None:
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    srv.start()
    log.info(json.dumps({"event": "serving", "socket": socket_path, "workers": workers, "version": fairsim.__version__}))
    stopped.wait()
    srv.stop(grace=10).wait()
    pool.close()
    return 0
