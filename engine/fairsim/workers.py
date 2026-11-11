"""Worker processes for a run's chunks (F-005 design §3.3; AC-17).

``Workers(n)`` keeps ``n`` processes (started with ``spawn``: no state is
inherited from the server, whose gRPC threads must not be forked). A
run's chunks are sent as ``model.Task`` values with the bundle they belong
to; each worker reads the bundle into a model once and keeps the last few
(the fitted quantile tables are the costly part). Results come back in
task order, and the model merges them with exact sums, so a run's results
are identical with any number of workers and in any completion order.

At most ``2n`` tasks are in flight; closing the result iterator (a
cancelled run) cancels the tasks not yet started.
"""

from __future__ import annotations

import multiprocessing
from collections import OrderedDict, deque
from collections.abc import Iterator, Sequence
from concurrent.futures import Future, ProcessPoolExecutor
from dataclasses import dataclass

from fairsim import bundle as bd
from fairsim import model

CACHED_MODELS = 2


@dataclass(frozen=True)
class Source:
    """What a worker needs to rebuild a run's model: the bundle and its control sets."""

    raw: bytes
    control_sets: tuple[str, ...]


_models: OrderedDict[Source, bd.Model] = OrderedDict()


def _model(src: Source) -> bd.Model:
    m = _models.get(src)
    if m is None:
        m = bd.read(src.raw, src.control_sets)
        _models[src] = m
        while len(_models) > CACHED_MODELS:
            _models.popitem(last=False)
    else:
        _models.move_to_end(src)
    return m


def _work(src: Source, task: model.Task) -> model.TaskResult:
    return model.execute(_model(src), task)


class Workers:
    """A pool of ``n`` worker processes; ``n == 1`` runs in this process."""

    def __init__(self, n: int) -> None:
        if n < 1:
            raise ValueError("at least one worker")
        self.n = n
        self._pool = ProcessPoolExecutor(max_workers=n, mp_context=multiprocessing.get_context("spawn")) if n > 1 else None

    def runner(self, m: bd.Model, src: Source) -> model.Runner:
        pool = self._pool
        if pool is None:
            return model.local(m)
        window = 2 * self.n

        def run(tasks: Sequence[model.Task]) -> Iterator[model.TaskResult]:
            pending: deque[Future[model.TaskResult]] = deque()
            todo = iter(tasks)
            try:
                for t in todo:
                    pending.append(pool.submit(_work, src, t))
                    if len(pending) >= window:
                        break
                while pending:
                    r = pending.popleft().result()
                    nxt = next(todo, None)
                    if nxt is not None:
                        pending.append(pool.submit(_work, src, nxt))
                    yield r
            finally:
                for f in pending:
                    f.cancel()

        return run

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=True, cancel_futures=True)

    def __enter__(self) -> Workers:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
