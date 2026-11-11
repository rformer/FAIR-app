"""A simulated year (F-005 design §3.2; AC-08, AC-09).

For each iteration and control set: the year-level quantities, the control
set's changes from the current set, the frequencies (with Vulnerability
derived where the scenario derives it), the year's loss events, and each
event's primary and secondary losses. Every random number is addressed by
(seed, quantity, iteration, event) (§3.3), so control sets share their
draws (common random numbers), and the results are the same whatever the
chunk size: every per-iteration value is computed from that iteration's
draws alone, and sums run per iteration in event order from zero.

Rules the design leaves to the implementation, documented in the guide:

- A reduction of contact frequency or probability of action multiplies
  the threat event frequency, or the loss event frequency, when the
  scenario enters that instead (the product is the same).
- Event-level draws beyond the first 1,000 events of a year are replaced
  by a normal sum (``large_frequency``): its uniform is the quantity's at
  event index 2³² − 1, which no event uses.
- Loss per event is summarized over at most ``EVENT_SAMPLE`` events per
  control set: the first ``e`` events of every year, ``e`` the largest
  that fits (``loss_per_event_sampled``). Events of a year are identically
  distributed, so the sample is unbiased.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

import numpy as np
from numpy.typing import NDArray
from scipy.special import ndtri, pdtr, pdtrik

from fairsim import bundle as bd
from fairsim import rng
from fairsim.exact import ExactSum

CHUNK: Final = 10_000
EVENTS_EXACT: Final = 1_000
EVENT_SLICE: Final = 1_000_000
EVENT_SAMPLE: Final = 2_000_000
APPROX_EVENT: Final = rng.U32
REMOVAL_CAP: Final = 0.999

F64 = NDArray[np.float64]
I64 = NDArray[np.int64]

Progress = Callable[[int, int], None]


def poisson_ppf(u: F64, lam: F64) -> I64:
    """The Poisson quantile at ``u`` for rates ``lam`` (as ``scipy.stats.poisson.ppf``)."""
    out = np.zeros(u.shape, dtype=np.int64)
    pos = lam > 0
    if pos.any():
        uu, ll = u[pos], lam[pos]
        vals = np.ceil(pdtrik(uu, ll))
        vals1 = np.maximum(vals - 1, 0)
        out[pos] = np.where(pdtr(vals1, ll) >= uu, vals1, vals).astype(np.int64)
    return out


@dataclass
class SetSeries:
    """A control set's per-year results, and its sums for the breakdown."""

    name: str
    ale: F64
    lef: F64
    event_losses: F64
    primary: ExactSum = field(default_factory=ExactSum)
    secondary: ExactSum = field(default_factory=ExactSum)
    forms: dict[str, ExactSum] = field(default_factory=dict)
    stakeholders: dict[str, ExactSum] = field(default_factory=dict)
    large_frequency_years: int = 0
    events_per_year_sampled: int = EVENTS_EXACT
    # Each event-level input's per-year total (after reductions), when recorded.
    form_totals: dict[str, F64] | None = None


@dataclass(frozen=True)
class Simulation:
    sets: tuple[SetSeries, ...]
    warnings: tuple[bd.RunWarning, ...]


@dataclass
class _Year:
    """One control set's year-level values for a chunk."""

    lef: F64
    events: I64
    loss_mult: dict[str, F64]


def _moments(inp: bd.Input) -> tuple[float, float]:
    f = inp.fit
    if f.constant:
        return f.a, 0.0
    w, s = f.b - f.a, f.alpha + f.beta
    return f.a + f.alpha / s * w, f.alpha * f.beta / (s * s * (s + 1)) * w * w


class _Run:
    def __init__(self, m: bd.Model, seed: int, fixed: Mapping[str, float] | None = None) -> None:
        self.m = m
        self.seed = seed
        self.flags: list[bd.RunWarning] = []
        # Inputs held at a quantile (sensitivity, design §3.4): name → probability.
        self.fixed = dict(fixed or {})
        self._q: dict[tuple[str, int], float] = {}

    def u(self, name: str, i: NDArray[np.int64], k: NDArray[np.int64] | int = 0) -> F64:
        return rng.uniforms(self.seed, self.m.ids[name], i, k)

    def held(self, inp: bd.Input) -> float | None:
        """The input's fixed value, if it is held."""
        p = self.fixed.get(inp.name)
        if p is None:
            return None
        key = (inp.name, id(inp.dist))
        if key not in self._q:
            self._q[key] = float(inp.dist.quantile(p))
        return self._q[key]

    def draw(self, inp: bd.Input, i: NDArray[np.int64], k: NDArray[np.int64] | int = 0) -> F64:
        q = self.held(inp)
        if q is not None:
            return np.full(np.broadcast_shapes(np.shape(i), np.shape(k)), q)
        return inp.dist.ppf(self.u(inp.name, i, k))

    def moments(self, inp: bd.Input) -> tuple[float, float]:
        q = self.held(inp)
        return (q, 0.0) if q is not None else _moments(inp)

    def flag(self, code: str, cs: str, detail: str = "", pointer: str = "") -> None:
        self.flags.append(bd.RunWarning(code, pointer, cs, detail))

    def years(self, it: NDArray[np.int64]) -> tuple[list[_Year], dict[str, F64]]:
        m = self.m
        vals = {x.name: self.draw(x, it) for x in m.year_inputs()}
        eff: dict[tuple[str, int], F64] = {(e.input.name, id(e.input.dist)): self.draw(e.input, it) for e in m.effects()}
        u_events = self.u(bd.EVENTS, it)
        ones = np.ones(it.shape)
        out = []
        for cs in m.sets:
            mult: dict[str, F64] = {}
            rs = vals[m.resistance_strength.name] if m.resistance_strength is not None else None
            for e in cs.added:
                r = eff[(e.input.name, id(e.input.dist))]
                if e.factor == bd.RESISTANCE:
                    if rs is not None:
                        rs = np.maximum(rs, r)
                elif e.factor != bd.CAPABILITY or m.derived_vulnerability:
                    mult[e.factor] = mult.get(e.factor, ones) * (1.0 - r)
            for e in cs.removed:
                r = eff[(e.input.name, id(e.input.dist))]
                if e.factor == bd.RESISTANCE or (e.factor == bd.CAPABILITY and not m.derived_vulnerability):
                    continue
                if np.any(r > REMOVAL_CAP):
                    self.flag(
                        "reduction_capped", cs.name, f"{e.factor} of control {e.control}: removal capped at {REMOVAL_CAP}", e.input.pointer
                    )
                mult[e.factor] = mult.get(e.factor, ones) / (1.0 - np.minimum(r, REMOVAL_CAP))
            m_cf, m_poa = mult.get("contact_frequency", ones), mult.get("probability_of_action", ones)
            if m.lef is not None:
                lef = vals[m.lef.name] * m_cf * m_poa
            else:
                if m.contact_frequency is not None and m.probability_of_action is not None:
                    poa = vals[m.probability_of_action.name] * m_poa
                    if np.any(poa > 1.0):
                        self.flag("probability_clipped", cs.name, "probability of action clipped at 1", m.probability_of_action.pointer)
                        poa = np.minimum(poa, 1.0)
                    tef = vals[m.contact_frequency.name] * m_cf * poa
                elif m.tef is not None:
                    tef = vals[m.tef.name] * m_cf * m_poa
                else:
                    raise bd.BundleError("/lef/tef: no threat event frequency")
                if m.threat_capability is not None:
                    if rs is None:
                        raise bd.BundleError("/lef/vulnerability: no resistance strength")
                    with np.errstate(divide="ignore"):
                        x = rs / mult.get(bd.CAPABILITY, ones)
                    tc = self.held(m.threat_capability)
                    v = 1.0 - m.threat_capability.dist.cdf(x) if tc is None else (tc > x).astype(np.float64)
                elif m.vulnerability is not None:
                    v = vals[m.vulnerability.name]
                else:
                    raise bd.BundleError("/lef/vulnerability: no Vulnerability")
                lef = tef * v
            out.append(_Year(lef, poisson_ppf(u_events, lef), {f: mult.get("loss." + f, ones) for f in bd.FORMS}))
        slef = {g.stakeholder: vals[g.slef.name] for g in m.secondary}
        return out, slef


def _chunks(iterations: int, chunk: int) -> list[NDArray[np.int64]]:
    return [np.arange(lo, hi, dtype=np.int64) for lo, hi in _ranges(iterations, chunk)]


def _ranges(iterations: int, chunk: int) -> list[tuple[int, int]]:
    return [(lo, min(lo + chunk, iterations)) for lo in range(0, iterations, chunk)]


def _event_cap(events: Sequence[NDArray[np.int16]]) -> int:
    """The largest per-year event count ``e`` keeping the loss-per-event sample within ``EVENT_SAMPLE``."""
    n = np.concatenate(list(events)).astype(np.int64) if events else np.zeros(0, dtype=np.int64)

    def total(e: int) -> int:
        return int(np.minimum(n, e).sum())

    if total(EVENTS_EXACT) <= EVENT_SAMPLE:
        return EVENTS_EXACT
    lo, hi = 1, EVENTS_EXACT
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if total(mid) <= EVENT_SAMPLE:
            lo = mid
        else:
            hi = mid - 1
    return lo


class Cancelled(Exception):  # noqa: N818  (a state, not an error)
    """The run was cancelled."""


@dataclass(frozen=True)
class Task:
    """One chunk of work: the years ``[lo, hi)``.

    ``kind`` ``events`` counts each set's exactly sampled events per year
    (the first pass); ``losses`` computes the chunk's results.
    """

    kind: str
    lo: int
    hi: int
    seed: int
    fixed: tuple[tuple[str, float], ...] = ()
    caps: tuple[int, ...] = ()
    record: bool = False


@dataclass
class SetChunk:
    """One control set's results for a chunk."""

    ale: F64
    lef: F64
    event_losses: F64
    primary: ExactSum
    secondary: ExactSum
    forms: dict[str, ExactSum]
    stakeholders: dict[str, ExactSum]
    large_frequency_years: int
    form_totals: dict[str, F64] | None


@dataclass
class ChunkResult:
    sets: list[SetChunk]
    flags: list[bd.RunWarning]


TaskResult = list[NDArray[np.int16]] | ChunkResult
# Runs tasks and yields their results in task order, whatever order they ran in.
Runner = Callable[[Sequence[Task]], Iterator[TaskResult]]


def execute(m: bd.Model, t: Task) -> TaskResult:
    """Run one task on the model; the same in this process or a worker."""
    run = _Run(m, t.seed, dict(t.fixed))
    it = np.arange(t.lo, t.hi, dtype=np.int64)
    ys, slef = run.years(it)
    if t.kind == "events":
        return [np.minimum(y.events, EVENTS_EXACT).astype(np.int16) for y in ys]
    out = _chunk(run, it, ys, slef, t.caps, t.record)
    return ChunkResult(out, run.flags)


def local(m: bd.Model) -> Runner:
    """A runner in this process."""

    def runner(tasks: Sequence[Task]) -> Iterator[TaskResult]:
        return (execute(m, t) for t in tasks)

    return runner


def simulate(
    m: bd.Model,
    seed: int,
    iterations: int,
    *,
    chunk: int = CHUNK,
    progress: Progress | None = None,
    fixed: Mapping[str, float] | None = None,
    events: bool = True,
    record: bool = False,
    runner: Runner | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> Simulation:
    """Simulate ``iterations`` years of every control set of the model.

    ``fixed`` holds inputs at a quantile (by name); ``events=False`` skips
    the loss-per-event sample; ``record`` keeps each event-level input's
    per-year totals. ``runner`` runs the chunks (in this process by
    default); results are merged in chunk order and exact sums are
    order-free, so the result does not depend on the runner. ``cancelled``
    is checked after every chunk; when it returns true the run stops with
    ``Cancelled``.
    """
    if iterations < 1 or iterations > rng.U32:
        raise ValueError("iterations must be between 1 and 2³² − 1")
    run_tasks = runner or local(m)
    ranges = _ranges(iterations, chunk)
    fx = tuple(sorted((fixed or {}).items()))
    total = iterations * len(m.sets)

    def check() -> None:
        if cancelled is not None and cancelled():
            raise Cancelled

    caps = tuple(0 for _ in m.sets)
    if events:
        # Pass 1: the year's events, to size the loss-per-event sample.
        per_set: list[list[NDArray[np.int16]]] = [[] for _ in m.sets]
        results = run_tasks([Task("events", lo, hi, seed, fx) for lo, hi in ranges])
        try:
            for r in results:
                check()
                if not isinstance(r, list):
                    raise TypeError("an events task returned losses")
                for j, e in enumerate(r):
                    per_set[j].append(e)
        finally:
            _close(results)
        caps = tuple(_event_cap(e) for e in per_set)
        del per_set

    series = [
        SetSeries(
            cs.name,
            np.empty(iterations),
            np.empty(iterations),
            np.empty(0),
            forms={f: ExactSum() for f in m.primary},
            stakeholders={g.stakeholder: ExactSum() for g in m.secondary},
            events_per_year_sampled=caps[j],
            form_totals={x.name: np.empty(iterations) for x in m.event_inputs()} if record else None,
        )
        for j, cs in enumerate(m.sets)
    ]
    event_losses: list[list[F64]] = [[] for _ in m.sets]
    flags: list[bd.RunWarning] = []
    done = 0
    results = run_tasks([Task("losses", lo, hi, seed, fx, caps, record) for lo, hi in ranges])
    try:
        for (lo, hi), r in zip(ranges, results, strict=True):
            check()
            if not isinstance(r, ChunkResult):
                raise TypeError("a losses task returned events")
            flags += r.flags
            for j, c in enumerate(r.sets):
                s = series[j]
                s.ale[lo:hi] = c.ale
                s.lef[lo:hi] = c.lef
                event_losses[j].append(c.event_losses)
                s.primary.merge(c.primary)
                s.secondary.merge(c.secondary)
                for f, fs in c.forms.items():
                    s.forms[f].merge(fs)
                for g, gs in c.stakeholders.items():
                    s.stakeholders[g].merge(gs)
                s.large_frequency_years += c.large_frequency_years
                if s.form_totals is not None and c.form_totals is not None:
                    for name, v in c.form_totals.items():
                        s.form_totals[name][lo:hi] = v
            done += (hi - lo) * len(m.sets)
            if progress is not None:
                progress(done, total)
    finally:
        _close(results)
    for j, s in enumerate(series):
        s.event_losses = np.concatenate(event_losses[j]) if event_losses[j] else np.zeros(0)
        if s.large_frequency_years:
            flags.append(
                bd.RunWarning("large_frequency", "", s.name, f"{s.large_frequency_years} years with more than {EVENTS_EXACT} loss events")
            )
        if events and s.events_per_year_sampled < EVENTS_EXACT:
            flags.append(bd.RunWarning("loss_per_event_sampled", "", s.name, f"the first {s.events_per_year_sampled} events of each year"))
    warnings = tuple(dict.fromkeys((*m.warnings, *flags)))
    return Simulation(tuple(series), warnings)


def _close(results: Iterator[TaskResult]) -> None:
    close = getattr(results, "close", None)
    if close is not None:
        close()


def _chunk(
    run: _Run,
    it: NDArray[np.int64],
    ys: list[_Year],
    slef: Mapping[str, F64],
    caps: Sequence[int],
    record: bool,
) -> list[SetChunk]:
    m, n = run.m, it.size
    exact = [np.minimum(y.events, EVENTS_EXACT) for y in ys]
    kmax = np.max(np.stack(exact), axis=0)
    ends = np.cumsum(kmax)
    starts = ends - kmax
    prim = [{f: np.zeros(n) for f in m.primary} for _ in ys]
    sec = [{(g.stakeholder, f): np.zeros(n) for g in m.secondary for f in g.forms} for _ in ys]
    event_losses: list[list[F64]] = [[] for _ in ys]
    # Event slices hold whole iterations, so each iteration's sums run in event order from zero.
    a = 0
    while a < n:
        b = max(int(np.searchsorted(ends, starts[a] + EVENT_SLICE, side="right")), a + 1)
        cnt = kmax[a:b]
        if int(cnt.sum()) > 0:
            loc = np.repeat(np.arange(a, b, dtype=np.int64), cnt)
            k = np.arange(loc.size, dtype=np.int64) - np.repeat(starts[a:b] - starts[a], cnt)
            gi = it[loc]
            x = {f: run.draw(inp, gi, k) for f, inp in m.primary.items()}
            occ = {g.stakeholder: run.u(g.occurrence, gi, k) < slef[g.stakeholder][loc] for g in m.secondary}
            y = {(g.stakeholder, f): run.draw(inp, gi, k) for g in m.secondary for f, inp in g.forms.items()}
            for j, yr in enumerate(ys):
                live = k < exact[j][loc]
                lj = loc[live]
                for f in m.primary:
                    prim[j][f] += np.bincount(lj, weights=x[f][live], minlength=n)
                for g in m.secondary:
                    o = live & occ[g.stakeholder]
                    for f in g.forms:
                        sec[j][(g.stakeholder, f)] += np.bincount(loc[o], weights=y[(g.stakeholder, f)][o], minlength=n)
                if not caps[j]:
                    continue
                sampled = live & (k < caps[j])
                ls = loc[sampled]
                ev = np.zeros(ls.size)
                for f in m.primary:
                    ev = ev + x[f][sampled] * yr.loss_mult[f][ls]
                for g in m.secondary:
                    gs = np.zeros(ls.size)
                    for f in g.forms:
                        gs = gs + y[(g.stakeholder, f)][sampled] * yr.loss_mult[f][ls]
                    ev = ev + np.where(occ[g.stakeholder][sampled], gs, 0.0)
                event_losses[j].append(ev)
        a = b

    out = []
    for j, yr in enumerate(ys):
        c = SetChunk(
            np.empty(0),
            yr.lef,
            np.concatenate(event_losses[j]) if event_losses[j] else np.zeros(0),
            ExactSum(),
            ExactSum(),
            {f: ExactSum() for f in m.primary},
            {g.stakeholder: ExactSum() for g in m.secondary},
            0,
            {} if record else None,
        )
        extra = np.maximum(yr.events - EVENTS_EXACT, 0).astype(np.float64)
        big = extra > 0
        c.large_frequency_years = int(big.sum())
        primary = np.zeros(n)
        for f, inp in m.primary.items():
            v = prim[j][f]
            if big.any():
                mu, var = run.moments(inp)
                z = ndtri(run.u(inp.name, it, APPROX_EVENT))
                v = v + np.where(big, np.maximum(0.0, extra * mu + np.sqrt(extra * var) * z), 0.0)
            v = v * yr.loss_mult[f]
            if c.form_totals is not None:
                c.form_totals[inp.name] = v
            c.forms[f].add(v)
            primary = primary + v
        secondary = np.zeros(n)
        for g in m.secondary:
            gv = np.zeros(n)
            for f, inp in g.forms.items():
                fv = sec[j][(g.stakeholder, f)] * yr.loss_mult[f]
                if c.form_totals is not None:
                    c.form_totals[inp.name] = fv
                gv = gv + fv
            if big.any():
                p = slef[g.stakeholder]
                mean_x = np.zeros(n)
                var_x = np.zeros(n)
                for f, inp in g.forms.items():
                    mu, var = run.moments(inp)
                    mean_x = mean_x + yr.loss_mult[f] * mu
                    var_x = var_x + yr.loss_mult[f] ** 2 * var
                mu_y = p * mean_x
                var_y = np.maximum(p * (var_x + mean_x**2) - mu_y**2, 0.0)
                z = ndtri(run.u(g.occurrence, it, APPROX_EVENT))
                gv = gv + np.where(big, np.maximum(0.0, extra * mu_y + np.sqrt(extra * var_y) * z), 0.0)
            c.stakeholders[g.stakeholder].add(gv)
            secondary = secondary + gv
        c.primary.add(primary)
        c.secondary.add(secondary)
        c.ale = primary + secondary
        out.append(c)
    return out
