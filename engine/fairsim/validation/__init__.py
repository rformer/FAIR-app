"""The statistical validation suite and the startup self-check (F-005 design §3.6; AC-20, AC-21).

``suite()`` runs every check with fixed seeds and stated tolerances and
returns the validation record the image carries at
``/engine/validation.json``:

``philox_vectors``
    Random123's known-answer vectors for Philox4x32-10.
``pert_fit``
    A grid of estimates over every unit: each non-fallback fit holds its
    stated confidence, each fallback is what §3.1 says, and every fallback
    occurs.
``sampler_moments``
    Draws by the engine's own sampler against the exact Beta-PERT: means,
    standard deviations and the 5th, 50th and 95th percentiles.
``quantile_table``
    The table's error against ``scipy.special.betaincinv``.
``known_constant``, ``known_poisson``, ``known_reduction``, ``known_vulnerability``
    Known answers of the model (§3.6).
``convergence_coverage``
    The distribution-free percentile intervals cover the true percentile.
``aggregation``
    Independent members add means (exactly) and variances.
``cross_feature``
    The F-003 corpus scenario as ``risk.BuildBundle`` makes it
    (``f003_corpus_bundle.json``, kept equal by a Go test) runs, and its
    results digest is the one recorded for this engine version and
    architecture in ``reference.json``: changing results without a new
    engine version fails here (§3.6).

``self_check()`` is the startup check (seconds): the vectors, a few fits,
a spot check of the table, and a small run of the corpus bundle whose
digest must equal the one the image's record holds.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Final

import numpy as np
from scipy import integrate
from scipy.special import betainc

import fairsim
from fairsim import aggregate, cpu, exact, pert, results, rng
from fairsim.run import run

SUITE_VERSION: Final = "1"
SEED: Final = 20261110

# The self-check's run: small, so it takes a second or two.
SELF_CHECK_ITERATIONS: Final = 2_000
CROSS_FEATURE_ITERATIONS: Final = 50_000
CORPUS_SETS: Final = ("Current", "With EDR")


@dataclass
class Check:
    name: str
    passed: bool = True
    detail: dict[str, Any] = field(default_factory=dict)

    def require(self, ok: bool, what: str, value: Any, tolerance: Any = None) -> None:
        """Record a measured value; a failure keeps the first few failing items."""
        self.detail.setdefault("measured", 0)
        self.detail["measured"] += 1
        if not ok:
            self.passed = False
            fails = self.detail.setdefault("failures", [])
            if len(fails) < 10:
                fails.append({"what": what, "value": _plain(value), "tolerance": _plain(tolerance)})


def _plain(v: Any) -> Any:
    if isinstance(v, float) and not math.isfinite(v):
        return str(v)
    if isinstance(v, np.floating | np.integer):
        return _plain(v.item())
    return v


def corpus_bundle() -> bytes:
    return resources.files(__package__).joinpath("f003_corpus_bundle.json").read_bytes()


def references() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = json.loads(resources.files(__package__).joinpath("reference.json").read_text(encoding="utf-8"))
    return out


def corpus_digest(iterations: int) -> str:
    return run(corpus_bundle(), SEED, iterations, list(CORPUS_SETS), 100).digest()


PHILOX_KAT: Final = (
    ((0, 0, 0, 0), (0, 0), (0x6627E8D5, 0xE169C58D, 0xBC57AC4C, 0x9B00DBD8)),
    ((0xFFFFFFFF,) * 4, (0xFFFFFFFF, 0xFFFFFFFF), (0x408F276D, 0x41C83B0E, 0xA20BC7C6, 0x6D5451FD)),
    ((0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344), (0xA4093822, 0x299F31D0), (0xD16CFE09, 0x94FDCCEB, 0x5001E420, 0x24126EA1)),
)


def check_philox() -> Check:
    c = Check("philox_vectors")
    for counter, key, want in PHILOX_KAT:
        got = tuple(int(w) for w in rng.philox4x32(counter, key))
        c.require(got == want, f"counter {counter} key {key}", [hex(x) for x in got], [hex(x) for x in want])
    return c


UNIT_RANGES: Final = (
    ("currency", 1_000.0, 50_000.0),
    ("currency", 2.5e8, 4e9),
    ("events_per_year", 0.1, 4.0),
    ("events_per_year", 0.0, 4.0),
    ("probability", 0.05, 0.6),
    ("probability", 0.3, 1.0),
    ("probability", 0.0, 1.0),
    ("fraction", 0.1, 0.5),
    ("percentile", 20.0, 80.0),
    ("percentile", 1.0, 99.0),
)
MODES: Final = (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0)
CONFIDENCES: Final = (0.5, 0.8, 0.9, 0.95, 0.99)
FIT_TOLERANCE: Final = 1e-9


def _missed(f: pert.Fit) -> float:
    w = f.b - f.a
    fl = float(betainc(f.alpha, f.beta, (f.lo - f.a) / w))
    fh = float(betainc(f.alpha, f.beta, (f.hi - f.a) / w))
    if f.fallback is None:
        return max(abs(fl - (1 - f.confidence) / 2), abs(fh - (1 + f.confidence) / 2))
    return abs(fh - fl - f.confidence)


def check_pert_fit(grid: tuple[tuple[str, float, float], ...] = UNIT_RANGES, *, every_fallback: bool = True) -> Check:
    c = Check("pert_fit", detail={"tolerance": FIT_TOLERANCE})
    seen: set[str | None] = set()
    for (unit, lo, hi), mf, conf in ((r, m, k) for r in grid for m in MODES for k in CONFIDENCES):
        ml = lo + mf * (hi - lo)
        f = pert.fit(lo, ml, hi, conf, unit)
        seen.add(f.fallback)
        what = f"{unit} {lo} {ml} {hi} at {conf}"
        d0, d1 = pert.DOMAINS[unit]
        c.require(d0 <= f.a <= lo and hi <= f.b <= d1, what + ": bounds within the domain", [f.a, f.b])
        if f.fallback == pert.BOUNDS:
            c.require((f.a, f.b) == (lo, hi), what + ": bounds fallback on the estimate's bounds", [f.a, f.b])
        else:
            c.require(_missed(f) <= FIT_TOLERANCE, what + ": confidence held", _missed(f), FIT_TOLERANCE)
        if f.fallback == pert.DOMAIN_LOW:
            c.require(f.a == d0, what + ": domain_low at the edge", f.a)
        if f.fallback == pert.DOMAIN_HIGH:
            c.require(f.b == d1, what + ": domain_high at the edge", f.b)
    f = pert.fit(5, 5, 5, 0.9, "currency")
    seen.add(f.fallback)
    c.require(f.fallback == pert.POINT and bool(np.all(pert.Distribution.of(f).ppf([0.01, 0.99]) == 5.0)), "point is constant", f.fallback)
    for code in (None, *pert.FALLBACKS) if every_fallback else ():
        c.require(code in seen, f"the grid exercises {code or 'the fit'}", sorted(str(x) for x in seen))
    return c


SAMPLED: Final = (
    ("1000", "5000", "50000", "0.9", "currency"),
    ("0.1", "0.5", "4", "0.9", "events_per_year"),
    ("20", "60", "90", "0.8", "percentile"),
    ("0.7", "0.9", "1", "0.8", "probability"),
    ("0", "1", "4", "0.9", "events_per_year"),
    ("0", "0.3", "1", "0.9", "probability"),
)
SAMPLES: Final = 200_000
Z: Final = 5.0  # standard errors allowed for sampling checks


def check_sampler() -> Check:
    c = Check("sampler_moments", detail={"draws": SAMPLES, "z": Z})
    for j, e in enumerate(SAMPLED):
        f = pert.fit(*e)
        d = pert.Distribution.of(f)
        x = d.ppf(rng.uniforms(SEED, j, np.arange(SAMPLES)))
        s, w = f.alpha + f.beta, f.b - f.a
        mean = f.a + f.alpha / s * w
        sd = math.sqrt(f.alpha * f.beta / (s * s * (s + 1))) * w
        m = exact.mean(x)
        c.require(abs(m - mean) <= Z * sd / math.sqrt(SAMPLES), f"{e}: mean", m, mean)
        got_sd = float(np.std(x, ddof=1))
        c.require(abs(got_sd - sd) <= 0.01 * sd, f"{e}: standard deviation", got_sd, sd)
        for q in (0.05, 0.5, 0.95):
            xq = float(np.percentile(x, q * 100, method="inverted_cdf"))
            fq = float(d.cdf(xq)[()])
            c.require(abs(fq - q) <= Z * math.sqrt(q * (1 - q) / SAMPLES), f"{e}: F(x_{q})", fq, q)
    return c


def check_table() -> Check:
    c = Check("quantile_table", detail={"tolerance": pert.TABLE_TOLERANCE})
    n = pert.TABLE_SIZE * 3
    u = np.concatenate([(np.arange(n) + 0.5) / n, [2.0**-53, 1e-12, 1e-9, 1e-6, 1 - 1e-6, 1 - 1e-9, 1 - 2.0**-53]])
    for e in SAMPLED:
        d = pert.Distribution.of(pert.fit(*e))
        f = d.fit
        if f.constant:
            continue
        err = float(np.max(np.abs(d.ppf(u) - d.quantile(u)))) / (f.b - f.a)
        c.require(err <= pert.TABLE_TOLERANCE, f"{e}: table error", err, pert.TABLE_TOLERANCE)
    return c


def _scenario(lef: dict[str, Any], primary: dict[str, Any], sets: list[Any] | None = None) -> dict[str, Any]:
    return {
        "kind": "scenario",
        "lef": lef,
        "primary_loss": primary,
        "control_sets": sets or [{"name": "Current", "current": True, "controls": []}],
    }


def _est(lo: str, ml: str, hi: str, unit: str) -> dict[str, Any]:
    return {"min": lo, "ml": ml, "max": hi, "unit": unit, "confidence": "0.9"}


def _bundle(doc: dict[str, Any], pins: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"format": "fair.scenario-input.v1", "currency": "USD", "scenario": {"document": doc}, "pins": pins or []}


def check_known() -> list[Check]:
    out = []
    c = Check("known_constant")
    r = run(
        _bundle(
            _scenario(
                {"level": "lef", "estimate": _est("2", "2", "2", "events_per_year")},
                {"productivity": _est("1000", "1000", "1000", "currency")},
            )
        ),
        SEED,
        20_000,
        ["Current"],
        100,
    )
    s = r.sets[0].summary
    c.require(s["lef"]["min"] == s["lef"]["max"] == 2.0, "constant LEF", [s["lef"]["min"], s["lef"]["max"]])
    c.require(
        s["loss_per_event"]["min"] == s["loss_per_event"]["max"] == 1000.0,
        "constant loss per event",
        [s["loss_per_event"]["min"], s["loss_per_event"]["max"]],
    )
    ale = r.sets[0].ale
    c.require(bool(np.array_equal(ale, np.round(ale / 1000.0) * 1000.0)), "annual loss is events × magnitude", None)
    out.append(c)

    c = Check("known_poisson")
    lam, m, n = 3.0, 500.0, 200_000
    ale = (
        run(
            _bundle(
                _scenario(
                    {"level": "lef", "estimate": _est("3", "3", "3", "events_per_year")},
                    {"response": _est("500", "500", "500", "currency")},
                )
            ),
            SEED,
            n,
            ["Current"],
            100,
        )
        .sets[0]
        .ale
    )
    se = math.sqrt(lam) * m / math.sqrt(n)
    c.require(abs(exact.mean(ale) - lam * m) <= Z * se, "mean λm", exact.mean(ale), lam * m)
    v = float(np.var(ale, ddof=1))
    c.require(abs(v / (lam * m * m) - 1) <= 0.02, "variance λm²", v, lam * m * m)
    out.append(c)

    c = Check("known_reduction")
    ctrl = "33333333-3333-4333-8333-333333333333"
    doc = _scenario(
        {"level": "lef", "estimate": _est("1", "2", "5", "events_per_year")},
        {"productivity": _est("1000", "5000", "20000", "currency")},
        [{"name": "Current", "current": True, "controls": []}, {"name": "Alt", "current": False, "controls": [{"id": ctrl, "version": 1}]}],
    )
    control = {"kind": "control", "effects": [{"factor": "loss.productivity", "estimate": _est("0.25", "0.25", "0.25", "fraction")}]}
    r = run(
        _bundle(doc, [{"pointer": "/control_sets/1/controls/0", "kind": "control", "document": control}]),
        SEED,
        20_000,
        ["Current", "Alt"],
        100,
    )
    ratio = r.sets[1].summary["ale"]["mean"] / r.sets[0].summary["ale"]["mean"]
    c.require(abs(ratio - 0.75) <= 1e-12, "a reduction r scales the mean by 1 − r", ratio, 0.75)
    c.require(bool(np.allclose(r.sets[1].ale, 0.75 * r.sets[0].ale, rtol=1e-12, atol=0)), "and every year", None)
    out.append(c)

    c = Check("known_vulnerability")
    n = 200_000
    doc = _scenario(
        {
            "level": "tef_vuln",
            "tef": {"level": "tef", "estimate": _est("10", "10", "10", "events_per_year")},
            "vulnerability": {
                "level": "derived",
                "threat_capability": {"source": "scenario", "estimate": _est("40", "60", "85", "percentile")},
                "resistance_strength": _est("50", "65", "80", "percentile"),
            },
        },
        {"productivity": _est("1", "1", "1", "currency")},
    )
    s = run(_bundle(doc), SEED, n, ["Current"], 100).sets[0].summary
    tc = pert.Distribution.of(pert.fit("40", "60", "85", "0.9", "percentile"))
    rs = pert.fit("50", "65", "80", "0.9", "percentile")
    lb = math.lgamma(rs.alpha) + math.lgamma(rs.beta) - math.lgamma(rs.alpha + rs.beta)

    def integrand(x: float) -> float:
        z = (x - rs.a) / (rs.b - rs.a)
        dens = math.exp((rs.alpha - 1) * math.log(z) + (rs.beta - 1) * math.log1p(-z) - lb) / (rs.b - rs.a) if 0 < z < 1 else 0.0
        return float((1.0 - tc.cdf(x)[()]) * dens)

    want, _ = integrate.quad(integrand, rs.a, rs.b, limit=200)
    got = s["lef"]["mean"] / 10.0
    tol = Z * s["lef"]["sd"] / 10.0 / math.sqrt(n)
    c.require(abs(got - want) <= tol, "derived Vulnerability against numerical integration", got, want)
    out.append(c)
    return out


def check_coverage(trials: int = 300, n: int = 2_000) -> Check:
    c = Check("convergence_coverage", detail={"trials": trials, "n": n, "nominal": results.INTERVAL_LEVEL, "minimum": 0.92})
    d = pert.Distribution.of(pert.fit("1000", "5000", "50000", "0.9", "currency"))
    hits = dict.fromkeys(results.INTERVALS, 0)
    for t in range(trials):
        x = d.ppf(rng.uniforms(SEED, 1_000 + t, np.arange(n)))
        iv = results.convergence(x, 100)["intervals"]
        for p in results.INTERVALS:
            lo, hi = iv[f"p{p}"]
            hits[p] += int(lo <= float(d.quantile(p / 100)[()]) <= hi)
    for p, h in hits.items():
        c.require(h / trials >= 0.92, f"coverage of p{p}", h / trials, 0.92)
    return c


def check_aggregation() -> Check:
    c = Check("aggregation")
    n = 100_000

    def series(lef: str, seed: int) -> Any:
        doc = _scenario(
            {"level": "lef", "estimate": _est(lef, lef, lef, "events_per_year")}, {"productivity": _est("100", "200", "400", "currency")}
        )
        return run(_bundle(doc), seed, n, ["Current"], 100).sets[0].ale

    a, b = series("2", 1), series("5", 2)
    summary, total = aggregate.aggregate(SEED, [aggregate.Member(0, a), aggregate.Member(1, b)])
    c.require(
        abs(summary["ale"]["mean"] - (exact.mean(a) + exact.mean(b))) <= 1e-12 * summary["ale"]["mean"], "means add", summary["ale"]["mean"]
    )
    v, va, vb = (float(np.var(x)) for x in (total, a, b))
    c.require(abs(v / (va + vb) - 1) <= 0.03, "variances add", v, va + vb)
    same = series("2", 1)
    _, t2 = aggregate.aggregate(SEED, [aggregate.Member(0, a), aggregate.Member(1, same)])
    v2 = float(np.var(t2))
    c.require(abs(v2 / (2 * va) - 1) <= 0.03, "a shared seed does not correlate members", v2, 2 * va)
    return c


def check_cross_feature() -> Check:
    c = Check("cross_feature", detail={"iterations": CROSS_FEATURE_ITERATIONS, "seed": SEED})
    got = corpus_digest(CROSS_FEATURE_ITERATIONS)
    want = references().get(fairsim.__version__, {}).get(cpu.architecture())
    c.detail["digest"] = got
    c.require(want is not None, f"a reference digest is recorded for {fairsim.__version__} on {cpu.architecture()}", None)
    if want is not None:
        c.require(got == want, "the corpus bundle's results equal the recorded reference", got, want)
    return c


CHECKS: Final[tuple[Callable[[], Check | list[Check]], ...]] = (
    check_philox,
    check_pert_fit,
    check_sampler,
    check_table,
    check_known,
    check_coverage,
    check_aggregation,
    check_cross_feature,
)


def suite() -> dict[str, Any]:
    """Run the suite; the validation record."""
    started = time.time()
    checks: list[Check] = []
    for fn in CHECKS:
        try:
            got = fn()
        except Exception as e:  # a check that cannot run fails
            got = Check(fn.__name__.removeprefix("check_"), passed=False, detail={"error": f"{type(e).__name__}: {e}"})
        checks.extend(got if isinstance(got, list) else [got])
    return {
        "suite_version": SUITE_VERSION,
        "engine_version": fairsim.__version__,
        "architecture": cpu.architecture(),
        "passed": all(c.passed for c in checks),
        "run_at_unix_ms": int(started * 1000),
        "seconds": round(time.time() - started, 1),
        "self_check_digest": corpus_digest(SELF_CHECK_ITERATIONS),
        "detail": {c.name: {"passed": c.passed, **c.detail} for c in checks},
    }


def self_check(record: dict[str, Any] | None) -> list[str]:
    """The startup check; the problems found (none means pass).

    With a record, it must be this engine's (version and architecture) and
    the small corpus run must give the digest the record holds.
    """
    problems = []
    for c in (check_philox(), check_pert_fit(UNIT_RANGES[:3], every_fallback=False), _table_spot()):
        if not c.passed:
            problems.append(f"{c.name}: {c.detail.get('failures', c.detail)}")
    if record is not None and record.get("self_check_digest") is not None:
        if record.get("engine_version") != fairsim.__version__ or record.get("architecture") != cpu.architecture():
            problems.append("the validation record is for another engine version or architecture")
        elif corpus_digest(SELF_CHECK_ITERATIONS) != record["self_check_digest"]:
            problems.append("the corpus run differs from the one validated at image build")
    return problems


def _table_spot() -> Check:
    c = Check("quantile_table")
    u = np.array([2.0**-53, 1e-6, 0.01, 0.37, 0.5, 0.93, 1 - 1e-6, 1 - 2.0**-53])
    d = pert.Distribution.of(pert.fit(*SAMPLED[0]))
    err = float(np.max(np.abs(d.ppf(u) - d.quantile(u)))) / (d.fit.b - d.fit.a)
    c.require(err <= pert.TABLE_TOLERANCE, "table spot check", err, pert.TABLE_TOLERANCE)
    return c
