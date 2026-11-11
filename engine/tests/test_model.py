"""F-005 T-06 (AC-08, AC-09, AC-11 to AC-13; design §3.2, §3.4): the model and its results."""

from __future__ import annotations

import math
from typing import Any

import numpy as np
import pytest
import scenarios as sc
from scipy import integrate

import fairsim  # noqa: F401  (pins NumPy's dispatch first)
from fairsim import bundle, exact, model, pert, results
from fairsim.run import Run, run

LEF = "events_per_year"
CUR = "currency"


def lef_direct(e: dict[str, Any]) -> dict[str, Any]:
    return {"level": "lef", "estimate": e}


def simple(lef: dict[str, Any], primary: dict[str, Any], **kw: Any) -> dict[str, Any]:
    return sc.bundle(sc.scenario(lef, primary, **kw))


def go(b: dict[str, Any], n: int = 20_000, sets: tuple[str, ...] = ("Current",), seed: int = 7, **kw: Any) -> Run:
    return run(b, seed, n, list(sets), 100, **kw)


def codes(r: Run) -> set[str]:
    return {w.code for w in r.warnings}


def test_constant_inputs() -> None:
    lam, m = 2.0, 1000.0
    r = go(simple(lef_direct(sc.point("2", LEF)), {"productivity": sc.point("1000", CUR)}))
    s = r.sets[0].summary
    assert s["lef"]["min"] == s["lef"]["max"] == lam
    assert s["loss_per_event"]["min"] == s["loss_per_event"]["max"] == m
    ale = r.sets[0].ale
    assert np.array_equal(ale, np.round(ale / m) * m)
    assert "point" in codes(r)


def test_poisson_mean_and_variance() -> None:
    lam, m, n = 3.0, 500.0, 200_000
    ale = go(simple(lef_direct(sc.point("3", LEF)), {"response": sc.point("500", CUR)}), n=n).sets[0].ale
    se = math.sqrt(lam) * m / math.sqrt(n)
    assert abs(ale.mean() - lam * m) < 4 * se
    assert ale.var(ddof=1) == pytest.approx(lam * m * m, rel=0.02)


def test_zero_frequency() -> None:
    r = go(simple(lef_direct(sc.point("0", LEF)), {"productivity": sc.est("1", "2", "3", CUR)}))
    s = r.sets[0].summary
    assert s["ale"]["max"] == 0.0
    assert s["ale"]["p_positive"] == 0.0
    assert s["curve"]["points"] == []
    assert s["loss_per_event"]["n"] == 0
    assert s["loss_per_event"]["mean"] is None
    assert s["convergence"]["rse"] is None
    assert s["convergence"]["converged"]


def _with_control(doc: dict[str, Any], effect: tuple[str, dict[str, Any]], *, in_current: bool = False) -> dict[str, Any]:
    use = {"id": sc.CTRL, "version": 1, "status": "proposed"}
    doc["control_sets"] = [
        {"name": "Current", "current": True, "controls": [use] if in_current else []},
        {"name": "Alt", "current": False, "controls": [] if in_current else [use]},
    ]
    return sc.bundle(doc, {sc.CTRL: sc.control(effect)})


def test_a_loss_reduction_scales_every_year() -> None:
    doc = sc.scenario(lef_direct(sc.est("1", "2", "5", LEF)), {"productivity": sc.est("1000", "5000", "20000", CUR)})
    r = go(_with_control(doc, ("loss.productivity", sc.point("0.25", "fraction"))), sets=("Current", "Alt"))
    cur, alt = r.sets[0].ale, r.sets[1].ale
    assert np.allclose(alt, cur * 0.75, rtol=1e-12, atol=0)
    assert r.sets[1].summary["ale"]["mean"] == pytest.approx(0.75 * r.sets[0].summary["ale"]["mean"], rel=1e-12)
    cmp = r.sets[1].summary["comparison"]
    assert cmp["against"] == "Current"
    assert cmp["mean"] == pytest.approx(-0.25 * r.sets[0].summary["ale"]["mean"], rel=1e-9)
    assert cmp["difference"]["max"] <= 0


def test_a_frequency_reduction_scales_the_mean() -> None:
    doc = sc.scenario(lef_direct(sc.point("4", LEF)), {"productivity": sc.point("1000", CUR)})
    r = go(_with_control(doc, ("contact_frequency", sc.point("0.5", "fraction"))), n=200_000, sets=("Current", "Alt"))
    assert r.sets[1].summary["lef"]["mean"] == pytest.approx(2.0, rel=1e-12)
    assert r.sets[1].summary["ale"]["mean"] == pytest.approx(2000.0, rel=0.01)
    # Common random numbers: fewer events in every year, never more.
    assert np.all(r.sets[1].ale <= r.sets[0].ale)


def test_removing_a_control_divides() -> None:
    doc = sc.scenario(lef_direct(sc.point("1", LEF)), {"productivity": sc.est("100", "200", "400", CUR)})
    r = go(_with_control(doc, ("loss.productivity", sc.point("0.5", "fraction")), in_current=True), sets=("Current", "Alt"))
    assert np.allclose(r.sets[1].ale, r.sets[0].ale * 2.0, rtol=1e-12, atol=0)


def test_identical_set_has_zero_difference() -> None:
    b = sc.corpus()
    b["scenario"]["document"]["control_sets"].append(
        {"name": "Same", "current": False, "controls": [{"id": sc.CTRL, "version": 1, "status": "in_place"}]}
    )
    b["pins"].append(
        {
            "pointer": "/control_sets/2/controls/0",
            "kind": "control",
            "id": sc.CTRL,
            "version": 1,
            "digest": "0" * 64,
            "document": b["pins"][0]["document"],
        }
    )
    r = go(b, sets=("Current", "With EDR", "Same"))
    assert np.array_equal(r.sets[2].ale, r.sets[0].ale)
    d = r.sets[2].summary["comparison"]
    assert d["mean"] == 0.0
    assert d["difference"]["min"] == d["difference"]["max"] == 0.0
    assert r.sets[1].summary["ale"]["mean"] < r.sets[0].summary["ale"]["mean"]


def test_derived_vulnerability_against_integration() -> None:
    tc, rs = sc.est("40", "60", "85", "percentile"), sc.est("50", "65", "80", "percentile")
    doc = sc.scenario(
        {
            "level": "tef_vuln",
            "tef": {"level": "tef", "estimate": sc.point("10", LEF)},
            "vulnerability": {"level": "derived", "threat_capability": {"source": "scenario", "estimate": tc}, "resistance_strength": rs},
        },
        {"productivity": sc.point("1", CUR)},
    )
    n = 200_000
    r = go(sc.bundle(doc), n=n)
    v_mc = r.sets[0].summary["lef"]["mean"] / 10.0
    ftc = pert.Distribution.of(pert.fit("40", "60", "85", "0.9", "percentile"))
    frs = pert.Distribution.of(pert.fit("50", "65", "80", "0.9", "percentile"))
    f = frs.fit

    def integrand(x: float) -> float:
        z = (x - f.a) / (f.b - f.a)
        dens = (
            z ** (f.alpha - 1)
            * (1 - z) ** (f.beta - 1)
            / math.exp(math.lgamma(f.alpha) + math.lgamma(f.beta) - math.lgamma(f.alpha + f.beta))
            / (f.b - f.a)
        )
        return float((1.0 - ftc.cdf(x)) * dens)

    v_exact, _ = integrate.quad(integrand, f.a, f.b, limit=200)
    lef_sd = r.sets[0].summary["lef"]["sd"] / 10.0
    assert abs(v_mc - v_exact) < 4 * lef_sd / math.sqrt(n)


def test_threat_capability_from_the_community_and_reduction() -> None:
    doc = sc.scenario(
        {
            "level": "tef_vuln",
            "tef": {"level": "tef", "estimate": sc.point("10", LEF)},
            "vulnerability": {
                "level": "derived",
                "threat_capability": {"source": "threat_community"},
                "resistance_strength": sc.point("60", "percentile"),
            },
        },
        {"productivity": sc.point("1", CUR)},
    )
    tc = {"kind": "threat_community", "schema_version": 1, "name": "Crime", "threat_capability": sc.est("30", "60", "90", "percentile")}
    doc["control_sets"] = [
        {"name": "Current", "current": True, "controls": []},
        {"name": "Alt", "current": False, "controls": [{"id": sc.CTRL, "version": 1, "status": "proposed"}]},
    ]
    b = sc.bundle(doc, {sc.CTRL: sc.control(("threat_capability", sc.point("0.2", "fraction")))}, tc=tc)
    r = go(b, sets=("Current", "Alt"))
    d = pert.Distribution.of(pert.fit("30", "60", "90", "0.9", "percentile"))
    assert r.sets[0].summary["lef"]["mean"] == pytest.approx(10 * (1 - float(d.cdf(60.0))), rel=1e-12)
    assert r.sets[1].summary["lef"]["mean"] == pytest.approx(10 * (1 - float(d.cdf(60.0 / 0.8))), rel=1e-12)


def test_cf_poa_and_direct_vulnerability() -> None:
    doc = sc.scenario(
        {
            "level": "tef_vuln",
            "tef": {"level": "cf_poa", "contact_frequency": sc.point("8", LEF), "probability_of_action": sc.point("0.5", "probability")},
            "vulnerability": {"level": "direct", "estimate": sc.point("0.25", "probability")},
        },
        {"productivity": sc.point("1", CUR)},
    )
    r = go(sc.bundle(doc))
    assert r.sets[0].summary["lef"]["mean"] == 1.0


def test_secondary_loss() -> None:
    sec = [{"stakeholder": "Customers", "slef": sc.point("0.5", "probability"), "loss": {"reputation": sc.point("100", CUR)}}]
    r = go(simple(lef_direct(sc.point("2", LEF)), {"response": sc.point("10", CUR)}, secondary=sec), n=200_000)
    b = r.sets[0].summary["breakdown"]
    assert b["primary"] == pytest.approx(20.0, rel=0.01)
    assert b["secondary"] == pytest.approx(100.0, rel=0.01)
    assert b["stakeholders"]["Customers"] == b["secondary"]
    assert b["forms"] == {"response": b["primary"]}
    assert set(r.sets[0].summary["loss_per_event"]["percentiles"].values()) == {10.0, 110.0}


def test_flags() -> None:
    # point, domain_low (a range from zero), bounds (a wide 50% interval at both edges)
    r = go(simple(lef_direct(sc.est("0", "1", "3", LEF)), {"productivity": sc.point("5", CUR), "response": sc.est("0", "1", "2", CUR)}))
    assert {"domain_low", "point"} <= codes(r)
    w = next(w for w in r.warnings if w.code == "domain_low")
    assert w.pointer in ("/lef/estimate", "/primary_loss/response")

    doc = sc.scenario(
        {
            "level": "tef_vuln",
            "tef": {
                "level": "cf_poa",
                "contact_frequency": sc.point("4", LEF),
                "probability_of_action": sc.est("0.8", "0.9", "1", "probability"),
            },
            "vulnerability": {
                "level": "derived",
                "threat_capability": {"source": "scenario", "estimate": sc.est("20", "50", "80", "percentile", "0.5")},
                "resistance_strength": sc.point("50", "percentile"),
            },
        },
        {"productivity": sc.point("1", CUR)},
    )
    doc["control_sets"] = [
        {"name": "Current", "current": True, "controls": [{"id": sc.CTRL, "version": 1, "status": "in_place"}]},
        {"name": "None", "current": False, "controls": []},
    ]
    ctrl = sc.control(
        ("probability_of_action", sc.est("0.5", "0.9995", "1", "fraction")),
        ("resistance_strength", sc.point("70", "percentile")),
    )
    r = go(sc.bundle(doc, {sc.CTRL: ctrl}), sets=("Current", "None"))
    by = {(w.code, w.control_set) for w in r.warnings}
    assert ("reduction_capped", "None") in by
    assert ("probability_clipped", "None") in by
    assert ("resistance_removal_not_modelled", "None") in by
    assert "bounds" in codes(r)

    doc = sc.scenario(lef_direct(sc.point("1", LEF)), {"productivity": sc.point("1", CUR)})
    r = go(_with_control(doc, ("resistance_strength", sc.point("70", "percentile"))), sets=("Current", "Alt"))
    assert ("effect_not_modelled", "Alt") in {(w.code, w.control_set) for w in r.warnings}


def test_changed_effect() -> None:
    doc = sc.scenario(lef_direct(sc.point("1", LEF)), {"productivity": sc.est("100", "200", "400", CUR)})
    use = {"id": sc.CTRL, "version": 1, "status": "in_place"}
    over = dict(use, effects=[{"factor": "loss.productivity", "estimate": sc.point("0.5", "fraction")}])
    doc["control_sets"] = [
        {"name": "Current", "current": True, "controls": [use]},
        {"name": "Stronger", "current": False, "controls": [over]},
    ]
    r = go(sc.bundle(doc, {sc.CTRL: sc.control(("loss.productivity", sc.point("0.2", "fraction")))}), sets=("Current", "Stronger"))
    assert np.allclose(r.sets[1].ale, r.sets[0].ale * 0.5 / 0.8, rtol=1e-12, atol=0)
    assert "control_effect_changed" in codes(r)


def test_large_frequency() -> None:
    r = go(simple(lef_direct(sc.point("2000", LEF)), {"productivity": sc.est("1", "2", "4", CUR)}), n=2_000)
    s = r.sets[0]
    assert "large_frequency" in codes(r)
    d = pert.Distribution.of(pert.fit("1", "2", "4", "0.9", CUR))
    f = d.fit
    mu = f.a + f.alpha / (f.alpha + f.beta) * (f.b - f.a)
    assert s.summary["ale"]["mean"] == pytest.approx(2000 * mu, rel=0.002)
    assert s.summary["loss_per_event"]["n"] <= 1000 * 2000


def test_loss_per_event_sample(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(model, "EVENT_SAMPLE", 30_000)
    r = go(simple(lef_direct(sc.point("5", LEF)), {"productivity": sc.est("1", "2", "4", CUR)}), n=10_000)
    s = r.sets[0].summary["loss_per_event"]
    assert s["n"] <= 30_000
    assert s["events_per_year_sampled"] < 1000
    assert "loss_per_event_sampled" in codes(r)


def test_not_converged() -> None:
    r = run(
        simple(lef_direct(sc.est("0.01", "0.05", "0.2", LEF)), {"productivity": sc.est("1", "100", "100000", CUR)}),
        1,
        1_000,
        ["Current"],
        10,
    )
    assert not r.sets[0].summary["convergence"]["converged"]
    assert ("not_converged", "Current") in {(w.code, w.control_set) for w in r.warnings}


def test_results_independent_of_chunking() -> None:
    sec = [
        {
            "stakeholder": "Regulators",
            "slef": sc.est("0.1", "0.3", "0.6", "probability"),
            "loss": {"fines_judgments": sc.est("10", "100", "1000", CUR)},
        }
    ]
    b = simple(lef_direct(sc.est("500", "1200", "3000", LEF)), {"productivity": sc.est("1", "2", "4", CUR)}, secondary=sec)
    a = go(b, n=5_000, chunk=model.CHUNK)
    c = go(b, n=5_000, chunk=777)
    assert np.array_equal(a.sets[0].ale, c.sets[0].ale)
    assert a.sets[0].summary == c.sets[0].summary
    assert a.warnings == c.warnings
    b2 = sc.corpus()
    assert (
        go(b2, n=12_345, sets=("Current", "With EDR")).sets[1].summary
        == go(b2, n=12_345, sets=("Current", "With EDR"), chunk=1_000).sets[1].summary
    )


def test_runs_are_deterministic_and_seeded() -> None:
    b = sc.corpus()
    one, two = go(b, seed=99), go(b, seed=99)
    assert np.array_equal(one.sets[0].ale, two.sets[0].ale)
    assert not np.array_equal(one.sets[0].ale, go(b, seed=100).sets[0].ale)
    # A set's draws do not depend on which other sets run with it.
    assert np.array_equal(go(b, seed=99, sets=("Current", "With EDR")).sets[0].ale, one.sets[0].ale)


def test_result_shapes() -> None:
    r = go(sc.corpus(), sets=("Current", "With EDR"))
    for j, s in enumerate(r.sets):
        sm = s.summary
        assert sm["independence"] == results.INDEPENDENCE
        assert sm["iterations"] == s.ale.size == 20_000
        assert s.ale.dtype == np.float64
        assert np.all(np.isfinite(s.ale))
        assert np.all(s.ale >= 0)
        for key in ("ale", "lef", "loss_per_event"):
            q = list(sm[key]["percentiles"].values())
            assert q == sorted(q)
            assert list(sm[key]["percentiles"]) == [f"p{p}" for p in results.PERCENTILES]
        assert 0 < sm["ale"]["p_positive"] <= 1
        pts = sm["curve"]["points"]
        assert len(pts) == results.CURVE_POINTS
        xs, ps = [p[0] for p in pts], [p[1] for p in pts]
        assert xs == sorted(xs)
        assert ps == sorted(ps, reverse=True)
        assert ps[-1] == 0.0
        assert set(sm["curve"]["at_percentiles"]) == set(sm["ale"]["percentiles"])
        b = sm["breakdown"]
        assert b["primary"] + b["secondary"] == pytest.approx(sm["ale"]["mean"], rel=1e-12)
        assert sum(b["forms"].values()) == pytest.approx(b["primary"], rel=1e-12)
        c = sm["convergence"]
        assert c["se"] == pytest.approx(sm["ale"]["sd"] / math.sqrt(20_000))
        for p in results.INTERVALS:
            lo, hi = c["intervals"][f"p{p}"]
            assert lo <= sm["ale"]["percentiles"][f"p{p}"] <= hi
        assert (sm["comparison"] is None) == (j == 0)


def test_exact_sum() -> None:
    rng_ = np.random.default_rng(0)
    x = rng_.normal(0, 1e6, 100_001) * 10.0 ** rng_.integers(-20, 20, 100_001)
    assert exact.fsum(x) == math.fsum(x.tolist())
    s = exact.ExactSum()
    for part in np.array_split(x[::-1], 7):
        s.add(part)
    assert s.value() == math.fsum(x.tolist())
    assert exact.ExactSum().mean() != exact.ExactSum().mean()  # NaN
    with pytest.raises(ValueError, match="finite"):
        exact.fsum([1.0, math.inf])


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda b: b.update(format="other"), "format"),
        (lambda b: b["scenario"]["document"]["lef"].update(level="x"), "/lef/level"),
        (lambda b: b["scenario"]["document"]["lef"]["estimate"].update(unit="currency"), "unit"),
        (lambda b: b["scenario"]["document"]["primary_loss"].update(theft=sc.point("1", CUR)), "form of loss"),
        (lambda b: b["scenario"]["document"]["lef"]["estimate"].update(min="5"), "ordered"),
    ],
)
def test_invalid_bundles(mutate: Any, match: str) -> None:
    b = simple(lef_direct(sc.est("1", "2", "3", LEF)), {"productivity": sc.point("1", CUR)})
    mutate(b)
    with pytest.raises(bundle.BundleError, match=match):
        go(b)


def test_control_set_order() -> None:
    b = sc.corpus()
    with pytest.raises(bundle.BundleError, match="current"):
        go(b, sets=("With EDR", "Current"))
    with pytest.raises(bundle.BundleError, match="no control set"):
        go(b, sets=("Current", "Nope"))
    with pytest.raises(bundle.BundleError, match="twice"):
        go(b, sets=("Current", "Current"))


def test_progress() -> None:
    seen: list[tuple[int, int]] = []
    go(sc.corpus(), n=25_000, sets=("Current", "With EDR"), progress=lambda d, t: seen.append((d, t)))
    total = seen[-1][1]
    assert seen[-1] == (total, total)
    assert {t for _, t in seen} == {total}
    assert total > 50_000  # the main pass and the sensitivity passes
    assert (50_000, total) in seen
    assert [d for d, _ in seen] == sorted(d for d, _ in seen)
