"""F-005 T-07 (AC-14, AC-18; design §3.4, §3.5): sensitivity and aggregation."""

from __future__ import annotations

from typing import Any

import numpy as np
import pytest
import scenarios as sc
from scipy import stats

import fairsim  # noqa: F401  (pins NumPy's dispatch first)
from fairsim import aggregate, bundle, exact, model, sensitivity
from fairsim.run import run

LEF = "events_per_year"
CUR = "currency"


def rows(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["input"]: r for r in summary["sensitivity"]["inputs"]}


def test_strongest_input_first_and_no_effect_swings_zero() -> None:
    doc = sc.scenario(
        {"level": "lef", "estimate": sc.est("0.5", "2", "20", LEF)},
        {"productivity": sc.est("900", "1000", "1100", CUR)},
    )
    doc["control_sets"] = [
        {"name": "Current", "current": True, "controls": []},
        {"name": "Alt", "current": False, "controls": [{"id": sc.CTRL, "version": 1, "status": "proposed"}]},
    ]
    # The control reduces a form of loss the scenario does not have.
    b = sc.bundle(doc, {sc.CTRL: sc.control(("loss.reputation", sc.est("0.1", "0.5", "0.9", "fraction")))})
    r = run(b, 3, 30_000, ["Current", "Alt"], 100)
    cur = r.sets[0].summary["sensitivity"]
    assert cur["iterations"] == 20_000
    assert [x["input"] for x in cur["inputs"]] == ["/lef/estimate", "/primary_loss/productivity"]
    lef = cur["inputs"][0]
    assert lef["low"]["change"] < 0 < lef["high"]["change"]
    assert lef["swing"] > 10 * cur["inputs"][1]["swing"]
    assert lef["spearman"] > 0.8
    alt = rows(r.sets[1].summary)
    eff = alt[f"control:{sc.CTRL}/loss.reputation"]
    assert eff["kind"] == "control_effect"
    assert eff["control"] == sc.CTRL
    assert eff["factor"] == "loss.reputation"
    assert eff["swing"] == 0.0
    assert eff["low"]["change"] == eff["high"]["change"] == 0.0
    assert eff["spearman"] is not None
    assert abs(eff["spearman"]) < 0.05
    # The current set changes no controls, so it lists no effects.
    assert all(x["kind"] == "estimate" for x in cur["inputs"])


def test_a_point_input_has_no_swing_and_no_correlation() -> None:
    b = sc.bundle(sc.scenario({"level": "lef", "estimate": sc.point("2", LEF)}, {"productivity": sc.est("1", "2", "4", CUR)}))
    r = rows(run(b, 1, 5_000, ["Current"], 100).sets[0].summary)
    assert r["/lef/estimate"]["swing"] == 0.0
    assert r["/lef/estimate"]["spearman"] is None


def test_every_input_of_the_corpus() -> None:
    r = run(sc.corpus(), 11, 5_000, ["Current", "With EDR"], 100)
    cur, edr = rows(r.sets[0].summary), rows(r.sets[1].summary)
    want = {
        "/lef/tef/contact_frequency",
        "/lef/tef/probability_of_action",
        "/lef/vulnerability/resistance_strength",
        "/lef/vulnerability/threat_capability/estimate",
        "/primary_loss/productivity",
        "/primary_loss/response",
        "/secondary_risk/0/slef",
        "/secondary_risk/0/loss/fines_judgments",
    }
    assert set(cur) == want
    assert set(edr) == want | {f"control:{sc.CTRL2}/resistance_strength", f"control:{sc.CTRL2}/loss.response"}
    assert cur["/lef/vulnerability/threat_capability/estimate"]["spearman"] is None
    # Stronger resistance lowers loss; a higher threat capability raises it.
    assert cur["/lef/vulnerability/resistance_strength"]["high"]["change"] < 0
    assert cur["/lef/vulnerability/threat_capability/estimate"]["high"]["change"] > 0
    assert cur["/lef/vulnerability/resistance_strength"]["spearman"] < 0
    swings = [x["swing"] for x in r.sets[1].summary["sensitivity"]["inputs"]]
    assert swings == sorted(swings, reverse=True)


def test_spearman_against_scipy() -> None:
    g = np.random.default_rng(5)
    x = np.round(g.lognormal(0, 1, 5_000), 1)  # ties
    y = x * 0.3 + g.normal(0, 1, 5_000)
    y[:200] = 0.0
    want = stats.spearmanr(x, y).statistic
    assert sensitivity.spearman(x, stats.rankdata(y)) == pytest.approx(want, abs=1e-12)
    assert sensitivity.spearman(np.ones(10), stats.rankdata(np.arange(10.0))) is None


def test_spearman_of_a_year_input_against_the_series() -> None:
    b = sc.bundle(sc.scenario({"level": "lef", "estimate": sc.est("1", "3", "9", LEF)}, {"productivity": sc.est("10", "20", "40", CUR)}))
    m = bundle.read(b, ["Current"])
    r = run(b, 21, 8_000, ["Current"], 100)
    lef = model.simulate(m, 21, 8_000, events=False).sets[0].lef
    want = stats.spearmanr(lef, r.sets[0].ale).statistic
    assert rows(r.sets[0].summary)["/lef/estimate"]["spearman"] == pytest.approx(want, abs=1e-12)


def test_sensitivity_is_deterministic_and_chunk_free() -> None:
    a = run(sc.corpus(), 4, 6_000, ["Current", "With EDR"], 100)
    c = run(sc.corpus(), 4, 6_000, ["Current", "With EDR"], 100, chunk=1_234)
    assert a.sets[1].summary["sensitivity"] == c.sets[1].summary["sensitivity"]


def _series(lef: str, seed: int, n: int) -> np.ndarray[Any, np.dtype[np.float64]]:
    b = sc.bundle(sc.scenario({"level": "lef", "estimate": sc.point(lef, LEF)}, {"productivity": sc.est("100", "200", "400", CUR)}))
    return run(b, seed, n, ["Current"], 100).sets[0].ale


def test_independent_members_add_means_and_variances() -> None:
    n = 100_000
    a, b = _series("2", 1, n), _series("5", 2, n)
    summary, total = aggregate.aggregate(9, [aggregate.Member(0, a, "A"), aggregate.Member(1, b, "B")])
    assert summary["iterations"] == n
    assert summary["members"] == 2
    assert summary["independence"] == aggregate.INDEPENDENCE
    assert exact.fsum(total) == pytest.approx(exact.fsum(a) + exact.fsum(b), rel=1e-12)
    assert summary["ale"]["mean"] == pytest.approx(a.mean() + b.mean(), rel=1e-12)
    assert total.var() == pytest.approx(a.var() + b.var(), rel=0.03)
    c = {x["label"]: x for x in summary["contributions"]}
    assert c["A"]["mean"] == exact.mean(a)
    assert c["A"]["share_of_p95_year"] + c["B"]["share_of_p95_year"] == pytest.approx(1.0)
    assert summary["p95_year"]["loss"] == summary["ale"]["percentiles"]["p95"]
    assert len(summary["curve"]["points"]) == 200


def test_permutations_stop_shared_seeds_correlating() -> None:
    n = 100_000
    a = _series("3", 1, n)
    same = _series("3", 1, n)
    assert np.array_equal(a, same)  # two runs of one scenario with one seed
    _, total = aggregate.aggregate(17, [aggregate.Member(0, a), aggregate.Member(1, same)])
    # Fully correlated, the variance would be 4 var(a); independent, 2 var(a).
    assert total.var() == pytest.approx(2 * a.var(), rel=0.03)
    p0, p1 = aggregate.permutation(17, 0, n), aggregate.permutation(17, 1, n)
    assert sorted(p0.tolist()) == list(range(n))
    assert not np.array_equal(p0, p1)
    assert abs(np.corrcoef(a[p0], same[p1])[0, 1]) < 0.02


def test_aggregate_is_deterministic_and_order_free() -> None:
    a, b, c = _series("1", 1, 1_000), _series("2", 2, 1_000), _series("4", 3, 1_000)
    ms = [aggregate.Member(0, a), aggregate.Member(1, b), aggregate.Member(2, c)]
    s1, t1 = aggregate.aggregate(5, ms)
    s2, t2 = aggregate.aggregate(5, list(reversed(ms)))
    assert np.array_equal(t1, t2)
    assert s1 == s2
    _, t3 = aggregate.aggregate(6, ms)
    assert not np.array_equal(t1, t3)


@pytest.mark.parametrize(
    ("members", "match"),
    [
        ([aggregate.Member(0, np.ones(10))], "2 to 200"),
        ([aggregate.Member(0, np.ones(10)), aggregate.Member(0, np.ones(10))], "same position"),
        ([aggregate.Member(0, np.ones(10)), aggregate.Member(1, np.ones(9))], "iterations"),
        ([aggregate.Member(0, np.ones(10)), aggregate.Member(1, np.full(10, np.nan))], "finite"),
        ([aggregate.Member(i, np.ones(2)) for i in range(201)], "2 to 200"),
    ],
)
def test_aggregate_refusals(members: list[aggregate.Member], match: str) -> None:
    with pytest.raises(aggregate.AggregateError, match=match):
        aggregate.aggregate(1, members)
