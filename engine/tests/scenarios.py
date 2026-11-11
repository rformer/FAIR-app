"""Bundles for the engine's tests, shaped as F-003's ``fair.scenario-input.v1``.

``corpus()`` mirrors ``internal/risk/model/modeltest.Scenario()``.
"""

from __future__ import annotations

import copy
from typing import Any

TC = "22222222-2222-4222-8222-222222222222"
CTRL = "33333333-3333-4333-8333-333333333333"
CTRL2 = "44444444-4444-4444-8444-444444444444"


def est(lo: str, ml: str, hi: str, unit: str, confidence: str = "0.9") -> dict[str, Any]:
    return {
        "min": lo,
        "ml": ml,
        "max": hi,
        "unit": unit,
        "confidence": confidence,
        "rationale": "Calibrated estimate.",
        "sources": [{"type": "document", "ref": "test"}],
    }


def point(v: str, unit: str) -> dict[str, Any]:
    return est(v, v, v, unit)


def control(*effects: tuple[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "kind": "control",
        "schema_version": 1,
        "name": "A control",
        "effects": [{"factor": f, "estimate": e} for f, e in effects],
    }


def scenario(
    lef: dict[str, Any], primary: dict[str, Any], secondary: list[Any] | None = None, sets: list[Any] | None = None
) -> dict[str, Any]:
    return {
        "kind": "scenario",
        "schema_version": 1,
        "name": "Test scenario",
        "lef": lef,
        "primary_loss": primary,
        "secondary_risk": secondary or [],
        "control_sets": sets or [{"name": "Current", "current": True, "controls": []}],
    }


def bundle(doc: dict[str, Any], controls: dict[str, dict[str, Any]] | None = None, tc: dict[str, Any] | None = None) -> dict[str, Any]:
    """A bundle; ``controls`` maps a control id to its document, pinned wherever a set uses it."""
    pins: list[dict[str, Any]] = []
    for i, cs in enumerate(doc["control_sets"]):
        for j, use in enumerate(cs["controls"]):
            pins.append(
                {
                    "pointer": f"/control_sets/{i}/controls/{j}",
                    "kind": "control",
                    "id": use["id"],
                    "version": use["version"],
                    "digest": "0" * 64,
                    "document": (controls or {})[use["id"]],
                }
            )
    if tc is not None:
        pins.append(
            {"pointer": "/threat_community", "kind": "threat_community", "id": TC, "version": 2, "digest": "0" * 64, "document": tc}
        )
    pins.sort(key=lambda p: str(p["pointer"]))
    return {
        "format": "fair.scenario-input.v1",
        "currency": "USD",
        "scenario": {"id": "s", "version": 1, "digest": "0" * 64, "document": copy.deepcopy(doc)},
        "pins": pins,
    }


def corpus() -> dict[str, Any]:
    """modeltest.Scenario() with its pins: two control sets, EDR proposed in the second."""
    doc = scenario(
        {
            "level": "tef_vuln",
            "tef": {
                "level": "cf_poa",
                "contact_frequency": est("2", "6", "12", "events_per_year"),
                "probability_of_action": est("0.1", "0.3", "0.5", "probability"),
            },
            "vulnerability": {
                "level": "derived",
                "threat_capability": {"source": "scenario", "estimate": est("40", "60", "85", "percentile")},
                "resistance_strength": est("50", "65", "80", "percentile"),
            },
        },
        {
            "productivity": est("100000", "400000", "2000000", "currency"),
            "response": est("50000", "150000", "600000", "currency"),
        },
        [
            {
                "stakeholder": "Regulators",
                "slef": est("0.2", "0.4", "0.7", "probability"),
                "loss": {"fines_judgments": est("0", "250000", "5000000", "currency")},
            }
        ],
        [
            {"name": "Current", "current": True, "controls": [{"id": CTRL, "version": 1, "status": "in_place"}]},
            {
                "name": "With EDR",
                "current": False,
                "controls": [
                    {"id": CTRL, "version": 1, "status": "in_place"},
                    {
                        "id": CTRL2,
                        "version": 3,
                        "status": "proposed",
                        "effects": [{"factor": "resistance_strength", "estimate": est("70", "80", "90", "percentile")}],
                    },
                ],
            },
        ],
    )
    controls = {
        CTRL: control(
            ("resistance_strength", est("60", "75", "90", "percentile")), ("loss.response", est("0.1", "0.3", "0.5", "fraction"))
        ),
        CTRL2: control(
            ("resistance_strength", est("60", "75", "90", "percentile")), ("loss.response", est("0.1", "0.3", "0.5", "fraction"))
        ),
    }
    return bundle(doc, controls)
