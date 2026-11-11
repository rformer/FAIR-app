"""The input bundle, read into the model's inputs (F-005 design §3.2, §3.3).

A bundle is F-003's canonical ``fair.scenario-input.v1``: the scenario
version's document, every pinned document (the threat community, each
control set's controls) and the currency. ``read`` fits every estimate the
model uses (``fairsim.pert``), names every random quantity, and works out
each control set's controls relative to the current set: which effects it
adds and which it removes.

Quantity names (design §3.3): an estimate's JSON pointer in the scenario,
``control:<id>/<factor>`` for a control's effect, ``events`` for the
year's loss events and ``secondary:<stakeholder>`` for a secondary loss
event's occurrence.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from fairsim import pert, rng

FORMAT: Final = "fair.scenario-input.v1"

FORMS: Final = ("productivity", "response", "replacement", "fines_judgments", "competitive_advantage", "reputation")
FREQUENCY_FACTORS: Final = ("contact_frequency", "probability_of_action")
RESISTANCE: Final = "resistance_strength"
CAPABILITY: Final = "threat_capability"

EVENTS: Final = "events"


class BundleError(ValueError):
    """The bundle cannot be simulated (``invalid_bundle``)."""


@dataclass(frozen=True)
class RunWarning:
    """A flag on a run (design §3.1, §3.2, §3.4)."""

    code: str
    pointer: str = ""
    control_set: str = ""
    detail: str = ""


@dataclass(frozen=True, eq=False)
class Input:
    """A sampled input: where it is, its random quantity and its distribution."""

    name: str
    pointer: str
    dist: pert.Distribution

    @property
    def fit(self) -> pert.Fit:
        return self.dist.fit


@dataclass(frozen=True, eq=False)
class Effect:
    """One control's effect on one factor, as a control set uses it."""

    control: str
    factor: str
    input: Input

    @property
    def key(self) -> tuple[str, str]:
        return self.control, self.factor


@dataclass(frozen=True, eq=False)
class ControlSet:
    """A control set and its changes from the current set (design §3.2 step 2)."""

    name: str
    current: bool
    effects: Mapping[tuple[str, str], Effect]
    added: tuple[Effect, ...] = ()
    removed: tuple[Effect, ...] = ()


@dataclass(frozen=True, eq=False)
class Group:
    """A secondary stakeholder group: its SLEF and its forms of loss."""

    stakeholder: str
    occurrence: str
    slef: Input
    forms: Mapping[str, Input]


@dataclass(frozen=True, eq=False)
class Model:
    """The model's inputs for one run."""

    lef_level: str
    lef: Input | None
    tef: Input | None
    contact_frequency: Input | None
    probability_of_action: Input | None
    vulnerability: Input | None
    threat_capability: Input | None  # used through its CDF, never drawn
    resistance_strength: Input | None
    primary: Mapping[str, Input]
    secondary: tuple[Group, ...]
    sets: tuple[ControlSet, ...]
    ids: Mapping[str, int]
    warnings: tuple[RunWarning, ...] = field(default=())

    @property
    def derived_vulnerability(self) -> bool:
        return self.threat_capability is not None

    def year_inputs(self) -> list[Input]:
        """Inputs drawn once a year, as the model uses them."""
        out = [
            x
            for x in (self.lef, self.tef, self.contact_frequency, self.probability_of_action, self.vulnerability, self.resistance_strength)
            if x is not None
        ]
        out += [g.slef for g in self.secondary]
        return out

    def event_inputs(self) -> list[Input]:
        """Inputs drawn per loss event: each form of primary and of secondary loss."""
        return [*self.primary.values(), *(x for g in self.secondary for x in g.forms.values())]

    def effects(self) -> list[Effect]:
        """Every control effect any set adds or removes, once per quantity and distribution."""
        seen: dict[tuple[str, int], Effect] = {}
        for s in self.sets:
            for e in (*s.added, *s.removed):
                seen.setdefault((e.input.name, id(e.input.dist)), e)
        return list(seen.values())


class _Reader:
    def __init__(self) -> None:
        self.warnings: list[RunWarning] = []
        self.names: list[str] = [EVENTS]
        self._dists: dict[tuple[Any, ...], pert.Distribution] = {}

    def dist(self, est: Any, pointer: str, unit: str, note: str = "") -> pert.Distribution:
        if not isinstance(est, Mapping):
            raise BundleError(f"{pointer}: an estimate is required")
        if est.get("unit") != unit:
            raise BundleError(f"{pointer}/unit: is {est.get('unit')!r}, want {unit!r}")
        try:
            key = (str(est["min"]), str(est["ml"]), str(est["max"]), str(est["confidence"]), unit)
        except KeyError as e:
            raise BundleError(f"{pointer}: {e.args[0]} is required") from None
        d = self._dists.get(key)
        if d is None:
            try:
                d = pert.Distribution.of(pert.fit(*key))
            except pert.EstimateError as e:
                raise BundleError(f"{pointer}: {e}") from None
            self._dists[key] = d
        if d.fit.fallback is not None:
            what = f"{unit} {key[0]} to {key[2]}, most likely {key[1]}, at {key[3]}"
            self.warnings.append(RunWarning(d.fit.fallback, pointer, detail=f"{note}: {what}" if note else what))
        return d

    def input(self, est: Any, pointer: str, unit: str, name: str | None = None) -> Input:
        name = name or pointer
        self.names.append(name)
        return Input(name, pointer, self.dist(est, pointer, unit))


def _obj(v: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(v, Mapping):
        raise BundleError(f"{what}: an object is required")
    return v


def _list(v: Any, what: str) -> Sequence[Any]:
    if v is None:
        return ()
    if not isinstance(v, list):
        raise BundleError(f"{what}: a list is required")
    return v


def _effect_unit(factor: str) -> str:
    if factor in (*FREQUENCY_FACTORS, CAPABILITY):
        return "fraction"
    if factor == RESISTANCE:
        return "percentile"
    if factor.startswith("loss.") and factor[5:] in FORMS:
        return "fraction"
    raise BundleError(f"{factor!r} is not a factor a control affects")


def _same(a: Effect, b: Effect) -> bool:
    fa, fb = a.input.fit, b.input.fit
    return (fa.lo, fa.ml, fa.hi, fa.confidence) == (fb.lo, fb.ml, fb.hi, fb.confidence)


def read(raw: bytes | Mapping[str, Any], control_sets: Sequence[str]) -> Model:
    """Read a bundle for the named control sets (the current set first)."""
    try:
        b = json.loads(raw) if isinstance(raw, bytes | bytearray) else raw
    except (ValueError, UnicodeDecodeError) as e:
        raise BundleError(f"the bundle is not JSON: {e}") from None
    b = _obj(b, "the bundle")
    if b.get("format") != FORMAT:
        raise BundleError(f"the bundle's format is {b.get('format')!r}, want {FORMAT!r}")
    s = _obj(_obj(b.get("scenario"), "/scenario").get("document"), "the scenario's document")
    pins = {_obj(p, "a pin").get("pointer"): _obj(p, "a pin") for p in _list(b.get("pins"), "/pins")}
    r = _Reader()

    lef_ = _obj(s.get("lef"), "/lef")
    level = lef_.get("level")
    lef = tef = cf = poa = vuln = rs = None
    tcap: Input | None = None
    if level == "lef":
        lef = r.input(lef_.get("estimate"), "/lef/estimate", "events_per_year")
    elif level == "tef_vuln":
        t = _obj(lef_.get("tef"), "/lef/tef")
        if t.get("level") == "tef":
            tef = r.input(t.get("estimate"), "/lef/tef/estimate", "events_per_year")
        elif t.get("level") == "cf_poa":
            cf = r.input(t.get("contact_frequency"), "/lef/tef/contact_frequency", "events_per_year")
            poa = r.input(t.get("probability_of_action"), "/lef/tef/probability_of_action", "probability")
        else:
            raise BundleError(f"/lef/tef/level: {t.get('level')!r} is not a level")
        v = _obj(lef_.get("vulnerability"), "/lef/vulnerability")
        if v.get("level") == "direct":
            vuln = r.input(v.get("estimate"), "/lef/vulnerability/estimate", "probability")
        elif v.get("level") == "derived":
            tc = _obj(v.get("threat_capability"), "/lef/vulnerability/threat_capability")
            if tc.get("source") == "scenario":
                ptr = "/lef/vulnerability/threat_capability/estimate"
                tcap = Input(ptr, ptr, r.dist(tc.get("estimate"), ptr, "percentile"))
            elif tc.get("source") == "threat_community":
                pin = pins.get("/threat_community")
                if pin is None:
                    raise BundleError("/threat_community: the pinned threat community is not in the bundle")
                doc = _obj(pin.get("document"), "the threat community")
                d = r.dist(doc.get("threat_capability"), "/threat_community", "percentile", "the threat community's threat capability")
                tcap = Input("/threat_community/threat_capability", "/threat_community", d)
            else:
                raise BundleError(f"/lef/vulnerability/threat_capability/source: {tc.get('source')!r} is not a source")
            rs = r.input(v.get("resistance_strength"), "/lef/vulnerability/resistance_strength", "percentile")
        else:
            raise BundleError(f"/lef/vulnerability/level: {v.get('level')!r} is not a level")
    else:
        raise BundleError(f"/lef/level: {level!r} is not a level")

    primary = {
        f: r.input(e, f"/primary_loss/{f}", "currency")
        for f, e in sorted(_obj(s.get("primary_loss") or {}, "/primary_loss").items())
        if _check_form(f, "/primary_loss")
    }
    groups = []
    for j, raw_g in enumerate(_list(s.get("secondary_risk"), "/secondary_risk")):
        g = _obj(raw_g, f"/secondary_risk/{j}")
        name = str(g.get("stakeholder", ""))
        occurrence = f"secondary:{name}"
        r.names.append(occurrence)
        forms = {
            f: r.input(e, f"/secondary_risk/{j}/loss/{f}", "currency")
            for f, e in sorted(_obj(g.get("loss") or {}, f"/secondary_risk/{j}/loss").items())
            if _check_form(f, f"/secondary_risk/{j}/loss")
        }
        groups.append(Group(name, occurrence, r.input(g.get("slef"), f"/secondary_risk/{j}/slef", "probability"), forms))

    sets = _control_sets(r, s, pins, control_sets, derived=tcap is not None)
    try:
        ids = rng.quantity_ids(r.names)
    except rng.QuantityCollisionError as e:
        raise BundleError(str(e)) from None
    return Model(level, lef, tef, cf, poa, vuln, tcap, rs, primary, tuple(groups), sets, ids, warnings=tuple(dict.fromkeys(r.warnings)))


def _check_form(form: str, where: str) -> bool:
    if form not in FORMS:
        raise BundleError(f"{where}/{form}: is not an Open FAIR form of loss")
    return True


def _control_sets(
    r: _Reader, s: Mapping[str, Any], pins: Mapping[Any, Mapping[str, Any]], names: Sequence[str], derived: bool
) -> tuple[ControlSet, ...]:
    declared = _list(s.get("control_sets"), "/control_sets")
    by_name: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for i, raw in enumerate(declared):
        cs = _obj(raw, f"/control_sets/{i}")
        by_name[str(cs.get("name"))] = (i, cs)
    if not names:
        raise BundleError("no control sets to simulate")
    if len(set(names)) != len(names):
        raise BundleError("a control set is named twice")
    for n in names:
        if n not in by_name:
            raise BundleError(f"the scenario has no control set {n!r}")
    if not by_name[names[0]][1].get("current"):
        raise BundleError(f"{names[0]!r} is not the current control set; it must come first")
    current_name = next((n for n, (_, cs) in by_name.items() if cs.get("current")), names[0])
    if current_name != names[0]:
        raise BundleError("the scenario's current control set must come first")

    def effects_of(i: int, cs: Mapping[str, Any]) -> dict[tuple[str, str], Effect]:
        out: dict[tuple[str, str], Effect] = {}
        for j, raw_use in enumerate(_list(cs.get("controls"), f"/control_sets/{i}/controls")):
            use = _obj(raw_use, f"/control_sets/{i}/controls/{j}")
            ptr = f"/control_sets/{i}/controls/{j}"
            pin = pins.get(ptr)
            if pin is None:
                raise BundleError(f"{ptr}: the pinned control is not in the bundle")
            cid = str(use.get("id"))
            own = _list(_obj(pin.get("document"), f"{ptr}: the control").get("effects"), f"{ptr}/effects")
            # The control's own effects (pointer: the control's place in the
            # set), each replaced by the set's override for its factor.
            listed: dict[str, tuple[str, str, Any]] = {}
            for k, raw_e in enumerate(own):
                e = _obj(raw_e, f"{ptr}: the control's effect {k}")
                listed[str(e.get("factor"))] = (ptr, f"the control's effect {k} ({e.get('factor')})", e.get("estimate"))
            for k, raw_e in enumerate(_list(use.get("effects"), f"{ptr}/effects")):
                e = _obj(raw_e, f"{ptr}/effects/{k}")
                listed[str(e.get("factor"))] = (f"{ptr}/effects/{k}", "", e.get("estimate"))
            for factor, (where, note, est) in sorted(listed.items()):
                unit = _effect_unit(factor)
                d = r.dist(est, where, unit, note)
                out[(cid, factor)] = Effect(cid, factor, Input(f"control:{cid}/{factor}", where, d))
        return out

    current = effects_of(*by_name[names[0]])
    out = [ControlSet(names[0], True, current)]
    for n in names:
        r.names.extend(e.input.name for e in current.values())
        if n == names[0]:
            continue
        mine = effects_of(*by_name[n])
        added, removed = [], []
        for key, e in sorted(mine.items()):
            c = current.get(key)
            if c is None:
                added.append(e)
            elif not _same(c, e):
                removed.append(c)
                added.append(e)
                r.warnings.append(
                    RunWarning(
                        "control_effect_changed", e.input.pointer, n, f"{e.factor} of control {e.control} differs from the current set's"
                    )
                )
        removed += [c for key, c in sorted(current.items()) if key not in mine]
        r.names.extend(e.input.name for e in mine.values())
        out.append(ControlSet(n, False, mine, tuple(added), tuple(removed)))
    for spec in out:
        for e in (*spec.added, *spec.removed):
            if e.factor in (RESISTANCE, CAPABILITY) and not derived:
                r.warnings.append(
                    RunWarning(
                        "effect_not_modelled", e.input.pointer, spec.name, f"{e.factor}: Vulnerability is not derived in this scenario"
                    )
                )
        for e in spec.removed:
            if e.factor == RESISTANCE and derived:
                r.warnings.append(RunWarning("resistance_removal_not_modelled", e.input.pointer, spec.name, f"control {e.control}"))
    return tuple(out)
