"""F-005 T-14 (AC-10): every warning and fallback code the engine records is documented in
docs/guides/simulation.md, and the guide's code table lists no other."""

from __future__ import annotations

import re
from pathlib import Path

from fairsim import pert

ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "docs" / "guides" / "simulation.md"
SOURCE = ROOT / "engine" / "fairsim"


def engine_codes() -> set[str]:
    codes = set(pert.FALLBACKS)
    pattern = re.compile(r"""(?:RunWarning|flag)\(\s*"([a-z_]+)\"""")
    for f in SOURCE.rglob("*.py"):
        if "_proto" in f.parts:
            continue
        codes.update(pattern.findall(f.read_text(encoding="utf-8")))
    return codes


def guide_table(title: str) -> set[str]:
    text = GUIDE.read_text(encoding="utf-8")
    section = text.split(f"## {title}\n", 1)[1].split("\n## ", 1)[0]
    return set(re.findall(r"^\| `([a-z_]+)` \|", section, flags=re.MULTILINE))


def test_every_code_is_documented() -> None:
    codes = engine_codes()
    assert {"point", "domain_low", "large_frequency", "not_converged", "control_effect_changed"} <= codes
    assert guide_table("Warning codes") == codes
