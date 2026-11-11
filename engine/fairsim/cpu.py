"""NumPy CPU feature dispatch, pinned to each architecture's baseline (ADR-013).

NumPy dispatches some loops at run time to the newest instruction set the
CPU offers. Different paths can round differently in the last bit, so the
same inputs could give different results on different CPU models. The
engine therefore disables every feature NumPy dispatches above its
baseline, before NumPy is imported, and refuses to run if one is still on.
"""

from __future__ import annotations

import importlib
import os
import platform

ENV = "NPY_DISABLE_CPU_FEATURES"

# The features NumPy 2.5 dispatches above its baseline, per architecture
# (numpy._core._multiarray_umath.__cpu_dispatch__). amd64's baseline is
# X86_V2. arm64 is pinned when its images are built (design §14).
DISPATCHED: dict[str, tuple[str, ...]] = {
    "amd64": ("X86_V3", "X86_V4", "AVX512_ICL", "AVX512_SPR"),
}


class CPUPinError(RuntimeError):
    """NumPy's dispatch could not be pinned."""


def architecture() -> str:
    """The CPU architecture in the platform's names: amd64 or arm64."""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    raise CPUPinError(f"unsupported architecture {m!r}")


def pin() -> None:
    """Disable NumPy's dispatched features. Must run before NumPy is imported."""
    features = DISPATCHED.get(architecture(), ())
    if not features:
        return
    want = " ".join(features)
    have = os.environ.get(ENV)
    if have is not None and set(have.split()) != set(features):
        raise CPUPinError(f"{ENV} is {have!r}; the engine needs {want!r}")
    os.environ[ENV] = want


def check() -> dict[str, bool]:
    """Every dispatched feature is off; returns NumPy's view of them."""
    umath = importlib.import_module("numpy._core._multiarray_umath").__dict__  # NumPy's runtime CPU tables
    dispatch: list[str] = list(umath["__cpu_dispatch__"])
    features: dict[str, bool] = dict(umath["__cpu_features__"])
    state = {f: bool(features.get(f, False)) for f in dispatch}
    on = [f for f, enabled in state.items() if enabled]
    if on:
        raise CPUPinError(f"NumPy dispatches {', '.join(on)}: results would depend on the CPU model")
    return state
