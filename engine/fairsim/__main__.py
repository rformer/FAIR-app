"""The engine's command line.

``python -m fairsim info``
    The version, architecture and CPU pin.
``python -m fairsim serve --socket PATH [--workers N] [--validation PATH]``
    The gRPC contract on a Unix socket, after the startup self-check
    (refuses to serve if it fails).
``python -m fairsim validate [--out PATH]``
    The statistical validation suite; writes the record (to PATH or
    stdout) and exits 0 only if every check passed.
``python -m fairsim validate --record-reference``
    Records this version's cross-feature reference digest in
    ``fairsim/validation/reference.json`` (a release step when results
    change: with a new engine version, design §3.6).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import fairsim
from fairsim import cpu

USAGE = (
    "usage: python -m fairsim info | serve --socket PATH [--workers N] [--validation PATH]"
    " | validate [--out PATH] | validate --record-reference"
)


def info() -> dict[str, object]:
    """The engine's version, architecture and CPU pin."""
    import numpy as np  # noqa: PLC0415
    import scipy  # noqa: PLC0415

    return {
        "version": fairsim.__version__,
        "architecture": cpu.architecture(),
        "numpy": np.__version__,
        "scipy": scipy.__version__,
        "cpu_dispatch": cpu.check(),
    }


def _options(args: list[str], allowed: tuple[str, ...]) -> dict[str, str] | None:
    out: dict[str, str] = {}
    if len(args) % 2:
        return None
    for flag, value in zip(args[::2], args[1::2], strict=True):
        if flag not in allowed or flag in out:
            return None
        out[flag] = value
    return out


def _validate(args: list[str]) -> int | None:
    from fairsim import validation  # noqa: PLC0415

    cpu.check()
    if args == ["--record-reference"]:
        path = Path(validation.__file__).with_name("reference.json")
        refs = validation.references()
        refs.setdefault(fairsim.__version__, {})[cpu.architecture()] = validation.corpus_digest(validation.CROSS_FEATURE_ITERATIONS)
        path.write_text(json.dumps(refs, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"recorded {fairsim.__version__} {cpu.architecture()} in {path}")
        return 0
    opts = _options(args, ("--out",))
    if opts is None:
        return None
    record = validation.suite()
    text = json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if "--out" in opts:
        Path(opts["--out"]).parent.mkdir(parents=True, exist_ok=True)
        Path(opts["--out"]).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    failed = [name for name, c in record["detail"].items() if not c["passed"]]
    print(f"validation {'passed' if record['passed'] else 'FAILED: ' + ', '.join(failed)} in {record['seconds']} s", file=sys.stderr)
    return 0 if record["passed"] else 1


def main(argv: list[str]) -> int:
    if argv[1:] == ["info"]:
        print(json.dumps(info(), sort_keys=True))
        return 0
    if argv[1:2] == ["validate"]:
        code = _validate(argv[2:])
        if code is not None:
            return code
    if argv[1:2] == ["serve"]:
        opts = _options(argv[2:], ("--socket", "--workers", "--validation"))
        if opts is not None and "--socket" in opts:
            from fairsim import server  # noqa: PLC0415  (gRPC only when serving)

            try:
                workers = int(opts.get("--workers", str(os.cpu_count() or 1)))
            except ValueError:
                workers = 0
            if workers >= 1:
                return server.serve(opts["--socket"], workers, opts.get("--validation", server.VALIDATION_PATH))
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
