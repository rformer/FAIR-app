"""The engine's command line.

``python -m fairsim info`` prints the version, architecture and CPU pin.
``python -m fairsim serve --socket PATH [--workers N] [--validation PATH]``
serves the gRPC contract on a Unix socket (T-08). ``validate`` (the
statistical validation suite) follows with T-09.
"""

from __future__ import annotations

import json
import os
import sys

import fairsim
from fairsim import cpu

USAGE = "usage: python -m fairsim info | serve --socket PATH [--workers N] [--validation PATH]"


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


def _options(args: list[str]) -> dict[str, str] | None:
    out: dict[str, str] = {}
    if len(args) % 2:
        return None
    for flag, value in zip(args[::2], args[1::2], strict=True):
        if flag not in ("--socket", "--workers", "--validation") or flag in out:
            return None
        out[flag] = value
    return out


def main(argv: list[str]) -> int:
    if argv[1:] == ["info"]:
        print(json.dumps(info(), sort_keys=True))
        return 0
    if argv[1:2] == ["serve"]:
        opts = _options(argv[2:])
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
