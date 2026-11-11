"""The engine's command line: ``python -m fairsim info``.

Later tasks add ``serve`` (the gRPC server on its Unix socket, T-08) and
``validate`` (the statistical validation suite, T-09).
"""

from __future__ import annotations

import json
import sys

import fairsim
from fairsim import cpu


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


def main(argv: list[str]) -> int:
    if argv[1:] == ["info"]:
        print(json.dumps(info(), sort_keys=True))
        return 0
    print("usage: python -m fairsim info", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
