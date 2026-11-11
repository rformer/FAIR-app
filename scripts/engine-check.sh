#!/usr/bin/env bash
# The engine's checks (F-005 T-04): lint, format, types and tests, with the
# locked tools, in the engine's Python, from the repository root:
#   docker run --rm -v "$PWD:/src" -w /src python:3.12-slim-bookworm scripts/engine-check.sh
set -euo pipefail
python -m venv /tmp/engine-venv
/tmp/engine-venv/bin/pip install --quiet --disable-pip-version-check --no-cache-dir --require-hashes --no-deps -r engine/requirements-dev.lock
export PATH="/tmp/engine-venv/bin:$PATH"
cd engine
ruff check .
ruff format --check .
mypy
python -m pytest -q
