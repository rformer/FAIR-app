#!/usr/bin/env bash
# Regenerates the engine's lock files with hashes (F-005 T-04, ADR-013), in
# the engine's Python, from the repository root:
#   docker run --rm -v "$PWD:/src" -w /src python:3.12-slim-bookworm scripts/engine-lock.sh
# CI runs it and fails if the committed locks differ (the engine job).
set -euo pipefail
PIP_TOOLS=7.6.2
pip install --quiet --disable-pip-version-check --no-cache-dir "pip-tools==${PIP_TOOLS}"
cd engine
export CUSTOM_COMPILE_COMMAND="scripts/engine-lock.sh"
pip-compile --quiet --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url --resolver=backtracking \
  --output-file requirements.lock requirements.in
pip-compile --quiet --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url --resolver=backtracking \
  --output-file requirements-dev.lock requirements-dev.in
