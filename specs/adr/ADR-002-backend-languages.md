# ADR-002 Go for services, Python for the analytics engine
Status: Accepted (language choice); service split Proposed
Date: 2026-10-24

## Decision
- **Go** handles the API gateway/BFF, the domain services (register, acceptance workflow, audit, notifications), and the integrations. It gives small static binaries, distroless images, strong concurrency, and a native FIPS 140-3 module.
- **Python** handles the FAIR simulation engine and analytics: Monte Carlo, distribution fitting, calibration aids, and report math. It uses NumPy, SciPy, and pandas/Polars.
- Contracts between them are **gRPC/protobuf**, and the protos are versioned with the specs.

## Consequences
- Two toolchains in CI. Shared lint, test, and SBOM standards.
- The engine is versioned independently, and the version is stamped on every run (constitution A4).
