# ADR-013 Simulation engine runtime: Python behind a Go FIPS gate
Status: Accepted (2026-11-10)
Date: 2026-11-10

## Context
F-005 puts the Monte Carlo engine in Python (ADR-002: NumPy, SciPy). The risk service calls it over gRPC with mutually authenticated TLS, and every cryptographic module in the platform must be FIPS 140-validated (constitution S2, ADR-006). The Python gRPC library's wheels embed BoringSSL, which is not a validated module. The engine must also produce bit-for-bit identical results for the same inputs on the same engine version and CPU architecture (F-005-AC-17), whatever the CPU model, worker count or execution order.

## Decision
- **TLS is terminated by a Go sidecar.** `engine-gate` (`cmd/engine-gate`) is built with `GOFIPS140=v1.0.0` like every Go binary of the platform. It runs in the engine pod, accepts mTLS 1.2+ connections from clients whose certificates it pins, and forwards each gRPC stream to the Python engine over a Unix socket in a shared in-memory volume. The engine listens on nothing else. Python does no cryptography: no TLS, no signing, no hashing for security. Digests of results are computed by the risk service (Go).
- **Python runtime.** Python 3.12 on a minimal Debian 12 base, non-root, read-only root filesystem, no shell in the final image. Dependencies (NumPy, SciPy, grpcio, protobuf) are pinned with hashes in `engine/requirements.lock` and recorded in the image's SBOM. The engine package is `fairsim` in `engine/`.
- **Determinism.** Random numbers come from a counter-based generator (Philox4x32-10, written in NumPy integer arithmetic) keyed by the run's seed and a stable identifier of each sampled quantity, and addressed by iteration and event, so no draw depends on how iterations are split across workers or how many events another quantity produced. Reductions that feed results use correctly rounded sums (`math.fsum`) and order statistics, never order-dependent floating-point accumulation. NumPy's runtime CPU feature dispatch is pinned to the architecture's baseline in the image (`NPY_DISABLE_CPU_FEATURES`), and a CI test compares results under different feature sets.
- **Validation travels with the image.** The image build runs the statistical validation suite and writes its record into the image; the engine reports it and refuses to serve if its startup self-check fails.

**Image (F-005 T-04).** The final stage is distroless static with exactly the Debian libraries Python and the wheels link against, copied with their dpkg records so the SBOM and the vulnerability scan see them. Python's `_ssl` and `_hashlib` modules are removed and the build fails if OpenSSL is linked: the image holds no OpenSSL at all. The distroless cc base was not used because its OpenSSL is a library the engine does not need and whose vulnerabilities would gate every release.

## Consequences
- One FIPS story for the platform: the Go module validated for everything else also protects the engine's channel.
- Two containers in the engine pod, and keys for the gate (`engine-gate/tls`) and for the risk service's client (`risk/engine-client`) in the key layout (F-001 T-41).
- A second toolchain in CI (Python lint, tests, validation suite, lock-file check), as ADR-002 foresaw.
- Results are reproducible within an architecture; an amd64 and an arm64 run of the same inputs may differ in the last bits, and runs record their architecture.

## Alternatives considered
- grpcio built from source against a FIPS-validated OpenSSL 3 in a UBI 9 image: one container, but a source build of grpcio in CI, a RHEL-family base image, and a second validated module to track.
- A commercial FIPS-validated Python image: least build work, but a paid, vendor-specific dependency for self-hosted and air-gapped installs.
- NumPy's sequential `Generator` streams: simplest, but draws then depend on chunking and on event counts, which breaks worker-invariance and common random numbers across control sets.
