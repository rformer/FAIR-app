"""fairsim: the FAIR Risk Platform's Monte Carlo simulation engine (F-005).

The engine is stateless (design §1): it receives an input bundle and
parameters over gRPC, computes, and streams results back. It does no
cryptography (ADR-013): TLS is terminated by engine-gate.

Import ``fairsim.cpu`` before NumPy anywhere in the engine: it pins NumPy's
runtime CPU feature dispatch so results do not depend on the CPU model
(F-005-AC-17, ADR-013).
"""

from fairsim import cpu as _cpu

__version__ = "0.1.0"

__all__ = ["__version__"]

_cpu.pin()
