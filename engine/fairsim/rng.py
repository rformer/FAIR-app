"""Counter-based random numbers (F-005 design §3.3; AC-09, AC-17).

Every uniform is addressed: ``u(seed, q, i, k)`` is Philox4x32-10 keyed by
the run's 64-bit seed, with the counter ``(i, k, q, 0)``: the iteration
``i``, the event ``k`` within it, and the 32-bit quantity id ``q``. The
same quantity therefore draws the same numbers in every control set, in
any chunking and on any number of workers, and adding a quantity shifts no
other's draws. The generator is NumPy integer arithmetic on unsigned
arrays: the same on every CPU.

Philox4x32 has a 64-bit key, which the seed fills; the quantity id is the
third counter word, which plays the same role as a stream key.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

import numpy as np
from numpy.typing import ArrayLike, NDArray

U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF

# Philox4x32 multipliers and Weyl key increments (Salmon et al., SC'11).
_M0 = np.uint64(0xD2511F53)
_M1 = np.uint64(0xCD9E8D57)
_W0 = 0x9E3779B9
_W1 = 0xBB67AE85
_LO = np.uint64(U32)
_SHIFT = np.uint64(32)

ROUNDS = 10

_FNV_OFFSET = 0x811C9DC5
_FNV_PRIME = 0x01000193


def philox4x32(
    counter: tuple[ArrayLike, ArrayLike, ArrayLike, ArrayLike],
    key: tuple[int, int],
    rounds: int = ROUNDS,
) -> tuple[NDArray[np.uint32], NDArray[np.uint32], NDArray[np.uint32], NDArray[np.uint32]]:
    """Philox4x32-R of each counter (four 32-bit words, broadcast) under one key."""
    words = [np.asarray(c) for c in counter]
    for w in words:
        if w.dtype.kind not in "iu":
            raise ValueError("counter words are integers")
        if w.size and (int(w.min()) < 0 or int(w.max()) > U32):
            raise ValueError("counter words are 32-bit")
    c0, c1, c2, c3 = (np.array(w, dtype=np.uint64) for w in np.broadcast_arrays(*words))
    k0, k1 = key
    if not (0 <= k0 <= U32 and 0 <= k1 <= U32):
        raise ValueError("key words are 32-bit")
    for r in range(rounds):
        if r:
            k0 = (k0 + _W0) & U32
            k1 = (k1 + _W1) & U32
        p0 = c0 * _M0
        p1 = c2 * _M1
        c0, c1, c2, c3 = (p1 >> _SHIFT) ^ c1 ^ np.uint64(k0), p1 & _LO, (p0 >> _SHIFT) ^ c3 ^ np.uint64(k1), p0 & _LO
    return c0.astype(np.uint32), c1.astype(np.uint32), c2.astype(np.uint32), c3.astype(np.uint32)


def seed_key(seed: int) -> tuple[int, int]:
    """The Philox key of a 64-bit seed: its low and high words."""
    if not 0 <= seed <= U64:
        raise ValueError("the seed is a 64-bit unsigned integer")
    return seed & U32, seed >> 32


_TWO_M53 = 2.0**-53


def uniforms(seed: int, q: int, i: ArrayLike, k: ArrayLike = 0) -> NDArray[np.float64]:
    """``u(seed, q, i, k)`` in (0, 1) for every iteration ``i`` and event ``k`` (broadcast).

    A double from 53 bits: the top 27 bits of the first output word and the
    top 26 of the second, ``m · 2⁻⁵³``; ``m = 0`` is read as 1, so the value
    is never 0 (and never 1).
    """
    if not 0 <= q <= U32:
        raise ValueError("quantity ids are 32-bit")
    x0, x1, _, _ = philox4x32((i, k, q, 0), seed_key(seed))
    m = (x0.astype(np.uint64) >> np.uint64(5)) << np.uint64(26) | (x1.astype(np.uint64) >> np.uint64(6))
    out: NDArray[np.float64] = np.maximum(m, np.uint64(1)).astype(np.float64) * _TWO_M53
    return out


def fnv1a32(name: str) -> int:
    """FNV-1a (32-bit) over the name's UTF-8 bytes."""
    h = _FNV_OFFSET
    for b in name.encode("utf-8"):
        h = ((h ^ b) * _FNV_PRIME) & U32
    return h


class QuantityCollisionError(ValueError):
    """Two quantities of one run have the same id: they would share draws."""


def quantity_ids(names: Iterable[str]) -> Mapping[str, int]:
    """Each quantity's id (``fnv1a32`` of its name), refusing collisions.

    Names are the estimate's JSON pointer in the scenario,
    ``control:<id>/<effect>`` for control effects, ``events`` and
    ``secondary:<group>`` (design §3.3).
    """
    ids: dict[str, int] = {}
    seen: dict[int, str] = {}
    for name in names:
        if name in ids:
            continue
        q = fnv1a32(name)
        if q in seen:
            raise QuantityCollisionError(f"{name!r} and {seen[q]!r} have the same quantity id {q:#010x}")
        ids[name] = q
        seen[q] = name
    return ids
