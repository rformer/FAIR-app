"""F-005 T-05 (AC-09, AC-17; design §3.3): counter-based random numbers."""

from __future__ import annotations

import numpy as np
import pytest

import fairsim  # noqa: F401  (pins NumPy's dispatch first)
from fairsim import rng

# Random123's published known-answer vectors for Philox4x32-10
# (kat_vectors: counter, key, output).
PHILOX_KAT = [
    ((0x00000000, 0x00000000, 0x00000000, 0x00000000), (0x00000000, 0x00000000), (0x6627E8D5, 0xE169C58D, 0xBC57AC4C, 0x9B00DBD8)),
    ((0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF), (0xFFFFFFFF, 0xFFFFFFFF), (0x408F276D, 0x41C83B0E, 0xA20BC7C6, 0x6D5451FD)),
    ((0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344), (0xA4093822, 0x299F31D0), (0xD16CFE09, 0x94FDCCEB, 0x5001E420, 0x24126EA1)),
]


@pytest.mark.parametrize(("counter", "key", "want"), PHILOX_KAT)
def test_philox_known_answers(counter: tuple[int, int, int, int], key: tuple[int, int], want: tuple[int, int, int, int]) -> None:
    got = rng.philox4x32(counter, key)
    assert tuple(int(w) for w in got) == want


def test_philox_vectorized_matches_scalar() -> None:
    i = np.arange(1000, dtype=np.uint64)
    many = rng.philox4x32((i, 7, 99, 0), (1, 2))
    for j in (0, 1, 500, 999):
        one = rng.philox4x32((j, 7, 99, 0), (1, 2))
        assert [int(w[j]) for w in many] == [int(w) for w in one]


def test_uniforms_open_interval_and_53_bits() -> None:
    u = rng.uniforms(2**64 - 1, 0xFFFFFFFF, np.arange(200_000))
    assert u.dtype == np.float64
    assert u.min() > 0.0
    assert u.max() < 1.0
    assert np.all(np.round(u * 2.0**53) == u * 2.0**53)
    assert abs(u.mean() - 0.5) < 0.005


def test_draws_independent_of_chunking() -> None:
    seed, q = 0x0123456789ABCDEF, rng.fnv1a32("/loss_event_frequency/estimate")
    whole = rng.uniforms(seed, q, np.arange(30_000))
    chunks = [rng.uniforms(seed, q, np.arange(lo, min(lo + 7_001, 30_000))) for lo in range(0, 30_000, 7_001)]
    assert np.array_equal(whole, np.concatenate(chunks))
    rev = np.arange(30_000)[::-1]
    assert np.array_equal(rng.uniforms(seed, q, rev), whole[::-1])


def test_events_address_their_own_draws() -> None:
    i = np.repeat(np.arange(100), 5)
    k = np.tile(np.arange(5), 100)
    grid = rng.uniforms(3, 4, i, k).reshape(100, 5)
    assert np.array_equal(grid[:, 0], rng.uniforms(3, 4, np.arange(100)))
    assert np.array_equal(grid[42], rng.uniforms(3, 4, 42, np.arange(5)))
    assert len(np.unique(grid)) == 500


def test_quantities_and_seeds_differ() -> None:
    i = np.arange(1000)
    a, b, c = rng.uniforms(1, 10, i), rng.uniforms(1, 11, i), rng.uniforms(2, 10, i)
    assert not np.array_equal(a, b)
    assert not np.array_equal(a, c)
    assert abs(np.corrcoef(a, b)[0, 1]) < 0.1


def test_fnv1a32() -> None:
    # The FNV reference values.
    assert rng.fnv1a32("") == 0x811C9DC5
    assert rng.fnv1a32("a") == 0xE40C292C
    assert rng.fnv1a32("foobar") == 0xBF9CF968
    assert rng.fnv1a32("/primary/productivity") == rng.fnv1a32("/primary/productivity")


def test_quantity_ids_refuse_collisions() -> None:
    ids = rng.quantity_ids(["events", "secondary:regulators", "control:c1/reduction", "events"])
    assert ids["events"] == rng.fnv1a32("events")
    assert len(ids) == 3
    # A known FNV-1a 32-bit collision.
    with pytest.raises(rng.QuantityCollisionError):
        rng.quantity_ids(["costarring", "liquid"])


def test_bounds_are_checked() -> None:
    with pytest.raises(ValueError, match="64-bit"):
        rng.seed_key(2**64)
    with pytest.raises(ValueError, match="32-bit"):
        rng.uniforms(1, 2**32, [0])
    with pytest.raises(ValueError, match="32-bit"):
        rng.uniforms(1, 1, [2**32])
