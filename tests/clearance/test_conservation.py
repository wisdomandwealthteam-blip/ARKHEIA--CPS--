"""Law IV: SPL-1 (sum bps == 10000) and CON-1 (sum amount == pool), u128, largest remainder."""
from __future__ import annotations

import json
import random

import pytest

from arkheia_clearance.aegis import X_STAR
from arkheia_clearance.conservation import ConservationError, allocate, check_bps
from arkheia_clearance.u import U128_MAX

MAX = 64


@pytest.mark.parametrize("entries", [
    [("a", 10_000)],
    [("a", 5_000), ("b", 5_000)],
    [("a", 1)] + [(f"r{i}", 1) for i in range(1, 64)][:0] + [("z", 9_999)],
])
def test_spl1_accepts_exact_sum(entries):
    check_bps(entries, MAX)


@pytest.mark.parametrize("entries", [
    [], [("a", 9_999)], [("a", 10_001)], [("a", 6_000), ("b", 4_001)],
    [("a", 0), ("b", 10_000)], [("a", 5_000), ("a", 5_000)], [("a", True)],
    [("a", -1), ("b", 10_001)], [(f"r{i}", 1) for i in range(65)],
])
def test_spl1_rejects(entries):
    with pytest.raises(ConservationError):
        check_bps(entries, MAX)


def test_con1_property_random_pools_and_splits():
    rng = random.Random(10_000)
    for _ in range(3_000):
        n = rng.randrange(1, 12)
        cuts = sorted(rng.sample(range(1, 10_000), n - 1))
        bps = [b - a for a, b in zip([0] + cuts, cuts + [10_000])]
        entries = [(f"r{rng.randrange(10**6):06d}-{i}", b) for i, b in enumerate(bps)]
        pool = rng.choice([0, 1, 7, 9_999, 10_000, 10_001, rng.randrange(1 << 64), rng.randrange(U128_MAX + 1), U128_MAX])
        shares = allocate(pool, entries, MAX)
        assert sum(s.amount for s in shares) == pool
        for s in shares:  # each within one unit of its exact share: |amount*10000 - pool*bps| < 10000
            assert abs(s.amount * 10_000 - pool * s.bps) < 10_000


def test_hamilton_tie_break_rem_desc_then_id_asc():
    shares = allocate(1, [("zeta", 5_000), ("alpha", 5_000)], MAX)  # equal remainders: id ASC wins
    assert {s.recipient: s.amount for s in shares} == {"zeta": 0, "alpha": 1}
    shares = allocate(10, [("a", 3_333), ("b", 3_333), ("c", 3_334)], MAX)
    assert [s.amount for s in shares] == [3, 3, 4]


def test_u128_extremes_do_not_overflow():
    shares = allocate(U128_MAX, [("a", 1), ("b", 9_999)], MAX)
    assert sum(s.amount for s in shares) == U128_MAX


def test_engine_conservation_breach_is_hard(h):
    w, a = h.w, h.w.agent("alpha")
    lease = w.lease(a, issued=0)
    r, reason = h.mandate(w.mandate(a, lease, t=h.t(), tag="bad", allocations=[("x", 6_000), ("y", 3_999)]))
    assert (r.status, reason, h.state(a)) == (403, "CONSERVATION_BREACH", X_STAR)


def test_engine_cleared_allocations_are_conserved(h):
    w, a = h.w, h.w.agent("alpha")
    pool = 10 ** 30 + 3
    r, _ = h.mandate(w.mandate(a, w.lease(a, issued=0, max_amount=10 ** 31), t=h.t(), tag="ok", pool=pool,
                               allocations=[("x", 3_333), ("y", 3_333), ("z", 3_334)]))
    body = json.loads(r.body)
    assert r.status == 200
    assert sum(int(s["amount"]) for s in body["allocations"]) == pool
    assert all(type(s["amount"]) is str for s in body["allocations"])  # u128 never as JSON number
