"""ARKHEIA Clearance — exact basis-point conservation (Law IV · SPL-1 · CON-1).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

SPL-1:  every bps_i in 1..=10_000, recipients unique, sum(bps_i) == 10_000.
CON-1:  sum(amount_i) == pool, via Hamilton / largest-remainder apportionment,
        ties broken by (rem_i DESC, recipient ASC). Checked before return.

Overflow-free in u128 without a wider intermediate: with
``pool = q * 10_000 + r`` (0 <= r < 10_000)::

    amount_i = q * bps_i + floor(r * bps_i / 10_000)   [+1 for the top `leftover` remainders]

``q * bps_i <= pool`` and ``r * bps_i < 10^8``, so no step leaves u128.
``leftover = sum(rem_i) / 10_000`` is an integer < n, and is handed out
only to entries with rem_i > 0, so no recipient ever exceeds its exact
real-valued share rounded up.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .u import BPS_SCALE, add64, add128, mul128, sub128, u64, u128


class ConservationError(Exception):
    """SPL-1 or CON-1 violated."""


@dataclass(frozen=True)
class Share:
    recipient: str
    bps: int
    amount: int


def check_bps(entries: Sequence[tuple[str, int]], max_entries: int) -> None:
    if not entries or len(entries) > max_entries:
        raise ConservationError("allocation count out of range")
    seen: set[str] = set()
    total = 0
    for recipient, bps in entries:
        if type(bps) is not int or bps < 1 or bps > BPS_SCALE:
            raise ConservationError("bps out of range")
        if recipient in seen:
            raise ConservationError("duplicate recipient")
        seen.add(recipient)
        total = add64(total, u64(bps))
    if total != BPS_SCALE:
        raise ConservationError("sum(bps) != 10000")


def allocate(pool: int, entries: Sequence[tuple[str, int]], max_entries: int) -> tuple[Share, ...]:
    check_bps(entries, max_entries)
    u128(pool)
    q, r = divmod(pool, BPS_SCALE)
    bases: list[int] = []
    rems: list[int] = []
    distributed = 0
    for _, bps in entries:
        frac_num = r * bps  # < 10^8
        base = add128(mul128(q, bps), frac_num // BPS_SCALE)
        bases.append(base)
        rems.append(frac_num % BPS_SCALE)
        distributed = add128(distributed, base)
    leftover = sub128(pool, distributed)
    if leftover >= len(entries):
        raise ConservationError("apportionment invariant broken")
    order = sorted(range(len(entries)), key=lambda i: (-rems[i], entries[i][0]))
    bonus = [0] * len(entries)
    for i in order[:leftover]:
        if rems[i] == 0:
            raise ConservationError("apportionment invariant broken")
        bonus[i] = 1
    shares = tuple(
        Share(recipient=entries[i][0], bps=entries[i][1], amount=add128(bases[i], bonus[i]))
        for i in range(len(entries))
    )
    total = 0
    for s in shares:
        total = add128(total, s.amount)
    if total != pool:  # CON-1, enforced before return
        raise ConservationError("sum(amount) != pool")
    return shares
