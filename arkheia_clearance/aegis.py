"""ARKHEIA Aegis-Swarm — the four-state swarm defense machine (pure functions).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

    S_swarm = { ALLOW, THROTTLE, QUARANTINE_X_STAR, HUMAN_RELEASE }

Transition function δ(mem, d, hard) for an observation step, where d is the
integer drift d_OP(t) in bps and ``hard`` is any hard-invariant breach:

    state              | condition                         | next
    -------------------+-----------------------------------+-------------------------------
    QUARANTINE_X_STAR  | (any)                             | QUARANTINE_X_STAR  (absorbing)
    *                  | hard  or  d >= Θ3                 | QUARANTINE_X_STAR
    ALLOW|HUMAN_RELEASE| Θ2 <= d < Θ3                      | THROTTLE
    ALLOW|HUMAN_RELEASE| d < Θ2                            | ALLOW
    THROTTLE           | d >= Θ2, or d > last_d (I rising) | THROTTLE, clean := 0
    THROTTLE           | d < Θ2 and d <= last_d (descent)  | clean+1; ALLOW once clean == N

The *only* edge out of QUARANTINE_X_STAR is ``release()``, which the engine
calls solely after verifying a signed human Release artifact bound to the
exact quarantine receipt hash. Nothing in ``step()`` can leave X*: this is
what the golden suite checks exhaustively.

Scott's Law descent is enforced in its deterministic integer form:
I(x_{t+1}) <= I(x_t), with I = d_OP. Any rise resets the clean counter.
"""
from __future__ import annotations

from dataclasses import dataclass

from .policy import Policy
from .u import BPS_SCALE, mul64, u64

ALLOW = "ALLOW"
THROTTLE = "THROTTLE"
X_STAR = "QUARANTINE_X_STAR"
HUMAN_RELEASE = "HUMAN_RELEASE"
STATES = (ALLOW, THROTTLE, X_STAR, HUMAN_RELEASE)


@dataclass(frozen=True)
class Window:
    request_count: int
    reject_count: int
    fanout: int
    scope_violations: int
    signature_failures: int
    override_attempts: int


@dataclass(frozen=True)
class Mem:
    state: str = ALLOW
    clean_steps: int = 0
    last_drift: int | None = None


def _ratio_bps(num: int, den: int) -> int:
    """min(10000, floor(num * 10000 / den)) in pure integer arithmetic."""
    if den == 0:
        return 0
    v = mul64(u64(num), BPS_SCALE) // den
    return BPS_SCALE if v > BPS_SCALE else v


def drift_bps(w: Window, p: Policy) -> int:
    reject = _ratio_bps(w.reject_count, w.request_count)
    rate = _ratio_bps(w.request_count, p.rate_cap)
    fan = _ratio_bps(w.fanout, p.fanout_cap)
    d = (p.w_reject_bps * reject + p.w_rate_bps * rate + p.w_fanout_bps * fan) // BPS_SCALE
    if not 0 <= d <= BPS_SCALE:
        raise ArithmeticError("drift out of range")
    return d


def is_hard(w: Window) -> bool:
    return w.scope_violations > 0 or w.signature_failures > 0 or w.override_attempts > 0


def step(mem: Mem, d: int, hard: bool, p: Policy) -> Mem:
    if mem.state == X_STAR:
        return mem
    if hard or d >= p.theta3_bps:
        return Mem(X_STAR, 0, d)
    if mem.state in (ALLOW, HUMAN_RELEASE):
        return Mem(THROTTLE, 0, d) if d >= p.theta2_bps else Mem(ALLOW, 0, d)
    if mem.state != THROTTLE:
        raise ValueError("unknown state")
    if d >= p.theta2_bps:
        return Mem(THROTTLE, 0, d)
    if mem.last_drift is not None and d > mem.last_drift:
        return Mem(THROTTLE, 0, d)
    n = mem.clean_steps + 1
    return Mem(ALLOW, 0, d) if n >= p.recover_steps else Mem(THROTTLE, n, d)


def quarantine(mem: Mem) -> Mem:
    return mem if mem.state == X_STAR else Mem(X_STAR, 0, mem.last_drift)


def release(mem: Mem) -> Mem:
    if mem.state != X_STAR:
        raise ValueError("release is only defined from QUARANTINE_X_STAR")
    return Mem(HUMAN_RELEASE, 0, None)


def after_clear(mem: Mem) -> Mem:
    """A CLEARED mandate under a fresh post-release lease completes HUMAN_RELEASE -> ALLOW."""
    if mem.state == X_STAR:
        raise ValueError("X* subject cannot clear")
    return Mem(ALLOW, 0, None) if mem.state == HUMAN_RELEASE else mem
