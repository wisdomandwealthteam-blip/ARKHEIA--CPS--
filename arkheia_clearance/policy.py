"""ARKHEIA Clearance — policy pack (all integer, version-pinned).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Identical inputs + identical ``policy_version`` MUST yield byte-identical
outputs (Kernel 7, DETERMINISTIC_BEHAVIOR). Any change to a value here is a
policy change and must bump ``policy_version``.
"""
from __future__ import annotations

from dataclasses import dataclass

from .u import BPS_SCALE, WIRE_INT_MAX

POLICY_VERSION = "arkheia.mandate-aegis/1.0.1"
MCP_PROTOCOL_VERSION = "2026-07-28"
MCP_METHOD = "tools/call"


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Policy:
    policy_version: str = POLICY_VERSION
    # Lamport bounds
    max_lamport_skew: int = 1_000          # request lamport may lead the engine clock by at most this
    max_lease_ttl: int = 100_000           # Δt upper bound for any CUSTOS lease or A2A hop
    permit_ttl: int = 64                   # execution permit validity in Lamport ticks
    # A2A delegation
    max_delegation_depth: int = 4
    max_scopes: int = 64
    # bps-ledger
    max_allocations: int = 64
    # Aegis drift d_OP(t) in basis points
    theta2_bps: int = 4_000                # THROTTLE band:  Θ2 <= d < Θ3
    theta3_bps: int = 8_000                # QUARANTINE_X_STAR: d >= Θ3
    recover_steps: int = 3                 # N consecutive clean Lamport steps THROTTLE -> ALLOW
    w_reject_bps: int = 5_000              # drift weights; must sum to exactly 10_000
    w_rate_bps: int = 3_000
    w_fanout_bps: int = 2_000
    rate_cap: int = 1_000                  # requests per window that saturate the rate term
    fanout_cap: int = 16                   # sub-agent fan-out that saturates the fan-out term
    throttle_interval: int = 10            # THROTTLE: at most one CLEARED mandate per this many ticks
    # HUMAN_RELEASE
    release_quorum: int = 1
    max_approvals: int = 5
    # Spec table: "expired/escalated CUSTOS lease" is a hard X* trigger.
    expired_lease_is_hard: bool = True
    # Transport
    max_body_bytes: int = 65_536

    def validate(self) -> "Policy":
        ints = {k: v for k, v in self.__dict__.items() if k not in ("policy_version", "expired_lease_is_hard")}
        for name, v in ints.items():
            if type(v) is not int or v < 0 or v > WIRE_INT_MAX:
                raise PolicyError(f"{name} must be a non-negative wire integer")
        if type(self.expired_lease_is_hard) is not bool:
            raise PolicyError("expired_lease_is_hard must be bool")
        if not (0 < self.theta2_bps < self.theta3_bps <= BPS_SCALE):
            raise PolicyError("require 0 < theta2 < theta3 <= 10000")
        if self.w_reject_bps + self.w_rate_bps + self.w_fanout_bps != BPS_SCALE:
            raise PolicyError("drift weights must sum to 10000 bps")
        for name in ("max_lease_ttl", "permit_ttl", "max_delegation_depth", "max_scopes", "max_allocations",
                     "recover_steps", "rate_cap", "fanout_cap", "release_quorum", "max_approvals", "max_body_bytes"):
            if getattr(self, name) < 1:
                raise PolicyError(f"{name} must be >= 1")
        if self.release_quorum > self.max_approvals:
            raise PolicyError("release_quorum cannot exceed max_approvals")
        return self
