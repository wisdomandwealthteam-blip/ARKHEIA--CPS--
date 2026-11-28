"""ARKHEIA Clearance — deterministic golden world and scenario (TEST ONLY).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

All seeds here are SHA-256 of public labels: they are PUBLIC and must never
sign anything in production. Ed25519 signatures are deterministic (RFC 8032)
and the engine reads no clock and no randomness, so the scenario below yields
byte-identical requests, responses and receipt hashes on every run — that is
what ``golden/clearance_vectors.json`` pins.

    python -m arkheia_clearance.golden > tests/clearance/golden/clearance_vectors.json
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from . import artifacts as A
from .engine import AEGIS_EP, MANDATE_EP, ClearanceEngine, Response
from .policy import Policy
from .wire import Signer, sha256_hex

SCOPES = ("payments.quote", "payments.transfer")


def golden_signer(label: str) -> Signer:
    return Signer.from_seed(hashlib.sha256(b"ARKHEIA/clearance/golden/" + label.encode("ascii")).digest())


def golden_hex(label: str, nbytes: int) -> str:
    return hashlib.sha256(b"ARKHEIA/clearance/golden/id/" + label.encode("ascii")).hexdigest()[: nbytes + nbytes]


@dataclass
class World:
    policy: Policy = field(default_factory=Policy)
    engine_key: Signer = field(default_factory=lambda: golden_signer("engine"))
    issuer: Signer = field(default_factory=lambda: golden_signer("custos-issuer"))
    sensor: Signer = field(default_factory=lambda: golden_signer("aegis-sensor"))
    humans: tuple[Signer, ...] = field(default_factory=lambda: tuple(golden_signer(f"human-{i}") for i in range(3)))
    audit_key: bytes = hashlib.sha256(b"ARKHEIA/clearance/golden/audit-key").digest()

    def agent(self, name: str) -> Signer:
        return golden_signer("agent-" + name)

    def engine(self, ledger_path=None, policy: Policy | None = None) -> ClearanceEngine:
        return ClearanceEngine(signer=self.engine_key, audit_key=self.audit_key,
                               custos_issuers=[self.issuer.public_hex], sensors=[self.sensor.public_hex],
                               release_authorities=[h.public_hex for h in self.humans],
                               policy=policy or self.policy, ledger_path=ledger_path)

    # ---- artifact shortcuts -------------------------------------------------------------------
    def lease(self, holder: Signer, *, issued: int, ttl: int = 5_000, scopes=SCOPES,
              max_amount: int = 1_000_000_000_000_000_000_000_000, lease_id: str | None = None, issuer: Signer | None = None) -> dict:
        return A.lease(issuer or self.issuer, holder=holder.public_hex,
                       lease_id=lease_id or golden_hex(f"lease-{holder.public_hex[:8]}-{issued}", 16),
                       scopes=scopes, max_amount=max_amount, lamport_issued=issued, ttl=ttl)

    def mandate(self, actor: Signer, lease_obj: dict, *, t: int, tag: str, pool: int = 1_000_000,
                allocations=(("treasury", 6_000), ("ops", 4_000)), mcp_name: str = "payments.transfer",
                delegations=()) -> dict:
        return A.mandate(actor, mandate_id=golden_hex("mandate-" + tag, 16), lamport=t, mcp_name=mcp_name,
                         pool=pool, allocations=allocations, lease_obj=lease_obj, delegations=delegations)

    def observe(self, subject: Signer, *, t: int, sensor: Signer | None = None, **window) -> dict:
        return A.observation(sensor or self.sensor, subject=subject.public_hex, lamport=t, **window)

    def release(self, subject: Signer, qhash: str, *, t: int, tag: str, approvers=None, **kw) -> dict:
        return A.human_release(list(approvers if approvers is not None else self.humans[:1]),
                               subject=subject.public_hex, quarantine_receipt_hash=qhash, lamport=t,
                               nonce=golden_hex("nonce-" + tag, 16),
                               evidence_digest=golden_hex("evidence-" + tag, 32), **kw)


def _send(engine: ClearanceEngine, endpoint: str, obj: dict, headers=None) -> Response:
    raw = A.to_bytes(obj)
    return engine.verify_mandate(raw, headers) if endpoint == MANDATE_EP else engine.evaluate_aegis(raw, headers)


def run_scenario(world: World | None = None, engine: ClearanceEngine | None = None) -> list[dict[str, Any]]:
    """The canonical ALLOW → THROTTLE → ALLOW → X* → (absorbed) → HUMAN_RELEASE → ALLOW walk."""
    w = world or World()
    e = engine or w.engine()
    a, c = w.agent("alpha"), w.agent("charlie")
    steps: list[dict[str, Any]] = []

    def record(name: str, endpoint: str, obj: dict, subject: Signer) -> Response:
        r = _send(e, endpoint, obj)
        steps.append({
            "step": name, "endpoint": endpoint, "request": obj, "status": r.status,
            "response_sha256": sha256_hex(r.body), "receipt_hash": r.receipt_hash,
            "state_after": e.state_of(subject.public_hex), "engine_lamport": e.clock,
        })
        return r

    lease_a = w.lease(a, issued=0)
    record("01_allow_clear", MANDATE_EP, w.mandate(a, lease_a, t=e.clock + 1, tag="01"), a)
    record("02_drift_into_throttle", AEGIS_EP, w.observe(a, t=e.clock + 1, request_count=10, reject_count=10), a)
    record("03_throttled_within_interval", MANDATE_EP, w.mandate(a, lease_a, t=e.clock + 1, tag="03"), a)
    record("04_throttle_interval_elapsed", MANDATE_EP,
           w.mandate(a, lease_a, t=e.clock + w.policy.throttle_interval + 1, tag="04"), a)
    for i in range(w.policy.recover_steps):
        record(f"05_clean_descent_{i}", AEGIS_EP, w.observe(a, t=e.clock + 1, request_count=10, reject_count=1), a)
    # alpha (delegator) tries to hand charlie a scope it does not hold -> alpha enters X*
    hop = A.delegation(a, delegate=c.public_hex, lease_id=lease_a["lease_id"],
                       scopes=("payments.transfer", "treasury.sweep"), max_amount=100_000_000_000_000_000_000,
                       lamport_issued=1, ttl=4_000)
    r = record("06_scope_escalation_quarantines_delegator", MANDATE_EP,
               w.mandate(c, lease_a, t=e.clock + 1, tag="06", delegations=[hop]), a)
    qhash = r.receipt_hash
    record("07_x_star_absorbs_clean_observation", AEGIS_EP, w.observe(a, t=e.clock + 1, request_count=0), a)
    record("08_x_star_rejects_mandate", MANDATE_EP, w.mandate(a, lease_a, t=e.clock + 1, tag="08"), a)
    record("09_self_release_is_override_attempt", AEGIS_EP,
           w.release(a, qhash, t=e.clock + 1, tag="09", approvers=[a]), a)
    record("10_release_wrong_quarantine_hash", AEGIS_EP,
           w.release(a, "00" * 32, t=e.clock + 1, tag="10"), a)
    rel = w.release(a, qhash, t=e.clock + 1, tag="11")
    record("11_signed_human_release", AEGIS_EP, rel, a)
    record("12_pre_quarantine_lease_revoked", MANDATE_EP, w.mandate(a, lease_a, t=e.clock + 1, tag="12"), a)
    fresh = w.lease(a, issued=e.clock + 1)
    record("13_fresh_lease_returns_to_allow", MANDATE_EP, w.mandate(a, fresh, t=e.clock + 1, tag="13"), a)
    record("14_release_replay_rejected", AEGIS_EP, rel, a)
    return steps


def vectors() -> dict[str, Any]:
    w = World()
    e = w.engine()
    steps = run_scenario(w, e)
    return {
        "warning": "TEST ONLY - every key is derived from a public label. Never use in production.",
        "policy_version": w.policy.policy_version,
        "engine_public_key": w.engine_key.public_hex,
        "engine_public_key_id": w.engine_key.key_id,
        "steps": steps,
        "head_hash": e.head_hash,
        "chain_length": len(e.records()),
    }


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=2, sort_keys=True))
