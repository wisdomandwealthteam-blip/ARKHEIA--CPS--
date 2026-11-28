"""ARKHEIA Clearance — builders for signed wire artifacts.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Used by CUSTOS issuers, agents, sensors and human operators to produce the
exact canonical bytes the engine verifies — and by the golden suite and the
"Rogue Agent vs. ARKHEIA Mandate" playground. Every builder returns plain
JSON-ready dicts; ``to_bytes`` gives the canonical request body.
"""
from __future__ import annotations

from typing import Any, Iterable, Sequence

from . import wire
from .policy import MCP_METHOD, POLICY_VERSION
from .u import format_u128


def to_bytes(obj: Any) -> bytes:
    return wire.jcs(obj)


def _signed(domain: bytes, obj: dict[str, Any], signer: wire.Signer, field: str = "sig") -> dict[str, Any]:
    obj = dict(obj)
    obj[field] = signer.sign_hex(wire.signing_input(domain, obj, field))
    return obj


def lease(issuer: wire.Signer, *, holder: str, lease_id: str, scopes: Iterable[str], max_amount: int,
          lamport_issued: int, ttl: int, swarm_id: str = "swarm-1") -> dict[str, Any]:
    return _signed(wire.DOMAIN_LEASE, {
        "lease_id": lease_id, "issuer": issuer.public_hex, "holder": holder, "swarm_id": swarm_id,
        "scopes": sorted(scopes), "max_amount": format_u128(max_amount),
        "lamport_issued": lamport_issued, "ttl": ttl,
    }, issuer)


def delegation(delegator: wire.Signer, *, delegate: str, lease_id: str, scopes: Iterable[str],
               max_amount: int, lamport_issued: int, ttl: int) -> dict[str, Any]:
    return _signed(wire.DOMAIN_DELEGATION, {
        "delegator": delegator.public_hex, "delegate": delegate, "lease_id": lease_id,
        "scopes": sorted(scopes), "max_amount": format_u128(max_amount),
        "lamport_issued": lamport_issued, "ttl": ttl,
    }, delegator)


def mandate(actor: wire.Signer, *, mandate_id: str, lamport: int, mcp_name: str, pool: int,
            allocations: Sequence[tuple[str, int]], lease_obj: dict[str, Any],
            delegations: Sequence[dict[str, Any]] = ()) -> dict[str, Any]:
    return _signed(wire.DOMAIN_MANDATE, {
        "type": "MANDATE", "mandate_id": mandate_id, "lamport": lamport,
        "tool_call": {"mcp_method": MCP_METHOD, "mcp_name": mcp_name},
        "pool": format_u128(pool),
        "allocations": [{"recipient": r, "bps": b} for r, b in allocations],
        "lease": lease_obj, "delegations": list(delegations), "actor": actor.public_hex,
    }, actor)


def observation(sensor: wire.Signer, *, subject: str, lamport: int, request_count: int = 0,
                reject_count: int = 0, fanout: int = 0, scope_violations: int = 0,
                signature_failures: int = 0, override_attempts: int = 0) -> dict[str, Any]:
    return _signed(wire.DOMAIN_OBSERVATION, {
        "type": "OBSERVATION", "subject": subject, "lamport": lamport, "sensor": sensor.public_hex,
        "window": {"request_count": request_count, "reject_count": reject_count, "fanout": fanout,
                   "scope_violations": scope_violations, "signature_failures": signature_failures,
                   "override_attempts": override_attempts},
    }, sensor)


def human_release(approvers: Sequence[wire.Signer], *, subject: str, quarantine_receipt_hash: str,
                  lamport: int, nonce: str, evidence_digest: str, passed: bool = True,
                  policy_version: str = POLICY_VERSION) -> dict[str, Any]:
    body = {
        "type": "HUMAN_RELEASE", "subject": subject, "quarantine_receipt_hash": quarantine_receipt_hash,
        "policy_version": policy_version,
        "invariant_check": {"passed": passed, "evidence_digest": evidence_digest},
        "lamport": lamport, "nonce": nonce,
    }
    message = wire.signing_input(wire.DOMAIN_RELEASE, body, "approvals")
    body["approvals"] = [{"authority": s.public_hex, "sig": s.sign_hex(message)} for s in approvers]
    return body
