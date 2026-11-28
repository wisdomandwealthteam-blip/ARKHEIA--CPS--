"""7™ v1.0.1: a signed permit never outlives its verified CUSTOS authority.

All expiry fields are exclusive Lamport ticks, not wall-clock timestamps.
"""
from __future__ import annotations

import copy
import json

import pytest
from fastapi.testclient import TestClient

from arkheia_clearance import POLICY_VERSION, __version__, artifacts as A, wire
from arkheia_clearance.aegis import X_STAR
from arkheia_clearance.engine import verify_permit
from arkheia_clearance.receipts import receipt_hash, verify_chain
from arkheia_clearance.service import ClearanceService
from arkheia_clearance.u import WIRE_INT_MAX
from cps_backend.main import app
from cps_backend.routers import clearance


def clear(h, *, ttl=10, t=1):
    a = h.w.agent("permit-bounds")
    lease = h.w.lease(a, issued=0, ttl=ttl)
    response, reason = h.mandate(h.w.mandate(a, lease, t=t, tag=f"permit-{ttl}-{t}"))
    assert (response.status, reason) == (200, "OK")
    return json.loads(response.body), lease


@pytest.mark.parametrize("ttl,t", [(5000, 1), (10, 1), (10, 8), (3, 1)])
def test_permit_ttl_is_capped_to_verified_custos_lease(h, ttl, t):
    body, lease = clear(h, ttl=ttl, t=t)
    permit = body["permit"]
    lease_end = lease["lamport_issued"] + lease["ttl"]
    assert permit["issued_lamport"] == body["receipt"]["lamport"] == t + 1
    expected = min(permit["issued_lamport"] + h.e.policy.permit_ttl, lease_end)
    assert permit["expires_at"] == permit["not_after_lamport"] == expected
    assert permit["lease_expires_at"] == lease_end
    assert permit["issued_lamport"] < expected <= lease_end
    assert verify_permit(permit, h.e.public_key_hex, current_lamport=permit["issued_lamport"])
    assert body["receipt_hash"] == receipt_hash(body["receipt"])
    assert verify_chain(h.e.records(), h.e.trusted_keys())["valid"]


@pytest.mark.parametrize("t", [9, 10, 11])
def test_expired_at_issuance_or_request_never_emits_a_permit(h, t):
    a = h.w.agent("expired-lease")
    lease = h.w.lease(a, issued=0, ttl=10)
    r, reason = h.mandate(h.w.mandate(a, lease, t=t, tag=f"expired-{t}"))
    body = json.loads(r.body)
    assert (r.status, reason, h.state(a)) == (403, "LEASE_EXPIRED", X_STAR)
    assert body["code"] == "X*" and "permit" not in body
    assert h.e.records()[-1]["decision"] == "REJECTED"
    assert h.e.records()[-1]["decision_core"]["effects"]["mandate_id"] is None
    assert verify_chain(h.e.records(), h.e.trusted_keys())["valid"]


def test_stale_request_clock_cannot_reanimate_an_expired_lease(h):
    a = h.w.agent("stale-clock")
    lease = h.w.lease(a, issued=0, ttl=10)
    mandate = h.w.mandate(a, lease, t=1, tag="valid-request-time-only")
    for _ in range(12):
        h.e.verify_mandate(b"{}")
    assert h.e.clock > 10
    r, reason = h.mandate(mandate)
    assert (r.status, reason) == (403, "LEASE_EXPIRED")
    assert "permit" not in json.loads(r.body)


@pytest.mark.parametrize("hop_ttl", [20, 5])
def test_permit_is_capped_to_narrower_a2a_delegation(h, hop_ttl):
    w = h.w
    delegator, actor = w.agent("bounded-parent"), w.agent("bounded-child")
    root = w.lease(delegator, issued=0, ttl=100)
    hop = A.delegation(delegator, delegate=actor.public_hex, lease_id=root["lease_id"],
                       scopes=("payments.transfer",), max_amount=10 ** 20,
                       lamport_issued=0, ttl=hop_ttl)
    r, reason = h.mandate(w.mandate(actor, root, t=1, tag=f"hop-{hop_ttl}", delegations=(hop,)))
    assert (r.status, reason) == (200, "OK")
    permit = json.loads(r.body)["permit"]
    assert permit["expires_at"] == permit["lease_expires_at"] == hop_ttl
    assert permit["expires_at"] < root["lamport_issued"] + root["ttl"]


def test_expired_delegation_rejects_even_when_root_lease_is_live(h):
    w = h.w
    delegator, actor = w.agent("live-root"), w.agent("expired-hop")
    root = w.lease(delegator, issued=0, ttl=100)
    hop = A.delegation(delegator, delegate=actor.public_hex, lease_id=root["lease_id"],
                       scopes=("payments.transfer",), max_amount=10 ** 20, lamport_issued=0, ttl=3)
    r, reason = h.mandate(w.mandate(actor, root, t=2, tag="hop-expired-at-issue", delegations=(hop,)))
    assert (r.status, reason) == (403, "LEASE_EXPIRED")
    assert "permit" not in json.loads(r.body)


@pytest.mark.parametrize("clock,valid", [(2, True), (9, True), (10, False), (11, False), (1, False), (True, False), (None, True)])
def test_verifier_rejects_expired_permits_using_trusted_lamport_clock(h, clock, valid):
    body, _ = clear(h)
    assert verify_permit(body["permit"], h.e.public_key_hex, current_lamport=clock) is valid


@pytest.mark.parametrize("mutation", ["outlives-lease", "empty-window", "alias-mismatch", "legacy-policy"])
def test_even_resigned_invalid_bounds_or_legacy_permits_fail_closed(h, mutation):
    body, _ = clear(h)
    permit = copy.deepcopy(body["permit"])
    if mutation == "outlives-lease":
        permit["expires_at"] = permit["not_after_lamport"] = permit["lease_expires_at"] + 1
    elif mutation == "empty-window":
        permit["expires_at"] = permit["not_after_lamport"] = permit["issued_lamport"]
    elif mutation == "alias-mismatch":
        permit["not_after_lamport"] = permit["expires_at"] - 1
    else:
        permit["policy_version"] = "arkheia.mandate-aegis/1.0.0"
        permit.pop("expires_at")
        permit.pop("lease_expires_at")
    permit["signature"]["value"] = h.w.engine_key.sign_hex(wire.signing_input(wire.DOMAIN_PERMIT, permit, "signature"))
    assert not verify_permit(permit, h.e.public_key_hex, current_lamport=2)


def test_expiry_fields_are_signed_not_unsigned_metadata(h):
    body, _ = clear(h)
    for field in ("expires_at", "not_after_lamport", "lease_expires_at"):
        permit = copy.deepcopy(body["permit"])
        permit[field] += 1
        assert not verify_permit(permit, h.e.public_key_hex)


def test_wire_integer_horizon_never_overflows_signed_permit(h):
    h.e._clock = WIRE_INT_MAX - 5
    a = h.w.agent("wire-horizon")
    lease = h.w.lease(a, issued=WIRE_INT_MAX - 10, ttl=20)
    r, reason = h.mandate(h.w.mandate(a, lease, t=WIRE_INT_MAX - 4, tag="wire-bound"))
    assert (r.status, reason) == (200, "OK")
    permit = json.loads(r.body)["permit"]
    assert permit["expires_at"] == permit["lease_expires_at"] == WIRE_INT_MAX
    assert verify_permit(permit, h.e.public_key_hex, current_lamport=WIRE_INT_MAX - 3)


@pytest.mark.parametrize("t,expected", [(1, 200), (9, 403)])
def test_fastapi_enforces_capped_or_expired_lease_without_coercion(h, t, expected):
    clearance.set_service(ClearanceService(h.e, 0))
    try:
        a = h.w.agent("http-lease-bounds")
        lease = h.w.lease(a, issued=0, ttl=10)
        obj = h.w.mandate(a, lease, t=t, tag=f"http-{t}")
        response = TestClient(app).post("/api/mandate/verify", content=A.to_bytes(obj),
                                        headers={"Content-Type": "application/json"})
        assert response.status_code == expected
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        if expected == 200:
            assert body["permit"]["expires_at"] == 10
            assert verify_permit(body["permit"], h.e.public_key_hex, current_lamport=2)
        else:
            assert body["code"] == "X*" and "permit" not in body and "LEASE_EXPIRED" not in response.text
    finally:
        clearance.set_service(None)


def test_hardening_version_is_pinned_without_module_rename():
    assert __version__ == "1.0.1"
    assert POLICY_VERSION == "arkheia.mandate-aegis/1.0.1"
