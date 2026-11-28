"""Opaque, constant-shape, constant-work X* rejections."""
from __future__ import annotations

import json
import re

from arkheia_clearance import artifacts as A
from arkheia_clearance.engine import REASONS
from arkheia_clearance.service import ClearanceService
from arkheia_clearance import timing

REJECTION_RE = re.compile(
    rb'\{"code":"X\*","decision":"REJECTED","receipt_hash":"[0-9a-f]{64}","schema":"ARKHEIA/clearance/rejection/v1"\}')


def _mandate_failures(h):
    w, a = h.w, h.w.agent("alpha")
    lease = w.lease(a, issued=0)
    good = w.mandate(a, lease, t=1, tag="g")
    return {
        "STRUCT": b'{"type":"MANDATE"}',
        "STRUCT_FLOAT": A.to_bytes(dict(good, lamport=1)).replace(b'"lamport":1', b'"lamport":1.0'),
        "STRUCT_DUPKEY": b'{"type":"MANDATE","type":"MANDATE"}',
        "STRUCT_NAN": b'{"lamport":NaN}',
        "STRUCT_UTF8": b"\xff\xfe",
        "OVERSIZE": b" " * (h.e.policy.max_body_bytes + 1),
        "REQUEST_SIG": A.to_bytes(dict(good, pool="7")),
        "LEASE_SIG": A.to_bytes(w.mandate(a, dict(lease, ttl=9), t=1, tag="ls")),
        "CONSERVATION": A.to_bytes(w.mandate(w.agent("b"), w.lease(w.agent("b"), issued=0), t=1, tag="c",
                                             allocations=[("x", 9_999)])),
        "SCOPE": A.to_bytes(w.mandate(w.agent("c"), w.lease(w.agent("c"), issued=0), t=1, tag="s",
                                      mcp_name="treasury.sweep")),
        "EXPIRED": A.to_bytes(w.mandate(w.agent("d"), w.lease(w.agent("d"), issued=50), t=2, tag="e")),
    }


def test_all_rejections_are_byte_identical_modulo_receipt_hash(h):
    bodies = set()
    for name, raw in _mandate_failures(h).items():
        r = h.e.verify_mandate(raw)
        assert r.status == 403, name
        assert REJECTION_RE.fullmatch(r.body), name
        bodies.add(r.body.replace(r.receipt_hash.encode(), b"H" * 64))
    for raw in (b"", b"[]", b'{"type":"OBSERVATION"}', A.to_bytes(h.w.observe(h.w.agent("x"), t=10 ** 9))):
        r = h.e.evaluate_aegis(raw)
        assert r.status == 403 and REJECTION_RE.fullmatch(r.body)
        bodies.add(r.body.replace(r.receipt_hash.encode(), b"H" * 64))
    assert len(bodies) == 1, "rejection bodies must not vary by reason or endpoint"


def test_rejection_body_leaks_no_reason_vocabulary(h):
    for raw in _mandate_failures(h).values():
        body = h.e.verify_mandate(raw).body.decode()
        for code in REASONS:
            if code not in ("OK",):
                assert code not in body


def test_signature_work_is_constant_per_endpoint(h):
    w, a = h.w, h.w.agent("alpha")
    expected = 2 + h.e.policy.max_delegation_depth
    samples = list(_mandate_failures(h).values()) + [A.to_bytes(w.mandate(a, w.lease(a, issued=0), t=h.t(), tag="ok"))]
    for raw in samples:
        before = h.e.sig_verifications
        h.e.verify_mandate(raw)
        assert h.e.sig_verifications - before == expected
    q = h.quarantine(w.agent("q"))
    for raw in (b"{}", A.to_bytes(w.observe(a, t=h.t())), A.to_bytes(w.release(w.agent("q"), q, t=h.t(), tag="r"))):
        before = h.e.sig_verifications
        h.e.evaluate_aegis(raw)
        assert h.e.sig_verifications - before == h.e.policy.max_approvals


def test_reason_is_recoverable_only_with_audit_key(h):
    from arkheia_clearance.engine import decode_reason

    h.e.verify_mandate(b"{}")
    rec = h.e.records()[-1]
    assert decode_reason(rec, h.w.audit_key) == "STRUCT"
    assert decode_reason(rec, b"\x00" * 32) is None


def test_internal_fault_fails_closed_with_a_receipt(h, monkeypatch):
    import arkheia_clearance.engine as eng

    def boom(*a, **k):
        raise RuntimeError("injected")

    w, a = h.w, h.w.agent("alpha")
    monkeypatch.setattr(eng, "allocate", boom)
    r, reason = h.mandate(w.mandate(a, w.lease(a, issued=0), t=h.t(), tag="f"))
    assert (r.status, reason) == (403, "INTERNAL_FAULT") and REJECTION_RE.fullmatch(r.body)
    assert h.state(a) == "ALLOW"


def test_latency_floor_applies_to_approvals_and_rejections(h):
    floor = 30_000_000
    svc = ClearanceService(h.e, floor_ns=floor)
    w, a = h.w, h.w.agent("alpha")
    for raw in (b"{}", A.to_bytes(w.mandate(a, w.lease(a, issued=0), t=h.t(), tag="ok"))):
        start = timing.now_ns()
        svc.dispatch("POST", "/api/mandate/verify", raw)
        assert timing.now_ns() - start >= floor


def test_ledger_fault_returns_fixed_503_and_no_verdict(h, monkeypatch):
    svc = ClearanceService(h.e, floor_ns=0)

    def broken(_receipt):
        raise OSError("disk gone")

    monkeypatch.setattr(h.e._ledger, "append", broken)
    status, _, body = svc.dispatch("POST", "/api/mandate/verify", b"{}")
    assert status == 503 and json.loads(body)["receipt_hash"] is None
