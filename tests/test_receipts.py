"""Tests for the ARKHEIA DVE receipt mapping and verify-only gateway guard.

cps_backend must hold no private signing keys: these tests sign with an
ephemeral in-test "upstream engine" key and verify that cps_backend only
forwards bodies that are valid receipts from the trusted keyring —
anything else (or any misconfiguration) yields HTTP 502, fail closed.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from arkheia_receipt import (
    InMemoryLedger,
    ReceiptSigner,
    canonical_bytes,
    digest_bytes,
    signing_key_from_seed_hex,
)
from cps_backend.main import app
from cps_backend.schemas.clearcheck import Finding
from cps_backend.services.receipt_gateway import (
    BPS_SCALE,
    ReceiptGatewayError,
    check_id_evidence_digest,
    clearcheck_verdict_payload,
    guard,
)

client = TestClient(app)

CHECK_ID = "chk_" + "a" * 64
SEED_HEX = "11" * 32
COMMIT_SHA = "b" * 40


def _finding(code: str, severity: str) -> dict:
    return {
        "code": code,
        "severity": severity,
        "account_ref": "****1234",
        "field": "status",
        "description": "test",
    }


@pytest.fixture()
def upstream(tmp_path, monkeypatch):
    """An ephemeral signing engine plus a trusted keyring for cps_backend."""
    key = signing_key_from_seed_hex(SEED_HEX)
    signer = ReceiptSigner(
        signing_key=key,
        engine_id="cps_statute_engine",
        commit_sha=COMMIT_SHA,
        ledger=InMemoryLedger(),
    )
    keyring_path = tmp_path / "arkheia-public-keys.json"
    keyring_path.write_text(json.dumps({
        "keys": [{
            "public_key_id": key.public_key_id,
            "algorithm": "Ed25519",
            "public_key_hex": key.public_key_hex,
            "status": "active",
        }]
    }))
    monkeypatch.delenv("ARKHEIA_SIGNING_SEED_HEX", raising=False)
    monkeypatch.setenv("ARKHEIA_TRUSTED_KEYS_FILE", str(keyring_path))
    return signer


def _signed_receipt_bytes(signer: ReceiptSigner, findings: list[dict]) -> bytes:
    payload = clearcheck_verdict_payload(CHECK_ID, findings)
    receipt, _ = signer.issue(
        wrapper_domain="clearcheck",
        input_digest=digest_bytes(b'{"raw":"request"}'),
        verdict_payload=payload,
    )
    return canonical_bytes(receipt)


# ---------------------------------------------------------------------------
# ClearCheck -> verdict_payload mapping (integer basis points)
# ---------------------------------------------------------------------------

def test_no_findings_maps_to_cleared_with_zero_risk():
    payload = clearcheck_verdict_payload(CHECK_ID, [])
    assert payload["verdict"] == "CLEARED"
    assert payload["reason_codes"] == []
    assert payload["rule_set"] == {"id": "cps.clearcheck", "version": "1.0.0"}
    assert payload["evidence_digests"] == ["a" * 64]
    assert payload["metrics"]["risk_score_bps"] == 0
    assert payload["metrics"]["clean_confidence_bps"] == BPS_SCALE
    assert payload["determinism"] == {"mode": "deterministic", "fallback_used": False}


def test_high_severity_maps_to_blocked_and_bps_are_bounded_integers():
    findings = [
        _finding("BALANCE_ON_CLOSED_ACCOUNT", "high"),
        _finding("DATE_IN_FUTURE", "medium"),
        _finding("CLOSED_WITHOUT_DATE", "low"),
    ]
    payload = clearcheck_verdict_payload(CHECK_ID, findings)
    assert payload["verdict"] == "BLOCKED"
    assert payload["reason_codes"] == sorted(
        ["BALANCE_ON_CLOSED_ACCOUNT", "CLOSED_WITHOUT_DATE", "DATE_IN_FUTURE"]
    )
    metrics = payload["metrics"]
    for name, value in metrics.items():
        assert isinstance(value, int) and not isinstance(value, bool), name
    for name in (
        "risk_score_bps",
        "clean_confidence_bps",
        "high_severity_share_bps",
        "medium_severity_share_bps",
        "low_severity_share_bps",
    ):
        assert 0 <= metrics[name] <= BPS_SCALE, name
    # (10000 + 5000 + 2000) // 3 == 5666 — integer division, no floats.
    assert metrics["risk_score_bps"] == 5666
    assert metrics["clean_confidence_bps"] == BPS_SCALE - 5666
    assert metrics["high_severity_share_bps"] == BPS_SCALE // 3
    assert metrics["findings_total"] == 3


def test_medium_and_low_only_maps_to_requires_review_and_accepts_models():
    findings = [
        Finding(**_finding("DATE_IN_FUTURE", "medium")),
        Finding(**_finding("CLOSED_WITHOUT_DATE", "low")),
    ]
    payload = clearcheck_verdict_payload(CHECK_ID, findings)
    assert payload["verdict"] == "REQUIRES_REVIEW"
    assert payload["metrics"]["findings_medium"] == 1
    assert payload["metrics"]["findings_low"] == 1


def test_unknown_severity_weighs_as_maximum_risk():
    payload = clearcheck_verdict_payload(CHECK_ID, [_finding("SOMETHING_NEW", "critical")])
    assert payload["metrics"]["risk_score_bps"] == BPS_SCALE


def test_malformed_check_id_is_rejected():
    with pytest.raises(ReceiptGatewayError) as excinfo:
        check_id_evidence_digest("chk_not-a-digest")
    assert excinfo.value.code == "EVIDENCE_DIGEST_INVALID"


def test_mapping_passes_the_signing_schema_gate(upstream):
    # The signer validates against DVE schema v1.0.0 before signing;
    # issuance succeeding proves the mapping meets the contract.
    body = _signed_receipt_bytes(upstream, [_finding("PAID_WITH_PAST_DUE", "high")])
    receipt = json.loads(body)
    assert receipt["wrapper_domain"] == "clearcheck"
    assert receipt["verdict_payload"]["verdict"] == "BLOCKED"


# ---------------------------------------------------------------------------
# Gateway guard — fail closed, HTTP 502 on anything unverified
# ---------------------------------------------------------------------------

def test_guard_forwards_valid_receipt(upstream):
    body = _signed_receipt_bytes(upstream, [])
    status, headers, forwarded = guard(body)
    assert status == 200
    assert forwarded == body
    assert any(name == "x-arkheia-receipt-hash" for name, _ in headers)


def test_guard_rejects_tampered_receipt_with_502(upstream):
    receipt = json.loads(_signed_receipt_bytes(upstream, []))
    receipt["verdict_payload"]["verdict"] = "BLOCKED"
    status, _, body = guard(canonical_bytes(receipt))
    assert status == 502
    assert json.loads(body)["error_code"] == "UPSTREAM_RECEIPT_INVALID"


def test_guard_rejects_unsigned_json_with_502(upstream):
    status, _, body = guard(b'{"verdict": "CLEARED"}')
    assert status == 502
    assert json.loads(body)["error_code"] == "UPSTREAM_RECEIPT_INVALID"


def test_guard_rejects_untrusted_signer_with_502(upstream, tmp_path, monkeypatch):
    body = _signed_receipt_bytes(upstream, [])
    other = signing_key_from_seed_hex("22" * 32)
    other_keyring = tmp_path / "other-keys.json"
    other_keyring.write_text(json.dumps({
        "keys": [{
            "public_key_id": other.public_key_id,
            "algorithm": "Ed25519",
            "public_key_hex": other.public_key_hex,
            "status": "active",
        }]
    }))
    monkeypatch.setenv("ARKHEIA_TRUSTED_KEYS_FILE", str(other_keyring))
    status, _, out = guard(body)
    assert status == 502
    assert json.loads(out)["reason"] == "UNKNOWN_SIGNER"


def test_guard_fails_closed_without_keyring(monkeypatch):
    monkeypatch.delenv("ARKHEIA_SIGNING_SEED_HEX", raising=False)
    monkeypatch.delenv("ARKHEIA_TRUSTED_KEYS_FILE", raising=False)
    status, _, body = guard(b"{}")
    assert status == 502
    assert json.loads(body)["reason"] == "TRUSTED_KEYS_NOT_CONFIGURED"


def test_guard_refuses_to_run_with_a_private_signing_key(upstream, monkeypatch):
    body = _signed_receipt_bytes(upstream, [])
    monkeypatch.setenv("ARKHEIA_SIGNING_SEED_HEX", SEED_HEX)
    status, _, out = guard(body)
    assert status == 502
    assert json.loads(out)["reason"] == "GATEWAY_HOLDS_SIGNING_KEY"


# ---------------------------------------------------------------------------
# Verifier routes (additive; existing routes untouched)
# ---------------------------------------------------------------------------

def test_verify_receipt_route_validates_a_signed_receipt(upstream):
    body = _signed_receipt_bytes(upstream, [_finding("DATE_IN_FUTURE", "medium")])
    resp = client.post(
        "/v1/verify-receipt",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 200
    out = resp.json()
    assert out["valid"] is True
    assert out["wrapper_domain"] == "clearcheck"
    assert out["engine_id"] == "cps_statute_engine"


def test_verify_receipt_route_reports_invalid_receipts(upstream):
    resp = client.post(
        "/v1/verify-receipt",
        content=b'{"not": "a receipt"}',
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 200
    out = resp.json()
    assert out["valid"] is False
    assert out["error_code"] == "SCHEMA_INVALID"


def test_public_keys_route_publishes_the_keyring(upstream):
    resp = client.get("/v1/public-keys")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert keys[0]["public_key_id"] == upstream.public_key_id
    assert "public_key_hex" in keys[0]


def test_routes_fail_closed_when_unconfigured(monkeypatch):
    monkeypatch.delenv("ARKHEIA_SIGNING_SEED_HEX", raising=False)
    monkeypatch.delenv("ARKHEIA_TRUSTED_KEYS_FILE", raising=False)
    resp = client.get("/v1/public-keys")
    assert resp.status_code == 503
    assert resp.json()["error_code"] == "TRUSTED_KEYS_NOT_CONFIGURED"


def test_existing_routes_are_untouched():
    assert client.get("/health").status_code == 200
