"""Egress helpers: signed or explicit error, never an unsigned verdict."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from arkheia_receipt import (
    BpsLedgerAdapter, InMemoryLedger, Keyring, ReceiptSigner, build_verdict_payload, digest_json, parse_strict_json,
    signing_key_from_seed_hex, verify_receipt,
)
from arkheia_receipt.respond import RECEIPT_HASH_HEADER, send_signed_ws, signed_response

V = json.loads((Path(__file__).resolve().parents[2] / "test-vectors" / "vectors.json").read_text("utf-8"))
KEY = signing_key_from_seed_hex(V["rfc8032_kat"]["seed_hex"])
RING = Keyring(V["keyring"])
COMMIT = "0600a668543e268da504a74c1a4999df8328057b"
PAYLOAD = build_verdict_payload(verdict="NON_COMPLIANT", reason_codes=["AC_2_3_VIOLATION"], rule_set={"id": "custos.ac2", "version": "1.0.0"})


def test_signed_response_and_fail_closed():
    s = ReceiptSigner(signing_key=KEY, engine_id="custos", commit_sha=COMMIT, ledger=InMemoryLedger())
    status, headers, body = signed_response(s, wrapper_domain="governancecheck", input_digest=digest_json({"x": 1}), verdict_payload=PAYLOAD)
    res = verify_receipt(parse_strict_json(body), RING)
    assert status == 200 and res["valid"] and dict(headers)[RECEIPT_HASH_HEADER] == res["receipt_hash"]

    broken = ReceiptSigner(signing_key=KEY, engine_id="custos", commit_sha=COMMIT, ledger=BpsLedgerAdapter())
    status, _, body = signed_response(broken, wrapper_domain="governancecheck", input_digest=digest_json({}), verdict_payload=PAYLOAD)
    assert status == 500 and json.loads(body) == {"error_code": "LEDGER_NOT_CONFIGURED"}


def test_ws_frames():
    frames: list[dict] = []

    async def send_text(t: str) -> None:
        frames.append(json.loads(t))

    s = ReceiptSigner(signing_key=KEY, engine_id="custos", commit_sha=COMMIT, ledger=InMemoryLedger())
    assert asyncio.run(send_signed_ws(send_text, s, wrapper_domain="governancecheck", input_digest=digest_json({}), verdict_payload=PAYLOAD))
    assert not asyncio.run(send_signed_ws(send_text, s, wrapper_domain="musicguard", input_digest=digest_json({}), verdict_payload=PAYLOAD))
    assert frames[0]["type"] == "arkheia.receipt" and verify_receipt(frames[0]["receipt"], RING)["valid"]
    assert frames[1] == {"type": "arkheia.error", "error_code": "SCHEMA_INVALID"}


def test_signer_from_env_fails_closed(tmp_path):
    import pytest
    from arkheia_receipt import ReceiptError, signer_from_env

    base = {"ARKHEIA_SIGNING_SEED_HEX": V["rfc8032_kat"]["seed_hex"], "ARKHEIA_ENGINE_ID": "custos", "ARKHEIA_ENGINE_COMMIT_SHA": COMMIT}
    s = signer_from_env({**base, "ARKHEIA_LEDGER": f"jsonl:{tmp_path}"})
    r, _ = s.issue(wrapper_domain="governancecheck", input_digest=digest_json({}), verdict_payload=PAYLOAD)
    assert r["engine_id"] == "custos" and r["commit_sha"] == COMMIT
    for bad in ({**base}, {**base, "ARKHEIA_LEDGER": "redis"}, {**base, "ARKHEIA_LEDGER": "memory", "ARKHEIA_ENGINE_ID": "clearcheck"},
                {**base, "ARKHEIA_LEDGER": "memory", "ARKHEIA_ENGINE_COMMIT_SHA": "abc"}):
        with pytest.raises(ReceiptError):
            signer_from_env(bad)


def test_gateway_upstream_guard():
    from arkheia_receipt.gateway import verify_upstream

    good = json.dumps(V["chain"][0]["receipt"]).encode()
    status, headers, body = verify_upstream(good, RING)
    assert status == 200 and dict(headers)["x-arkheia-receipt-hash"] == V["chain"][0]["receipt_hash"]
    assert json.loads(body) == V["chain"][0]["receipt"]
    for bad in (b'{"verdict":"CLEARED"}', b"not json", json.dumps(V["negative"][0]["receipt"]).encode()):
        status, _, body = verify_upstream(bad, RING)
        assert status == 502 and json.loads(body)["error_code"] == "UPSTREAM_RECEIPT_INVALID"
