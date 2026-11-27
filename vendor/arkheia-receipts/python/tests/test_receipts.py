"""ARKHEIA DVE — Python receipt suite. Run: pytest -q"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from wsgiref.simple_server import WSGIRequestHandler, make_server

import pytest

from arkheia_receipt import (
    GENESIS_HASH,
    BpsLedgerAdapter,
    InMemoryLedger,
    JsonlFileLedger,
    Keyring,
    LedgerConflictError,
    LedgerNotConfiguredError,
    ReceiptError,
    ReceiptKeyError,
    ReceiptSigner,
    SchemaDefinitionError,
    StrictJsonError,
    build_verdict_payload,
    canonicalize,
    compile_schema,
    digest_json,
    load_signing_key_from_env,
    parse_strict_json,
    receipt_hash,
    sign_receipt,
    signing_input,
    signing_key_from_seed_hex,
    verify_chain,
    verify_receipt,
)
from arkheia_receipt.gateway import handle_request, make_asgi_app, make_wsgi_app

ROOT = Path(__file__).resolve().parents[2]
V = json.loads((ROOT / "test-vectors" / "vectors.json").read_text("utf-8"))
KEYRING = Keyring(V["keyring"])
KEY = signing_key_from_seed_hex(V["rfc8032_kat"]["seed_hex"])
COMMIT = "c40f49580a627dfd8f9975ef4bd0905ece623346"
FIXED_NOW = lambda: datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)  # noqa: E731


def test_schema_copy_is_byte_identical():
    pkg = Path(__file__).resolve().parents[1] / "arkheia_receipt" / "schema" / "arkheia-receipt-schema-v1.json"
    root = ROOT / "schema" / "arkheia-receipt-schema-v1.json"
    assert hashlib.sha256(pkg.read_bytes()).hexdigest() == hashlib.sha256(root.read_bytes()).hexdigest()


def test_rfc8032_known_answer():
    assert KEY.public_key_hex == V["rfc8032_kat"]["public_key_hex"]
    assert KEY.sign(b"").hex() == V["rfc8032_kat"]["empty_message_signature_hex"]


def test_jcs_matches_rfc8785_rules():
    assert canonicalize({"b": 1, "a": [True, None, "x"], "\u20ac": 1, "\r": 2, "\U0001F600": 3, "\ufb33": 4}) == (
        '{"\\r":2,"a":[true,null,"x"],"b":1,"\u20ac":1,"\U0001F600":3,"\ufb33":4}'
    )
    assert canonicalize("\u0001\u001f\u007f\u2028") == '"\\u0001\\u001f\u007f\u2028"'
    for bad in ({"a": 1.5}, {"a": float("nan")}, {1: "x"}, "\ud800", 2**53, {"a": object()}):
        with pytest.raises(ValueError):
            canonicalize(bad)


def test_strict_json_rejects_raw_negatives():
    for c in V["raw_negative"]:
        with pytest.raises(StrictJsonError):
            parse_strict_json(c["text"])
    with pytest.raises(StrictJsonError):
        parse_strict_json(b"\xef\xbb\xbf{}")
    with pytest.raises(StrictJsonError):
        parse_strict_json(b'{"a":"\xff"}')
    with pytest.raises(StrictJsonError):
        parse_strict_json("[" * 100 + "]" * 100)
    assert parse_strict_json('{"a":[1,-2,0],"b":"\\u00e9\\ud83d\\ude00"}') == {"a": [1, -2, 0], "b": "\u00e9\U0001F600"}


def test_vector_chain_is_byte_identical_and_signatures_reproduce():
    for step in V["chain"]:
        r = step["receipt"]
        assert canonicalize(step["input"]) == step["input_canonical"]
        assert digest_json(step["input"]) == r["input_digest"]
        assert canonicalize(r) == step["receipt_canonical"]
        assert signing_input(r).hex() == step["signing_input_hex"]
        assert receipt_hash(r) == step["receipt_hash"]
        # Ed25519 is deterministic: re-signing in Python must reproduce Node's exact receipt.
        fields = {k: v for k, v in r.items() if k not in ("schema_version", "signature")}
        assert sign_receipt(KEY, **fields) == r
        res = verify_receipt(parse_strict_json(json.dumps(r)), KEYRING)
        assert res == {"valid": True, "signer": V["keyring"]["keys"][0]["public_key_id"], "receipt_hash": step["receipt_hash"]}
    assert verify_chain([s["receipt"] for s in V["chain"]], KEYRING) == {"valid": True, "length": 3, "head_hash": V["chain"][2]["receipt_hash"]}


@pytest.mark.parametrize("case", V["negative"], ids=[n["name"] for n in V["negative"]])
def test_negative_vectors_fail_with_exact_code(case):
    res = verify_receipt(case["receipt"], KEYRING)
    assert res["valid"] is False
    assert res["error_code"] == case["expected_error_code"]


def test_tamper_every_bit_flip_in_verdict_payload_and_prev_hash_fails():
    original = V["chain"][1]["receipt"]
    canonical = canonicalize(original)
    checked = 0
    for field in ("verdict_payload", "prev_receipt_hash"):
        fj = canonicalize(original[field])
        start = canonical.index(f'"{field}":') + len(field) + 3
        assert canonical[start : start + len(fj)] == fj
        for i, ch in enumerate(fj):
            for bit in (0x01, 0x20):
                mutated = canonical[:start] + fj[:i] + chr(ord(ch) ^ bit) + fj[i + 1 :] + canonical[start + len(fj) :]
                try:
                    parsed = parse_strict_json(mutated)
                except StrictJsonError:
                    checked += 1
                    continue
                assert verify_receipt(parsed, KEYRING)["valid"] is False, f"{field}[{i}]^{bit}"
                checked += 1
    assert checked > 300


def test_chain_link_checks():
    r0, r1, r2 = (s["receipt"] for s in V["chain"])
    assert verify_receipt(r2, KEYRING, r1)["valid"] is True
    assert verify_receipt(r2, KEYRING, r0)["error_code"] == "CHAIN_LINK_MISMATCH"
    assert verify_chain([r0, r2], KEYRING)["error_code"] == "CHAIN_LINK_MISMATCH"
    revoked = Keyring({"keys": [{**V["keyring"]["keys"][0], "status": "revoked"}]})
    assert verify_receipt(r0, revoked)["error_code"] == "REVOKED_SIGNER"
    with pytest.raises(ReceiptKeyError):
        Keyring({"keys": [{**V["keyring"]["keys"][0], "public_key_id": "ed25519:0000000000000000"}]})


def _payload(verdict="CLEARED"):
    return build_verdict_payload(
        verdict=verdict, reason_codes=["Z_LAST", "A_FIRST"], rule_set={"id": "clearcheck.rules", "version": "1.0.0"}, metrics={"n": 1}
    )


def _clock():
    t = [datetime(2026, 11, 25, tzinfo=timezone.utc)]

    def tick():
        t[0] += timedelta(milliseconds=1)
        return t[0]

    return tick


def test_signer_chain_concurrency_and_fail_closed():
    ledger = InMemoryLedger()
    s = ReceiptSigner(signing_key=KEY, engine_id="custos", commit_sha=COMMIT, ledger=ledger, clock=_clock())
    with ThreadPoolExecutor(8) as ex:
        out = list(ex.map(lambda i: s.issue(wrapper_domain="clearcheck", input_digest=digest_json({"i": i}), verdict_payload=_payload()), range(40)))
    receipts = sorted((r for r, _ in out), key=lambda r: r["sequence"])
    assert [r["sequence"] for r in receipts] == list(range(40))
    assert receipts[0]["prev_receipt_hash"] == GENESIS_HASH
    assert receipts[0]["verdict_payload"]["reason_codes"] == ["A_FIRST", "Z_LAST"]
    assert verify_chain(receipts, KEYRING)["valid"] is True

    fresh = InMemoryLedger()
    s2 = ReceiptSigner(signing_key=KEY, engine_id="custos", commit_sha=COMMIT, ledger=fresh)
    for kwargs in (
        {"wrapper_domain": "musicguard", "input_digest": digest_json({}), "verdict_payload": _payload("CLEARED")},
        {"wrapper_domain": "clearcheck", "input_digest": "nope", "verdict_payload": _payload()},
        {"wrapper_domain": "clearcheck", "input_digest": digest_json({}), "verdict_payload": {**_payload(), "extra": 1}},
    ):
        with pytest.raises(ReceiptError) as ei:
            s2.issue(**kwargs)
        assert ei.value.code == "SCHEMA_INVALID"
    bad_metrics = _payload()
    bad_metrics["metrics"]["score"] = 0.5
    with pytest.raises(ValueError):
        s2.issue(wrapper_domain="clearcheck", input_digest=digest_json({}), verdict_payload=bad_metrics)
    wrapper_engine = ReceiptSigner(signing_key=KEY, engine_id="clearcheck", commit_sha=COMMIT, ledger=fresh)
    with pytest.raises(ReceiptError):
        wrapper_engine.issue(wrapper_domain="clearcheck", input_digest=digest_json({}), verdict_payload=_payload())
    assert fresh.head(s2.chain_id) is None


def test_ledger_conflict_retry_and_stub(tmp_path):
    inner = InMemoryLedger()
    state = {"conflicts": 1}

    class Flaky:
        def head(self, c):
            return inner.head(c)

        def get(self, h):
            return inner.get(h)

        def append(self, c, **kw):
            if state["conflicts"] > 0:
                state["conflicts"] -= 1
                raise LedgerConflictError("simulated")
            inner.append(c, **kw)

    s = ReceiptSigner(signing_key=KEY, engine_id="custos", commit_sha=COMMIT, ledger=Flaky())
    assert s.issue(wrapper_domain="clearcheck", input_digest=digest_json({}), verdict_payload=_payload())[0]["sequence"] == 0
    state["conflicts"] = 99
    with pytest.raises(LedgerConflictError):
        s.issue(wrapper_domain="clearcheck", input_digest=digest_json({}), verdict_payload=_payload())

    a = ReceiptSigner(signing_key=KEY, engine_id="securus", commit_sha=COMMIT, ledger=JsonlFileLedger(tmp_path))
    r1, h1 = a.issue(wrapper_domain="governancecheck", input_digest=digest_json({"a": 1}), verdict_payload=_payload("COMPLIANT"))
    b = ReceiptSigner(signing_key=KEY, engine_id="securus", commit_sha=COMMIT, ledger=JsonlFileLedger(tmp_path))
    r2, _ = b.issue(wrapper_domain="governancecheck", input_digest=digest_json({"a": 2}), verdict_payload=_payload("COMPLIANT"))
    assert r2["prev_receipt_hash"] == h1
    assert JsonlFileLedger(tmp_path).get(h1) == r1
    with pytest.raises(LedgerNotConfiguredError):
        ReceiptSigner(signing_key=KEY, engine_id="securus", commit_sha=COMMIT, ledger=BpsLedgerAdapter()).issue(
            wrapper_domain="governancecheck", input_digest=digest_json({}), verdict_payload=_payload("COMPLIANT")
        )


def test_env_loading_and_keygen(tmp_path):
    seed = V["rfc8032_kat"]["seed_hex"]
    out = subprocess.run(
        [sys.executable, "-m", "arkheia_receipt.keygen", "--out-dir", str(tmp_path), "--from-seed", seed],
        capture_output=True, text=True, check=True, cwd=Path(__file__).resolve().parents[1],
    )
    info = json.loads(out.stdout)
    assert info["public_key_hex"] == V["rfc8032_kat"]["public_key_hex"]
    env_file = tmp_path / ".env.arkheia-signing"
    assert stat.S_IMODE(os.stat(env_file).st_mode) == 0o600
    again = subprocess.run([sys.executable, "-m", "arkheia_receipt.keygen", "--out-dir", str(tmp_path)], capture_output=True, cwd=Path(__file__).resolve().parents[1])
    assert again.returncode == 1
    assert load_signing_key_from_env(env={}, env_file=env_file).public_key_id == info["public_key_id"]
    assert Keyring.from_file(tmp_path / "arkheia-public-keys.json").to_json() == V["keyring"]
    with pytest.raises(ReceiptKeyError):
        load_signing_key_from_env(env={})
    with pytest.raises(ReceiptKeyError):
        load_signing_key_from_env(env={"ARKHEIA_SIGNING_SEED_HEX": seed, "ARKHEIA_SIGNING_PUBLIC_KEY_ID": "ed25519:0000000000000000"})


def test_schema_interpreter_rejects_unknown_keywords():
    with pytest.raises(SchemaDefinitionError):
        compile_schema({"type": "object", "format": "date-time"})


# ---------------- /v1/verify-receipt ----------------

def _call(body, *, method="POST", path="/v1/verify-receipt", ct="application/json"):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    status, headers, out = handle_request(method=method, path=path, content_type=ct, body=data, keyring=KEYRING, now=FIXED_NOW)
    return status, dict(headers), json.loads(out)


def test_endpoint_valid_receipt_and_chain_link():
    r1, r2 = V["chain"][1]["receipt"], V["chain"][2]["receipt"]
    status, headers, body = _call(r2)
    assert status == 200 and headers["content-type"].startswith("application/json")
    assert body == {
        "valid": True, "verified_at": "2026-11-25T12:00:00.000Z", "signer": "ed25519:21fe31dfa154a261",
        "receipt_hash": V["chain"][2]["receipt_hash"], "engine_id": "supreme_kernel", "wrapper_domain": "governancecheck",
        "sequence": 2, "chain_link_verified": False,
    }
    assert _call({"receipt": r2, "previous_receipt": r1})[2]["chain_link_verified"] is True
    assert _call({"receipt": r2, "previous_receipt": V["chain"][0]["receipt"]})[2]["error_code"] == "CHAIN_LINK_MISMATCH"


def test_endpoint_deterministic_output():
    a = handle_request(method="POST", path="/v1/verify-receipt", content_type="application/json", body=json.dumps(V["chain"][0]["receipt"]).encode(), keyring=KEYRING, now=FIXED_NOW)
    b = handle_request(method="POST", path="/v1/verify-receipt", content_type="application/json; charset=utf-8", body=json.dumps(V["chain"][0]["receipt"], indent=4).encode(), keyring=KEYRING, now=FIXED_NOW)
    assert a == b


@pytest.mark.parametrize("case", V["negative"], ids=[n["name"] for n in V["negative"]])
def test_endpoint_negative_vectors(case):
    status, _, body = _call(case["receipt"])
    assert status == 200 and body["valid"] is False and body["error_code"] == case["expected_error_code"]


def test_endpoint_request_errors():
    r = V["chain"][0]["receipt"]
    assert _call(r, method="GET")[0] == 405
    assert _call(r, ct="text/plain")[0] == 415
    assert _call(r, ct=None)[0] == 415
    assert _call(b"x" * (256 * 1024 + 1))[0] == 413
    assert _call(b'{"a":1,"a":2}')[2]["error_code"] == "BODY_PARSE_ERROR"
    assert _call(b"[1]")[2]["error_code"] == "BODY_NOT_OBJECT"
    assert _call({"receipt": r, "x": 1})[2]["error_code"] == "UNKNOWN_ENVELOPE_FIELD"
    assert _call(r, path="/v1/nope")[0] == 404
    status, _, keys = _call(b"", method="GET", path="/v1/public-keys")
    assert status == 200 and keys == V["keyring"]


def test_endpoint_over_real_http_wsgi():
    class Quiet(WSGIRequestHandler):
        def log_message(self, *a):
            pass

    srv = make_server("127.0.0.1", 0, make_wsgi_app(KEYRING), handler_class=Quiet)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/v1/verify-receipt"
        req = Request(url, data=json.dumps(V["chain"][0]["receipt"]).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read())
        assert resp.status == 200 and body["valid"] is True and body["signer"] == "ed25519:21fe31dfa154a261"
        bad = Request(url, data=b"{}", headers={"Content-Type": "text/plain"}, method="POST")
        with pytest.raises(HTTPError) as ei:
            urlopen(bad, timeout=5)
        assert ei.value.code == 415
    finally:
        srv.shutdown()
        srv.server_close()


def test_endpoint_asgi():
    app = make_asgi_app(KEYRING)
    body = json.dumps(V["chain"][1]["receipt"]).encode()
    msgs = [{"type": "http.request", "body": body[:100], "more_body": True}, {"type": "http.request", "body": body[100:], "more_body": False}]
    sent = []

    async def receive():
        return msgs.pop(0)

    async def send(m):
        sent.append(m)

    scope = {"type": "http", "method": "POST", "path": "/v1/verify-receipt", "headers": [(b"content-type", b"application/json")]}
    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 200
    assert json.loads(sent[1]["body"])["valid"] is True
