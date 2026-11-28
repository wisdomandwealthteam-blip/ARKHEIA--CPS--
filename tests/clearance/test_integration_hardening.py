"""Additive integration hardening; existing policy and golden vectors stay pinned."""
from __future__ import annotations

import concurrent.futures
import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from arkheia_clearance.aegis import X_STAR
from arkheia_clearance.receipts import GENESIS, receipt_hash
from arkheia_clearance.service import ClearanceService, ConfigError, UNAVAILABLE, engine_from_env
from cps_backend.main import app
from cps_backend.routers import clearance


def env_for(tmp_path, world):
    (tmp_path / "seed").write_text("11" * 32)
    (tmp_path / "audit").write_text("22" * 32)
    (tmp_path / "trust.json").write_text(json.dumps({
        "custos_issuers": [world.issuer.public_hex], "sensors": [world.sensor.public_hex],
        "release_authorities": [world.humans[0].public_hex]}))
    return {"ARKHEIA_CLEARANCE_SIGNING_SEED_FILE": str(tmp_path / "seed"),
            "ARKHEIA_CLEARANCE_AUDIT_KEY_FILE": str(tmp_path / "audit"),
            "ARKHEIA_CLEARANCE_TRUST_FILE": str(tmp_path / "trust.json"),
            "ARKHEIA_CLEARANCE_LEDGER": "jsonl:" + str(tmp_path / "chain.jsonl")}


@pytest.mark.parametrize("fault", ["corrupt-ledger", "blocked-parent", "unhashable-trust", "non-string-trust"])
def test_bad_bootstrap_disables_only_clearance(tmp_path, world, monkeypatch, fault):
    env = env_for(tmp_path, world)
    if fault == "corrupt-ledger":
        (tmp_path / "chain.jsonl").write_bytes(b"{corrupt}\n")
    elif fault == "blocked-parent":
        (tmp_path / "blocked").write_text("not a directory")
        env["ARKHEIA_CLEARANCE_LEDGER"] = "jsonl:" + str(tmp_path / "blocked" / "chain.jsonl")
    else:
        trust_path = tmp_path / "trust.json"
        trust = json.loads(trust_path.read_text())
        trust["sensors"] = [[]] if fault == "unhashable-trust" else [42]
        trust_path.write_text(json.dumps(trust))
    with pytest.raises(ConfigError):
        engine_from_env(env)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    clearance.set_service(None)
    try:
        client = TestClient(app, raise_server_exceptions=False)
        for path in ("/api/mandate/verify", "/api/aegis/evaluate", "/api/clearance/head"):
            r = client.get(path) if path.endswith("/head") else client.post(path, content=b"{}")
            assert r.status_code == 503 and r.content == UNAVAILABLE
            assert r.headers["cache-control"] == "no-store"
        assert client.get("/health").status_code == 200
    finally:
        clearance.set_service(None)


def test_bootstrap_is_once_across_embedding_threads(h, monkeypatch):
    calls = []

    def factory():
        calls.append(1)
        time.sleep(0.01)
        return h.e

    monkeypatch.setattr(clearance, "engine_from_env", factory)
    monkeypatch.setattr(clearance, "floor_ns_from_env", lambda: 0)
    clearance.set_service(None)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            services = list(pool.map(lambda _: clearance.get_service(), range(24)))
        assert len(calls) == 1
        assert all(s is services[0] for s in services)
    finally:
        clearance.set_service(None)


def test_atomic_head_during_receipt_commits(h):
    service = ClearanceService(h.e, 0)

    def writer():
        for _ in range(60):
            h.e.verify_mandate(b"{}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        job = pool.submit(writer)
        for _ in range(100):
            status, _, body = service.dispatch("GET", "/api/clearance/head", b"")
            assert status == 200
            head = json.loads(body)
            records = h.e.records()
            if head["length"]:
                rec = records[head["length"] - 1]
                assert head["head_hash"] == receipt_hash(rec)
                assert head["lamport"] == rec["lamport"]
            else:
                assert head["head_hash"] == GENESIS and head["lamport"] == 0
        job.result()


@pytest.mark.parametrize("fault", ["fsync", "zero-write", "close"])
def test_uncertain_disk_fault_latches_until_verified_restart(tmp_path, world, monkeypatch, fault):
    path = tmp_path / "chain.jsonl"
    engine = world.engine(ledger_path=path)
    service = ClearanceService(engine, 0)

    def fail(*args):
        raise OSError("injected persistence fault")

    with monkeypatch.context() as m:
        if fault == "fsync":
            m.setattr(os, "fsync", fail)
        elif fault == "zero-write":
            m.setattr(os, "write", lambda *args: 0)
        else:
            real_close = os.close

            def bad_close(fd):
                real_close(fd)
                fail()

            m.setattr(os, "close", bad_close)
        status, _, body = service.dispatch("POST", "/api/mandate/verify", b"{}")
        assert status == 503 and body == UNAVAILABLE
    # Even after the injected fault is removed, stale memory must not issue another verdict.
    assert engine.clock == 0 and engine.records() == []
    for _ in range(2):
        status, _, body = service.dispatch("POST", "/api/mandate/verify", b"{}")
        assert status == 503 and body == UNAVAILABLE
    recovered = world.engine(ledger_path=path)
    assert recovered.verify_mandate(b"{}").status == 403
    records = world.engine(ledger_path=path).records()
    assert len(records) == (1 if fault == "zero-write" else 2)


def test_mcp_metadata_mismatch_cannot_hide_authenticated_hard_breach(h):
    w, a = h.w, h.w.agent("metadata-hard-breach")
    m = w.mandate(a, w.lease(a, issued=0, max_amount=10), t=h.t(), tag="mcp-budget", pool=11)
    r, reason = h.mandate(m, {"Mcp-Name": "payments.quote"})
    assert (r.status, reason, h.state(a)) == (403, "MCP_HEADER_MISMATCH", X_STAR)
    assert h.e.records()[-1]["decision_core"]["effects"]["quarantined"] == [a.public_hex]
