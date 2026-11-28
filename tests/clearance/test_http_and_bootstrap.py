"""Live stdlib sidecar over a real socket, plus fail-closed environment bootstrap."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from arkheia_clearance import artifacts as A
from arkheia_clearance.server import build_server
from arkheia_clearance.service import ClearanceService, ConfigError, engine_from_env


@pytest.fixture
def live(h):
    srv = build_server(ClearanceService(h.e, floor_ns=0), "127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield h, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _call(url, data=None, method="POST", headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_live_endpoints(live):
    h, base = live
    w, a = h.w, h.w.agent("alpha")
    m = w.mandate(a, w.lease(a, issued=0), t=h.t(), tag="live")
    s, hdrs, body = _call(base + "/api/mandate/verify", A.to_bytes(m),
                          headers={"Content-Type": "application/json", "Mcp-Method": "tools/call",
                                   "Mcp-Name": "payments.transfer"})
    assert s == 200 and json.loads(body)["decision"] == "CLEARED"
    assert hdrs["Cache-Control"] == "no-store"
    s, _, body = _call(base + "/api/mandate/verify", A.to_bytes(m))
    assert s == 403 and json.loads(body)["code"] == "X*"
    s, _, body = _call(base + "/api/aegis/evaluate", A.to_bytes(w.observe(w.agent("b"), t=h.t(), request_count=5)))
    assert s == 200 and json.loads(body)["state"] == "ALLOW"
    s, _, body = _call(base + "/api/clearance/head", method="GET")
    head = json.loads(body)
    assert s == 200 and head["head_hash"] == h.e.head_hash and head["length"] == 3
    assert _call(base + "/api/mandate/verify", method="GET")[0] == 405
    assert _call(base + "/nope", b"{}")[0] == 404


def test_unconfigured_service_is_503_opaque():
    svc = ClearanceService(None, 0)
    for path in ("/api/mandate/verify", "/api/aegis/evaluate"):
        status, _, body = svc.dispatch("POST", path, b"{}")
        assert status == 503 and json.loads(body)["code"] == "X*"


def _env(tmp_path, world, **over):
    (tmp_path / "seed").write_text("11" * 32)
    (tmp_path / "audit").write_text("22" * 32)
    (tmp_path / "trust.json").write_text(json.dumps({
        "custos_issuers": [world.issuer.public_hex], "sensors": [world.sensor.public_hex],
        "release_authorities": [world.humans[0].public_hex]}))
    env = {"ARKHEIA_CLEARANCE_SIGNING_SEED_FILE": str(tmp_path / "seed"),
           "ARKHEIA_CLEARANCE_AUDIT_KEY_FILE": str(tmp_path / "audit"),
           "ARKHEIA_CLEARANCE_TRUST_FILE": str(tmp_path / "trust.json"),
           "ARKHEIA_CLEARANCE_LEDGER": f"jsonl:{tmp_path / 'ledger' / 'chain.jsonl'}"}
    env.update(over)
    return env


def test_bootstrap_from_env(tmp_path, world):
    e = engine_from_env(_env(tmp_path, world))
    assert e.verify_mandate(b"{}").status == 403
    assert (tmp_path / "ledger" / "chain.jsonl").exists()


@pytest.mark.parametrize("over", [
    {"ARKHEIA_CLEARANCE_LEDGER": ""},
    {"ARKHEIA_CLEARANCE_LEDGER": "sqlite:x"},
    {"ARKHEIA_CLEARANCE_SIGNING_SEED_FILE": ""},
    {"ARKHEIA_CLEARANCE_SIGNING_SEED_FILE": "/nonexistent"},
    {"ARKHEIA_CLEARANCE_TRUST_FILE": ""},
])
def test_bootstrap_fails_closed(tmp_path, world, over):
    with pytest.raises(ConfigError):
        engine_from_env(_env(tmp_path, world, **over))


def test_bootstrap_rejects_bad_key_material(tmp_path, world):
    env = _env(tmp_path, world)
    (tmp_path / "seed").write_text("zz" * 32)
    with pytest.raises(ConfigError):
        engine_from_env(env)
    (tmp_path / "seed").write_text("11" * 32)
    (tmp_path / "audit").write_text("22" * 8)
    with pytest.raises(ConfigError):
        engine_from_env(env)
