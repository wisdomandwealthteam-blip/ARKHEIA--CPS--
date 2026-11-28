"""CPS FastAPI wiring. Skipped where FastAPI/httpx are not installed (they are in CPS CI)."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from arkheia_clearance import artifacts as A  # noqa: E402
from arkheia_clearance.service import ClearanceService  # noqa: E402
from cps_backend.main import app  # noqa: E402
from cps_backend.routers import clearance  # noqa: E402


@pytest.fixture
def client(h):
    clearance.set_service(ClearanceService(h.e, floor_ns=0))
    yield h, TestClient(app, raise_server_exceptions=False)
    clearance.set_service(None)


def test_routes_are_mounted_and_bodies_reach_the_engine_unparsed(client):
    h, c = client
    w, a = h.w, h.w.agent("alpha")
    m = w.mandate(a, w.lease(a, issued=0), t=h.t(), tag="cps")
    r = c.post("/api/mandate/verify", content=A.to_bytes(m), headers={"content-type": "application/json"})
    assert r.status_code == 200 and r.json()["decision"] == "CLEARED"
    r = c.post("/api/mandate/verify", content=b'{"lamport":1.5}')
    assert r.status_code == 403 and r.json()["code"] == "X*"
    assert "detail" not in r.text and "validation" not in r.text
    r = c.post("/api/aegis/evaluate", content=A.to_bytes(w.observe(a, t=h.t(), request_count=1)))
    assert r.status_code == 200
    head = c.get("/api/clearance/head").json()
    assert head["head_hash"] == h.e.head_hash


def test_unconfigured_cps_routes_are_503(monkeypatch):
    clearance.set_service(ClearanceService(None, 0))
    try:
        r = TestClient(app).post("/api/mandate/verify", content=b"{}")
        assert r.status_code == 503 and json.loads(r.content)["code"] == "X*"
    finally:
        clearance.set_service(None)
