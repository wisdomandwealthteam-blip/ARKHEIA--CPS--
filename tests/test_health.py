"""Tests for the /health endpoint platform metadata."""
from __future__ import annotations

from fastapi.testclient import TestClient

from cps_backend.main import app

client = TestClient(app)


def test_health_reports_platform_metadata():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["engine"] == "ARKHEIA DVE™"
    assert body["architecture_version"] == "PLATFORM-ARCHITECTURE-2026-V1"
    assert body["modules"] == ["dve-clearcheck", "dve-riskcheck"]
