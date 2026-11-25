"""Replayed POST must not trust a schema-valid but contradictory stored gate."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from cps_backend.main import app
from cps_backend.schemas.governance import FINDING_REASONS


@pytest.mark.parametrize("actual_gate", ["PASS", "HOLD"])
def test_contradictory_stored_receipt_fails_closed(actual_gate, tmp_path, monkeypatch):
    path = tmp_path / "governance.json"
    monkeypatch.setenv("CPS_GOVERNANCE_STORE_PATH", str(path))
    payload = {
        "model_id": "underwriting-v1",
        "decision_domain": "underwriting",
        "proposed_action": "APPROVE",
        "confidence_score": 0.96 if actual_gate == "PASS" else 0.68,
        "human_override_required": actual_gate == "PASS",
        "policy_thresholds": {"min_confidence": 0.85, "max_unsupervised_amount": 10000},
        "transaction_amount": 5000 if actual_gate == "PASS" else 45000,
        "redacted_subject_ref": "*******0001",
    }
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/api/governance/check", json=payload)
        assert response.status_code == 200
        receipt = response.json()
        assert receipt["gate"] == actual_gate
        data = json.loads(path.read_text())
        record = data["checks"][receipt["receipt_id"]]
        if actual_gate == "HOLD":
            record["gate"] = "PASS"
            record["findings"] = []
        else:
            record["gate"] = "HOLD"
            record["findings"] = [{
                "code": "LOW_MODEL_CONFIDENCE",
                "reason": FINDING_REASONS["LOW_MODEL_CONFIDENCE"],
            }]
        path.write_text(json.dumps(data))
        before = path.read_bytes()
        replay = client.post("/api/governance/check", json=payload)
        assert replay.status_code == 503
        assert replay.json()["detail"] == "Governance records are temporarily unavailable."
        assert replay.headers["cache-control"] == "no-store"
        assert "conflicts" not in replay.text
        assert path.read_bytes() == before
