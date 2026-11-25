"""GovernanceCheck contract tests; every receipt store is isolated."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from cps_backend.main import app
from cps_backend.schemas.governance import (
    ARCHITECTURE_VERSION,
    FINDING_REASONS,
    GovernanceCheckRequest,
)
from cps_backend.services import governance_store
from cps_backend.services.clearcheck_engine import compute_check_id
from cps_backend.services.governance_engine import compute_receipt_id, run_checks

client = TestClient(app, raise_server_exceptions=False)
SECRET = "private-subject@example.invalid"
RECEIPT_KEYS = {
    "receipt_id", "gate", "architecture_version", "sha256_digest", "findings", "evaluated_at"
}


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    path = tmp_path / "nested" / "governance_checks.json"
    monkeypatch.setenv("CPS_GOVERNANCE_STORE_PATH", str(path))
    return path


def sample_payload(**changes) -> dict:
    payload = {
        "model_id": "model-2026-v1",
        "decision_domain": "finance",
        "proposed_action": "approve-transfer",
        "confidence_score": 0.95,
        "human_override_required": False,
        "policy_thresholds": {"min_confidence": 0.85, "max_unsupervised_amount": 10000},
        "transaction_amount": 100,
        "redacted_subject_ref": "subject-redacted-0001",
    }
    payload.update(changes)
    return payload


def post(payload=None):
    return client.post("/api/governance/check", json=sample_payload() if payload is None else payload)


def codes(body):
    return [finding["code"] for finding in body["findings"]]


def test_pass_receipt_contract_and_utc():
    response = post()
    assert response.status_code == 200
    body = response.json()
    assert set(body) == RECEIPT_KEYS
    assert body["gate"] == "PASS"
    assert body["findings"] == []
    assert body["architecture_version"] == ARCHITECTURE_VERSION
    assert re.fullmatch(r"gov_[0-9a-f]{64}", body["receipt_id"])
    assert body["receipt_id"] == "gov_" + body["sha256_digest"]
    timestamp = datetime.fromisoformat(body["evaluated_at"].replace("Z", "+00:00"))
    assert timestamp.utcoffset() == timedelta(0)
    assert abs((datetime.now(timezone.utc) - timestamp).total_seconds()) < 60
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({"confidence_score": 0.84}, ["LOW_MODEL_CONFIDENCE"]),
        ({"transaction_amount": 10000.01}, ["UNSUPERVISED_HIGH_VALUE_ACTION"]),
        ({"model_id": ""}, ["MISSING_MODEL_PROVENANCE"]),
        ({"model_id": " \t\n"}, ["MISSING_MODEL_PROVENANCE"]),
        ({"model_id": "unknown"}, ["MISSING_MODEL_PROVENANCE"]),
        ({"model_id": "  UnKnOwN\t"}, ["MISSING_MODEL_PROVENANCE"]),
    ],
)
def test_each_hold_rule(changes, expected):
    response = post(sample_payload(**changes))
    assert response.status_code == 200
    body = response.json()
    assert body["gate"] == "HOLD"
    assert codes(body) == expected
    assert all(set(finding) == {"code", "reason"} for finding in body["findings"])
    assert all(finding["reason"] == FINDING_REASONS[finding["code"]] for finding in body["findings"])


def test_defective_sample_has_exactly_two_ordered_findings():
    response = post(sample_payload(confidence_score=0.6, transaction_amount=25000))
    assert response.status_code == 200
    assert response.json()["gate"] == "HOLD"
    assert codes(response.json()) == ["LOW_MODEL_CONFIDENCE", "UNSUPERVISED_HIGH_VALUE_ACTION"]


def test_all_rules_have_fixed_order_and_static_non_echoing_reasons():
    response = post(sample_payload(
        model_id="  UNKNOWN  ", confidence_score=0.01,
        transaction_amount=25000, decision_domain=SECRET,
        proposed_action=SECRET, redacted_subject_ref=SECRET,
    ))
    assert response.status_code == 200
    assert codes(response.json()) == list(FINDING_REASONS)
    assert SECRET not in response.text


@pytest.mark.parametrize(
    "changes,gate,expected",
    [
        ({"confidence_score": 0.85}, "PASS", []),
        ({"confidence_score": 1}, "PASS", []),
        ({"confidence_score": 0}, "HOLD", ["LOW_MODEL_CONFIDENCE"]),
        ({"transaction_amount": 10000}, "PASS", []),
        ({"transaction_amount": 0}, "PASS", []),
        ({"transaction_amount": 10001, "human_override_required": True}, "PASS", []),
        ({"confidence_score": 0.5, "human_override_required": True}, "HOLD", ["LOW_MODEL_CONFIDENCE"]),
        ({"model_id": "known-unknown-model"}, "PASS", []),
        ({"policy_thresholds": {"min_confidence": 0, "max_unsupervised_amount": 0},
          "confidence_score": 0, "transaction_amount": 0}, "PASS", []),
        ({"policy_thresholds": {"min_confidence": 1}, "confidence_score": 1}, "PASS", []),
        ({"policy_thresholds": {"max_unsupervised_amount": 0}, "transaction_amount": 0.01},
         "HOLD", ["UNSUPERVISED_HIGH_VALUE_ACTION"]),
    ],
)
def test_boundaries_and_override(changes, gate, expected):
    response = post(sample_payload(**changes))
    assert response.status_code == 200
    assert response.json()["gate"] == gate
    assert codes(response.json()) == expected


@pytest.mark.parametrize("thresholds", [None, {}, {"min_confidence": 0.85}, {"max_unsupervised_amount": 10000}])
def test_defaults_and_partial_thresholds_share_canonical_id(thresholds):
    payload = sample_payload(transaction_amount=0)
    del payload["policy_thresholds"]
    del payload["transaction_amount"]
    if thresholds is not None:
        payload["policy_thresholds"] = thresholds
    request = GovernanceCheckRequest.model_validate(payload)
    assert request.transaction_amount == 0.0
    assert request.policy_thresholds.min_confidence == 0.85
    assert request.policy_thresholds.max_unsupervised_amount == 10000.0
    response = post(payload)
    assert response.status_code == 200
    explicit = post(sample_payload(transaction_amount=0))
    assert response.json() == explicit.json()


def test_receipt_digest_parity_with_existing_clearcheck_canonical_function():
    request = GovernanceCheckRequest.model_validate(sample_payload())
    existing_id = compute_check_id(request)
    canonical = json.dumps(request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    body = post().json()
    assert existing_id == "chk_" + digest
    assert compute_receipt_id(request) == "gov_" + digest
    assert body["receipt_id"] == "gov_" + digest
    assert body["sha256_digest"] == digest


def test_engine_calls_existing_digest_function(monkeypatch):
    from cps_backend.services import governance_engine

    seen = []

    def canonical(request):
        seen.append(request)
        return "chk_" + "a" * 64

    monkeypatch.setattr(governance_engine, "compute_check_id", canonical)
    request = GovernanceCheckRequest.model_validate(sample_payload())
    assert compute_receipt_id(request) == "gov_" + "a" * 64
    assert seen == [request]


def test_replay_preserves_entire_first_receipt_and_file_with_reordered_keys(isolated_store, monkeypatch):
    payload = sample_payload(confidence_score=0.4, transaction_amount=12000)
    first = post(payload).json()
    before = isolated_store.read_bytes()
    reordered = dict(reversed(list(payload.items())))
    reordered["policy_thresholds"] = dict(reversed(list(payload["policy_thresholds"].items())))

    def do_not_write(*args):
        raise AssertionError("Replay must not rewrite the first receipt")

    monkeypatch.setattr(governance_store, "_write_all", do_not_write)
    assert post(reordered).json() == first
    assert client.get(f'/api/governance/checks/{first["receipt_id"]}').json() == first
    assert isolated_store.read_bytes() == before


def test_different_validated_content_changes_digest():
    first = post().json()
    second = post(sample_payload(redacted_subject_ref="different-redacted-subject")).json()
    assert first["receipt_id"] != second["receipt_id"]
    assert first["findings"] == second["findings"]


def test_lookup_persists_through_module_reload_and_fresh_process(isolated_store):
    first_response = post(sample_payload(confidence_score=0.6))
    assert first_response.status_code == 200
    first = first_response.json()
    importlib.reload(governance_store)
    response = client.get(f'/api/governance/checks/{first["receipt_id"]}')
    assert response.status_code == 200
    assert response.json() == first
    assert response.headers["cache-control"] == "no-store"
    script = (
        "import json, sys; from cps_backend.services.governance_store import get_check; "
        "print(json.dumps(get_check(sys.argv[1]).model_dump(mode='json'), sort_keys=True))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, first["receipt_id"]],
        cwd=os.path.dirname(os.path.dirname(__file__)), env=os.environ.copy(),
        capture_output=True, text=True, check=True, timeout=30,
    )
    assert json.loads(result.stdout) == first
    assert json.loads(isolated_store.read_text())["checks"][first["receipt_id"]] == first


def test_unknown_well_formed_receipt_is_404(isolated_store):
    response = client.get("/api/governance/checks/gov_" + "0" * 64)
    assert response.status_code == 404
    assert response.headers["cache-control"] == "no-store"
    assert not isolated_store.exists()


@pytest.mark.parametrize("receipt_id", [
    "gov_nope", "chk_" + "a" * 64, "gov_" + "A" * 64,
    "gov_" + "0" * 63, "gov_" + "0" * 65, "gov_" + "g" * 64,
    SECRET, "gov_" + "0" * 64 + "%0A",
])
def test_malformed_ids_are_safely_rejected(receipt_id, isolated_store, caplog):
    response = client.get("/api/governance/checks/" + receipt_id)
    assert response.status_code == 422
    assert SECRET not in response.text
    assert SECRET not in caplog.text
    assert not isolated_store.exists()


@pytest.mark.parametrize("field", [
    "model_id", "decision_domain", "proposed_action", "confidence_score",
    "human_override_required", "redacted_subject_ref",
])
def test_missing_required_fields_rejected_without_payload_echo(field, isolated_store, caplog):
    payload = sample_payload(redacted_subject_ref=SECRET, proposed_action=SECRET)
    del payload[field]
    response = post(payload)
    assert response.status_code == 422
    assert SECRET not in response.text
    assert SECRET not in caplog.text
    assert not isolated_store.exists()


@pytest.mark.parametrize("field", ["model_id", "decision_domain", "proposed_action", "redacted_subject_ref"])
@pytest.mark.parametrize("value", [None, 123, False, {}, []])
def test_non_string_input_rejected(field, value, isolated_store):
    response = post(sample_payload(**{field: value}))
    assert response.status_code == 422
    assert not isolated_store.exists()


@pytest.mark.parametrize("value", [None, "true", "false", "1", "0", 1, 0, [], {}])
def test_human_override_is_strict_boolean(value, isolated_store):
    response = post(sample_payload(human_override_required=value))
    assert response.status_code == 422
    assert not isolated_store.exists()


@pytest.mark.parametrize("field", ["confidence_score", "transaction_amount", "min_confidence", "max_unsupervised_amount"])
@pytest.mark.parametrize("value", [None, True, False, "0.5", "nan", "Infinity", [], {}, -0.01])
def test_invalid_numeric_inputs_rejected(field, value, isolated_store):
    payload = sample_payload()
    if field in payload["policy_thresholds"]:
        payload["policy_thresholds"][field] = value
    else:
        payload[field] = value
    response = post(payload)
    assert response.status_code == 422
    assert not isolated_store.exists()


@pytest.mark.parametrize("field", ["confidence_score", "min_confidence"])
def test_confidence_above_one_rejected(field):
    payload = sample_payload()
    if field == "min_confidence":
        payload["policy_thresholds"][field] = 1.01
    else:
        payload[field] = 1.01
    assert post(payload).status_code == 422


@pytest.mark.parametrize("field", ["confidence_score", "transaction_amount", "min_confidence", "max_unsupervised_amount"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_numeric_inputs_rejected_safely(field, value, isolated_store, caplog):
    payload = sample_payload(redacted_subject_ref=SECRET)
    if field in payload["policy_thresholds"]:
        payload["policy_thresholds"][field] = value
    else:
        payload[field] = value
    # httpx correctly rejects non-JSON constants in json=; use raw content to
    # exercise Pydantic's finite-number checks on Python's permissive decoder.
    response = client.post(
        "/api/governance/check", content=json.dumps(payload),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert SECRET not in response.text
    assert SECRET not in caplog.text
    assert not isolated_store.exists()


@pytest.mark.parametrize("field", ["confidence_score", "transaction_amount", "min_confidence", "max_unsupervised_amount"])
def test_overflow_json_number_is_rejected(field, isolated_store):
    payload = sample_payload()
    if field in payload["policy_thresholds"]:
        payload["policy_thresholds"][field] = "OVERFLOW"
    else:
        payload[field] = "OVERFLOW"
    response = client.post(
        "/api/governance/check", content=json.dumps(payload).replace('"OVERFLOW"', "1e999"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert not isolated_store.exists()


@pytest.mark.parametrize("thresholds", [None, [], "thresholds", 1, True])
def test_thresholds_must_be_an_object(thresholds, isolated_store):
    assert post(sample_payload(policy_thresholds=thresholds)).status_code == 422
    assert not isolated_store.exists()


@pytest.mark.parametrize("nested", [False, True])
def test_unknown_extra_fields_rejected_and_not_logged_or_stored(nested, isolated_store, caplog):
    payload = sample_payload()
    target = payload["policy_thresholds"] if nested else payload
    target[SECRET] = "secret-PII-value"
    response = post(payload)
    assert response.status_code == 422
    assert SECRET not in response.text + caplog.text
    assert "secret-PII-value" not in response.text + caplog.text
    assert not isolated_store.exists()


def test_only_response_persisted_and_no_payload_fields_or_values(isolated_store, caplog):
    response = post(sample_payload(
        model_id="private-model-identity", decision_domain="private-domain-value",
        proposed_action="private-action-value", redacted_subject_ref=SECRET,
    ))
    assert response.status_code == 200
    raw = isolated_store.read_text(encoding="utf-8")
    data = json.loads(raw)
    assert set(data) == {"checks"}
    assert data["checks"] == {response.json()["receipt_id"]: response.json()}
    for field in sample_payload():
        assert field not in raw
    for private in (SECRET, "private-model-identity", "private-domain-value", "private-action-value"):
        assert private not in raw + response.text + caplog.text
    assert "signature" not in raw
    assert "payload" not in raw


def test_rules_are_pure_repeatable_functions():
    request = GovernanceCheckRequest.model_validate(sample_payload(
        model_id="unknown", confidence_score=0.1, transaction_amount=20000,
    ))
    before = request.model_dump(mode="json")
    assert run_checks(request) == run_checks(request)
    assert compute_receipt_id(request) == compute_receipt_id(request)
    assert request.model_dump(mode="json") == before
