"""Additive platform check contracts, strict evidence rules and canonical hashes."""
from __future__ import annotations

import copy
import hashlib
import itertools
import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from cps_backend.main import app
from cps_backend.schemas.platform_checks import (
    ARCHITECTURE_VERSION, FINDING_REASONS, RULE_ORDER, CustodyCheckRequest,
    EdgeCheckRequest, PlatformCheckResponse, PlatformFinding,
    ProvenanceCheckRequest, SettlementCheckRequest,
)
from cps_backend.services import platform_check_engine
from cps_backend.services.clearcheck_engine import compute_check_id

client = TestClient(app, raise_server_exceptions=False)
RECEIPT_KEYS = {"receipt_id", "gate", "findings", "sha256", "timestamp", "architecture_version"}
SECRET = "private-subject@example.invalid"
CASES = {
    "settlement": {
        "prefix": "stl_", "model": SettlementCheckRequest,
        "payload": {"splits_bps": [6000, 4000], "gross_amount_cents": 12000},
        "failures": [{"splits_bps": [6000, 3999]}, {"gross_amount_cents": 0}],
        "fields": {
            "splits_bps": "SPLIT_CONSERVATION_VIOLATION",
            "gross_amount_cents": "INVALID_GROSS_AMOUNT",
        },
    },
    "provenance": {
        "prefix": "prv_", "model": ProvenanceCheckRequest,
        "payload": {"isrc": "USAAA2600001", "audio_fingerprint_sha256": "a" * 64,
                    "rights_cleared": True, "splits_bps": [6000, 4000]},
        "failures": [{"isrc": ""}, {"rights_cleared": False}, {"splits_bps": [9999]}],
        "fields": {
            "isrc": "MISSING_PROVENANCE_HASH",
            "audio_fingerprint_sha256": "MISSING_PROVENANCE_HASH",
            "rights_cleared": "UNVERIFIED_RIGHTS_CHAIN",
            "splits_bps": "SPLIT_CONSERVATION_VIOLATION",
        },
    },
    "custody": {
        "prefix": "cst_", "model": CustodyCheckRequest,
        "payload": {"signatures_collected": 3, "quorum_required": 2,
                    "policy_window_active": True, "release_amount": 1000, "custody_limit": 1500},
        "failures": [{"signatures_collected": 1}, {"policy_window_active": False},
                     {"release_amount": 1501}],
        "fields": {
            "signatures_collected": "INSUFFICIENT_QUORUM_SIGNATURES",
            "quorum_required": "INSUFFICIENT_QUORUM_SIGNATURES",
            "policy_window_active": "EXPIRED_OR_INACTIVE_CUSTODY_POLICY",
            "release_amount": "CUSTODY_LIMIT_EXCEEDED",
            "custody_limit": "CUSTODY_LIMIT_EXCEEDED",
        },
    },
    "edge": {
        "prefix": "edg_", "model": EdgeCheckRequest,
        "payload": {"node_attestation_valid": True, "telemetry_within_bounds": True,
                    "offline_queue_hash": "b" * 64},
        "failures": [{"node_attestation_valid": False}, {"telemetry_within_bounds": False},
                     {"offline_queue_hash": ""}],
        "fields": {
            "node_attestation_valid": "UNATTESTED_EDGE_NODE",
            "telemetry_within_bounds": "SENSOR_INVARIANT_BREACH",
            "offline_queue_hash": "MISSING_LOCAL_AUDIT_HASH",
        },
    },
}


def sample(domain, **changes):
    payload = copy.deepcopy(CASES[domain]["payload"])
    payload.update(changes)
    return payload


def post(domain, payload):
    return client.post(f"/api/{domain}/check", json=payload)


def assert_receipt(response, domain, expected):
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == RECEIPT_KEYS
    assert body["architecture_version"] == ARCHITECTURE_VERSION
    assert body["gate"] == ("HOLD" if expected else "PASS")
    assert [finding["code"] for finding in body["findings"]] == expected
    assert body["findings"] == [
        {"code": code, "reason": FINDING_REASONS[code]} for code in expected
    ]
    assert re.fullmatch(CASES[domain]["prefix"] + r"[0-9a-f]{64}", body["receipt_id"])
    assert body["receipt_id"] == CASES[domain]["prefix"] + body["sha256"]
    timestamp = datetime.fromisoformat(body["timestamp"].replace("Z", "+00:00"))
    assert timestamp.utcoffset() == timedelta(0)
    assert abs((datetime.now(timezone.utc) - timestamp).total_seconds()) < 60
    assert response.headers["cache-control"] == "no-store"
    PlatformCheckResponse.model_validate(body)
    return body


@pytest.mark.parametrize("domain", CASES)
def test_pass_canonical_envelope(domain):
    assert_receipt(post(domain, sample(domain)), domain, [])


COMBINATIONS = [
    (domain, enabled)
    for domain, case in CASES.items()
    for enabled in itertools.product([False, True], repeat=len(case["failures"]))
    if any(enabled)
]


@pytest.mark.parametrize("domain,enabled", COMBINATIONS)
def test_every_individual_and_combined_finding_in_fixed_order(domain, enabled):
    changes = {}
    expected = []
    for index, fails in enumerate(enabled):
        if fails:
            changes.update(CASES[domain]["failures"][index])
            expected.append(RULE_ORDER[CASES[domain]["prefix"]][index])
    assert_receipt(post(domain, sample(domain, **changes)), domain, expected)


FIELD_CASES = [(domain, field, code) for domain, case in CASES.items()
               for field, code in case["fields"].items()]


@pytest.mark.parametrize("domain,field,code", FIELD_CASES)
def test_each_missing_field_has_relevant_hold_finding(domain, field, code):
    payload = sample(domain)
    del payload[field]
    assert_receipt(post(domain, payload), domain, [code])


@pytest.mark.parametrize("domain,field,code", FIELD_CASES)
@pytest.mark.parametrize("value", [None, {}, [], "", False])
def test_malformed_evidence_never_coerces_or_passes(domain, field, code, value):
    assert_receipt(post(domain, sample(domain, **{field: value})), domain, [code])


@pytest.mark.parametrize("domain", ["settlement", "provenance"])
@pytest.mark.parametrize("value", [
    True, 10000, 10000.0, "10000", [], [9999], [10001], [5000, 4999],
    [5000, 5000.0], [10000.0], [True, 9999], [False, 10000], ["10000"],
    [[10000]], [{"bps": 10000}], {"artist": 10000}, [-1, 10001],
])
def test_splits_require_nonnegative_exact_integer_array_conservation(domain, value):
    assert_receipt(post(domain, sample(domain, splits_bps=value)), domain,
                   ["SPLIT_CONSERVATION_VIOLATION"])


@pytest.mark.parametrize("domain", ["settlement", "provenance"])
@pytest.mark.parametrize("value", [[10000], [0, 10000], [3333, 3333, 3334], [5000, 5000]])
def test_conserved_split_boundaries_pass(domain, value):
    assert_receipt(post(domain, sample(domain, splits_bps=value)), domain, [])


@pytest.mark.parametrize("value", [True, 1.0, 0.0, 0, -1, "12000", "1", "1.0"])
def test_gross_requires_positive_exact_integer_cents(value):
    assert_receipt(post("settlement", sample("settlement", gross_amount_cents=value)),
                   "settlement", ["INVALID_GROSS_AMOUNT"])


@pytest.mark.parametrize("value", [1, 12000, 10**100])
def test_positive_integer_gross_boundaries_pass(value):
    assert_receipt(post("settlement", sample("settlement", gross_amount_cents=value)),
                   "settlement", [])


BOOL_FIELDS = [("provenance", "rights_cleared", "UNVERIFIED_RIGHTS_CHAIN"),
               ("custody", "policy_window_active", "EXPIRED_OR_INACTIVE_CUSTODY_POLICY"),
               ("edge", "node_attestation_valid", "UNATTESTED_EDGE_NODE"),
               ("edge", "telemetry_within_bounds", "SENSOR_INVARIANT_BREACH")]


@pytest.mark.parametrize("domain,field,code", BOOL_FIELDS)
@pytest.mark.parametrize("value", [1, 0, 1.0, "true", "True", "false", "yes", [True]])
def test_required_boolean_must_be_exactly_true(domain, field, code, value):
    assert_receipt(post(domain, sample(domain, **{field: value})), domain, [code])


STRING_FIELDS = [("provenance", "isrc", "MISSING_PROVENANCE_HASH"),
                 ("provenance", "audio_fingerprint_sha256", "MISSING_PROVENANCE_HASH"),
                 ("edge", "offline_queue_hash", "MISSING_LOCAL_AUDIT_HASH")]


@pytest.mark.parametrize("domain,field,code", STRING_FIELDS)
@pytest.mark.parametrize("value", ["", " \t\n", True, 123, 1.0])
def test_provenance_and_audit_fields_require_nonempty_strings(domain, field, code, value):
    assert_receipt(post(domain, sample(domain, **{field: value})), domain, [code])


@pytest.mark.parametrize("field", ["signatures_collected", "quorum_required"])
@pytest.mark.parametrize("value", [True, 2.0, "2", -1])
def test_custody_signature_counts_are_nonnegative_exact_integers(field, value):
    assert_receipt(post("custody", sample("custody", **{field: value})), "custody",
                   ["INSUFFICIENT_QUORUM_SIGNATURES"])


@pytest.mark.parametrize("field", ["release_amount", "custody_limit"])
@pytest.mark.parametrize("value", [True, -0.1, "1000", "Infinity", "nan"])
def test_custody_amounts_are_nonnegative_finite_numbers_not_booleans(field, value):
    assert_receipt(post("custody", sample("custody", **{field: value})), "custody",
                   ["CUSTODY_LIMIT_EXCEEDED"])


@pytest.mark.parametrize("changes", [
    {"signatures_collected": 2},
    {"signatures_collected": 0, "quorum_required": 0},
    {"release_amount": 1500},
    {"release_amount": 0, "custody_limit": 0},
    {"release_amount": 12.5, "custody_limit": 12.5},
    {"release_amount": 10**400, "custody_limit": 10**400},
])
def test_custody_equality_zero_and_finite_amount_boundaries_pass(changes):
    assert_receipt(post("custody", sample("custody", **changes)), "custody", [])


@pytest.mark.parametrize("domain", CASES)
@pytest.mark.parametrize("payload", [{}, None, [], [10000], True, 123, 1.5, "payload"])
def test_empty_or_nonobject_body_fails_every_domain_rule(domain, payload):
    assert_receipt(post(domain, payload), domain, list(RULE_ORDER[CASES[domain]["prefix"]]))


@pytest.mark.parametrize("domain", CASES)
@pytest.mark.parametrize("content", [b"", b"{", b"not-json", b'{"field":}', b"\xff"])
def test_invalid_json_and_encoding_return_canonical_hold_without_echo(domain, content, caplog):
    response = client.post(f"/api/{domain}/check", content=content,
                           headers={"Content-Type": "application/json"})
    assert_receipt(response, domain, list(RULE_ORDER[CASES[domain]["prefix"]]))
    assert "not-json" not in response.text + caplog.text


@pytest.mark.parametrize("domain", CASES)
def test_absent_body_returns_hold(domain):
    assert_receipt(client.post(f"/api/{domain}/check"), domain,
                   list(RULE_ORDER[CASES[domain]["prefix"]]))


@pytest.mark.parametrize("domain", CASES)
def test_duplicate_json_keys_cannot_override_failed_evidence(domain):
    payload = json.dumps(sample(domain))
    first_field = next(iter(CASES[domain]["fields"]))
    ambiguous = '{' + json.dumps(first_field) + ':null,' + payload[1:]
    response = client.post(f"/api/{domain}/check", content=ambiguous,
                           headers={"Content-Type": "application/json"})
    assert_receipt(response, domain, list(RULE_ORDER[CASES[domain]["prefix"]]))


@pytest.mark.parametrize("domain,field,code", [
    ("settlement", "gross_amount_cents", "INVALID_GROSS_AMOUNT"),
    ("custody", "release_amount", "CUSTODY_LIMIT_EXCEEDED"),
    ("custody", "custody_limit", "CUSTODY_LIMIT_EXCEEDED"),
])
@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"])
def test_nonfinite_numeric_evidence_normalizes_to_null_and_fails_relevant_rule(domain, field, code, token):
    payload = json.dumps(sample(domain, **{field: "NONFINITE"})).replace('"NONFINITE"', token)
    response = client.post(f"/api/{domain}/check", content=payload,
                           headers={"Content-Type": "application/json"})
    body = assert_receipt(response, domain, [code])
    null_body = post(domain, sample(domain, **{field: None})).json()
    assert body["sha256"] == null_body["sha256"]


@pytest.mark.parametrize("domain", CASES)
def test_canonical_hash_parity_reordering_stability_and_content_change(domain):
    payload = sample(domain, redacted_subject_ref="subject-redacted-0001")
    normalized = CASES[domain]["model"].model_validate(payload)
    canonical = json.dumps(normalized.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    first = assert_receipt(post(domain, payload), domain, [])
    second = assert_receipt(post(domain, dict(reversed(list(payload.items())))), domain, [])
    assert first["sha256"] == digest
    assert first["receipt_id"] == CASES[domain]["prefix"] + digest
    assert compute_check_id(normalized) == "chk_" + digest
    assert platform_check_engine.compute_receipt_id(normalized, CASES[domain]["prefix"]) == first["receipt_id"]
    assert {k: v for k, v in first.items() if k != "timestamp"} == {
        k: v for k, v in second.items() if k != "timestamp"
    }
    changed = post(domain, sample(domain, redacted_subject_ref="subject-redacted-0002")).json()
    assert changed["receipt_id"] != first["receipt_id"]
    assert changed["findings"] == first["findings"]


@pytest.mark.parametrize("domain", CASES)
def test_missing_and_explicit_null_evidence_hash_identically(domain):
    assert post(domain, {}).json()["sha256"] == post(
        domain, {field: None for field in CASES[domain]["fields"]}
    ).json()["sha256"]


@pytest.mark.parametrize("domain", CASES)
def test_engine_reuses_existing_canonical_hash_function(domain, monkeypatch):
    seen = []

    def canonical(request):
        seen.append(request)
        return "chk_" + "a" * 64

    monkeypatch.setattr(platform_check_engine, "compute_check_id", canonical)
    request = CASES[domain]["model"].model_validate(sample(domain))
    assert platform_check_engine.compute_receipt_id(request, CASES[domain]["prefix"]) == (
        CASES[domain]["prefix"] + "a" * 64
    )
    assert seen == [request]


@pytest.mark.parametrize("domain", CASES)
def test_only_masked_allowlisted_subject_reference_enters_hash_and_no_input_echo(domain, monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("CPS_GOVERNANCE_STORE_PATH", str(tmp_path / "governance.json"))
    monkeypatch.setenv("CPS_CLEARCHECK_STORE_PATH", str(tmp_path / "clearcheck.json"))
    payload = sample(domain, redacted_subject_ref=SECRET)
    payload[SECRET] = "private-extra-value"
    normalized = CASES[domain]["model"].model_validate(payload).model_dump(mode="json")
    assert normalized["redacted_subject_ref"] != SECRET
    assert normalized["redacted_subject_ref"].endswith(SECRET[-4:])
    assert SECRET not in json.dumps(normalized)
    assert "private-extra-value" not in json.dumps(normalized)
    first = assert_receipt(post(domain, payload), domain, [])
    without_extra = assert_receipt(post(domain, sample(domain, redacted_subject_ref=SECRET)), domain, [])
    assert first["sha256"] == without_extra["sha256"]
    assert SECRET not in json.dumps(first) + caplog.text
    assert "private-extra-value" not in json.dumps(first) + caplog.text
    assert "redacted_subject_ref" not in first
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("domain", CASES)
def test_nonstring_optional_reference_is_ignored_without_affecting_gate(domain):
    response = assert_receipt(post(domain, sample(domain, redacted_subject_ref={"secret": SECRET})), domain, [])
    assert response["sha256"] == post(domain, sample(domain)).json()["sha256"]


@pytest.mark.parametrize("domain", CASES)
def test_rule_engine_is_repeatable_and_does_not_mutate_evidence(domain):
    changes = {key: value for failure in CASES[domain]["failures"] for key, value in failure.items()}
    request = CASES[domain]["model"].model_validate(sample(domain, **changes))
    before = request.model_dump(mode="json")
    assert platform_check_engine.run_checks(request) == platform_check_engine.run_checks(request)
    assert [finding.code for finding in platform_check_engine.run_checks(request)] == list(RULE_ORDER[CASES[domain]["prefix"]])
    assert request.model_dump(mode="json") == before


@pytest.mark.parametrize("changes", [
    {"gate": "HOLD"}, {"sha256": "b" * 64}, {"receipt_id": "gov_" + "a" * 64},
    {"receipt_id": "stl_" + "A" * 64}, {"timestamp": 0},
    {"timestamp": "2026-01-01T00:00:00"}, {"timestamp": "2026-01-01T01:00:00+01:00"},
    {"architecture_version": "1.0.0"}, {"signature": "not-signed"},
    {"findings": [{"code": "INVALID_GROSS_AMOUNT", "reason": SECRET}]},
    {"gate": "HOLD", "findings": [{"code": "MISSING_LOCAL_AUDIT_HASH", "reason": FINDING_REASONS["MISSING_LOCAL_AUDIT_HASH"]}]},
])
def test_receipt_model_rejects_inconsistent_or_noncanonical_envelopes(changes):
    receipt = {"receipt_id": "stl_" + "a" * 64, "gate": "PASS", "findings": [],
               "sha256": "a" * 64, "timestamp": "2026-01-01T00:00:00Z",
               "architecture_version": ARCHITECTURE_VERSION}
    receipt.update(changes)
    with pytest.raises(ValidationError):
        PlatformCheckResponse.model_validate(receipt)


@pytest.mark.parametrize("codes", [
    ["INVALID_GROSS_AMOUNT", "SPLIT_CONSERVATION_VIOLATION"],
    ["INVALID_GROSS_AMOUNT", "INVALID_GROSS_AMOUNT"],
])
def test_receipt_model_rejects_reordered_or_duplicate_findings(codes):
    with pytest.raises(ValidationError):
        PlatformCheckResponse(
            receipt_id="stl_" + "a" * 64, gate="HOLD", sha256="a" * 64,
            timestamp=datetime.now(timezone.utc), findings=[
                PlatformFinding(code=code, reason=FINDING_REASONS[code]) for code in codes
            ],
        )
