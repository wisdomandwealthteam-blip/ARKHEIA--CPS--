"""Privacy-safe, atomic governance persistence under corruption and I/O failures."""
from __future__ import annotations

import builtins
import json
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from cps_backend.main import app
from cps_backend.schemas.governance import (
    ARCHITECTURE_VERSION,
    FINDING_REASONS,
    GovernanceCheckRequest,
    GovernanceCheckResponse,
    GovernanceFinding,
)
from cps_backend.services import governance_store as store
from cps_backend.services.governance_engine import compute_receipt_id

client = TestClient(app, raise_server_exceptions=False)
SECRET = "secret-store-subject@example.invalid"


@pytest.fixture(autouse=True)
def store_path(tmp_path, monkeypatch):
    path = tmp_path / "nested" / "governance_checks.json"
    monkeypatch.setenv("CPS_GOVERNANCE_STORE_PATH", str(path))
    return path


def payload():
    return {
        "model_id": "known-model-v1", "decision_domain": "finance",
        "proposed_action": "transfer", "confidence_score": 0.95,
        "human_override_required": False, "redacted_subject_ref": SECRET,
    }


def record(digest="a" * 64, findings=None, timestamp=None):
    return GovernanceCheckResponse(
        receipt_id="gov_" + digest, gate="HOLD" if findings else "PASS",
        architecture_version=ARCHITECTURE_VERSION, sha256_digest=digest,
        findings=findings or [], evaluated_at=timestamp or datetime.now(timezone.utc),
    )


def put_bytes(path, contents):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)


def assert_safe_exception(exc):
    assert exc.value.__context__ is None
    assert SECRET not in str(exc.value)
    assert SECRET not in "".join(traceback.format_exception(exc.value))


def assert_api_unavailable(receipt_id, caplog):
    for response in (
        client.post("/api/governance/check", json=payload()),
        client.get("/api/governance/checks/" + receipt_id),
    ):
        assert response.status_code == 503
        assert response.json() == {"detail": "Governance records are temporarily unavailable."}
        assert response.headers["cache-control"] == "no-store"
        assert SECRET not in response.text
        assert "Traceback" not in response.text
    assert SECRET not in caplog.text


@pytest.mark.parametrize("contents", [
    b'{"checks": {"secret-store-subject@example.invalid":',
    b'{"checks": {}', b'\xffsecret-store-subject@example.invalid',
    b'[]', b'null', b'{}', b'{"checks": []}', b'{"checks": null}',
    b'{"checks": {}, "extra": "secret-store-subject@example.invalid"}',
    b'{"checks": {"gov_bad": {}}}', b'{"checks": {"gov_bad": null}}',
    b'{"checks": {"gov_bad": "secret-store-subject@example.invalid"}}',
    b'{"checks": {}, "checks": {}}', b'{"checks": {}, "extra": NaN}',
    b'{"checks": {}, "extra": Infinity}', b'{"checks": {}, "extra": -Infinity}',
], ids=[
    "truncated-record", "truncated-root", "invalid-utf8", "list-root", "null-root",
    "missing-checks", "checks-list", "checks-null", "extra-root", "empty-record",
    "null-record", "string-record", "duplicate-root", "nan", "infinity", "negative-infinity",
])
def test_corrupt_store_returns_sanitized_503_and_preserves_bytes(store_path, contents, caplog):
    put_bytes(store_path, contents)
    for operation in (
        lambda: store.get_check("gov_" + "a" * 64),
        lambda: store.save_check(record()),
    ):
        with pytest.raises(store.GovernanceStoreCorruptError) as exc:
            operation()
        assert_safe_exception(exc)
        assert store_path.read_bytes() == contents
    assert_api_unavailable("gov_" + "a" * 64, caplog)
    assert store_path.read_bytes() == contents
    assert not list(store_path.parent.glob(".governance-*.tmp"))


@pytest.mark.parametrize("tamper", [
    "extra-receipt", "extra-finding", "private-reason", "unknown-code", "id-mismatch",
    "digest-mismatch", "invalid-id", "invalid-digest", "missing-timestamp",
    "naive-timestamp", "non-utc-timestamp", "numeric-timestamp", "private-timestamp",
    "private-architecture", "private-gate", "pass-with-findings", "hold-without-findings",
    "duplicate-findings", "out-of-order-findings", "missing-field", "null-findings",
    "findings-object", "private-finding", "uppercase-digest",
])
def test_invalid_persisted_receipt_cannot_echo_stored_pii(store_path, tamper, caplog):
    finding = GovernanceFinding(code="LOW_MODEL_CONFIDENCE", reason=FINDING_REASONS["LOW_MODEL_CONFIDENCE"])
    receipt = record(findings=[finding]).model_dump(mode="json")
    key = receipt["receipt_id"]
    if tamper == "extra-receipt":
        receipt["subject_email"] = SECRET
    elif tamper == "extra-finding":
        receipt["findings"][0]["subject_email"] = SECRET
    elif tamper == "private-reason":
        receipt["findings"][0]["reason"] = SECRET
    elif tamper == "unknown-code":
        receipt["findings"][0]["code"] = SECRET
    elif tamper == "id-mismatch":
        key = "gov_" + "b" * 64
    elif tamper == "digest-mismatch":
        receipt["sha256_digest"] = "b" * 64
    elif tamper == "invalid-id":
        receipt["receipt_id"] = SECRET
    elif tamper == "invalid-digest":
        receipt["sha256_digest"] = SECRET
    elif tamper == "missing-timestamp":
        del receipt["evaluated_at"]
    elif tamper == "naive-timestamp":
        receipt["evaluated_at"] = "2026-11-25T18:00:00"
    elif tamper == "non-utc-timestamp":
        receipt["evaluated_at"] = "2026-11-25T18:00:00+01:00"
    elif tamper == "numeric-timestamp":
        receipt["evaluated_at"] = 1700000000
    elif tamper == "private-timestamp":
        receipt["evaluated_at"] = SECRET
    elif tamper == "private-architecture":
        receipt["architecture_version"] = SECRET
    elif tamper == "private-gate":
        receipt["gate"] = SECRET
    elif tamper == "pass-with-findings":
        receipt["gate"] = "PASS"
    elif tamper == "hold-without-findings":
        receipt["findings"] = []
    elif tamper == "duplicate-findings":
        receipt["findings"] *= 2
    elif tamper == "out-of-order-findings":
        receipt["findings"].insert(0, {
            "code": "MISSING_MODEL_PROVENANCE", "reason": FINDING_REASONS["MISSING_MODEL_PROVENANCE"]
        })
    elif tamper == "missing-field":
        del receipt["sha256_digest"]
    elif tamper == "null-findings":
        receipt["findings"] = None
    elif tamper == "findings-object":
        receipt["findings"] = {SECRET: "private"}
    elif tamper == "private-finding":
        receipt["findings"] = [SECRET]
    elif tamper == "uppercase-digest":
        receipt["receipt_id"] = "gov_" + "A" * 64
        receipt["sha256_digest"] = "A" * 64
        key = receipt["receipt_id"]
    original = json.dumps({"checks": {key: receipt}}).encode()
    put_bytes(store_path, original)
    with pytest.raises(store.GovernanceStoreCorruptError) as exc:
        store.get_check(key)
    assert_safe_exception(exc)
    assert_api_unavailable("gov_" + "a" * 64, caplog)
    assert store_path.read_bytes() == original


def test_corruption_in_other_record_also_fails_closed(store_path, caplog):
    valid = record().model_dump(mode="json")
    bad = record("b" * 64).model_dump(mode="json")
    bad["private"] = SECRET
    original = json.dumps({"checks": {valid["receipt_id"]: valid, bad["receipt_id"]: bad}}).encode()
    put_bytes(store_path, original)
    assert_api_unavailable(valid["receipt_id"], caplog)
    assert store_path.read_bytes() == original


def test_duplicate_nested_keys_are_corrupt(store_path):
    receipt = record().model_dump(mode="json")
    raw = json.dumps({"checks": {receipt["receipt_id"]: receipt}})
    raw = raw.replace('"gate": "PASS"', '"gate": "PASS", "gate": "PASS"')
    put_bytes(store_path, raw.encode())
    with pytest.raises(store.GovernanceStoreCorruptError) as exc:
        store.get_check(receipt["receipt_id"])
    assert_safe_exception(exc)
    assert store_path.read_text() == raw


def test_read_io_failure_is_sanitized_and_preserves_file(store_path, monkeypatch, caplog):
    saved = store.save_check(record())
    before = store_path.read_bytes()
    real_open = builtins.open

    def denied(path, mode="r", *args, **kwargs):
        if str(path) == str(store_path) and mode == "r":
            raise PermissionError(SECRET)
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", denied)
    with pytest.raises(store.GovernanceStoreUnavailableError) as exc:
        store.get_check(saved.receipt_id)
    assert_safe_exception(exc)
    assert_api_unavailable(saved.receipt_id, caplog)
    assert store_path.read_bytes() == before


@pytest.mark.parametrize("failure_stage", ["directory", "temporary-file", "write", "fsync", "replace"])
def test_failed_write_is_atomic_sanitized_and_cleans_temporary_file(store_path, monkeypatch, caplog, failure_stage):
    first = store.save_check(record())
    before = store_path.read_bytes()

    def denied(*args, **kwargs):
        raise OSError(SECRET)

    if failure_stage == "directory":
        monkeypatch.setattr(store.os, "makedirs", denied)
    elif failure_stage == "temporary-file":
        monkeypatch.setattr(store.tempfile, "NamedTemporaryFile", denied)
    elif failure_stage == "write":
        monkeypatch.setattr(store.json, "dump", denied)
    elif failure_stage == "fsync":
        monkeypatch.setattr(store.os, "fsync", denied)
    else:
        monkeypatch.setattr(store.os, "replace", denied)
    with pytest.raises(store.GovernanceStoreUnavailableError) as exc:
        store.save_check(record("b" * 64))
    assert_safe_exception(exc)
    response = client.post("/api/governance/check", json=payload())
    assert response.status_code == 503
    assert response.json() == {"detail": "Governance records are temporarily unavailable."}
    assert SECRET not in response.text + caplog.text
    assert store_path.read_bytes() == before
    assert not list(store_path.parent.glob(".governance-*.tmp"))
    assert store.get_check(first.receipt_id) == first
    assert store.get_check("gov_" + "b" * 64) is None


def test_initial_creation_failure_returns_503_not_pass(store_path, monkeypatch, caplog):
    def denied(*args, **kwargs):
        raise PermissionError(SECRET)

    monkeypatch.setattr(store.os, "makedirs", denied)
    response = client.post("/api/governance/check", json=payload())
    assert response.status_code == 503
    assert "PASS" not in response.text
    assert SECRET not in response.text + caplog.text
    assert not store_path.exists()


@pytest.mark.parametrize("path_kind", ["directory", "parent-is-file", "blank", "null-byte"])
def test_invalid_or_unavailable_path_is_sanitized(store_path, monkeypatch, caplog, path_kind):
    if path_kind == "directory":
        store_path.mkdir(parents=True)
        configured = str(store_path)
    elif path_kind == "parent-is-file":
        store_path.parent.mkdir(parents=True)
        store_path.write_text(SECRET)
        configured = str(store_path / "child.json")
    elif path_kind == "blank":
        configured = " "
    else:
        configured = SECRET + "\x00"
    if path_kind == "null-byte":
        # POSIX refuses NUL bytes in real environment variables; substitute
        # the mapping to exercise the defensive configuration guard instead.
        monkeypatch.setattr(store.os, "environ", {
            **store.os.environ, "CPS_GOVERNANCE_STORE_PATH": configured,
        })
    else:
        monkeypatch.setenv("CPS_GOVERNANCE_STORE_PATH", configured)
    assert_api_unavailable("gov_" + "a" * 64, caplog)
    if path_kind == "parent-is-file":
        assert store_path.read_text() == SECRET


def test_default_path_is_exact_and_environment_is_direct(monkeypatch):
    monkeypatch.delenv("CPS_GOVERNANCE_STORE_PATH", raising=False)
    assert store._path() == "/opt/render/project/src/data/governance_checks.json"
    monkeypatch.setenv("CPS_GOVERNANCE_STORE_PATH", "custom-governance.json")
    assert store._path() == "custom-governance.json"


def test_atomic_replace_uses_same_directory_and_preserves_other_receipts(store_path, monkeypatch):
    first = store.save_check(record())
    real_replace = store.os.replace
    replacements = []

    def checked_replace(source, destination):
        from pathlib import Path

        replacements.append((source, destination))
        assert Path(source).parent == store_path.parent
        assert Path(destination) == store_path
        assert Path(source).stat().st_mode & 0o777 == 0o600
        assert store_path.read_text()
        real_replace(source, destination)

    monkeypatch.setattr(store.os, "replace", checked_replace)
    second = store.save_check(record("b" * 64))
    assert len(replacements) == 1
    assert store.get_check(first.receipt_id) == first
    assert store.get_check(second.receipt_id) == second
    assert set(json.loads(store_path.read_text())["checks"]) == {first.receipt_id, second.receipt_id}
    assert not list(store_path.parent.glob(".governance-*.tmp"))


def test_store_replay_preserves_first_timestamp_and_all_fields(store_path):
    first = record(timestamp=datetime(2026, 11, 25, tzinfo=timezone.utc))
    saved = store.save_check(first)
    original = store_path.read_bytes()
    later = record(timestamp=first.evaluated_at + timedelta(days=1))
    assert store.save_check(later) == saved
    assert store_path.read_bytes() == original


def test_invalid_outgoing_receipt_never_replaces_file(store_path):
    first = store.save_check(record())
    before = store_path.read_bytes()
    invalid = first.model_copy(update={"receipt_id": "gov_" + "b" * 64, "gate": "HOLD"})
    with pytest.raises(store.GovernanceStoreCorruptError) as exc:
        store.save_check(invalid)
    assert_safe_exception(exc)
    assert store_path.read_bytes() == before


def test_returned_receipt_mutation_does_not_mutate_disk():
    first = store.save_check(record())
    received = store.get_check(first.receipt_id)
    received.gate = "HOLD"
    received.findings.append(GovernanceFinding(
        code="LOW_MODEL_CONFIDENCE", reason=FINDING_REASONS["LOW_MODEL_CONFIDENCE"]
    ))
    assert store.get_check(first.receipt_id).gate == "PASS"
    assert store.get_check(first.receipt_id).findings == []


def test_concurrent_identical_submissions_return_the_same_first_receipt(store_path):
    digest = compute_receipt_id(GovernanceCheckRequest.model_validate(payload())).removeprefix("gov_")
    candidates = [record(digest, timestamp=datetime(2026, 11, 25, tzinfo=timezone.utc) + timedelta(seconds=i))
                  for i in range(20)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(store.save_check, candidates))
    assert all(result == results[0] for result in results)
    data = json.loads(store_path.read_text())
    assert data == {"checks": {results[0].receipt_id: results[0].model_dump(mode="json")}}


def test_concurrent_different_receipts_are_not_lost(store_path):
    candidates = [record(f"{i:064x}") for i in range(20)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(store.save_check, candidates))
    persisted = json.loads(store_path.read_text())["checks"]
    assert set(persisted) == {result.receipt_id for result in results}
    assert len(persisted) == 20


@pytest.mark.parametrize("contents", [
    b'{"checks": {}, "extra": ' + b"9" * 5000 + b"}",
    b'{"checks": ' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}",
], ids=["oversized-integer", "excessive-nesting"])
def test_json_decoder_limits_fail_closed_without_overwriting(store_path, contents, caplog):
    put_bytes(store_path, contents)
    with pytest.raises(store.GovernanceStoreCorruptError) as exc:
        store.get_check("gov_" + "a" * 64)
    assert_safe_exception(exc)
    assert_api_unavailable("gov_" + "a" * 64, caplog)
    assert store_path.read_bytes() == contents
