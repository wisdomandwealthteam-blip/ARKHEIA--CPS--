"""Fail-closed behavior for ClearCheck's single-process JSON store."""
from __future__ import annotations

import builtins
import json
import traceback

import pytest

from cps_backend.config import settings
from cps_backend.services import clearcheck_store as store


@pytest.fixture
def store_path(tmp_path):
    path = tmp_path / "nested" / "clearcheck.json"
    original = settings.clearcheck_store_path
    object.__setattr__(settings, "clearcheck_store_path", str(path))
    try:
        yield path
    finally:
        object.__setattr__(settings, "clearcheck_store_path", original)


def _put_bytes(path, contents):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)


def _record(check_id="chk_test"):
    return {
        "check_id": check_id,
        "jurisdiction": "US",
        "findings": [],
        "findings_count": 0,
        "redacted_summary": [],
    }


@pytest.mark.parametrize(
    "contents",
    [
        b'{"checks": {"secret":',
        b'{"checks": {}, "processed_events": {}',
        b'\xffsecret-contents',
        b'[]',
        b'null',
        b'{}',
        b'{"checks": {}, "processed_events": []}',
        b'{"checks": [], "processed_events": {}}',
        b'{"checks": {"chk_test": "bad record"}, "processed_events": {}}',
        b'{"checks": {"chk_test": null}, "processed_events": {}}',
        b'{"checks": {"chk_test": {}}, "processed_events": {}}',
        b'{"checks": {"chk_test": {"unlocked": "false"}}, "processed_events": {}}',
        b'{"checks": {"chk_test": {"check_id": "other"}}, "processed_events": {}}',
        b'{"checks": {"chk_test": {"findings": ["bad"]}}, "processed_events": {}}',
        b'{"checks": {}, "processed_events": {"evt_secret": null}}',
        b'{"checks": {}, "checks": {}, "processed_events": {}}',
        b'{"checks": {}, "processed_events": {}, "extra": NaN}',
    ],
    ids=[
        "truncated-record", "truncated-object", "non-utf8", "top-list", "top-null",
        "missing-sections", "events-list", "checks-list", "record-string", "record-null",
        "empty-record", "unlocked-string", "id-mismatch", "finding-string", "event-value",
        "duplicate-key", "not-json-nan",
    ],
)
def test_corrupt_store_is_rejected_without_overwriting(store_path, contents, caplog):
    _put_bytes(store_path, contents)

    for operation in (
        lambda: store.get_check("chk_test"),
        lambda: store.save_check(_record()),
        lambda: store.mark_unlocked("chk_test", "evt_test"),
        lambda: store.was_event_processed("evt_test"),
    ):
        with pytest.raises(store.ClearCheckStoreCorruptError) as exc:
            operation()
        assert isinstance(exc.value, store.ClearCheckStoreError)
        assert exc.value.__context__ is None
        assert "secret" not in str(exc.value)
        assert "secret" not in "".join(traceback.format_exception(exc.value))
        assert store_path.read_bytes() == contents
    assert "secret" not in caplog.text
    assert not store_path.with_name(store_path.name + ".tmp").exists()


def test_absent_store_is_created_and_persists_records_and_events(store_path):
    assert store.get_check("chk_test") is None
    assert json.loads(store_path.read_text(encoding="utf-8")) == {
        "checks": {}, "processed_events": {}
    }

    store.save_check(_record())
    store.save_check(_record("chk_other"))
    first = store.get_check("chk_test")
    assert first["unlocked"] is False
    assert first["created_at"]
    assert store.mark_unlocked("chk_test", "evt_1") == store.UNLOCKED
    unlocked = store.get_check("chk_test")
    assert unlocked["unlocked"] is True
    assert unlocked["unlock_event_id"] == "evt_1"
    assert store.was_event_processed("evt_1")
    assert store.mark_unlocked("chk_test", "evt_1") == store.DUPLICATE_EVENT

    # A repeated preview must not relock a paid record or erase other data.
    store.save_check(_record())
    reloaded = store.get_check("chk_test")
    assert reloaded["unlocked"] is True
    assert reloaded["unlocked_at"] == unlocked["unlocked_at"]
    assert reloaded["unlock_event_id"] == "evt_1"
    assert store.get_check("chk_other") is not None
    assert store.was_event_processed("evt_1")


def test_existing_valid_store_is_preserved_when_updated(store_path):
    original = {
        "checks": {"chk_old": {"check_id": "chk_old", "unlocked": True}},
        "processed_events": {"evt_old": "2025-01-01T00:00:00+00:00"},
        "other_metadata": {"version": 1},
    }
    _put_bytes(store_path, json.dumps(original).encode())
    store.save_check(_record())
    result = json.loads(store_path.read_text(encoding="utf-8"))
    assert result["checks"]["chk_old"] == original["checks"]["chk_old"]
    assert result["processed_events"] == original["processed_events"]
    assert result["other_metadata"] == original["other_metadata"]


def test_unreadable_store_raises_unavailable_without_leaking_cause(store_path, monkeypatch):
    contents = b'{"checks": {}, "processed_events": {}}'
    _put_bytes(store_path, contents)
    real_open = builtins.open

    def denied_open(path, mode="r", *args, **kwargs):
        if str(path) == str(store_path) and mode == "r":
            raise PermissionError("secret-sensitive-error")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", denied_open)
    with pytest.raises(store.ClearCheckStoreUnavailableError) as exc:
        store.get_check("chk_test")
    assert isinstance(exc.value, store.ClearCheckStoreError)
    assert exc.value.__context__ is None
    assert "secret-sensitive-error" not in "".join(traceback.format_exception(exc.value))
    assert store_path.read_bytes() == contents


def test_initial_creation_failure_is_unavailable(store_path, monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError("secret-directory-name")

    monkeypatch.setattr(store.os, "makedirs", denied)
    with pytest.raises(store.ClearCheckStoreUnavailableError) as exc:
        store.get_check("chk_test")
    assert exc.value.__context__ is None
    assert "secret-directory-name" not in "".join(traceback.format_exception(exc.value))
    assert not store_path.exists()


@pytest.mark.parametrize("failure_stage", ["write", "replace"])
def test_write_failure_leaves_previous_store_intact(store_path, monkeypatch, failure_stage):
    store.save_check(_record("chk_existing"))
    previous = store_path.read_bytes()

    def fail(*args, **kwargs):
        raise OSError("secret-write-error")

    if failure_stage == "write":
        monkeypatch.setattr(store.json, "dump", fail)
    else:
        monkeypatch.setattr(store.os, "replace", fail)

    with pytest.raises(store.ClearCheckStoreUnavailableError) as exc:
        store.save_check(_record("chk_new"))
    assert exc.value.__context__ is None
    assert "secret-write-error" not in "".join(traceback.format_exception(exc.value))
    assert store_path.read_bytes() == previous
    assert store.get_check("chk_existing") is not None
    assert store.get_check("chk_new") is None


def test_failed_unlock_does_not_record_event_or_unlock_check(store_path, monkeypatch):
    store.save_check(_record())
    previous = store_path.read_bytes()

    def fail_replace(*args, **kwargs):
        raise PermissionError("write denied")

    monkeypatch.setattr(store.os, "replace", fail_replace)
    with pytest.raises(store.ClearCheckStoreUnavailableError):
        store.mark_unlocked("chk_test", "evt_test")
    assert store_path.read_bytes() == previous
    assert store.get_check("chk_test")["unlocked"] is False
    assert not store.was_event_processed("evt_test")


def test_invalid_outgoing_data_does_not_replace_store(store_path):
    store.save_check(_record("chk_existing"))
    previous = store_path.read_bytes()
    with pytest.raises(store.ClearCheckStoreCorruptError):
        store._write_all({"checks": {"chk_new": []}, "processed_events": {}})
    assert store_path.read_bytes() == previous


def test_unlock_logs_do_not_include_untrusted_check_or_event_ids(store_path, caplog):
    caplog.set_level("INFO", logger="cps_backend")
    check_id = "private-check-identity@example.invalid"
    event_id = "private-event-identifier"
    store.save_check(_record(check_id))
    assert store.mark_unlocked("unknown-private-check", "unknown-private-event") == store.UNKNOWN_CHECK
    assert store.mark_unlocked(check_id, event_id) == store.UNLOCKED
    assert store.mark_unlocked(check_id, event_id) == store.DUPLICATE_EVENT
    assert check_id not in caplog.text
    assert event_id not in caplog.text
    assert "unknown-private-check" not in caplog.text
    assert "unknown-private-event" not in caplog.text
