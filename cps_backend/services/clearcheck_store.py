"""
cps_backend.services.clearcheck_store
========================================
Persists ClearCheck check records and processed Stripe webhook event IDs
to a JSON file (data/clearcheck_checks.json by default — configurable
via CPS_CLEARCHECK_STORE_PATH).

Same design rationale and caveats as services/billing_store.py: durable
across restarts, single-instance only, and every other module talks to
the file exclusively through the functions below so the internals can be
swapped for a real database without touching callers. The lock protects
threads in this process only; it is not a cross-process lock.

File layout:
    {
      "checks": {
        "<check_id>": {
          "check_id": ..., "created_at": ..., "jurisdiction": ...,
          "findings": [...], "findings_count": N,
          "unlocked": bool, "unlocked_at": ..., "unlock_event_id": ...
        }
      },
      "processed_events": { "<stripe_event_id>": "<iso timestamp>" }
    }

`processed_events` is what makes webhook handling idempotent: Stripe can
(and does) redeliver events, and a replayed event ID is a recorded no-op.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

from cps_backend.config import settings
from cps_backend.utils.logging_setup import logger

_lock = threading.Lock()

UNLOCKED = "unlocked"
DUPLICATE_EVENT = "duplicate_event"
UNKNOWN_CHECK = "unknown_check"

_EMPTY: dict = {"checks": {}, "processed_events": {}}


class ClearCheckStoreError(Exception):
    """Base class for failures accessing the ClearCheck store."""


class ClearCheckStoreUnavailableError(ClearCheckStoreError):
    """The store could not be read or written because of an I/O failure."""


class ClearCheckStoreCorruptError(ClearCheckStoreError):
    """The store contents cannot be decoded or have an invalid structure."""


def _path() -> str:
    return settings.clearcheck_store_path


def _ensure_store_file() -> None:
    path = _path()
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        # Exclusive creation never truncates an existing file, including if it
        # appears between the directory creation and this open.
        try:
            store_file = open(path, "x", encoding="utf-8")
        except FileExistsError:
            return
        with store_file:
            json.dump(_EMPTY, store_file)
    except OSError:
        error = ClearCheckStoreUnavailableError("ClearCheck store is unavailable")
    else:
        return
    # Raise outside the handler so the original exception is not retained as
    # context (it may contain a sensitive path or other details).
    raise error


def _validate_store(data: object) -> None:
    """Reject invalid structures without exposing any stored values.

    Both sections are required: assuming a missing one is empty can erase
    checks or processed event IDs on the next write. Individual optional
    record fields remain optional for compatibility with older records.
    """
    def corrupt() -> None:
        raise ClearCheckStoreCorruptError("ClearCheck store has an invalid structure")

    if not isinstance(data, dict):
        corrupt()
    checks = data.get("checks")
    events = data.get("processed_events")
    if not isinstance(checks, dict) or not isinstance(events, dict):
        corrupt()
    if any(not isinstance(key, str) or not isinstance(value, str)
           for key, value in events.items()):
        corrupt()

    for check_id, record in checks.items():
        if not isinstance(check_id, str) or not isinstance(record, dict) or not record:
            corrupt()
        if "check_id" in record and record["check_id"] != check_id:
            corrupt()
        for field in ("check_id", "created_at", "jurisdiction"):
            if field in record and not isinstance(record[field], str):
                corrupt()
        for field in ("unlocked_at", "unlock_event_id"):
            if field in record and record[field] is not None and not isinstance(record[field], str):
                corrupt()
        if "unlocked" in record and not isinstance(record["unlocked"], bool):
            corrupt()
        if "findings_count" in record and (
            type(record["findings_count"]) is not int or record["findings_count"] < 0
        ):
            corrupt()
        if "redacted_summary" in record and (
            not isinstance(record["redacted_summary"], list)
            or any(not isinstance(item, str) for item in record["redacted_summary"])
        ):
            corrupt()
        if "findings" in record:
            findings = record["findings"]
            if not isinstance(findings, list):
                corrupt()
            for finding in findings:
                if not isinstance(finding, dict) or any(
                    not isinstance(finding.get(field), str)
                    for field in ("code", "severity", "account_ref", "field", "description")
                ):
                    corrupt()


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate JSON keys rather than silently discarding values."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ClearCheckStoreCorruptError("ClearCheck store has duplicate keys")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    # Python's decoder otherwise accepts NaN and infinities, which are not JSON.
    raise ClearCheckStoreCorruptError("ClearCheck store has an invalid JSON value")


def _read_all() -> dict:
    _ensure_store_file()
    try:
        with open(_path(), "r", encoding="utf-8") as f:
            data = json.load(
                f, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
            )
    except (UnicodeDecodeError, json.JSONDecodeError):
        error = ClearCheckStoreCorruptError("ClearCheck store cannot be decoded")
    except OSError:
        error = ClearCheckStoreUnavailableError("ClearCheck store is unavailable")
    else:
        _validate_store(data)
        return data
    # Decoder exceptions can retain the entire document in their attributes.
    # Raising outside the handler avoids retaining them as exception context.
    raise error


def _write_all(data: dict) -> None:
    _validate_store(data)
    path = _path()
    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)  # atomic on POSIX — avoids a half-written file
    except OSError:
        error = ClearCheckStoreUnavailableError("ClearCheck store is unavailable")
    else:
        return
    raise error


def get_check(check_id: str) -> dict | None:
    with _lock:
        record = _read_all()["checks"].get(check_id)
        return dict(record) if record else None


def save_check(record: dict) -> None:
    """Inserts or refreshes a check record. An existing record's unlock
    state is preserved — re-running a preview must never re-lock a check
    the consumer already paid for."""
    check_id = record["check_id"]
    with _lock:
        data = _read_all()
        existing = data["checks"].get(check_id, {})
        if existing.get("unlocked"):
            record = {
                **record,
                "unlocked": True,
                "unlocked_at": existing.get("unlocked_at"),
                "unlock_event_id": existing.get("unlock_event_id"),
            }
        else:
            record.setdefault("created_at", _now())
            record.setdefault("unlocked", False)
        record.setdefault("created_at", existing.get("created_at") or _now())
        data["checks"][check_id] = record
        _write_all(data)


def mark_unlocked(check_id: str, event_id: str) -> str:
    """Marks `check_id` unlocked, attributed to Stripe event `event_id`.
    Idempotent on the event ID: a redelivered event is recorded as a
    no-op (DUPLICATE_EVENT) and never re-processes anything. Returns one
    of UNLOCKED / DUPLICATE_EVENT / UNKNOWN_CHECK."""
    with _lock:
        data = _read_all()
        if event_id in data["processed_events"]:
            logger.info("clearcheck webhook event already processed (idempotent no-op)")
            return DUPLICATE_EVENT
        record = data["checks"].get(check_id)
        if record is None:
            logger.error("clearcheck unlock references an unknown check")
            return UNKNOWN_CHECK
        record["unlocked"] = True
        record["unlocked_at"] = _now()
        record["unlock_event_id"] = event_id
        data["processed_events"][event_id] = _now()
        _write_all(data)
    logger.info("clearcheck check unlocked")
    return UNLOCKED


def was_event_processed(event_id: str) -> bool:
    with _lock:
        return event_id in _read_all()["processed_events"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
