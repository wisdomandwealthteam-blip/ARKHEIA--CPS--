"""
cps_backend.services.clearcheck_store
========================================
Persists ClearCheck check records and processed Stripe webhook event IDs
to a JSON file (data/clearcheck_checks.json by default — configurable
via CPS_CLEARCHECK_STORE_PATH).

Same design rationale and caveats as services/billing_store.py: durable
across restarts, single-instance only, and every other module talks to
the file exclusively through the functions below so the internals can be
swapped for a real database without touching callers.

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


def _path() -> str:
    return settings.clearcheck_store_path


def _ensure_store_file() -> None:
    path = _path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(_EMPTY, f)


def _read_all() -> dict:
    _ensure_store_file()
    with open(_path(), "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            logger.error("clearcheck store file is corrupt; treating as empty")
            return {"checks": {}, "processed_events": {}}
    data.setdefault("checks", {})
    data.setdefault("processed_events", {})
    return data


def _write_all(data: dict) -> None:
    path = _path()
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)  # atomic on POSIX — avoids a half-written file


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
            logger.info(
                "clearcheck webhook event %s already processed (idempotent no-op)",
                event_id,
            )
            return DUPLICATE_EVENT
        record = data["checks"].get(check_id)
        if record is None:
            logger.error(
                "clearcheck unlock for unknown check_id=%s event=%s",
                check_id,
                event_id,
            )
            return UNKNOWN_CHECK
        record["unlocked"] = True
        record["unlocked_at"] = _now()
        record["unlock_event_id"] = event_id
        data["processed_events"][event_id] = _now()
        _write_all(data)
    logger.info("clearcheck check unlocked check_id=%s event=%s", check_id, event_id)
    return UNLOCKED


def was_event_processed(event_id: str) -> bool:
    with _lock:
        return event_id in _read_all()["processed_events"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
