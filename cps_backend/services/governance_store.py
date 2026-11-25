"""Response-only JSON persistence for GovernanceCheck.

Configured directly by CPS_GOVERNANCE_STORE_PATH; no shared settings changes.
The default is /opt/render/project/src/data/governance_checks.json. Like the
existing ClearCheck store, this is single-instance/single-process persistence:
the lock serializes threads, not processes or replicas. A persistent volume is
required for durability across redeploys; use a database before scaling writers.

Layout: {"checks": {"gov_<full SHA-256>": <validated response>}}. No request
payload, subject reference, signing secret, or authenticated signature is stored.
Every read validates the entire file, including static finding reasons, so an
invalid record cannot be echoed on lookup or silently preserved on a write.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading

from pydantic import ValidationError

from cps_backend.schemas.governance import GovernanceCheckResponse

DEFAULT_STORE_PATH = "/opt/render/project/src/data/governance_checks.json"
_lock = threading.Lock()


class GovernanceStoreError(Exception):
    """Sanitized base error for governance persistence failures."""


class GovernanceStoreUnavailableError(GovernanceStoreError):
    """The store cannot be accessed or atomically written."""


class GovernanceStoreCorruptError(GovernanceStoreError):
    """The file is not valid JSON or contains invalid receipts."""


def _path() -> str:
    path = os.environ.get("CPS_GOVERNANCE_STORE_PATH", DEFAULT_STORE_PATH)
    if not path.strip() or "\x00" in path:
        raise GovernanceStoreUnavailableError("Governance store is unavailable")
    return path


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise GovernanceStoreCorruptError("Governance store has duplicate keys")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise GovernanceStoreCorruptError("Governance store has an invalid JSON value")


def _validate_store(data: object) -> dict[str, GovernanceCheckResponse]:
    if not isinstance(data, dict) or set(data) != {"checks"}:
        raise GovernanceStoreCorruptError("Governance store has an invalid structure")
    if not isinstance(data["checks"], dict):
        raise GovernanceStoreCorruptError("Governance store has an invalid structure")
    validated = {}
    for receipt_id, record in data["checks"].items():
        try:
            receipt = GovernanceCheckResponse.model_validate(record)
        except (ValidationError, TypeError, ValueError):
            error = GovernanceStoreCorruptError("Governance store has an invalid receipt")
        else:
            if receipt.receipt_id != receipt_id:
                raise GovernanceStoreCorruptError("Governance store has an invalid receipt")
            validated[receipt_id] = receipt
            continue
        # Validation errors may retain the entire stored input. Raise outside
        # the handler so those values are not retained in exception context.
        raise error
    return validated


def _read_all(path: str) -> dict[str, GovernanceCheckResponse]:
    try:
        with open(path, "r", encoding="utf-8") as store_file:
            data = json.load(
                store_file, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
            )
    except FileNotFoundError:
        # Absence is a new store, not corruption. GET need not create a file.
        return {}
    except (ValueError, RecursionError):
        # Includes malformed JSON/UTF-8 and oversized JSON integer literals.
        error = GovernanceStoreCorruptError("Governance store cannot be decoded")
    except OSError:
        error = GovernanceStoreUnavailableError("Governance store is unavailable")
    else:
        return _validate_store(data)
    raise error


def _write_all(path: str, records: dict[str, GovernanceCheckResponse]) -> None:
    data = {"checks": {key: value.model_dump(mode="json") for key, value in records.items()}}
    _validate_store(data)
    temporary_path = None
    try:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        # Unique, same-directory temporary files allow atomic POSIX replacement
        # and have owner-only permissions. Never truncate the live store.
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory,
            prefix=".governance-", suffix=".tmp", delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(data, temporary_file, sort_keys=True, indent=2, allow_nan=False)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
    except OSError:
        error = GovernanceStoreUnavailableError("Governance store is unavailable")
    else:
        return
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
    raise error


def get_check(receipt_id: str) -> GovernanceCheckResponse | None:
    with _lock:
        return _read_all(_path()).get(receipt_id)


def save_check(receipt: GovernanceCheckResponse) -> GovernanceCheckResponse:
    """Persist and return the first receipt; identical replays never rewrite it."""
    with _lock:
        path = _path()
        records = _read_all(path)
        existing = records.get(receipt.receipt_id)
        if existing is not None:
            # The digest identifies the request, not authenticated storage.
            # Recompute on POST and fail closed if stored deterministic fields
            # disagree; only the original evaluation timestamp may differ.
            if existing.model_dump(exclude={"evaluated_at"}) != receipt.model_dump(exclude={"evaluated_at"}):
                raise GovernanceStoreCorruptError("Governance receipt conflicts with evaluation")
            return existing
        records[receipt.receipt_id] = receipt
        _write_all(path, records)
        return receipt
