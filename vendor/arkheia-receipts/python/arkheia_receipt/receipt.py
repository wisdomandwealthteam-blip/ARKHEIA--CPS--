"""ARKHEIA DVE — receipt issuance and verification.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
"""

from __future__ import annotations

import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Sequence

from .jcs import CanonicalizationError, canonical_bytes
from .keys import Keyring, SigningKey, sha256_hex
from .ledger import GENESIS_HASH, LedgerConflictError, ReceiptLedger
from .schema import validate_receipt_schema

SCHEMA_VERSION = "1.0.0"
SIGNING_DOMAIN = b"arkheia.receipt.v1\x00"
WRAPPER_DOMAINS = ("clearcheck", "musicguard", "governancecheck", "provenancecheck", "settlementcheck", "riskcheck")
PLACEHOLDER_SIGNATURE = {"algorithm": "Ed25519", "public_key_id": "ed25519:0000000000000000", "value": "0" * 128}
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z")


class ReceiptError(ValueError):
    def __init__(self, code: str, message: str, details: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


def format_timestamp(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ReceiptError("TIMESTAMP_INVALID", "datetime must be timezone-aware")
    u = dt.astimezone(timezone.utc)
    return (
        f"{u.year:04d}-{u.month:02d}-{u.day:02d}T{u.hour:02d}:{u.minute:02d}:{u.second:02d}."
        f"{u.microsecond // 1000:03d}Z"
    )


def is_valid_timestamp(ts: Any) -> bool:
    if not isinstance(ts, str) or not _TS.match(ts):
        return False
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return format_timestamp(dt) == ts


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def digest_bytes(data: bytes) -> str:
    return sha256_hex(data)


def digest_json(value: Any) -> str:
    """SHA-256 of the JCS form of an integers-only JSON value."""
    return sha256_hex(canonical_bytes(value))


def build_verdict_payload(
    *,
    verdict: str,
    rule_set: Mapping[str, str],
    reason_codes: Iterable[str] = (),
    evidence_digests: Iterable[str] = (),
    metrics: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "reason_codes": sorted(reason_codes),
        "rule_set": {"id": rule_set.get("id"), "version": rule_set.get("version")},
        "evidence_digests": sorted(evidence_digests),
        "metrics": dict(metrics or {}),
        "determinism": {"mode": "deterministic", "fallback_used": False},
    }


def _unsigned(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in receipt.items() if k != "signature"}


def signing_input(receipt: Mapping[str, Any]) -> bytes:
    return SIGNING_DOMAIN + canonical_bytes(_unsigned(receipt))


def receipt_hash(receipt: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_bytes(receipt))


def _schema_check(receipt: Mapping[str, Any]) -> None:
    ok, errors = validate_receipt_schema(receipt)
    if not ok:
        raise ReceiptError("SCHEMA_INVALID", "receipt failed ARKHEIA DVE schema v1.0.0", errors)
    if not is_valid_timestamp(receipt["timestamp_utc"]):
        raise ReceiptError("TIMESTAMP_INVALID", "timestamp_utc is not a real UTC instant")


def sign_receipt(
    key: SigningKey,
    *,
    engine_id: str,
    commit_sha: str,
    wrapper_domain: str,
    timestamp_utc: str,
    sequence: int,
    input_digest: str,
    verdict_payload: Mapping[str, Any],
    prev_receipt_hash: str,
) -> dict[str, Any]:
    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "engine_id": engine_id,
        "commit_sha": commit_sha,
        "wrapper_domain": wrapper_domain,
        "timestamp_utc": timestamp_utc,
        "sequence": sequence,
        "input_digest": input_digest,
        "verdict_payload": verdict_payload,
        "prev_receipt_hash": prev_receipt_hash,
    }
    _schema_check({**unsigned, "signature": PLACEHOLDER_SIGNATURE})
    sig = key.sign(signing_input(unsigned))
    receipt = {**unsigned, "signature": {"algorithm": "Ed25519", "public_key_id": key.public_key_id, "value": sig.hex()}}
    _schema_check(receipt)
    return receipt


class ReceiptSigner:
    """Thread-safe issuer: validate -> sign -> compare-and-append to ledger. Fails closed."""

    def __init__(
        self,
        *,
        signing_key: SigningKey,
        engine_id: str,
        commit_sha: str,
        ledger: ReceiptLedger,
        chain_id: str | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._key = signing_key
        self._ledger = ledger
        self._clock = clock
        self._lock = threading.Lock()
        self.engine_id = engine_id
        self.commit_sha = commit_sha
        self.chain_id = chain_id or f"{engine_id}:{signing_key.public_key_id}"

    @property
    def public_key_id(self) -> str:
        return self._key.public_key_id

    def issue(self, *, wrapper_domain: str, input_digest: str, verdict_payload: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
        with self._lock:
            for attempt in range(3):
                head = self._ledger.head(self.chain_id)
                receipt = sign_receipt(
                    self._key,
                    engine_id=self.engine_id,
                    commit_sha=self.commit_sha,
                    wrapper_domain=wrapper_domain,
                    timestamp_utc=format_timestamp(self._clock()),
                    sequence=head["sequence"] + 1 if head else 0,
                    input_digest=input_digest,
                    verdict_payload=verdict_payload,
                    prev_receipt_hash=head["receipt_hash"] if head else GENESIS_HASH,
                )
                h = receipt_hash(receipt)
                try:
                    self._ledger.append(self.chain_id, receipt=receipt, receipt_hash=h, expected_prev_hash=receipt["prev_receipt_hash"])
                    return receipt, h
                except LedgerConflictError:
                    if attempt == 2:
                        raise
            raise ReceiptError("LEDGER_CONFLICT", "ledger head kept moving")  # pragma: no cover


def verify_receipt(receipt: Any, keyring: Keyring, previous_receipt: Any = None) -> dict[str, Any]:
    """Never raises for bad receipts; returns {"valid": bool, ...}."""

    def fail(code: str, **extra: Any) -> dict[str, Any]:
        return {"valid": False, "error_code": code, **extra}

    try:
        ok, errors = validate_receipt_schema(receipt)
        if not ok:
            return fail("SCHEMA_INVALID", errors=errors)
        if not is_valid_timestamp(receipt["timestamp_utc"]):
            return fail("TIMESTAMP_INVALID")
        key = keyring.get(receipt["signature"]["public_key_id"])
        if key is None:
            return fail("UNKNOWN_SIGNER")
        if key.status != "active":
            return fail("REVOKED_SIGNER")
        if not key.verify(signing_input(receipt), bytes.fromhex(receipt["signature"]["value"])):
            return fail("SIGNATURE_INVALID")
        h = receipt_hash(receipt)
        if previous_receipt is not None:
            prev = verify_receipt(previous_receipt, keyring)
            if not prev["valid"]:
                return fail("PREVIOUS_RECEIPT_INVALID", previous_error_code=prev["error_code"])
            if prev["receipt_hash"] != receipt["prev_receipt_hash"]:
                return fail("CHAIN_LINK_MISMATCH")
            if previous_receipt["sequence"] + 1 != receipt["sequence"]:
                return fail("CHAIN_SEQUENCE_GAP")
        return {"valid": True, "signer": key.public_key_id, "receipt_hash": h}
    except CanonicalizationError:
        return fail("CANONICALIZATION_ERROR")
    except Exception:  # noqa: BLE001 — verification must return a verdict, never crash the caller
        return fail("VERIFICATION_ERROR")


def verify_chain(receipts: Sequence[Any], keyring: Keyring) -> dict[str, Any]:
    for i, r in enumerate(receipts):
        res = verify_receipt(r, keyring, receipts[i - 1] if i > 0 else None)
        if not res["valid"]:
            return {"valid": False, "index": i, "error_code": res["error_code"]}
    return {"valid": True, "length": len(receipts), "head_hash": receipt_hash(receipts[-1]) if receipts else GENESIS_HASH}


_COMMIT = re.compile(r"([0-9a-f]{40}|[0-9a-f]{64})\Z")


def ledger_from_env(env: Mapping[str, str] | None = None) -> "ReceiptLedger":
    """ARKHEIA_LEDGER = memory | jsonl:<dir> | bps:<base_url>. Unset or unknown -> error (fail closed)."""
    from .ledger import BpsLedgerAdapter, InMemoryLedger, JsonlFileLedger

    e = os.environ if env is None else env
    spec = (e.get("ARKHEIA_LEDGER") or "").strip()
    if spec == "memory":
        return InMemoryLedger()
    if spec.startswith("jsonl:") and len(spec) > 6:
        return JsonlFileLedger(spec[6:])
    if spec.startswith("bps:"):
        return BpsLedgerAdapter(base_url=spec[4:] or None, api_token=e.get("ARKHEIA_BPS_LEDGER_TOKEN"))
    raise ReceiptError("SIGNER_MISCONFIGURED", "ARKHEIA_LEDGER must be memory | jsonl:<dir> | bps:<url>")


def signer_from_env(env: Mapping[str, str] | None = None, env_file: str | None = None) -> ReceiptSigner:
    """Builds a ReceiptSigner from ARKHEIA_ENGINE_ID, ARKHEIA_ENGINE_COMMIT_SHA, ARKHEIA_LEDGER and the signing key vars."""
    from .keys import load_env_file, load_signing_key_from_env

    merged: dict[str, str] = dict(os.environ if env is None else env)
    if env_file is not None:
        load_env_file(env_file, merged)
    engine_id = merged.get("ARKHEIA_ENGINE_ID", "")
    commit = merged.get("ARKHEIA_ENGINE_COMMIT_SHA", "") or merged.get("GITHUB_SHA", "")
    if engine_id in WRAPPER_DOMAINS or not re.fullmatch(r"[a-z][a-z0-9_-]{1,63}", engine_id):
        raise ReceiptError("SIGNER_MISCONFIGURED", "ARKHEIA_ENGINE_ID must be an engine id (never a wrapper name)")
    if not _COMMIT.match(commit):
        raise ReceiptError("SIGNER_MISCONFIGURED", "ARKHEIA_ENGINE_COMMIT_SHA (or GITHUB_SHA) must be a 40/64-hex commit")
    return ReceiptSigner(
        signing_key=load_signing_key_from_env(merged), engine_id=engine_id, commit_sha=commit, ledger=ledger_from_env(merged)
    )
