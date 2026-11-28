"""ARKHEIA Clearance — framework-neutral transport service + environment bootstrap.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

``ClearanceService.dispatch(method, path, body, headers)`` is the single
entry point used by the stdlib sidecar (``server.py``) and the CPS FastAPI
router. It enforces the latency floor and converts a ledger fault into a
fixed 503 — a decision is never released without its receipt.

Environment (all required unless noted; missing or invalid -> refuse to start):

    ARKHEIA_CLEARANCE_SIGNING_SEED_FILE   file holding the 64-hex Ed25519 seed (never an env value)
    ARKHEIA_CLEARANCE_AUDIT_KEY_FILE      file holding >= 64 hex of HMAC audit key
    ARKHEIA_CLEARANCE_TRUST_FILE          JSON {"custos_issuers":[..], "sensors":[..], "release_authorities":[..]}
    ARKHEIA_CLEARANCE_LEDGER              memory | jsonl:<path>
    ARKHEIA_CLEARANCE_FLOOR_MS            optional integer, default 25
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Mapping

from . import timing, wire
from .engine import AEGIS_EP, MANDATE_EP, REJECTION_SCHEMA, ClearanceEngine
from .policy import Policy
from .receipts import LedgerError

HEAD_EP = "/api/clearance/head"
JSON_HEADERS = [("Content-Type", "application/json"), ("Cache-Control", "no-store")]
UNAVAILABLE = wire.jcs({"code": "X*", "decision": "REJECTED", "receipt_hash": None, "schema": REJECTION_SCHEMA})


class ConfigError(RuntimeError):
    pass


class ClearanceService:
    def __init__(self, engine: ClearanceEngine | None, floor_ns: int = 25_000_000) -> None:
        if type(floor_ns) is not int or floor_ns < 0:
            raise ConfigError("floor_ns must be a non-negative integer")
        self.engine = engine
        self.floor_ns = floor_ns

    def dispatch(self, method: str, path: str, body: bytes,
                 headers: Mapping[str, str] | None = None) -> tuple[int, list[tuple[str, str]], bytes]:
        if path == HEAD_EP:
            if method != "GET":
                return 405, JSON_HEADERS, wire.jcs({"error": "method_not_allowed"})
            if self.engine is None:
                return 503, JSON_HEADERS, UNAVAILABLE
            return 200, JSON_HEADERS, wire.jcs(self.engine.head_snapshot())
        if path not in (MANDATE_EP, AEGIS_EP):
            return 404, JSON_HEADERS, wire.jcs({"error": "not_found"})
        if method != "POST":
            return 405, JSON_HEADERS, wire.jcs({"error": "method_not_allowed"})
        start = timing.now_ns()
        try:
            if self.engine is None:
                status, payload = 503, UNAVAILABLE
            else:
                fn = self.engine.verify_mandate if path == MANDATE_EP else self.engine.evaluate_aegis
                r = fn(body, headers)
                status, payload = r.status, r.body
        except Exception:  # noqa: BLE001 — ledger/signing fault: refuse, never emit an unreceipted verdict
            status, payload = 503, UNAVAILABLE
        timing.hold_until(start, self.floor_ns)
        return status, JSON_HEADERS, payload


_HEX = re.compile(r"[0-9a-f]+")


def _read_hex_file(var: str, env: Mapping[str, str], min_len: int, exact: bool) -> bytes:
    path = (env.get(var) or "").strip()
    if not path:
        raise ConfigError(f"{var} is not set")
    try:
        text = Path(path).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{var}: unreadable") from exc
    if _HEX.fullmatch(text) is None or len(text) < min_len or (exact and len(text) != min_len) or len(text) % 2:
        raise ConfigError(f"{var}: must contain {'exactly' if exact else 'at least'} {min_len} lowercase hex")
    return bytes.fromhex(text)


def _engine_from_env(env: Mapping[str, str] | None = None, policy: Policy | None = None) -> ClearanceEngine:
    e = os.environ if env is None else env
    seed = _read_hex_file("ARKHEIA_CLEARANCE_SIGNING_SEED_FILE", e, 64, True)
    audit = _read_hex_file("ARKHEIA_CLEARANCE_AUDIT_KEY_FILE", e, 64, False)
    trust_path = (e.get("ARKHEIA_CLEARANCE_TRUST_FILE") or "").strip()
    if not trust_path:
        raise ConfigError("ARKHEIA_CLEARANCE_TRUST_FILE is not set")
    try:
        trust = wire.parse_body(Path(trust_path).read_bytes())
        trust = wire.closed(trust, frozenset({"custos_issuers", "sensors", "release_authorities"}))
    except (OSError, wire.Malformed) as exc:
        raise ConfigError("ARKHEIA_CLEARANCE_TRUST_FILE: invalid") from exc
    for k, v in trust.items():
        if type(v) is not list:
            raise ConfigError(f"trust file: {k} must be a list")
        if any(type(item) is not str for item in v):
            raise ConfigError(f"trust file: {k} members must be public-key strings")
    spec = (e.get("ARKHEIA_CLEARANCE_LEDGER") or "").strip()
    if spec == "memory":
        ledger_path = None
    elif spec.startswith("jsonl:") and len(spec) > 6:
        ledger_path = Path(spec[6:])
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        raise ConfigError("ARKHEIA_CLEARANCE_LEDGER must be memory | jsonl:<path>")
    try:
        return ClearanceEngine(signer=wire.Signer.from_seed(seed), audit_key=audit,
                               custos_issuers=trust["custos_issuers"], sensors=trust["sensors"],
                               release_authorities=trust["release_authorities"], policy=policy,
                               ledger_path=ledger_path)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc


def engine_from_env(env: Mapping[str, str] | None = None, policy: Policy | None = None) -> ClearanceEngine:
    """Corrupt/unreadable ledgers and filesystem faults disable clearance, never leak 500s."""
    try:
        return _engine_from_env(env, policy)
    except (LedgerError, OSError, ValueError) as exc:
        raise ConfigError("clearance bootstrap failed: " + type(exc).__name__) from exc


def floor_ns_from_env(env: Mapping[str, str] | None = None) -> int:
    e = os.environ if env is None else env
    raw = (e.get("ARKHEIA_CLEARANCE_FLOOR_MS") or "25").strip()
    if re.fullmatch(r"[0-9]{1,6}", raw) is None:
        raise ConfigError("ARKHEIA_CLEARANCE_FLOOR_MS must be a non-negative integer")
    return int(raw) * 1_000_000
