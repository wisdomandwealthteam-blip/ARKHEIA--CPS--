"""ARKHEIA Clearance — hash-chained Ed25519 receipts (ARKHEIA/clearance/receipt/v1).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Receipt (all fields required, integers-only JCS):

    {
      "schema":             "ARKHEIA/clearance/receipt/v1",
      "seq":                u64,                 # 0-based, contiguous
      "prev_hash":          hex32,               # 64 zeros iff seq == 0
      "lamport":            u64,                 # engine Lamport clock, strictly increasing
      "policy_version":     str,
      "endpoint":           "/api/mandate/verify" | "/api/aegis/evaluate",
      "request_hash":       hex32,               # SHA-256 of the exact request bytes
      "decision":           "CLEARED" | "REJECTED" | "STATE_UPDATED" | "RELEASED",
      "decision_core":      {...},               # subject, states, reason digest, effects
      "decision_core_hash": hex32,               # SHA-256(JCS(decision_core))
      "signature":          {"algorithm":"Ed25519","public_key_id":"ed25519:<16hex>","value":hex64}
    }

    signed bytes = "ARKHEIA/clearance/receipt/v1" || 0x00 || JCS(receipt minus "signature")
    receipt_hash = SHA-256(JCS(full signed receipt))   -> next receipt's prev_hash

Same conventions (key id, JCS, hash-of-full-receipt) as the DVE toolkit, with
a distinct domain tag so a clearance receipt can never be replayed as a DVE
receipt or vice versa.

Durability: the JSONL ledger is written and fsync'd *before* the receipt is
committed in memory, and before any decision is released (AX-6). On start-up
the whole file is re-verified; a broken chain refuses to load (fail closed).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import wire
from .u import WIRE_INT_MAX

SCHEMA = "ARKHEIA/clearance/receipt/v1"
GENESIS = "0" * 64
ENDPOINTS = ("/api/mandate/verify", "/api/aegis/evaluate")
DECISIONS = ("CLEARED", "REJECTED", "STATE_UPDATED", "RELEASED")
RECEIPT_KEYS = frozenset({"schema", "seq", "prev_hash", "lamport", "policy_version", "endpoint",
                          "request_hash", "decision", "decision_core", "decision_core_hash", "signature"})
SIG_KEYS = frozenset({"algorithm", "public_key_id", "value"})


class LedgerError(Exception):
    pass


def receipt_hash(receipt: Mapping[str, Any]) -> str:
    return wire.sha256_hex(wire.jcs(receipt))


def receipt_signing_input(receipt: Mapping[str, Any]) -> bytes:
    return wire.signing_input(wire.DOMAIN_RECEIPT, receipt, "signature")


def sign_receipt(signer: wire.Signer, *, seq: int, prev_hash: str, lamport: int, policy_version: str,
                 endpoint: str, request_hash: str, decision: str, decision_core: Mapping[str, Any]) -> dict[str, Any]:
    unsigned = {
        "schema": SCHEMA,
        "seq": seq,
        "prev_hash": prev_hash,
        "lamport": lamport,
        "policy_version": policy_version,
        "endpoint": endpoint,
        "request_hash": request_hash,
        "decision": decision,
        "decision_core": dict(decision_core),
        "decision_core_hash": wire.sha256_hex(wire.jcs(decision_core)),
    }
    sig = signer.sign_hex(receipt_signing_input(unsigned))
    return {**unsigned, "signature": {"algorithm": "Ed25519", "public_key_id": signer.key_id, "value": sig}}


def _structural_ok(r: Any) -> bool:
    if type(r) is not dict or frozenset(r) != RECEIPT_KEYS:
        return False
    s = r["signature"]
    if type(s) is not dict or frozenset(s) != SIG_KEYS or s["algorithm"] != "Ed25519":
        return False
    for k in ("seq", "lamport"):
        if type(r[k]) is not int or not 0 <= r[k] <= WIRE_INT_MAX:
            return False
    for k in ("prev_hash", "request_hash", "decision_core_hash"):
        if type(r[k]) is not str or len(r[k]) != 64:
            return False
    return (r["schema"] == SCHEMA and r["endpoint"] in ENDPOINTS and r["decision"] in DECISIONS
            and type(r["decision_core"]) is dict and type(r["policy_version"]) is str
            and type(s["value"]) is str and len(s["value"]) == 128 and type(s["public_key_id"]) is str)


def verify_chain(records: Sequence[Any], trusted: Mapping[str, str]) -> dict[str, Any]:
    """trusted: public_key_id -> raw public key hex. Never raises for bad input."""

    def fail(i: int, code: str) -> dict[str, Any]:
        return {"valid": False, "index": i, "error_code": code}

    prev = GENESIS
    last_lamport = -1
    for i, r in enumerate(records):
        if not _structural_ok(r):
            return fail(i, "SCHEMA_INVALID")
        if r["seq"] != i:
            return fail(i, "SEQUENCE_GAP")
        if not wire.ct_equal(r["prev_hash"], prev):
            return fail(i, "CHAIN_LINK_MISMATCH")
        if r["lamport"] <= last_lamport:
            return fail(i, "LAMPORT_NOT_INCREASING")
        try:
            core_hash = wire.sha256_hex(wire.jcs(r["decision_core"]))
            signing = receipt_signing_input(r)
            h = receipt_hash(r)
        except wire.CanonicalizationError:
            return fail(i, "CANONICALIZATION_ERROR")
        if not wire.ct_equal(core_hash, r["decision_core_hash"]):
            return fail(i, "CORE_HASH_MISMATCH")
        pub = trusted.get(r["signature"]["public_key_id"])
        if pub is None:
            return fail(i, "UNKNOWN_SIGNER")
        if not wire.ed25519_verify(pub, r["signature"]["value"], signing):
            return fail(i, "SIGNATURE_INVALID")
        prev = h
        last_lamport = r["lamport"]
    return {"valid": True, "length": len(records), "head_hash": prev}


@dataclass
class Ledger:
    """Append-only receipt chain. ``path=None`` keeps it in memory only."""

    trusted: Mapping[str, str]
    path: Path | None = None
    records: list[dict[str, Any]] = field(default_factory=list)
    _head: str = GENESIS
    _unavailable: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.path is not None and self.path.exists():
            loaded = []
            with self.path.open("rb") as fh:
                for line in fh:
                    if line.strip():
                        try:
                            loaded.append(wire.parse_body(line.rstrip(b"\n")))
                        except wire.Malformed as exc:
                            raise LedgerError("ledger line is not strict JSON") from exc
            report = verify_chain(loaded, self.trusted)
            if not report["valid"]:
                raise LedgerError(f"ledger chain invalid at {report['index']}: {report['error_code']}")
            self.records = loaded
            self._head = report["head_hash"]

    @property
    def head_hash(self) -> str:
        return self._head

    @property
    def next_seq(self) -> int:
        return len(self.records)

    @property
    def last_lamport(self) -> int:
        return self.records[-1]["lamport"] if self.records else 0

    def append(self, receipt: dict[str, Any]) -> str:
        if self._unavailable:
            raise LedgerError("ledger unavailable until verified restart")
        if receipt["seq"] != self.next_seq or receipt["prev_hash"] != self._head:
            raise LedgerError("append does not extend head")
        h = receipt_hash(receipt)
        if self.path is not None:
            line = wire.jcs(receipt) + b"\n"
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    view = memoryview(line)
                    while view:
                        count = os.write(fd, view)
                        if count <= 0:
                            raise LedgerError("ledger write made no progress")
                        view = view[count:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except (OSError, LedgerError) as exc:
                # Disk may have a partial or fully written but unacknowledged
                # receipt. Do not append another seq using stale memory.
                self._unavailable = True
                raise LedgerError("ledger persistence failed; verified restart required") from exc
        self.records.append(receipt)
        self._head = h
        return h
