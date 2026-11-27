"""ARKHEIA DVE — receipt ledger protocol (bps-ledger plug point).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

append() MUST be an atomic compare-and-append: raise LedgerConflictError when
the chain head != expected_prev_hash (genesis = 64 zeros).
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Protocol, TypedDict

GENESIS_HASH = "0" * 64


class LedgerConflictError(RuntimeError):
    code = "LEDGER_CONFLICT"


class LedgerNotConfiguredError(RuntimeError):
    code = "LEDGER_NOT_CONFIGURED"


class LedgerHead(TypedDict):
    sequence: int
    receipt_hash: str


class ReceiptLedger(Protocol):
    def head(self, chain_id: str) -> LedgerHead | None: ...

    def append(self, chain_id: str, *, receipt: dict[str, Any], receipt_hash: str, expected_prev_hash: str) -> None: ...

    def get(self, receipt_hash: str) -> dict[str, Any] | None: ...


class InMemoryLedger:
    def __init__(self) -> None:
        self._chains: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        self._by_hash: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def head(self, chain_id: str) -> LedgerHead | None:
        with self._lock:
            c = self._chains.get(chain_id, [])
            return {"sequence": len(c) - 1, "receipt_hash": c[-1][0]} if c else None

    def append(self, chain_id: str, *, receipt: dict[str, Any], receipt_hash: str, expected_prev_hash: str) -> None:
        with self._lock:
            c = self._chains.setdefault(chain_id, [])
            current = c[-1][0] if c else GENESIS_HASH
            if current != expected_prev_hash:
                raise LedgerConflictError(f"head moved: {current} != {expected_prev_hash}")
            if receipt["sequence"] != len(c):
                raise LedgerConflictError(f"sequence {receipt['sequence']} != {len(c)}")
            c.append((receipt_hash, receipt))
            self._by_hash[receipt_hash] = receipt

    def get(self, receipt_hash: str) -> dict[str, Any] | None:
        with self._lock:
            return self._by_hash.get(receipt_hash)


_CHAIN_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


class JsonlFileLedger:
    """Append-only JSONL file per chain, fsync'd. Single-process only; use until bps-ledger is reachable."""

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, chain_id: str) -> Path:
        if not _CHAIN_ID.match(chain_id):
            raise LedgerConflictError(f"invalid chain id {chain_id}")
        return self._dir / (chain_id.replace(":", "_") + ".jsonl")

    def _rows(self, chain_id: str) -> list[dict[str, Any]]:
        p = self._path(chain_id)
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text("utf-8").splitlines() if line]

    def head(self, chain_id: str) -> LedgerHead | None:
        with self._lock:
            rows = self._rows(chain_id)
            return {"sequence": len(rows) - 1, "receipt_hash": rows[-1]["receipt_hash"]} if rows else None

    def append(self, chain_id: str, *, receipt: dict[str, Any], receipt_hash: str, expected_prev_hash: str) -> None:
        with self._lock:
            rows = self._rows(chain_id)
            current = rows[-1]["receipt_hash"] if rows else GENESIS_HASH
            if current != expected_prev_hash:
                raise LedgerConflictError(f"head moved: {current} != {expected_prev_hash}")
            with open(self._path(chain_id), "a", encoding="utf-8") as f:
                f.write(json.dumps({"receipt_hash": receipt_hash, "receipt": receipt}, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())

    def get(self, receipt_hash: str) -> dict[str, Any] | None:
        with self._lock:
            for p in self._dir.glob("*.jsonl"):
                for line in p.read_text("utf-8").splitlines():
                    if line:
                        row = json.loads(line)
                        if row["receipt_hash"] == receipt_hash:
                            return row["receipt"]
        return None


class BpsLedgerAdapter:
    """bps-ledger stub. Fails closed until wired; implement the three methods against bps-ledger."""

    def __init__(self, base_url: str | None = None, api_token: str | None = None, timeout_s: float = 5.0) -> None:
        self.base_url = base_url
        self.api_token = api_token
        self.timeout_s = timeout_s

    def head(self, chain_id: str) -> LedgerHead | None:
        raise LedgerNotConfiguredError("bps-ledger adapter not wired: implement head()")

    def append(self, chain_id: str, *, receipt: dict[str, Any], receipt_hash: str, expected_prev_hash: str) -> None:
        raise LedgerNotConfiguredError("bps-ledger adapter not wired: implement append() as atomic compare-and-append")

    def get(self, receipt_hash: str) -> dict[str, Any] | None:
        raise LedgerNotConfiguredError("bps-ledger adapter not wired: implement get()")
