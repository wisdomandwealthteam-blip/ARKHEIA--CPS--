"""ARKHEIA DVE — Ed25519 keys (pyca/cryptography).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Same RFC 8032 seed => same keypair as Node (node:crypto) and Rust (ed25519-dalek).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ReceiptKeyError(ValueError):
    code = "KEY_ERROR"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_key_id(raw_public_key: bytes) -> str:
    if len(raw_public_key) != 32:
        raise ReceiptKeyError("raw public key must be 32 bytes")
    return "ed25519:" + sha256_hex(raw_public_key)[:16]


@dataclass(frozen=True)
class SigningKey:
    private_key: Ed25519PrivateKey
    raw_public_key: bytes

    @property
    def public_key_hex(self) -> str:
        return self.raw_public_key.hex()

    @property
    def public_key_id(self) -> str:
        return public_key_id(self.raw_public_key)

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)


@dataclass(frozen=True)
class PublicKey:
    public_key: Ed25519PublicKey
    raw_public_key: bytes
    status: str = "active"

    @property
    def public_key_hex(self) -> str:
        return self.raw_public_key.hex()

    @property
    def public_key_id(self) -> str:
        return public_key_id(self.raw_public_key)

    def verify(self, message: bytes, signature: bytes) -> bool:
        if len(signature) != 64:
            return False
        try:
            self.public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False


def signing_key_from_seed_hex(seed_hex: str) -> SigningKey:
    if not isinstance(seed_hex, str) or not _HEX64.match(seed_hex):
        raise ReceiptKeyError("seed must be 64 lowercase hex characters")
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return SigningKey(private_key=sk, raw_public_key=sk.public_key().public_bytes_raw())


def public_key_from_hex(public_key_hex: str, status: str = "active") -> PublicKey:
    if not isinstance(public_key_hex, str) or not _HEX64.match(public_key_hex):
        raise ReceiptKeyError("public key must be 64 lowercase hex characters")
    raw = bytes.fromhex(public_key_hex)
    return PublicKey(public_key=Ed25519PublicKey.from_public_bytes(raw), raw_public_key=raw, status=status)


def generate_seed_hex() -> str:
    return os.urandom(32).hex()


def load_env_file(path: str | Path, env: dict[str, str] | None = None) -> None:
    """Minimal KEY=VALUE .env loader (no python-dotenv). Does not override existing keys."""
    target = os.environ if env is None else env
    for lineno, line in enumerate(Path(path).read_text("utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            raise ReceiptKeyError(f"{path}:{lineno}: expected KEY=VALUE")
        k, v = s.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        target.setdefault(k, v)


def load_signing_key_from_env(env: Mapping[str, str] | None = None, env_file: str | Path | None = None) -> SigningKey:
    e: dict[str, str] = dict(os.environ if env is None else env)
    if env_file is not None:
        load_env_file(env_file, e)
    seed = e.get("ARKHEIA_SIGNING_SEED_HEX")
    if not seed:
        raise ReceiptKeyError("ARKHEIA_SIGNING_SEED_HEX is not set")
    key = signing_key_from_seed_hex(seed.strip())
    expected = e.get("ARKHEIA_SIGNING_PUBLIC_KEY_ID")
    if expected and expected.strip() != key.public_key_id:
        raise ReceiptKeyError(f"seed does not match ARKHEIA_SIGNING_PUBLIC_KEY_ID ({expected} != {key.public_key_id})")
    return key


class Keyring:
    """{"keys":[{"public_key_id","algorithm":"Ed25519","public_key_hex","status":"active"|"revoked"}]}"""

    def __init__(self, doc: Mapping[str, Any]) -> None:
        keys = doc.get("keys") if isinstance(doc, Mapping) else None
        if not isinstance(keys, list) or not keys:
            raise ReceiptKeyError('keyring must contain a non-empty "keys" array')
        self._by_id: dict[str, PublicKey] = {}
        for entry in keys:
            if entry.get("algorithm") != "Ed25519":
                raise ReceiptKeyError("keyring entries must be Ed25519")
            if entry.get("status") not in ("active", "revoked"):
                raise ReceiptKeyError("keyring status must be active or revoked")
            pk = public_key_from_hex(entry.get("public_key_hex", ""), entry["status"])
            if pk.public_key_id != entry.get("public_key_id"):
                raise ReceiptKeyError(f"keyring id mismatch for {entry.get('public_key_id')}")
            if pk.public_key_id in self._by_id:
                raise ReceiptKeyError(f"duplicate keyring id {pk.public_key_id}")
            self._by_id[pk.public_key_id] = pk

    @classmethod
    def from_file(cls, path: str | Path) -> "Keyring":
        return cls(json.loads(Path(path).read_text("utf-8")))

    def get(self, key_id: str) -> PublicKey | None:
        return self._by_id.get(key_id)

    def to_json(self) -> dict[str, Any]:
        return {
            "keys": [
                {"public_key_id": k.public_key_id, "algorithm": "Ed25519", "public_key_hex": k.public_key_hex, "status": k.status}
                for k in sorted(self._by_id.values(), key=lambda k: k.public_key_id)
            ]
        }
