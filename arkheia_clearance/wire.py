"""ARKHEIA Clearance — Zone U → Zone I normalizer (Law I / AX-1, AX-2).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Boundary parsing and canonical signing inputs. Parsing reuses the DVE
receipt toolkit's strict JSON reader (duplicate keys, floats, NaN,
BOM, lone surrogates, deep nesting and unsafe integers are all rejected)
and RFC 8785 canonicalization, so every signed artifact here is
byte-identical across the Python / Node / Rust toolkits.

Every object schema is *closed*: the key set must match exactly.
Unknown fields are rejected, never ignored.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any, Mapping

from arkheia_receipt.jcs import CanonicalizationError, canonical_bytes
from arkheia_receipt.strict_json import StrictJsonError, parse_strict_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .u import IntDomainError, parse_u128_decimal, wire_u64

# --- domain separation tags (signing input = TAG || 0x00 || JCS(object minus signature field)) ---
DOMAIN_LEASE = b"ARKHEIA/custos/lease/v1"
DOMAIN_DELEGATION = b"ARKHEIA/a2a/delegation/v1"
DOMAIN_MANDATE = b"ARKHEIA/mandate/request/v1"
DOMAIN_OBSERVATION = b"ARKHEIA/aegis/observation/v1"
DOMAIN_RELEASE = b"ARKHEIA/aegis/human-release/v1"
DOMAIN_RECEIPT = b"ARKHEIA/clearance/receipt/v1"
DOMAIN_PERMIT = b"ARKHEIA/mandate/permit/v1"
DOMAIN_REASON = b"ARKHEIA/clearance/reason/v1"

_HEX = {n: re.compile("[0-9a-f]{%d}" % (n + n)) for n in (16, 32, 64)}
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.\-]{0,127}")
_SCOPE = re.compile(r"[a-z][a-z0-9_.\-]{0,127}")


class Malformed(Exception):
    """Input failed canonical normalization. Carries no detail by design."""


def parse_body(raw: object) -> Any:
    if type(raw) is not bytes:
        raise Malformed()
    try:
        return parse_strict_json(raw)
    except StrictJsonError as exc:
        raise Malformed() from exc


def closed(v: object, keys: frozenset[str]) -> dict[str, Any]:
    if type(v) is not dict or frozenset(v.keys()) != keys:
        raise Malformed()
    return v


def hexstr(v: object, nbytes: int) -> str:
    if type(v) is not str or _HEX[nbytes].fullmatch(v) is None:
        raise Malformed()
    return v


def ident(v: object) -> str:
    if type(v) is not str or _IDENT.fullmatch(v) is None:
        raise Malformed()
    return v


def scope(v: object) -> str:
    if type(v) is not str or _SCOPE.fullmatch(v) is None:
        raise Malformed()
    return v


def scope_set(v: object, max_items: int) -> frozenset[str]:
    """Non-empty, strictly ascending (hence unique, canonical) list of scopes."""
    if type(v) is not list or not v or len(v) > max_items:
        raise Malformed()
    items = [scope(s) for s in v]
    for i in range(1, len(items)):
        if not items[i - 1] < items[i]:
            raise Malformed()
    return frozenset(items)


def lamport(v: object) -> int:
    try:
        return wire_u64(v)
    except IntDomainError as exc:
        raise Malformed() from exc


def count(v: object) -> int:
    return lamport(v)


def amount(v: object) -> int:
    try:
        return parse_u128_decimal(v)
    except IntDomainError as exc:
        raise Malformed() from exc


def literal(v: object, expected: str) -> str:
    if type(v) is not str or v != expected:
        raise Malformed()
    return v


# --- hashing / signing ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jcs(value: Any) -> bytes:
    return canonical_bytes(value)


def signing_input(domain: bytes, obj: Mapping[str, Any], omit: str) -> bytes:
    """TAG || 0x00 || JCS(obj without the ``omit`` field)."""
    return domain + b"\x00" + canonical_bytes({k: v for k, v in obj.items() if k != omit})


def public_key_id(raw_public_key: bytes) -> str:
    """Same key-id convention as the DVE receipt toolkit."""
    return "ed25519:" + sha256_hex(raw_public_key)[:16]


def ed25519_verify(public_hex: str, signature_hex: str, message: bytes) -> bool:
    """Explicit two-outcome verifier: malformed key or bad signature -> False."""
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
    except ValueError:
        return False
    try:
        key.verify(bytes.fromhex(signature_hex), message)
    except InvalidSignature:
        return False
    return True


def ct_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))


def hmac_hex(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Signer:
    """Ed25519 signer from a 32-byte RFC 8032 seed (deterministic signatures)."""

    _key: Ed25519PrivateKey
    public_hex: str

    @classmethod
    def from_seed(cls, seed: bytes) -> "Signer":
        if type(seed) is not bytes or len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        key = Ed25519PrivateKey.from_private_bytes(seed)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(key, pub.hex())

    @property
    def key_id(self) -> str:
        return public_key_id(bytes.fromhex(self.public_hex))

    def sign_hex(self, message: bytes) -> str:
        return self._key.sign(message).hex()


__all__ = [
    "CanonicalizationError", "Malformed", "Signer", "amount", "closed", "count", "ct_equal",
    "ed25519_verify", "hexstr", "hmac_hex", "ident", "jcs", "lamport", "literal", "parse_body",
    "public_key_id", "scope", "scope_set", "sha256_hex", "signing_input",
]
