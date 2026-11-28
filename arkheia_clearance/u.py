"""ARKHEIA Clearance — unsigned integer domain (AX-4: zero floating point).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Every quantity the engine reasons about is an unsigned integer:

* ``u64``  — Lamport counters, basis points, counts, sequence numbers.
* ``u128`` — monetary / resource pools and allocation amounts.

Arithmetic is *checked*: any result outside the declared width raises
``IntDomainError`` instead of wrapping or widening. Python ints are
arbitrary precision, so the width limits are enforced explicitly here to
keep the semantics identical to a ``#![no_std]`` Rust port.

Wire encoding (RFC 8785 JCS, integers-only profile shared with the DVE
receipt toolkit):

* u64 fields travel as JSON integers and are additionally capped at
  ``WIRE_INT_MAX`` (2^53 - 1) so every runtime parses them exactly.
* u128 fields travel as canonical decimal strings (no sign, no leading
  zeros, no separators), because they can exceed 2^53.
"""
from __future__ import annotations

import re

U64_MAX = (1 << 64) - 1
U128_MAX = (1 << 128) - 1
WIRE_INT_MAX = (1 << 53) - 1
BPS_SCALE = 10_000

_U128_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,38})")


class IntDomainError(Exception):
    """An integer left its declared unsigned domain."""


def u64(v: object) -> int:
    # ``bool`` is a subclass of ``int``; exact type checks keep it out.
    if type(v) is not int or v < 0 or v > U64_MAX:
        raise IntDomainError("not a u64")
    return v


def u128(v: object) -> int:
    if type(v) is not int or v < 0 or v > U128_MAX:
        raise IntDomainError("not a u128")
    return v


def wire_u64(v: object) -> int:
    """u64 constrained to the exact-JSON range used on the wire."""
    if type(v) is not int or v < 0 or v > WIRE_INT_MAX:
        raise IntDomainError("not a wire u64")
    return v


def add64(a: int, b: int) -> int:
    r = u64(a) + u64(b)
    if r > U64_MAX:
        raise IntDomainError("u64 add overflow")
    return r


def sub64(a: int, b: int) -> int:
    if u64(b) > u64(a):
        raise IntDomainError("u64 sub underflow")
    return a - b


def mul64(a: int, b: int) -> int:
    r = u64(a) * u64(b)
    if r > U64_MAX:
        raise IntDomainError("u64 mul overflow")
    return r


def add128(a: int, b: int) -> int:
    r = u128(a) + u128(b)
    if r > U128_MAX:
        raise IntDomainError("u128 add overflow")
    return r


def sub128(a: int, b: int) -> int:
    if u128(b) > u128(a):
        raise IntDomainError("u128 sub underflow")
    return a - b


def mul128(a: int, b: int) -> int:
    r = u128(a) * u128(b)
    if r > U128_MAX:
        raise IntDomainError("u128 mul overflow")
    return r


def parse_u128_decimal(v: object) -> int:
    if type(v) is not str or _U128_DECIMAL.fullmatch(v) is None:
        raise IntDomainError("not a canonical u128 decimal string")
    return u128(int(v))


def format_u128(n: int) -> str:
    return str(u128(n))


def min64(a: int, b: int) -> int:
    return u64(a) if u64(a) <= u64(b) else b
