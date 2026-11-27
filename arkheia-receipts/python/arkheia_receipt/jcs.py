"""ARKHEIA DVE — RFC 8785 JSON Canonicalization (integers-only profile).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Receipts carry integers only, so this profile is byte-identical to the Node
and Rust implementations. Floats raise; they are never coerced.
"""

from __future__ import annotations

from typing import Any

MAX_SAFE_INTEGER = 9007199254740991
MAX_DEPTH = 64

_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


class CanonicalizationError(ValueError):
    code = "CANONICALIZATION_ERROR"

    def __init__(self, message: str, path: str) -> None:
        super().__init__(f"{message} at {path}")
        self.path = path


def _escape_string(s: str, path: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise CanonicalizationError("string contains lone surrogate", path)
        esc = _SHORT_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(k: str) -> bytes:
    return k.encode("utf-16-be")  # byte order of UTF-16BE == code-unit order (RFC 8785 §3.2.3)


def _serialize(value: Any, path: str, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise CanonicalizationError("maximum nesting depth exceeded", path)
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError("integer outside safe range", path)
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError("non-integer number forbidden", path)
    if isinstance(value, str):
        return _escape_string(value, path)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v, f"{path}[{i}]", depth + 1) for i, v in enumerate(value)) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise CanonicalizationError("non-string object key", path)
        parts = []
        for k in sorted(value.keys(), key=_utf16_key):
            parts.append(_escape_string(k, path) + ":" + _serialize(value[k], f"{path}.{k}", depth + 1))
        return "{" + ",".join(parts) + "}"
    raise CanonicalizationError(f"unsupported type {type(value).__name__}", path)


def canonicalize(value: Any) -> str:
    """Canonical JSON text. Raises CanonicalizationError; never coerces."""
    return _serialize(value, "$", 0)


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")
