"""ARKHEIA DVE — strict JSON parsing for boundary inputs.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Rejects duplicate keys, non-integer numbers, NaN/Infinity, unsafe integers,
lone surrogates, BOM, invalid UTF-8 and nesting deeper than 64.
"""

from __future__ import annotations

import json
from typing import Any

from .jcs import MAX_DEPTH, MAX_SAFE_INTEGER


class StrictJsonError(ValueError):
    code = "BODY_PARSE_ERROR"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise StrictJsonError(f'duplicate key "{k}"')
        out[k] = v
    return out


def _reject_float(s: str) -> Any:
    raise StrictJsonError(f"non-integer number forbidden: {s}")


def _reject_constant(s: str) -> Any:
    raise StrictJsonError(f"non-finite literal forbidden: {s}")


def _parse_int(s: str) -> int:
    v = int(s)
    if abs(v) > MAX_SAFE_INTEGER:
        raise StrictJsonError("integer outside safe range")
    return v


def _check(value: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise StrictJsonError("maximum nesting depth exceeded")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as e:
            raise StrictJsonError("lone surrogate in string") from e
    elif isinstance(value, list):
        for v in value:
            _check(v, depth + 1)
    elif isinstance(value, dict):
        for k, v in value.items():
            _check(k, depth + 1)
            _check(v, depth + 1)


def parse_strict_json(data: str | bytes) -> Any:
    if isinstance(data, bytes):
        if data.startswith(b"\xef\xbb\xbf"):
            raise StrictJsonError("byte order mark not allowed")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as e:
            raise StrictJsonError("body is not valid UTF-8") from e
    elif isinstance(data, str):
        text = data
    else:
        raise StrictJsonError("input must be str or bytes")
    if text.startswith("﻿"):
        raise StrictJsonError("byte order mark not allowed")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except StrictJsonError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as e:
        raise StrictJsonError(str(e)) from e
    _check(value, 0)
    return value
