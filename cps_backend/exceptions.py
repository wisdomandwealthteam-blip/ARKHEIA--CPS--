"""
cps_backend.exceptions
========================
Structured exception types. Callers can catch these specifically instead of
receiving a silent fallback or a bare KeyError/ValueError.
"""
from __future__ import annotations


class CPSBackendError(Exception):
    """Base class for all cps_backend errors."""


class SchemaValidationError(CPSBackendError):
    """Raised at import/construction time when a rule-set entry does not
    match its required schema (missing field, wrong type, etc.). This is
    intentionally raised eagerly — at module-load time, not at first
    lookup — so a malformed entry cannot silently ship."""


class UnsupportedJurisdictionError(CPSBackendError):
    """Raised when a caller requests a state/jurisdiction code that is not
    in SUPPORTED_STATES. Distinct from 'supported state with default
    rules' — this signals malformed or unrecognized input, never a silent
    fallback."""

    def __init__(self, code: str, supported: frozenset[str]) -> None:
        self.code = code
        self.supported = supported
        super().__init__(
            f"{code!r} is not a supported jurisdiction code. "
            f"Supported: {sorted(supported)} (or 'DEFAULT')."
        )
      
