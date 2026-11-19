"""
cps_backend.utils.redaction
=============================
Masking helpers for sensitive identifiers (VINs, customer emails, API
keys). Anything that could identify a person or vehicle, or act as a
credential, must pass through one of these before being written to a log
line or echoed back in an error/preview response.
"""
from __future__ import annotations

from typing import Any

# Request fields whose submitted values must never appear verbatim in
# logs or error responses.
SENSITIVE_FIELDS: frozenset[str] = frozenset(
    {
        "vin",
        "customer_email",
        "api_key",
        "x-api-key",
        # ClearCheck consumer identifiers
        "account_number",
        "consumer_name",
        "consumer_email",
        "ssn_last4",
    }
)

REDACTED = "[REDACTED]"


def mask_value(value: str, visible_suffix: int = 4) -> str:
    """Masks all but the last `visible_suffix` characters of a value.
    Values too short to safely expose a suffix are fully redacted."""
    if not value:
        return REDACTED
    if len(value) <= visible_suffix:
        return "*" * len(value)
    return "*" * (len(value) - visible_suffix) + value[-visible_suffix:]


def mask_vin(vin: str) -> str:
    """VINs are unique vehicle identifiers — show only the last 4
    characters, enough to correlate within a support conversation."""
    return mask_value(vin, visible_suffix=4)


def mask_email(email: str | None) -> str:
    """Masks the local part of an email, keeping its first character and
    the domain (e.g. 'j***@example.com')."""
    if not email:
        return REDACTED
    local, sep, domain = email.partition("@")
    if not sep or not local:
        return REDACTED
    return f"{local[0]}***@{domain}"


def _scrub_input(value: Any) -> Any:
    """Recursively masks sensitive keys inside an error's 'input' value.
    Pydantic attaches the *entire* submitted body as 'input' on some
    errors (e.g. a missing required field), so sensitive sibling fields
    must be scrubbed even when they themselves validated fine."""
    if isinstance(value, dict):
        return {
            k: REDACTED
            if isinstance(k, str) and k.lower() in SENSITIVE_FIELDS
            else _scrub_input(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub_input(v) for v in value]
    return value


def redact_validation_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Scrubs pydantic/FastAPI validation errors so submitted values for
    sensitive fields never leak into logs or error responses. The error
    location and message are kept; the offending 'input' value is masked
    when the field is sensitive, and sensitive keys nested inside a
    larger 'input' payload are masked too."""
    scrubbed: list[dict[str, Any]] = []
    for err in errors:
        err = dict(err)
        loc = err.get("loc", ())
        is_sensitive = any(
            isinstance(part, str) and part.lower() in SENSITIVE_FIELDS
            for part in loc
        )
        if "input" in err:
            err["input"] = REDACTED if is_sensitive else _scrub_input(err["input"])
        # ctx can embed the raw input in its messages too
        if is_sensitive and "ctx" in err:
            err["ctx"] = REDACTED
        scrubbed.append(err)
    return scrubbed
