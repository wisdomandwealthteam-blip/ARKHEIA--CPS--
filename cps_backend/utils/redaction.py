"""
cps_backend.utils.redaction
=============================
Masking helpers for sensitive identifiers (VINs, customer emails, API
keys). Anything that could identify a person or vehicle, or act as a
credential, must pass through one of these before being written to a log
line or echoed back in an error/preview response.
"""
from __future__ import annotations

from typing import Any, get_args

from pydantic_core import ErrorType

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


# Only these framework-defined codes, not arbitrary custom error types, may
# be returned. Messages are authored here rather than copied from Pydantic:
# custom validator messages (and some built-in messages) can contain inputs.
_VALIDATION_CODES = frozenset(get_args(ErrorType))
_VALIDATION_MESSAGES = {
    "missing": "Field required",
    "json_invalid": "Invalid JSON",
    "model_type": "Input should be a valid object",
    "model_attributes_type": "Input should be a valid object",
    "extra_forbidden": "Extra inputs are not permitted",
    "string_type": "Input should be a valid string",
    "string_too_short": "String is too short",
    "string_too_long": "String is too long",
    "string_pattern_mismatch": "String does not match the required pattern",
    "int_type": "Input should be a valid integer",
    "int_parsing": "Input should be a valid integer",
    "float_type": "Input should be a valid number",
    "float_parsing": "Input should be a valid number",
    "bool_type": "Input should be a valid boolean",
    "bool_parsing": "Input should be a valid boolean",
    "list_type": "Input should be a valid list",
    "dict_type": "Input should be a valid object",
    "date_type": "Input should be a valid date",
    "date_parsing": "Input should be a valid date",
    "date_from_datetime_parsing": "Input should be a valid date",
    "enum": "Input should be an allowed value",
    "literal_error": "Input should be an allowed value",
    "greater_than": "Input is below the allowed range",
    "greater_than_equal": "Input is below the allowed range",
    "less_than": "Input is above the allowed range",
    "less_than_equal": "Input is above the allowed range",
    "too_short": "Input has too few items",
    "too_long": "Input has too many items",
    "value_error": "Invalid value",
    "assertion_error": "Invalid value",
}


def safe_validation_errors(
    errors: list[dict[str, Any]], location_names: set[str]
) -> list[dict[str, Any]]:
    """Return only trusted codes, schema locations and static messages.

    Error input and ctx are intentionally omitted completely, even for
    seemingly non-sensitive fields. Unknown location components can be
    user-supplied dictionary/extra keys; numeric components are masked too,
    since they might be dictionary keys rather than array positions.
    """
    result = []
    for error in errors:
        code = error.get("type")
        if not isinstance(code, str) or code not in _VALIDATION_CODES:
            code = "validation_error"
        loc = error.get("loc", ())
        if not isinstance(loc, (tuple, list)):
            loc = ()
        safe_loc = tuple(
            part if isinstance(part, str) and part in location_names else REDACTED
            for part in loc
        )
        result.append(
            {
                "type": code,
                "loc": safe_loc,
                "msg": _VALIDATION_MESSAGES.get(code, "Invalid value"),
            }
        )
    return result
