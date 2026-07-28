"""
cps_backend.schemas
=====================
Frozen dataclass schemas for AUTO and HOUSING rule sets, plus the statute
citation schema shared by both domains.

Validation happens in `__post_init__`, which runs at *construction* time —
i.e. at module-import time for auto.py/housing.py, not at first lookup. A
malformed entry raises SchemaValidationError immediately rather than
failing silently or lazily.

No field in these schemas uses a bare `None` or `0.0` to mean "no limit" —
see sentinels.py for the explicit alternatives.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Union

from .exceptions import SchemaValidationError
from .sentinels import (
    MUST_BE_REASONABLE,
    NO_CAP,
    NO_NOTICE_REQUIRED,
    REQUIRES_ATTORNEY_REVIEW,
)

# Type aliases for fields that may hold a real number or an explicit sentinel.
NumericOrCap = Union[int, float, object]     # object narrows to NO_CAP/MUST_BE_REASONABLE at runtime
DaysOrNoNotice = Union[int, object]           # object narrows to NO_NOTICE_REQUIRED at runtime


@dataclass(frozen=True, slots=True)
class StatuteCitation:
    """A single citation entry, always UNVERIFIED_STATUTE by default in
    this artifact — see sentinels.py."""

    jurisdiction: str
    citation: str
    description: str

    def __post_init__(self) -> None:
        if not self.jurisdiction or not isinstance(self.jurisdiction, str):
            raise SchemaValidationError(
                f"StatuteCitation.jurisdiction must be a non-empty str, "
                f"got {self.jurisdiction!r}"
            )
        if not self.description or not isinstance(self.description, str):
            raise SchemaValidationError(
                f"StatuteCitation.description must be a non-empty str, "
                f"got {self.description!r}"
            )


@dataclass(frozen=True, slots=True)
class AutoRuleSet:
    """Schema for one jurisdiction's AUTO perfection/repossession rules."""

    state: str
    expected_max_days: int
    min_cure_days: int
    perfection_statute: str
    repo_statute: str
    notice_statute: str
    cure_statute: str
    deficiency_statute: str
    fbpa_statute: str
    last_reviewed: str | None  # ISO date string, or None if never reviewed
    review_status: str = REQUIRES_ATTORNEY_REVIEW

    def __post_init__(self) -> None:
        _require_positive_int(self, "expected_max_days")
        _require_positive_int(self, "min_cure_days")
        for field_name in (
            "perfection_statute", "repo_statute", "notice_statute",
            "cure_statute", "deficiency_statute", "fbpa_statute",
        ):
            _require_nonempty_str(self, field_name)


@dataclass(frozen=True, slots=True)
class HousingRuleSet:
    """Schema for one jurisdiction's HOUSING tenant-protection rules.

    Numeric-or-sentinel fields use NO_CAP / MUST_BE_REASONABLE.
    Notice-or-sentinel fields use NO_NOTICE_REQUIRED.
    """

    state: str
    max_security_deposit_months: NumericOrCap        # int, NO_CAP
    min_grace_period_days: int
    max_late_fee_pct: NumericOrCap                    # float, NO_CAP, or MUST_BE_REASONABLE
    notice_to_quit_days: int
    eviction_notice_days: int
    landlord_entry_notice_hours: DaysOrNoNotice        # int, or NO_NOTICE_REQUIRED
    habitability_statute: str
    security_deposit_statute: str
    eviction_statute: str
    consumer_protection_statute: str
    retaliation_statute: str
    last_reviewed: str | None
    review_status: str = REQUIRES_ATTORNEY_REVIEW

    def __post_init__(self) -> None:
        _require_int_or_sentinel(self, "max_security_deposit_months", {NO_CAP})
        _require_positive_int(self, "min_grace_period_days")
        _require_numeric_or_sentinel(
            self, "max_late_fee_pct", {NO_CAP, MUST_BE_REASONABLE}
        )
        _require_positive_int(self, "notice_to_quit_days")
        _require_positive_int(self, "eviction_notice_days")
        _require_int_or_sentinel(
            self, "landlord_entry_notice_hours", {NO_NOTICE_REQUIRED}
        )
        for field_name in (
            "habitability_statute", "security_deposit_statute",
            "eviction_statute", "consumer_protection_statute",
            "retaliation_statute",
        ):
            _require_nonempty_str(self, field_name)


# ── Internal validators ─────────────────────────────────────────────────────
# `obj` is typed as `Any` here (rather than left unannotated) so that strict
# mypy runs don't flag these — they're intentionally generic over both
# AutoRuleSet and HousingRuleSet instances, so a narrower type would be
# inaccurate, not just verbose.

def _require_positive_int(obj: Any, field_name: str) -> None:
    value = getattr(obj, field_name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SchemaValidationError(
            f"{type(obj).__name__}.{field_name} must be a non-negative int, "
            f"got {value!r}"
        )


def _require_nonempty_str(obj: Any, field_name: str) -> None:
    value = getattr(obj, field_name)
    if not isinstance(value, str) or not value.strip():
        raise SchemaValidationError(
            f"{type(obj).__name__}.{field_name} must be a non-empty str, "
            f"got {value!r}"
        )


def _require_int_or_sentinel(obj: Any, field_name: str, allowed_sentinels: set) -> None:
    value = getattr(obj, field_name)
    if value in allowed_sentinels:
        return
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SchemaValidationError(
            f"{type(obj).__name__}.{field_name} must be a non-negative int "
            f"or one of {allowed_sentinels}, got {value!r}"
        )


def _require_numeric_or_sentinel(obj: Any, field_name: str, allowed_sentinels: set) -> None:
    value = getattr(obj, field_name)
    if value in allowed_sentinels:
        return
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        raise SchemaValidationError(
            f"{type(obj).__name__}.{field_name} must be a non-negative "
            f"number or one of {allowed_sentinels}, got {value!r}"
        )


def schema_field_names(schema_cls: type) -> tuple[str, ...]:
    """Return the field names of a schema dataclass, for use in generic
    (non-domain-specific) tooling."""
    return tuple(f.name for f in fields(schema_cls))
    
