
"""
cps_backend.sentinels
======================
Explicit sentinel values used throughout the rule schema so that "no limit",
"no requirement", and "genuinely zero" are never conflated with each other
or with a bare `None` / `0.0`.

Each sentinel is its own singleton object with a readable repr, so a caller
inspecting a value in a debugger or log immediately sees what it means
instead of having to consult a comment.
"""
from __future__ import annotations


class _Sentinel:
    """A named singleton sentinel. Two sentinels with different names are
    never equal, even if constructed twice (there's only ever one of each,
    enforced via module-level constants below — do not instantiate this
    class directly elsewhere)."""

    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        self._name = name

    def __repr__(self) -> str:
        return f"<{self._name}>"

    def __bool__(self) -> bool:
        # Sentinels are intentionally falsy-neutral: code must check identity
        # (e.g. `value is NO_CAP`), never truthiness, to avoid silent misuse.
        raise TypeError(
            f"{self!r} has no truthiness — compare with `is` instead of "
            f"using it in a boolean context."
        )


# ── Numeric / limit sentinels ──────────────────────────────────────────────

NO_CAP = _Sentinel("NO_CAP")
"""No statutory numeric cap exists for this field (distinct from a cap of 0)."""

NO_NOTICE_REQUIRED = _Sentinel("NO_NOTICE_REQUIRED")
"""No statutory notice period is required for this field (distinct from a
notice period of 0 days, which would mean 'notice required but with no
minimum lead time')."""

MUST_BE_REASONABLE = _Sentinel("MUST_BE_REASONABLE")
"""No fixed numeric cap exists, but the value is statutorily constrained to
a 'reasonable' standard rather than being fully uncapped. Distinct from
NO_CAP (truly no constraint) and from a real numeric value."""


# ── Legal-content sentinels ─────────────────────────────────────────────────

UNVERIFIED_STATUTE = "UNVERIFIED_STATUTE"
"""Placeholder for a statute citation that has not been populated or
reviewed. Used in place of any real citation until attorney review occurs."""

REQUIRES_ATTORNEY_REVIEW = "REQUIRES_ATTORNEY_REVIEW"
"""Marker indicating a jurisdiction's entire rule set has not yet been
reviewed by counsel licensed in that jurisdiction."""
