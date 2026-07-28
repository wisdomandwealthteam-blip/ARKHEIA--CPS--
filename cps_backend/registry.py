"""
cps_backend.registry
======================
SUPPORTED_STATES registry and the single shared lookup function used by
both domains. This is the only place that decides what counts as a valid
jurisdiction code and how fallback-to-DEFAULT is signaled to the caller.

No silent fallback: `lookup()` always tells the caller, via
`LookupResult.used_default`, whether the code they passed was recognized
or whether they're seeing DEFAULT because their input didn't match a
known jurisdiction.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from .exceptions import UnsupportedJurisdictionError

T = TypeVar("T")

# Every real jurisdiction code known to either domain. DEFAULT is not a
# real state and is intentionally excluded from this set — it's reachable
# via lookup() but is never itself something a caller should "request" as
# though it were a jurisdiction. Domains derive their own supported sets
# from this shared registry to guarantee the two never silently diverge.
SUPPORTED_STATES: frozenset[str] = frozenset({"GA", "FL", "TX", "CA", "NY"})


@dataclass(frozen=True, slots=True)
class LookupResult(Generic[T]):
    """Wraps a rule-set lookup with an explicit signal about whether the
    requested code was recognized or whether DEFAULT was used."""

    value: T
    requested_code: str
    resolved_code: str
    used_default: bool


def lookup(
    table: dict[str, T],
    state: str,
    *,
    strict: bool = False,
) -> LookupResult[T]:
    """Look up `state` in `table`.

    If `state` (case-insensitive) is a recognized key in `table`, returns
    it directly with `used_default=False`.

    If not recognized:
      - strict=True  -> raises UnsupportedJurisdictionError
      - strict=False -> returns the "DEFAULT" entry with `used_default=True`,
                         so the caller can detect and surface this rather
                         than treating it identically to a real match.

    This replaces the original module's silent
    `table.get(state.upper(), DEFAULT)` — that pattern is still available
    here (strict=False), but the caller now always receives an explicit
    `used_default` flag instead of no signal at all.
    """
    code = state.strip().upper()

    if code in table and code != "DEFAULT":
        return LookupResult(
            value=table[code], requested_code=state, resolved_code=code,
            used_default=False,
        )

    if strict:
        raise UnsupportedJurisdictionError(state, SUPPORTED_STATES)

    return LookupResult(
        value=table["DEFAULT"], requested_code=state, resolved_code="DEFAULT",
        used_default=True,
    )
    
