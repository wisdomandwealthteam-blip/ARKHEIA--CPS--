"""
cps_backend — ARKHEIA-CPS backend implementation artifact.

NOT part of the ARKHEIA Master Binder. See api.py for the full legal-status
and determinism disclaimer, and registry.py / schemas.py for the
validation model.
"""
from .api import (
    get_auto_rules,
    get_auto_rules_strict,
    get_auto_statute_citations,
    get_housing_rules,
    get_housing_rules_strict,
    get_housing_statute_citations,
)
from .exceptions import (
    CPSBackendError,
    SchemaValidationError,
    UnsupportedJurisdictionError,
)
from .registry import SUPPORTED_STATES, LookupResult
from .schemas import AutoRuleSet, HousingRuleSet, StatuteCitation
from .sentinels import (
    MUST_BE_REASONABLE,
    NO_CAP,
    NO_NOTICE_REQUIRED,
    REQUIRES_ATTORNEY_REVIEW,
    UNVERIFIED_STATUTE,
)

__all__ = [
    "get_auto_rules",
    "get_auto_rules_strict",
    "get_auto_statute_citations",
    "get_housing_rules",
    "get_housing_rules_strict",
    "get_housing_statute_citations",
    "CPSBackendError",
    "SchemaValidationError",
    "UnsupportedJurisdictionError",
    "SUPPORTED_STATES",
    "LookupResult",
    "AutoRuleSet",
    "HousingRuleSet",
    "StatuteCitation",
    "MUST_BE_REASONABLE",
    "NO_CAP",
    "NO_NOTICE_REQUIRED",
    "REQUIRES_ATTORNEY_REVIEW",
    "UNVERIFIED_STATUTE",
]
