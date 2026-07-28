"""
cps_backend.auto
==================
AUTO domain rule DATA ONLY. This module contains no functions and no
lookup logic — see registry.py / api.py for that. Its sole job is to
construct validated AutoRuleSet instances; any malformed entry raises
SchemaValidationError immediately on import.

All statute citations are UNVERIFIED_STATUTE placeholders. See the module
docstring in api.py and every field's `review_status` for the required
attorney-review disclaimer.

STATE COVERAGE NOTE: CA and NY are listed in registry.SUPPORTED_STATES
(shared across both AUTO and HOUSING domains) but do not yet have
attorney-reviewed AUTO-specific data. To keep this module's explicit
entries in sync with SUPPORTED_STATES rather than relying only on the
implicit DEFAULT fallback, CA and NY are stubbed here using DEFAULT's
values. These stubs must be replaced with real, reviewed data before
CA/NY auto lookups are treated as anything more than the generic
fallback they currently are.
"""
from __future__ import annotations

from .schemas import AutoRuleSet
from .sentinels import UNVERIFIED_STATUTE

AUTO_RULES: dict[str, AutoRuleSet] = {
    "GA": AutoRuleSet(
        state="GA",
        expected_max_days=30,
        min_cure_days=10,
        perfection_statute=UNVERIFIED_STATUTE,
        repo_statute=UNVERIFIED_STATUTE,
        notice_statute=UNVERIFIED_STATUTE,
        cure_statute=UNVERIFIED_STATUTE,
        deficiency_statute=UNVERIFIED_STATUTE,
        fbpa_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    "FL": AutoRuleSet(
        state="FL",
        expected_max_days=30,
        min_cure_days=20,
        perfection_statute=UNVERIFIED_STATUTE,
        repo_statute=UNVERIFIED_STATUTE,
        notice_statute=UNVERIFIED_STATUTE,
        cure_statute=UNVERIFIED_STATUTE,
        deficiency_statute=UNVERIFIED_STATUTE,
        fbpa_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    "TX": AutoRuleSet(
        state="TX",
        expected_max_days=20,
        min_cure_days=10,
        perfection_statute=UNVERIFIED_STATUTE,
        repo_statute=UNVERIFIED_STATUTE,
        notice_statute=UNVERIFIED_STATUTE,
        cure_statute=UNVERIFIED_STATUTE,
        deficiency_statute=UNVERIFIED_STATUTE,
        fbpa_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    # --- Stub entries added for SUPPORTED_STATES parity (see module docstring) ---
    "CA": AutoRuleSet(
        state="CA",
        expected_max_days=30,
        min_cure_days=10,
        perfection_statute=UNVERIFIED_STATUTE,
        repo_statute=UNVERIFIED_STATUTE,
        notice_statute=UNVERIFIED_STATUTE,
        cure_statute=UNVERIFIED_STATUTE,
        deficiency_statute=UNVERIFIED_STATUTE,
        fbpa_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    "NY": AutoRuleSet(
        state="NY",
        expected_max_days=30,
        min_cure_days=10,
        perfection_statute=UNVERIFIED_STATUTE,
        repo_statute=UNVERIFIED_STATUTE,
        notice_statute=UNVERIFIED_STATUTE,
        cure_statute=UNVERIFIED_STATUTE,
        deficiency_statute=UNVERIFIED_STATUTE,
        fbpa_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    "DEFAULT": AutoRuleSet(
        state="DEFAULT",
        expected_max_days=30,
        min_cure_days=10,
        perfection_statute=UNVERIFIED_STATUTE,
        repo_statute=UNVERIFIED_STATUTE,
        notice_statute=UNVERIFIED_STATUTE,
        cure_statute=UNVERIFIED_STATUTE,
        deficiency_statute=UNVERIFIED_STATUTE,
        fbpa_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
}
