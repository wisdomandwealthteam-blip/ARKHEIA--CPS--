"""
cps_backend.housing
=====================
HOUSING domain rule DATA ONLY. No functions, no lookup logic — see
registry.py / api.py. Sentinel usage (NO_CAP, MUST_BE_REASONABLE,
NO_NOTICE_REQUIRED) replaces the ambiguous None/0.0 values from the
original module: each now states explicitly what it means.

All statute citations are UNVERIFIED_STATUTE placeholders — see api.py's
module docstring for the required attorney-review disclaimer.

STATE COVERAGE NOTE: FL is listed in registry.SUPPORTED_STATES (shared
across both AUTO and HOUSING domains) but does not yet have
attorney-reviewed HOUSING-specific data. To keep this module's explicit
entries in sync with SUPPORTED_STATES rather than relying only on the
implicit DEFAULT fallback, FL is stubbed here using DEFAULT's values.
This stub must be replaced with real, reviewed data before FL housing
lookups are treated as anything more than the generic fallback they
currently are.
"""
from __future__ import annotations

from .schemas import HousingRuleSet
from .sentinels import (
    MUST_BE_REASONABLE,
    NO_CAP,
    NO_NOTICE_REQUIRED,
    UNVERIFIED_STATUTE,
)

HOUSING_RULES: dict[str, HousingRuleSet] = {
    "GA": HousingRuleSet(
        state="GA",
        max_security_deposit_months=NO_CAP,          # was: None
        min_grace_period_days=0,
        max_late_fee_pct=0.05,
        notice_to_quit_days=60,
        eviction_notice_days=3,
        landlord_entry_notice_hours=24,
        habitability_statute=UNVERIFIED_STATUTE,
        security_deposit_statute=UNVERIFIED_STATUTE,
        eviction_statute=UNVERIFIED_STATUTE,
        consumer_protection_statute=UNVERIFIED_STATUTE,
        retaliation_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    "CA": HousingRuleSet(
        state="CA",
        max_security_deposit_months=2,
        min_grace_period_days=3,
        max_late_fee_pct=MUST_BE_REASONABLE,          # was: 0.0 (ambiguous)
        notice_to_quit_days=30,
        eviction_notice_days=3,
        landlord_entry_notice_hours=24,
        habitability_statute=UNVERIFIED_STATUTE,
        security_deposit_statute=UNVERIFIED_STATUTE,
        eviction_statute=UNVERIFIED_STATUTE,
        consumer_protection_statute=UNVERIFIED_STATUTE,
        retaliation_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    "NY": HousingRuleSet(
        state="NY",
        max_security_deposit_months=1,
        min_grace_period_days=5,
        max_late_fee_pct=0.05,
        notice_to_quit_days=30,
        eviction_notice_days=14,
        landlord_entry_notice_hours=24,
        habitability_statute=UNVERIFIED_STATUTE,
        security_deposit_statute=UNVERIFIED_STATUTE,
        eviction_statute=UNVERIFIED_STATUTE,
        consumer_protection_statute=UNVERIFIED_STATUTE,
        retaliation_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    "TX": HousingRuleSet(
        state="TX",
        max_security_deposit_months=NO_CAP,           # was: None
        min_grace_period_days=2,
        max_late_fee_pct=0.12,
        notice_to_quit_days=30,
        eviction_notice_days=3,
        landlord_entry_notice_hours=NO_NOTICE_REQUIRED,  # was: None
        habitability_statute=UNVERIFIED_STATUTE,
        security_deposit_statute=UNVERIFIED_STATUTE,
        eviction_statute=UNVERIFIED_STATUTE,
        consumer_protection_statute=UNVERIFIED_STATUTE,
        retaliation_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    # --- Stub entry added for SUPPORTED_STATES parity (see module docstring) ---
    "FL": HousingRuleSet(
        state="FL",
        max_security_deposit_months=2,
        min_grace_period_days=3,
        max_late_fee_pct=0.05,
        notice_to_quit_days=30,
        eviction_notice_days=5,
        landlord_entry_notice_hours=24,
        habitability_statute=UNVERIFIED_STATUTE,
        security_deposit_statute=UNVERIFIED_STATUTE,
        eviction_statute=UNVERIFIED_STATUTE,
        consumer_protection_statute=UNVERIFIED_STATUTE,
        retaliation_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
    "DEFAULT": HousingRuleSet(
        state="DEFAULT",
        max_security_deposit_months=2,
        min_grace_period_days=3,
        max_late_fee_pct=0.05,
        notice_to_quit_days=30,
        eviction_notice_days=5,
        landlord_entry_notice_hours=24,
        habitability_statute=UNVERIFIED_STATUTE,
        security_deposit_statute=UNVERIFIED_STATUTE,
        eviction_statute=UNVERIFIED_STATUTE,
        consumer_protection_statute=UNVERIFIED_STATUTE,
        retaliation_statute=UNVERIFIED_STATUTE,
        last_reviewed=None,
    ),
}
