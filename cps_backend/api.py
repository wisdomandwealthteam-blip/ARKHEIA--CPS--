"""
================================================================================
cps_backend.api — ARKHEIA-CPS Backend, Public API
================================================================================

STATUS: EXTERNAL IMPLEMENTATION ARTIFACT — NOT PART OF THE ARKHEIA MASTER
BINDER. This package is not numbered within the binder's ten-phase
structure and contains no invariant sets, transformation sets, or other
formal binder constructs. It is working code, evaluated and designed on
its own architectural merits.

LEGAL STATUS — READ BEFORE USE:
Every statute citation in this package is a placeholder
(UNVERIFIED_STATUTE) or, if you populate real citations, is unverified by
default until an attorney licensed in that jurisdiction signs off (see
`last_reviewed` / `review_status` on every rule-set entry). This backend
is legally neutral and must not be relied upon, deployed, or represented
as legally accurate until that review occurs, per jurisdiction.

DETERMINISM: This module performs no I/O, holds no mutable global state,
and uses no randomness. Every function is a pure function of its inputs
and the frozen data declared in auto.py/housing.py.
================================================================================

FUNCTION RENAMES FROM THE ORIGINAL MODULE (with rationale):

  get_auto_perfection_rules(state)  ->  get_auto_rules(state)
      Shortened; "perfection" was one of several rule categories the
      function actually returns (also repo/notice/cure/deficiency rules),
      so the old name underdescribed its own return value.

  get_housing_tenant_rules(state)   ->  get_housing_rules(state)
      Same rationale — "tenant" was narrower than the actual contents.

  get_auto_statutes(state)          ->  get_auto_statute_citations(state)
  get_housing_statutes(state)       ->  get_housing_statute_citations(state)
      Renamed for symmetry and to be explicit that these return
      StatuteCitation objects, not raw rule data.

All four new functions now return a `LookupResult`-wrapped value (for the
`_rules` functions) or a plain list (for `_statute_citations`, unchanged
shape from the original's List[dict] other than dict -> StatuteCitation).
Every `_rules` function also has a `_strict` variant that raises instead
of silently falling back to DEFAULT.
================================================================================
"""
from __future__ import annotations

from .auto import AUTO_RULES
from .housing import HOUSING_RULES
from .registry import LookupResult, lookup
from .schemas import AutoRuleSet, HousingRuleSet, StatuteCitation
from .statutes import CitationFieldSpec, build_statute_list

# ── Declarative citation field maps (one per domain, defined once) ─────────

AUTO_CITATION_FIELDS: tuple[CitationFieldSpec, ...] = (
    CitationFieldSpec("perfection_statute", "Lien perfection requirement"),
    CitationFieldSpec("repo_statute", "Self-help repossession rules"),
    CitationFieldSpec("notice_statute", "Default notice requirement"),
    CitationFieldSpec("cure_statute", "Right-to-cure notice requirement"),
    CitationFieldSpec(
        "", "Truth in Lending — APR and cost disclosure",
        jurisdiction_is_federal=True, federal_citation="UNVERIFIED_STATUTE",
    ),
    CitationFieldSpec(
        "", "Equal Credit Opportunity Act — anti-discrimination",
        jurisdiction_is_federal=True, federal_citation="UNVERIFIED_STATUTE",
    ),
)

HOUSING_CITATION_FIELDS: tuple[CitationFieldSpec, ...] = (
    CitationFieldSpec(
        "habitability_statute", "Landlord duty to maintain habitable premises"
    ),
    CitationFieldSpec(
        "security_deposit_statute",
        "Security deposit limits and return requirements",
    ),
    CitationFieldSpec(
        "eviction_statute", "Eviction notice and procedure requirements"
    ),
    CitationFieldSpec(
        "consumer_protection_statute",
        "Unfair or deceptive acts in consumer transactions",
    ),
    CitationFieldSpec(
        "retaliation_statute", "Protection against retaliatory eviction"
    ),
    CitationFieldSpec(
        "", "Anti-discrimination in housing",
        jurisdiction_is_federal=True, federal_citation="UNVERIFIED_STATUTE",
    ),
)


# ── Public rule-lookup functions ────────────────────────────────────────────

def get_auto_rules(state: str) -> LookupResult[AutoRuleSet]:
    """Return the AUTO rule set for `state`. Falls back to DEFAULT for
    unrecognized input; check `.used_default` to detect this. Renamed
    from `get_auto_perfection_rules` — see module docstring."""
    return lookup(AUTO_RULES, state, strict=False)


def get_auto_rules_strict(state: str) -> LookupResult[AutoRuleSet]:
    """Same as get_auto_rules, but raises UnsupportedJurisdictionError
    instead of falling back to DEFAULT on unrecognized input."""
    return lookup(AUTO_RULES, state, strict=True)


def get_housing_rules(state: str) -> LookupResult[HousingRuleSet]:
    """Return the HOUSING rule set for `state`. Falls back to DEFAULT for
    unrecognized input; check `.used_default` to detect this. Renamed
    from `get_housing_tenant_rules` — see module docstring."""
    return lookup(HOUSING_RULES, state, strict=False)


def get_housing_rules_strict(state: str) -> LookupResult[HousingRuleSet]:
    """Same as get_housing_rules, but raises UnsupportedJurisdictionError
    instead of falling back to DEFAULT on unrecognized input."""
    return lookup(HOUSING_RULES, state, strict=True)


# ── Public statute-citation functions ───────────────────────────────────────

def get_auto_statute_citations(state: str) -> list[StatuteCitation]:
    """Return applicable AUTO statute citations for `state`, using
    DEFAULT on unrecognized input. Renamed from `get_auto_statutes`."""
    result = get_auto_rules(state)
    return build_statute_list(result.value, result.resolved_code, AUTO_CITATION_FIELDS)


def get_housing_statute_citations(state: str) -> list[StatuteCitation]:
    """Return applicable HOUSING statute citations for `state`, using
    DEFAULT on unrecognized input. Renamed from `get_housing_statutes`."""
    result = get_housing_rules(state)
    return build_statute_list(
        result.value, result.resolved_code, HOUSING_CITATION_FIELDS
    )
    
