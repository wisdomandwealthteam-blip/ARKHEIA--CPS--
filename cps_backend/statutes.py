"""
cps_backend.statutes
======================
Single shared helper that turns a rule-set object into a list of
StatuteCitation entries, given a declarative field map. Both auto.py-based
and housing.py-based statute lists are produced by ONE function here,
eliminating the hand-duplicated logic between get_auto_statutes() and
get_housing_statutes() in the original module.

Each domain declares its own field map (which fields count as citations,
in what order, with what description) once, in api.py, rather than
duplicating list-building logic per domain.
"""
from __future__ import annotations

from dataclasses import dataclass

from .schemas import StatuteCitation


@dataclass(frozen=True, slots=True)
class CitationFieldSpec:
    """Declares one statute-bearing field on a rule-set schema."""

    field_name: str
    description: str
    jurisdiction_is_federal: bool = False
    federal_citation: str | None = None  # used only when jurisdiction_is_federal=True


def build_statute_list(
    rule_set: object,
    jurisdiction_code: str,
    field_specs: tuple[CitationFieldSpec, ...],
) -> list[StatuteCitation]:
    """Build a list of StatuteCitation from a rule-set object and a
    declarative field-spec tuple. This is the single derivation path used
    by every domain — see api.py for the AUTO_CITATION_FIELDS and
    HOUSING_CITATION_FIELDS declarations that drive it.
    """
    citations: list[StatuteCitation] = []
    for spec in field_specs:
        if spec.jurisdiction_is_federal:
            citations.append(
                StatuteCitation(
                    jurisdiction="Federal",
                    citation=spec.federal_citation or "UNVERIFIED_STATUTE",
                    description=spec.description,
                )
            )
        else:
            citation_value = getattr(rule_set, spec.field_name)
            citations.append(
                StatuteCitation(
                    jurisdiction=jurisdiction_code,
                    citation=citation_value,
                    description=spec.description,
                )
            )
    return citations
  
