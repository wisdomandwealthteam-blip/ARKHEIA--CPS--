from enum import Enum
from typing import Dict, Any


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# Deterministic high-risk fields (Claude-approved)
_HIGH_RISK_FIELDS = frozenset({
    "apr",
    "affordability",
    "doc_fee",
    "fees",
})


def compute_risk_level(flags: Dict[str, Any]) -> RiskLevel:
    """
    Deterministic mapping from flag set -> tier.

    Guardrail-compliant:
    - No heuristics
    - No scoring
    - No weighting
    - No generative logic
    - Pure structural mapping
    """

    # No flags → LOW
    if not flags:
        return RiskLevel.LOW

    # Any high-risk field → HIGH
    if any(name in _HIGH_RISK_FIELDS for name in flags.keys()):
        return RiskLevel.HIGH

    # Everything else → MEDIUM
    return RiskLevel.MEDIUM
