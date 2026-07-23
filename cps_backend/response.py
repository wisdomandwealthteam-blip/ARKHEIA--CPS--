from dataclasses import dataclass, field
from typing import Any, Dict, List

from .schemas import StatuteCitation  # existing type carrying review_status


@dataclass(frozen=True, slots=True)
class FlagDetail:
    flag_name: str
    actual_value: Any
    threshold_value: Any | None = None
    statute_ref: str | None = None


@dataclass(frozen=True, slots=True)
class EvaluationResponse:
    vertical: str
    inputs: Any  # the contract dataclass instance itself
    flags: Dict[str, FlagDetail]
    risk_level: "RiskLevel"
    statutory_hits: List[StatuteCitation] = field(default_factory=list)
