from typing import Any, Dict

from .registry import REGISTRY
from .response import EvaluationResponse, FlagDetail
from .risk import compute_risk_level, RiskLevel


def evaluate_contract(vertical: str, contract: Any) -> EvaluationResponse:
    """
    Unified Response Schema wrapper.
    Guardrail-compliant:
    - contract is a typed dataclass instance (not __dict__)
    - flags are structured FlagDetail objects
    - risk_level is deterministic (RiskLevel enum)
    - statutory_hits is typed (List[StatuteCitation])
    """

    if vertical not in REGISTRY:
        raise ValueError(f"Unknown vertical: {vertical}")

    evaluator = REGISTRY[vertical]
    raw_flags: Dict[str, Any] = evaluator(contract)

    flags: Dict[str, FlagDetail] = {}
    for name, value in raw_flags.items():
        flags[name] = FlagDetail(
            flag_name=name,
            actual_value=getattr(contract, name, None),
            threshold_value=None,
            statute_ref=None,
        )

    risk_level: RiskLevel = compute_risk_level(raw_flags)

    return EvaluationResponse(
        vertical=vertical,
        inputs=contract,      # typed dataclass instance
        flags=flags,
        risk_level=risk_level,
        statutory_hits=[],    # List[StatuteCitation], empty for now
    )
