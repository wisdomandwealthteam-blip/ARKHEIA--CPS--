from dataclasses import dataclass
from typing import Dict, Any

from cps_backend.response import ok, fail


@dataclass
class RiskAssessment:
    """
    Deterministic CPS risk assessment model.
    Replace with real logic as ARKHEIA-CPS evolves.
    """

    case_id: str
    factors: Dict[str, Any]

    def compute(self) -> Dict[str, Any]:
        """
        Deterministic placeholder logic.
        Produces a stable, predictable risk score.
        """
        score = 0

        # Example deterministic scoring logic
        for key, value in self.factors.items():
            if isinstance(value, (int, float)):
                score += value
            elif isinstance(value, str):
                score += len(value)

        return {
            "case_id": self.case_id,
            "risk_score": score,
            "details": self.factors,
        }


def assess(case_id: str, factors: Dict[str, Any]):
    """
    Public API wrapper for risk assessment.
    Always returns a ResponseEnvelope.
    """
    try:
        model = RiskAssessment(case_id=case_id, factors=factors)
        result = model.compute()
        return ok(result)
    except Exception as exc:
        return fail(f"Risk assessment failed: {exc}")
