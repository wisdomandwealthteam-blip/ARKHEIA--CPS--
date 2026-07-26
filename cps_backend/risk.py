from typing import Dict, Any


def aggregate_risk(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic ARKHEIA-CPS risk aggregation.
    Takes evaluator outputs and produces a unified risk envelope.
    """

    score = 0
    details = {}

    for key, value in results.items():
        details[key] = value

        if isinstance(value, (int, float)):
            score += value
        elif isinstance(value, str):
            score += len(value)
        elif isinstance(value, dict):
            score += len(value)

    return {
        "risk_score": score,
        "details": details,
    }
