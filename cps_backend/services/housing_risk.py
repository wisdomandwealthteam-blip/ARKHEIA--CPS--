"""
cps_backend.services.housing_risk
====================================
Housing risk evaluation logic. Same illustrative-model disclaimer as
cps_backend.services.auto_risk applies here.
"""
from __future__ import annotations

from datetime import date

from cps_backend.schemas.housing import (
    HousingContractIn,
    HousingRiskFactors,
    HousingRiskOut,
)

MODEL_VERSION = "housing-v1-illustrative"

WEIGHTS = {
    "age": 0.20,
    "value": 0.15,
    "location_risk": 0.30,
    "structural": 0.35,
}

RISK_TIER_THRESHOLDS = [
    (25, "LOW"),
    (50, "MODERATE"),
    (75, "ELEVATED"),
    (100, "HIGH"),
]


def _age_factor(year_built: int) -> float:
    """Older structures score modestly higher, flattening after ~80 years
    (renovation/code-update assumptions baked in as a simplification)."""
    age = max(0, date.today().year - year_built)
    return min(100.0, (min(age, 80) / 80.0) * 60.0)


def _value_factor(home_value: float) -> float:
    if home_value <= 0:
        return 0.0
    scaled = (home_value / 10_000.0) ** 0.5
    return min(100.0, scaled * 4.0)


def _location_risk_factor(location_risk_tier: int) -> float:
    return (location_risk_tier - 1) * 25.0


def _structural_factor(structural_score: int) -> float:
    """Structural score is 0-100 where HIGHER is better condition, so we
    invert it: worse condition -> higher risk factor."""
    return max(0.0, 100.0 - structural_score)


def _risk_tier_from_score(score: float) -> str:
    for threshold, label in RISK_TIER_THRESHOLDS:
        if score <= threshold:
            return label
    return "HIGH"


def evaluate_housing(contract: HousingContractIn) -> HousingRiskOut:
    """Pure function: same input always produces the same output."""
    factors = HousingRiskFactors(
        age_factor=round(_age_factor(contract.year_built), 2),
        value_factor=round(_value_factor(contract.home_value), 2),
        location_risk_factor=round(
            _location_risk_factor(contract.location_risk_tier), 2
        ),
        structural_factor=round(_structural_factor(contract.structural_score), 2),
    )

    weighted_score = (
        factors.age_factor * WEIGHTS["age"]
        + factors.value_factor * WEIGHTS["value"]
        + factors.location_risk_factor * WEIGHTS["location_risk"]
        + factors.structural_factor * WEIGHTS["structural"]
    )
    weighted_score = round(min(100.0, max(0.0, weighted_score)), 2)

    return HousingRiskOut(
        raw=factors,
        risk_score=weighted_score,
        risk_tier=_risk_tier_from_score(weighted_score),
        model_version=MODEL_VERSION,
  )
