"""
cps_backend.services.auto_risk
================================
Auto risk evaluation logic.

IMPORTANT: The weights and factor curves below are an ILLUSTRATIVE,
DESIGNED model — not licensed actuarial or underwriting data. They are
deterministic and extensible (same inputs always produce the same
outputs), which satisfies the engineering requirement of this system, but
they are not a substitute for real actuarial modeling if this is used
for actual pricing or underwriting decisions.
"""
from __future__ import annotations

from cps_backend.schemas.auto import AutoContractIn, AutoRiskFactors, AutoRiskOut

MODEL_VERSION = "auto-v1-illustrative"

# Weights sum to 1.0 — adjust here to retune the model. Centralizing them
# makes the model auditable and easy to version.
WEIGHTS = {
    "driver_age": 0.25,
    "vehicle_value": 0.20,
    "incident_history": 0.35,
    "region_risk": 0.20,
}

RISK_TIER_THRESHOLDS = [
    (25, "LOW"),
    (50, "MODERATE"),
    (75, "ELEVATED"),
    (100, "HIGH"),
]


def _driver_age_factor(driver_age: int) -> float:
    """U-shaped curve: very young and very old drivers score higher risk.
    Clamped to [0, 100]. Purely illustrative."""
    if driver_age < 25:
        return min(100.0, (25 - driver_age) * 6.0 + 20.0)
    if driver_age > 70:
        return min(100.0, (driver_age - 70) * 4.0 + 20.0)
    # Lowest risk band: 25-70
    midpoint_distance = abs(driver_age - 45)
    return max(0.0, 20.0 - midpoint_distance * 0.3)


def _vehicle_value_factor(vehicle_value: float) -> float:
    """Higher-value vehicles score modestly higher (replacement cost),
    but the curve flattens — this is intentionally not linear-unbounded."""
    if vehicle_value <= 0:
        return 0.0
    scaled = (vehicle_value / 1000.0) ** 0.5  # sqrt dampens large values
    return min(100.0, scaled * 3.0)


def _incident_history_factor(incident_history: int) -> float:
    """Each prior incident adds risk, with diminishing marginal weight
    after the first few (a driver with 10 incidents isn't proportionally
    10x a driver with 1)."""
    if incident_history <= 0:
        return 0.0
    capped = min(incident_history, 20)
    return min(100.0, 15.0 * (capped**0.7))


def _region_risk_factor(region_risk_tier: int) -> float:
    """Linear mapping from the illustrative 1-5 tier to a 0-100 factor."""
    return (region_risk_tier - 1) * 25.0


def _risk_tier_from_score(score: float) -> str:
    for threshold, label in RISK_TIER_THRESHOLDS:
        if score <= threshold:
            return label
    return "HIGH"


def evaluate_auto(contract: AutoContractIn) -> AutoRiskOut:
    """Pure function: same input always produces the same output.
    No I/O, no randomness, no external state."""
    factors = AutoRiskFactors(
        driver_age_factor=round(_driver_age_factor(contract.driver_age), 2),
        vehicle_value_factor=round(_vehicle_value_factor(contract.vehicle_value), 2),
        incident_history_factor=round(
            _incident_history_factor(contract.incident_history), 2
        ),
        region_risk_factor=round(_region_risk_factor(contract.region_risk_tier), 2),
    )

    weighted_score = (
        factors.driver_age_factor * WEIGHTS["driver_age"]
        + factors.vehicle_value_factor * WEIGHTS["vehicle_value"]
        + factors.incident_history_factor * WEIGHTS["incident_history"]
        + factors.region_risk_factor * WEIGHTS["region_risk"]
    )
    weighted_score = round(min(100.0, max(0.0, weighted_score)), 2)

    return AutoRiskOut(
        raw=factors,
        risk_score=weighted_score,
        risk_tier=_risk_tier_from_score(weighted_score),
        model_version=MODEL_VERSION,
    )
