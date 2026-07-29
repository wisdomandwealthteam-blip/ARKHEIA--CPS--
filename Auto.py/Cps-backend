"""
cps_backend.schemas.auto
==========================
Pydantic schemas for the Auto risk evaluation endpoint.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class AutoContractIn(BaseModel):
    """Input contract for auto risk evaluation.

    All fields are required; there are no server-side defaults. Extra
    fields beyond a v1-style flat contract (incident_history, region) are
    intentionally simple types so this remains easy to extend.
    """

    vin: str = Field(..., min_length=1, description="Vehicle identification number")
    driver_age: int = Field(..., ge=16, le=100, description="Driver age in years")
    vehicle_value: float = Field(..., ge=0, description="Vehicle value in USD")
    incident_history: int = Field(
        0, ge=0, le=20, description="Number of prior at-fault incidents on record"
    )
    region_risk_tier: int = Field(
        2,
        ge=1,
        le=5,
        description="Illustrative region risk tier, 1 (lowest) to 5 (highest). "
        "Not derived from any licensed actuarial dataset.",
    )


class AutoRiskFactors(BaseModel):
    """Raw, per-factor evaluator output before aggregation."""

    driver_age_factor: float
    vehicle_value_factor: float
    incident_history_factor: float
    region_risk_factor: float


class AutoRiskOut(BaseModel):
    type: str = "AUTO"
    raw: AutoRiskFactors
    risk_score: float
    risk_tier: str
    model_version: str
