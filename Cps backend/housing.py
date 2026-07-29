"""
cps_backend.schemas.housing
=============================
Pydantic schemas for the Housing risk evaluation endpoint.
"""
from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field, field_validator


class HousingContractIn(BaseModel):
    """Input contract for housing risk evaluation."""

    address: str = Field(..., min_length=1)
    home_value: float = Field(..., ge=0, description="Home value in USD")
    year_built: int = Field(..., ge=1700, le=date.today().year)
    location_risk_tier: int = Field(
        2,
        ge=1,
        le=5,
        description="Illustrative location risk tier, 1 (lowest) to 5 (highest). "
        "Not derived from any licensed actuarial dataset.",
    )
    structural_score: int = Field(
        70,
        ge=0,
        le=100,
        description="Illustrative structural condition score, 0-100 "
        "(higher is better condition).",
    )

    @field_validator("year_built")
    @classmethod
    def year_not_in_future(cls, v: int) -> int:
        if v > date.today().year:
            raise ValueError("year_built cannot be in the future")
        return v


class HousingRiskFactors(BaseModel):
    age_factor: float
    value_factor: float
    location_risk_factor: float
    structural_factor: float


class HousingRiskOut(BaseModel):
    type: str = "HOUSING"
    raw: HousingRiskFactors
    risk_score: float
    risk_tier: str
    model_version: str
