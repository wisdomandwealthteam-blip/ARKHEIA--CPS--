"""
cps_backend.schemas.common
============================
Shared response/error schemas used across endpoints.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    error: str
    detail: str
    request_id: str | None = None


class HealthResponse(BaseModel):
    status: str
    app: str
    environment: str
    version: str


class AggregateRiskOut(BaseModel):
    """Combined output when both auto and housing results are supplied."""

    combined_risk_score: float
    combined_risk_tier: str
    components: dict[str, Any]
