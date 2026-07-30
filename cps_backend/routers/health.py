"""
cps_backend.routers.health
=============================
"""
from __future__ import annotations

from fastapi import APIRouter

from cps_backend.config import settings
from cps_backend.schemas.common import HealthResponse

router = APIRouter(tags=["system"])

APP_VERSION = "0.2.0"


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        environment=settings.environment,
        version=APP_VERSION,
    )
