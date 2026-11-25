"""
cps_backend.schemas.billing
==============================
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from cps_backend.services.tiers import Tier


class CheckoutSessionRequest(BaseModel):
    tier: Tier  # must be PRO or ENTERPRISE — FREE is rejected by the router
    customer_email: str | None = None


class CheckoutSessionResponse(BaseModel):
    checkout_url: str


class PortalSessionResponse(BaseModel):
    portal_url: str


class SubscriptionStatusResponse(BaseModel):
    tenant_id: str
    tier: Tier
    display_name: str
    status: str  # "active", "free", "past_due", "canceled", etc.
    rate_limit_per_minute: int
    allowed_modules: list[str]
    monthly_price_usd: float | None
    current_period_end: str | None
    has_stripe_customer: bool


class TrialStatusResponse(BaseModel):
    trial_active: bool
    trial_expires_at: int | None


class TrialPortalRequest(BaseModel):
    session_id: str = Field(
        strict=True, min_length=24, max_length=255,
        pattern=r"^cs_(?:test|live)_[A-Za-z0-9]{16,}$",
    )


class TrialPortalResponse(BaseModel):
    url: str
    portal_url: str
