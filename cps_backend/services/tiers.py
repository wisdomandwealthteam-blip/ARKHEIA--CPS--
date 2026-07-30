"""
cps_backend.services.tiers
=============================
Defines the three subscription tiers and what each one grants. This is
the single source of truth other modules read from — rate limiting,
module access checks, and the frontend's "usage limits" display should
all derive from this, not hardcode their own copies of these numbers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Tier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True)
class TierConfig:
    tier: Tier
    display_name: str
    rate_limit_per_minute: int
    allowed_modules: frozenset[str]  # e.g. {"auto", "housing"} or {"*"} for all
    monthly_price_usd: float | None  # None for free / custom-priced enterprise


TIER_CONFIG: dict[Tier, TierConfig] = {
    Tier.FREE: TierConfig(
        tier=Tier.FREE,
        display_name="Free",
        rate_limit_per_minute=30,
        allowed_modules=frozenset({"auto"}),
        monthly_price_usd=0.0,
    ),
    Tier.PRO: TierConfig(
        tier=Tier.PRO,
        display_name="Pro",
        rate_limit_per_minute=300,
        allowed_modules=frozenset({"auto", "housing", "aggregate"}),
        monthly_price_usd=49.0,
    ),
    Tier.ENTERPRISE: TierConfig(
        tier=Tier.ENTERPRISE,
        display_name="Enterprise",
        rate_limit_per_minute=3000,
        allowed_modules=frozenset({"*"}),  # "*" means all modules, present and future
        monthly_price_usd=None,  # custom/negotiated pricing
    ),
}


def tier_config(tier: Tier) -> TierConfig:
    return TIER_CONFIG[tier]


def module_allowed(tier: Tier, module: str) -> bool:
    cfg = TIER_CONFIG[tier]
    return "*" in cfg.allowed_modules or module in cfg.allowed_modules


def rate_limit_for(tier: Tier) -> int:
    return TIER_CONFIG[tier].rate_limit_per_minute
