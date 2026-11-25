"""
cps_backend.config
====================
Centralized configuration, loaded from environment variables with sane
defaults for local development. Nothing here is a secret by default —
set real values via environment variables in production.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field


def _clearcheck_price_cents() -> int | None:
    """Preserve valid integer settings; defer invalid configuration to checkout."""
    value = os.environ.get("CPS_CLEARCHECK_PRICE_CENTS", "999").strip()
    if not re.fullmatch(r"[+-]?[0-9]+", value):
        return None
    try:
        return int(value)
    except ValueError:
        # Includes excessively long integers rejected by Python's safety limit.
        return None


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    val = os.environ.get(name)
    if val is None:
        return default
    # Strip surrounding whitespace/newlines; an empty or whitespace-only
    # value falls back to the default rather than producing an empty list.
    val = val.strip()
    if not val:
        return default
    return [v.strip() for v in val.split(",") if v.strip()]


# The production frontend origin — always allowed regardless of any
# formatting quirks in the CPS_ALLOWED_ORIGINS environment variable.
FRONTEND_ORIGIN = "https://fairnes.netlify.app"


def _allowed_origins() -> list[str]:
    origins = _env_list("CPS_ALLOWED_ORIGINS", ["*"])
    if FRONTEND_ORIGIN not in origins:
        origins.append(FRONTEND_ORIGIN)
    return origins


@dataclass(frozen=True)
class Settings:
    app_name: str = "ARKHEIA-CPS"
    environment: str = os.environ.get("CPS_ENV", "development")
    log_level: str = os.environ.get("CPS_LOG_LEVEL", "INFO")

    # CORS — restrict this in production via CPS_ALLOWED_ORIGINS
    allowed_origins: list[str] = field(default_factory=_allowed_origins)

    # Auth — token-based scaffolding. In development, auth can be disabled.
    require_auth: bool = _env_bool("CPS_REQUIRE_AUTH", False)
    valid_api_keys: list[str] = field(
        default_factory=lambda: _env_list("CPS_API_KEYS", ["demo-key-local-dev"])
    )

    # Rate limiting scaffolding
    rate_limit_enabled: bool = _env_bool("CPS_RATE_LIMIT_ENABLED", True)
    rate_limit_per_minute_free: int = int(
        os.environ.get("CPS_RATE_LIMIT_FREE", "30")
    )
    rate_limit_per_minute_paid: int = int(
        os.environ.get("CPS_RATE_LIMIT_PAID", "600")
    )

    # Stripe / billing configuration.
    # Secret key and webhook secret MUST come from environment variables —
    # never hardcode these or commit them to version control.
    stripe_secret_key: str = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    stripe_webhook_secret: str = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()

    # Price IDs from your Stripe Dashboard (see docs/BILLING.md for how to
    # create these). Free tier has no Stripe price — it's not a paid
    # subscription at all.
    stripe_price_id_pro: str = os.environ.get("STRIPE_PRICE_ID_PRO", "")
    stripe_price_id_enterprise: str = os.environ.get(
        "STRIPE_PRICE_ID_ENTERPRISE", ""
    )

    # Where Stripe Checkout / the Customer Portal should redirect back to.
    frontend_base_url: str = os.environ.get(
        "CPS_FRONTEND_BASE_URL", "http://localhost:5173"
    ).strip()

    # Where subscription records are persisted. A JSON file is used here
    # deliberately — see services/billing_store.py for why, and for the
    # swap-in path to a real database.
    billing_store_path: str = os.environ.get(
        "CPS_BILLING_STORE_PATH", "data/subscriptions.json"
    )

    # ClearCheck consumer product: where check records (and processed
    # Stripe event IDs for webhook idempotency) are persisted, and the
    # one-time unlock price in USD cents.
    clearcheck_store_path: str = os.environ.get(
        "CPS_CLEARCHECK_STORE_PATH", "data/clearcheck_checks.json"
    )
    clearcheck_price_cents: int | None = field(default_factory=_clearcheck_price_cents)


settings = Settings()
