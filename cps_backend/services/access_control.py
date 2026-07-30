"""
cps_backend.services.access_control
======================================
Enforces module-level access based on subscription tier (e.g., free tier
can call /risk/auto but not /risk/housing). This is deliberately separate
from rate limiting — a request can be within its rate limit and still be
denied because the tier doesn't include that module at all.
"""
from __future__ import annotations

from fastapi import HTTPException, status

from cps_backend.services.tiers import Tier, module_allowed


def require_module_access(tier: Tier, module: str) -> None:
    """Raises HTTP 403 if `tier` does not include access to `module`.
    Called explicitly inside each risk-evaluation route, after auth and
    rate-limit checks have already passed."""
    if not module_allowed(tier, module):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"The '{module}' module is not included in your current "
                f"'{tier.value}' plan. Upgrade to access it."
            ),
        )
