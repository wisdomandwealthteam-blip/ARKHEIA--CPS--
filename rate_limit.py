"""
cps_backend.services.rate_limit
=================================
In-memory, per-tenant rate limiting scaffolding.

This is intentionally simple: a sliding-window counter held in process
memory. It works for a single-process deployment and demonstrates the
enforcement path end-to-end, but it will NOT correctly enforce limits
across multiple worker processes or multiple server instances — for
that, swap the in-memory dict below for Redis (or similar) without
changing the public `check_rate_limit` interface.

Limits are now read from cps_backend.services.tiers (one limit per
subscription tier) instead of a hardcoded free/paid split.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, status

from cps_backend.config import settings
from cps_backend.services.tiers import Tier, rate_limit_for

# tenant_id -> deque of request timestamps (epoch seconds) within the window
_request_log: dict[str, deque[float]] = defaultdict(deque)

WINDOW_SECONDS = 60.0


def check_rate_limit(tenant_id: str, tier: Tier) -> None:
    """Raises HTTP 429 if the tenant has exceeded their per-minute limit.
    Otherwise records this request and returns None."""
    if not settings.rate_limit_enabled:
        return

    limit = rate_limit_for(tier)
    now = time.monotonic()
    log = _request_log[tenant_id]

    # Drop timestamps outside the sliding window
    while log and now - log[0] > WINDOW_SECONDS:
        log.popleft()

    if len(log) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({limit} requests/minute for the "
            f"{tier.value} tier). Upgrade your plan for a higher limit.",
        )

    log.append(now)
