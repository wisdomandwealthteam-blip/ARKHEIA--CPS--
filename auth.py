"""
cps_backend.services.auth
============================
Token-based auth scaffolding. This is NOT wired to a real identity
provider yet — it checks presented API keys against a configured list
(cps_backend.config.settings.valid_api_keys). Ready to be swapped for a
real provider (e.g., a database-backed key store, or an OAuth/JWT
provider) by replacing only `resolve_api_key` below; nothing in the
routers needs to change.

TIER RESOLUTION: as of the billing integration, `ApiKeyContext.tier` is
no longer a stub — it's read live from cps_backend.services.billing_store
on every request, which reflects whatever Stripe most recently reported
via webhook. A key that was "pro" yesterday and had its payment fail
overnight will correctly resolve to "free" on the next request, without
any code path needing to know that happened.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from cps_backend.config import settings
from cps_backend.services.billing_store import effective_tier
from cps_backend.services.tiers import Tier


@dataclass(frozen=True)
class ApiKeyContext:
    """What we know about the caller once their key is resolved."""

    key: str
    tier: Tier
    tenant_id: str


def resolve_api_key(api_key: str) -> ApiKeyContext:
    """Stub resolver: any key in settings.valid_api_keys is treated as a
    valid tenant, identified by the key itself. The key -> tenant_id
    mapping here is intentionally the simplest possible thing (the key
    IS the tenant id) — a real key store would map many keys to one
    tenant, support rotation, etc. Replace this function's body when
    wiring to a real key store; everything else depends only on this
    function's return type, not its implementation.
    """
    if api_key not in settings.valid_api_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unrecognized API key.",
        )
    tenant_id = f"tenant:{api_key}"
    return ApiKeyContext(
        key=api_key,
        tier=effective_tier(tenant_id),
        tenant_id=tenant_id,
    )


async def get_api_key_context(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> ApiKeyContext:
    """FastAPI dependency. If auth is not required (dev mode), returns a
    permissive default context when no key is presented. If auth IS
    required, a missing or invalid key raises 401."""
    if not settings.require_auth:
        if x_api_key is None:
            return ApiKeyContext(key="dev-mode", tier=Tier.ENTERPRISE, tenant_id="dev")
        return resolve_api_key(x_api_key)

    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
        )
    return resolve_api_key(x_api_key)
