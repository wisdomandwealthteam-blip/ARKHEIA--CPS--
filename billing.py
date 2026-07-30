"""
cps_backend.routers.billing
==============================
Checkout session creation, customer portal redirection, subscription
status, and the Stripe webhook receiver.
"""
from __future__ import annotations

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status

from cps_backend.schemas.billing import (
    CheckoutSessionRequest,
    CheckoutSessionResponse,
    PortalSessionResponse,
    SubscriptionStatusResponse,
)
from cps_backend.services.auth import ApiKeyContext, get_api_key_context
from cps_backend.services.billing_store import get_subscription
from cps_backend.services.stripe_service import (
    StripeNotConfiguredError,
    construct_webhook_event,
    create_checkout_session,
    create_portal_session,
    handle_webhook_event,
)
from cps_backend.services.tiers import Tier, tier_config
from cps_backend.utils.logging_setup import logger

router = APIRouter(prefix="/billing", tags=["billing"])


@router.post("/create-checkout-session", response_model=CheckoutSessionResponse)
def create_checkout(
    body: CheckoutSessionRequest,
    ctx: ApiKeyContext = Depends(get_api_key_context),
) -> CheckoutSessionResponse:
    if body.tier == Tier.FREE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The free tier has no checkout — it's the default, not "
            "a purchasable plan.",
        )
    try:
        url = create_checkout_session(
            tenant_id=ctx.tenant_id,
            tier=body.tier,
            customer_email=body.customer_email,
        )
    except StripeNotConfiguredError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    return CheckoutSessionResponse(checkout_url=url)


@router.post("/create-portal-session", response_model=PortalSessionResponse)
def create_portal(
    ctx: ApiKeyContext = Depends(get_api_key_context),
) -> PortalSessionResponse:
    record = get_subscription(ctx.tenant_id)
    if record is None or not record.stripe_customer_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No Stripe customer on file for this tenant yet — "
            "there's nothing to manage until you've subscribed at least "
            "once via checkout.",
        )
    try:
        url = create_portal_session(record.stripe_customer_id)
    except StripeNotConfiguredError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    return PortalSessionResponse(portal_url=url)


@router.get("/status", response_model=SubscriptionStatusResponse)
def billing_status(
    ctx: ApiKeyContext = Depends(get_api_key_context),
) -> SubscriptionStatusResponse:
    record = get_subscription(ctx.tenant_id)
    cfg = tier_config(ctx.tier)

    return SubscriptionStatusResponse(
        tenant_id=ctx.tenant_id,
        tier=ctx.tier,
        display_name=cfg.display_name,
        status=record.status if record else "free",
        rate_limit_per_minute=cfg.rate_limit_per_minute,
        allowed_modules=sorted(cfg.allowed_modules),
        monthly_price_usd=cfg.monthly_price_usd,
        current_period_end=record.current_period_end if record else None,
        has_stripe_customer=bool(record and record.stripe_customer_id),
    )


@router.post("/webhook", include_in_schema=False)
async def stripe_webhook(request: Request) -> dict:
    """Stripe calls this endpoint directly — it is NOT protected by our
    own X-API-Key auth (Stripe doesn't send one). It is instead protected
    by Stripe's webhook signature, verified inside construct_webhook_event.
    Never remove that verification step."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not sig_header:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Stripe-Signature header.",
        )

    try:
        event = construct_webhook_event(payload, sig_header)
    except stripe.error.SignatureVerificationError:
        logger.warning("stripe webhook signature verification failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid signature."
        )
    except StripeNotConfiguredError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )

    handle_webhook_event(event)
    return {"received": True}
