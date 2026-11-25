
"""
cps_backend.services.stripe_service
======================================
All direct interaction with the Stripe API lives here. Routers call these
functions; they never call the `stripe` library directly. This keeps the
Stripe SDK usage in one auditable place.

REQUIRES the `stripe` package (see requirements.txt) and a real
STRIPE_SECRET_KEY set via environment variable before any of these
functions will work against real Stripe — see docs/BILLING.md.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import stripe

from cps_backend.config import settings
from cps_backend.services import clearcheck_store
from cps_backend.services.billing_store import SubscriptionRecord, upsert_subscription
from cps_backend.services.tiers import Tier
from cps_backend.utils.logging_setup import logger
from cps_backend.utils.redaction import mask_email

stripe.api_key = settings.stripe_secret_key

# Maps Stripe Price IDs back to our internal Tier enum. Built from config
# so this stays correct if price IDs change per environment (test vs live).
_PRICE_ID_TO_TIER: dict[str, Tier] = {
    settings.stripe_price_id_pro: Tier.PRO,
    settings.stripe_price_id_enterprise: Tier.ENTERPRISE,
}


class StripeNotConfiguredError(Exception):
    """Raised when a Stripe operation is attempted without a secret key
    configured — fails loudly rather than silently no-op-ing."""


class StripeCheckoutConfigurationError(Exception):
    """Raised when ClearCheck checkout configuration is invalid."""


class StripeCheckoutInvalidSessionError(Exception):
    """Raised when Stripe returns an unsafe or missing checkout URL."""


class ClearCheckUnknownCheckError(Exception):
    """A paid webhook refers to a check not currently in the store."""


def _require_configured() -> None:
    if (
        not isinstance(settings.stripe_secret_key, str)
        or not settings.stripe_secret_key.strip()
    ):
        raise StripeNotConfiguredError(
            "STRIPE_SECRET_KEY is not set. See docs/BILLING.md before "
            "using billing endpoints."
        )


def _validated_url(value: object, *, schemes: set[str], no_query_fragment: bool = False):
    """Parse an unambiguous absolute web URL; never include its value in errors."""
    if (
        not isinstance(value, str)
        or not value
        or any(c.isspace() or ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
        or "\\" in value
        or (no_query_fragment and ("?" in value or "#" in value))
    ):
        raise ValueError("Invalid URL")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        # Accessing port validates both its syntax and numeric range.
        _ = parsed.port
        if (
            parsed.scheme not in schemes
            or not parsed.netloc
            or not host
            or "@" in parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.netloc.endswith(":")
            or "%" in host
        ):
            raise ValueError("Invalid URL")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            ascii_host = host.encode("idna").decode("ascii").rstrip(".")
            if len(ascii_host) > 253 or not ascii_host or any(
                not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in ascii_host.split(".")
            ):
                raise ValueError("Invalid URL")
        return parsed
    except (ValueError, UnicodeError):
        raise ValueError("Invalid URL") from None


def create_checkout_session(
    tenant_id: str,
    tier: Tier,
    customer_email: str | None = None,
) -> str:
    """Creates a Stripe Checkout session for upgrading `tenant_id` to
    `tier`. Returns the URL the frontend should redirect the user to.

    FREE tier cannot be "checked out" into — there's no Stripe price for
    it, since it isn't a paid subscription. Callers must guard against
    tier == Tier.FREE before calling this (the router does).
    """
    _require_configured()

    price_id = {
        Tier.PRO: settings.stripe_price_id_pro,
        Tier.ENTERPRISE: settings.stripe_price_id_enterprise,
    }.get(tier)

    if not price_id:
        raise ValueError(
            f"No Stripe price ID configured for tier={tier.value}. "
            f"Set STRIPE_PRICE_ID_{tier.value.upper()} — see docs/BILLING.md."
        )

    # NOTE: the frontend is a single-page app with tab state, not a real
    # router (no /billing path exists) — so these redirect to the root
    # with a query param, and App.jsx reads that param on mount to jump
    # to the Billing tab. If you later add real routing, change these to
    # actual paths.
    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{settings.frontend_base_url}/?checkout=success",
        cancel_url=f"{settings.frontend_base_url}/?checkout=cancelled",
        customer_email=customer_email,
        client_reference_id=tenant_id,
        # This is how the webhook handler knows which tenant a Stripe
        # subscription belongs to — set on the subscription itself, not
        # just the checkout session, so it survives into every later
        # webhook event.
        subscription_data={"metadata": {"tenant_id": tenant_id}},
    )
    logger.info(
        "checkout session created tenant=%s tier=%s session_id=%s customer_email=%s",
        tenant_id,
        tier.value,
        session.id,
        mask_email(customer_email),
    )
    return session.url


def create_clearcheck_checkout_session(
    check_id: str,
    customer_email: str | None = None,
) -> str:
    """Creates a one-time-payment Stripe Checkout session that unlocks
    the full ClearCheck report for `check_id`. The check_id travels in
    the session metadata — that's how the checkout.session.completed
    webhook knows which check to unlock."""
    _require_configured()

    price = settings.clearcheck_price_cents
    if type(price) is not int or price <= 0:
        raise StripeCheckoutConfigurationError("ClearCheck checkout is not configured.")
    try:
        frontend = _validated_url(
            settings.frontend_base_url,
            schemes={"http", "https"},
            no_query_fragment=True,
        )
    except ValueError:
        raise StripeCheckoutConfigurationError(
            "ClearCheck checkout is not configured."
        ) from None

    def callback(result: str) -> str:
        return urlunsplit((
            frontend.scheme,
            frontend.netloc,
            frontend.path.rstrip("/") + "/",
            urlencode({"clearcheck": result, "checkout": result, "check_id": check_id}),
            "",
        ))

    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[
            {
                "price_data": {
                    "currency": "usd",
                    "unit_amount": price,
                    "product_data": {"name": "ClearCheck full report"},
                },
                "quantity": 1,
            }
        ],
        success_url=callback("success"),
        cancel_url=callback("cancelled"),
        customer_email=customer_email,
        client_reference_id=check_id,
        metadata={"purpose": "clearcheck_unlock", "check_id": check_id},
    )
    checkout_url = getattr(session, "url", None)
    try:
        _validated_url(checkout_url, schemes={"https"})
    except ValueError:
        raise StripeCheckoutInvalidSessionError(
            "Stripe returned an invalid checkout session."
        ) from None
    logger.info("clearcheck checkout session created")
    return checkout_url


def create_portal_session(stripe_customer_id: str) -> str:
    """Creates a Stripe Customer Portal session so the user can manage
    their existing subscription (update card, cancel, view invoices)
    without you building any of that UI yourself."""
    _require_configured()

    session = stripe.billing_portal.Session.create(
        customer=stripe_customer_id,
        return_url=f"{settings.frontend_base_url}/?tab=billing",
    )
    return session.url


def construct_webhook_event(payload: bytes, sig_header: str | None) -> stripe.Event:
    """Verify the signature using the webhook secret, not the API key.
    Raises stripe.SignatureVerificationError on a bad signature —
    the router turns that into an HTTP 400. NEVER process a webhook body
    without this verification step; an unverified endpoint lets anyone
    on the internet claim to be Stripe and grant themselves a
    subscription."""
    if (
        not isinstance(settings.stripe_webhook_secret, str)
        or not settings.stripe_webhook_secret.strip()
    ):
        raise StripeNotConfiguredError("Stripe webhook is not configured.")
    event = stripe.Webhook.construct_event(
        payload, sig_header, settings.stripe_webhook_secret
    )
    event_dict = _as_dict(event)
    data = event_dict.get("data")
    if (
        not isinstance(event_dict.get("id"), str)
        or not event_dict["id"]
        or not isinstance(event_dict.get("type"), str)
        or not event_dict["type"]
        or not isinstance(data, dict)
        or not isinstance(data.get("object"), dict)
    ):
        raise ValueError("Invalid webhook event")
    return event


def _as_dict(obj: Any) -> dict:
    """Normalizes a Stripe typed resource (Session, Subscription, …) to a
    plain dict. Modern stripe-python returns typed objects whose dict
    methods like .get() are disabled; handlers below work with dicts."""
    if isinstance(obj, dict):
        return obj
    to_dict = getattr(obj, "to_dict_recursive", None) or getattr(obj, "to_dict", None)
    return to_dict() if to_dict else dict(obj)


def handle_webhook_event(event: stripe.Event) -> None:
    """Routes a verified Stripe event to the right handler. Unhandled
    event types are logged and ignored, not treated as errors — Stripe
    sends many event types we don't need to act on."""
    event_type = event["type"]
    logger.info("stripe webhook received")

    data_object = _as_dict(event["data"]["object"])

    if event_type in (
        "customer.subscription.created",
        "customer.subscription.updated",
    ):
        _handle_subscription_upsert(data_object)
    elif event_type == "customer.subscription.deleted":
        _handle_subscription_deleted(data_object)
    elif event_type == "invoice.payment_failed":
        _handle_payment_failed(data_object)
    elif event_type in (
        "checkout.session.completed",
        "checkout.session.async_payment_succeeded",
    ):
        _handle_checkout_completed(data_object, event["id"])
    elif event_type == "checkout.session.async_payment_failed":
        logger.info("checkout asynchronous payment failed; no unlock performed")
    else:
        logger.info("stripe webhook event not handled (no-op)")


def _handle_checkout_completed(session: dict, event_id: str) -> None:
    """Unlocks a ClearCheck report when its one-time payment completes.
    Idempotent on the Stripe event ID (see clearcheck_store.mark_unlocked)
    — Stripe redeliveries are recorded no-ops. Subscription checkouts
    (no clearcheck metadata) are ignored here; they're driven by the
    customer.subscription.* events instead."""
    metadata = session.get("metadata") or {}
    if metadata.get("purpose") != "clearcheck_unlock":
        logger.info("checkout session is not a clearcheck unlock (no-op)")
        return
    if session.get("mode") != "payment" or session.get("payment_status") != "paid":
        logger.info("clearcheck checkout is not a paid one-time payment (no-op)")
        return
    check_id = metadata.get("check_id")
    if not check_id:
        logger.error("clearcheck checkout lacks a check_id; no unlock performed")
        return
    outcome = clearcheck_store.mark_unlocked(check_id, event_id)
    if outcome == clearcheck_store.UNKNOWN_CHECK:
        raise ClearCheckUnknownCheckError("ClearCheck payment cannot yet be processed.")
    logger.info("clearcheck payment processed")


def _tenant_id_from_subscription(subscription: dict) -> str | None:
    tenant_id = subscription.get("metadata", {}).get("tenant_id")
    if not tenant_id:
        logger.error(
            "stripe subscription %s has no tenant_id metadata — cannot "
            "attribute this event to a tenant",
            subscription.get("id"),
        )
    return tenant_id


def _tier_from_subscription(subscription: dict) -> Tier:
    items = subscription.get("items", {}).get("data", [])
    if not items:
        logger.warning(
            "stripe subscription %s has no line items; defaulting to FREE",
            subscription.get("id"),
        )
        return Tier.FREE
    price_id = items[0]["price"]["id"]
    tier = _PRICE_ID_TO_TIER.get(price_id)
    if tier is None:
        logger.warning(
            "unrecognized stripe price_id=%s on subscription %s; "
            "defaulting to FREE",
            price_id,
            subscription.get("id"),
        )
        return Tier.FREE
    return tier


def _handle_subscription_upsert(subscription: dict) -> None:
    tenant_id = _tenant_id_from_subscription(subscription)
    if not tenant_id:
        return

    tier = _tier_from_subscription(subscription)
    period_end = subscription.get("current_period_end")

    upsert_subscription(
        SubscriptionRecord(
            tenant_id=tenant_id,
            stripe_customer_id=subscription.get("customer"),
            stripe_subscription_id=subscription.get("id"),
            tier=tier.value,
            status=subscription.get("status", "unknown"),
            current_period_end=(
                str(period_end) if period_end is not None else None
            ),
            updated_at="",  # set inside upsert_subscription
        )
    )


def _handle_subscription_deleted(subscription: dict) -> None:
    tenant_id = _tenant_id_from_subscription(subscription)
    if not tenant_id:
        return
    # Record the cancellation rather than deleting the row outright —
    # keeps a history and lets effective_tier() correctly downgrade to
    # FREE rather than the tenant just disappearing from the store.
    upsert_subscription(
        SubscriptionRecord(
            tenant_id=tenant_id,
            stripe_customer_id=subscription.get("customer"),
            stripe_subscription_id=subscription.get("id"),
            tier=_tier_from_subscription(subscription).value,
            status="canceled",
            current_period_end=None,
            updated_at="",
        )
    )


def _handle_payment_failed(invoice: dict) -> None:
    """A failed payment doesn't immediately cancel the subscription on
    Stripe's side (Stripe usually retries), but we log it prominently —
    the subsequent customer.subscription.updated event (status will
    become 'past_due') is what actually triggers the access downgrade
    via SubscriptionRecord.is_active()."""
    customer_id = invoice.get("customer")
    logger.warning(
        "stripe payment failed customer=%s invoice=%s — expect a "
        "subscription.updated event to follow with status=past_due",
        customer_id,
        invoice.get("id"),
    )
