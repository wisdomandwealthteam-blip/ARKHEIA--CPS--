"""
cps_backend.routers.clearcheck
=================================
Consumer-facing ClearCheck endpoints.

Flow:
  1. POST /api/clearcheck/preview   — run the deterministic checks, get a
     redacted preview (masked identifiers only) and a check_id.
  2. POST /api/clearcheck/checkout  — get a Stripe Checkout URL for the
     one-time unlock payment, or pass plan=trial_7d for a $1 seven-day trial.
  3. Stripe calls /billing/webhook with checkout.session.completed, which
     records paid access on disk (signature-verified, idempotent).
  4. GET /api/clearcheck/report/{check_id} — 402 until unlocked or accompanied
     by an opaque session_id for a paid, unexpired, non-revoked trial.

No raw sensitive identifiers (account numbers, emails, SSN fragments,
names) are ever stored or returned — findings carry masked references
only, so even the paid report cannot leak what was submitted.
"""
from __future__ import annotations

from typing import Annotated

import stripe

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from cps_backend.schemas.billing import TrialPortalRequest, TrialPortalResponse, TrialStatusResponse
from cps_backend.schemas.clearcheck import (
    ClearCheckCheckoutRequest,
    ClearCheckCheckoutResponse,
    ClearCheckPreviewRequest,
    ClearCheckPreviewResponse,
    ClearCheckReportResponse,
    Finding,
)
from cps_backend.services import clearcheck_store
from cps_backend.services.billing_store import BillingStoreError, get_trial
from cps_backend.services.clearcheck_engine import (
    NON_LEGAL_ADVICE_NOTICE,
    compute_check_id,
    jurisdiction_metadata,
    redacted_summary,
    run_checks,
)
from cps_backend.services.stripe_service import (
    ClearCheckNoRecurringSubscriptionError,
    StripeCheckoutConfigurationError,
    StripeCheckoutInvalidSessionError,
    StripeNotConfiguredError,
    create_clearcheck_checkout_session,
    create_clearcheck_trial_checkout_session,
    create_clearcheck_trial_portal_session,
)
from cps_backend.utils.logging_setup import logger

router = APIRouter(prefix="/api/clearcheck", tags=["clearcheck"])

# A Checkout session ID is a bearer credential, not a user-selected plan flag.
# Require Stripe's opaque token format and avoid returning/logging the token.
TrialSessionId = Annotated[str, Query(
    min_length=24, max_length=255, pattern=r"^cs_(?:test|live)_[A-Za-z0-9]{16,}$",
)]
OptionalTrialSessionId = Annotated[str | None, Query(
    min_length=24, max_length=255, pattern=r"^cs_(?:test|live)_[A-Za-z0-9]{16,}$",
)]


@router.post("/preview", response_model=ClearCheckPreviewResponse)
def clearcheck_preview(body: ClearCheckPreviewRequest) -> ClearCheckPreviewResponse:
    check_id = compute_check_id(body)
    findings = run_checks(body)
    summary = redacted_summary(findings)
    juris = body.jurisdiction.upper()

    # Persist the (already-masked) findings so the paid report can be
    # served later without re-submitting the sensitive input. save_check
    # preserves the unlock state of an already-paid identical check.
    clearcheck_store.save_check(
        {
            "check_id": check_id,
            "jurisdiction": juris,
            "findings": [f.model_dump() for f in findings],
            "findings_count": len(findings),
            "redacted_summary": summary,
        }
    )
    record = clearcheck_store.get_check(check_id)
    unlocked = bool(record and record.get("unlocked"))

    logger.info(
        "clearcheck preview check_id=%s findings=%d jurisdiction=%s unlocked=%s",
        check_id,
        len(findings),
        juris,
        unlocked,
    )
    return ClearCheckPreviewResponse(
        check_id=check_id,
        findings_count=len(findings),
        redacted_summary=summary,
        jurisdiction=juris,
        jurisdiction_metadata=jurisdiction_metadata(juris),
        notice=NON_LEGAL_ADVICE_NOTICE,
        unlock_required=not unlocked,
    )


@router.get("/report/{check_id:path}", response_model=ClearCheckReportResponse)
def clearcheck_report(
    check_id: str,
    session_id: OptionalTrialSessionId = None,
    response: Response = None,
) -> ClearCheckReportResponse:
    if response is not None:
        response.headers["Cache-Control"] = "no-store"
    record = clearcheck_store.get_check(check_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown check_id. Run POST /api/clearcheck/preview first.",
        )
    if not record.get("unlocked"):
        trial = None
        if session_id is not None:
            try:
                trial = get_trial(session_id)
            except BillingStoreError:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Trial records are temporarily unavailable.",
                    headers={"Cache-Control": "no-store"},
                ) from None
        if trial is None or not trial.is_active():
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=(
                    "This report is locked. Complete the one-time unlock "
                    "payment via POST /api/clearcheck/checkout first."
                ),
                headers={"Cache-Control": "no-store"},
            )
    juris = record.get("jurisdiction", "US")
    return ClearCheckReportResponse(
        check_id=check_id,
        unlocked=True,
        findings_count=record.get("findings_count", 0),
        findings=[Finding(**f) for f in record.get("findings", [])],
        jurisdiction=juris,
        jurisdiction_metadata=jurisdiction_metadata(juris),
        notice=NON_LEGAL_ADVICE_NOTICE,
    )


@router.post("/checkout", response_model=ClearCheckCheckoutResponse, response_model_exclude_none=True)
def clearcheck_checkout(
    request: Request,
    body: ClearCheckCheckoutRequest,
) -> ClearCheckCheckoutResponse | JSONResponse:
    def error_response(status_code: int, error: str, detail: str) -> JSONResponse:
        logger.warning(
            "clearcheck checkout request_id=%s error_code=%s",
            request.state.request_id,
            error,
        )
        return JSONResponse(
            status_code=status_code,
            content={"error": error, "detail": detail, "request_id": request.state.request_id},
        )

    if body.plan != "trial_7d":
        # Do not normalize nonblank IDs: legacy IDs remain valid lookup keys.
        if not body.check_id.strip():
            return error_response(
                status.HTTP_400_BAD_REQUEST,
                "invalid_checkout_request",
                "A non-empty check_id is required.",
            )

        try:
            record = clearcheck_store.get_check(body.check_id)
        except clearcheck_store.ClearCheckStoreCorruptError:
            return error_response(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "check_store_corrupt",
                "Check records are temporarily unavailable.",
            )
        except clearcheck_store.ClearCheckStoreError:
            return error_response(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "check_store_unavailable",
                "Check records are temporarily unavailable.",
            )

        if record is None:
            return error_response(
                status.HTTP_404_NOT_FOUND,
                "check_not_found",
                "Unknown check_id. Run POST /api/clearcheck/preview first.",
            )
        if record.get("unlocked"):
            return error_response(
                status.HTTP_400_BAD_REQUEST,
                "check_already_unlocked",
                "This check is already unlocked — fetch the report directly.",
            )
    try:
        if body.plan == "trial_7d":
            url = create_clearcheck_trial_checkout_session(customer_email=body.customer_email)
        else:
            url = create_clearcheck_checkout_session(
                check_id=body.check_id,
                customer_email=body.customer_email,
            )
    except StripeNotConfiguredError:
        return error_response(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "stripe_not_configured",
            "Checkout is not configured.",
        )
    except StripeCheckoutConfigurationError:
        return error_response(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "checkout_config_invalid",
            "Checkout is temporarily unavailable due to a configuration issue.",
        )
    except StripeCheckoutInvalidSessionError:
        return error_response(
            status.HTTP_502_BAD_GATEWAY,
            "stripe_invalid_session",
            "The payment provider returned an invalid checkout session.",
        )
    except stripe.StripeError as exc:
        logger.warning(
            "clearcheck checkout request_id=%s stripe_error_class=%s",
            request.state.request_id,
            type(exc).__name__,
        )
        return error_response(
            status.HTTP_502_BAD_GATEWAY,
            "stripe_upstream_error",
            "The payment provider is temporarily unavailable.",
        )
    return ClearCheckCheckoutResponse(checkout_url=url, url=url if body.plan == "trial_7d" else None)


@router.get("/trial/status", response_model=TrialStatusResponse)
def clearcheck_trial_status(
    session_id: TrialSessionId,
    response: Response,
) -> TrialStatusResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        trial = get_trial(session_id)
    except BillingStoreError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trial records are temporarily unavailable.",
            headers={"Cache-Control": "no-store"},
        ) from None
    return TrialStatusResponse(
        trial_active=bool(trial and trial.is_active()),
        trial_expires_at=trial.trial_expires_at if trial else None,
    )


@router.post("/trial/portal", response_model=TrialPortalResponse)
def clearcheck_trial_portal(
    body: TrialPortalRequest,
    response: Response,
) -> TrialPortalResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        url = create_clearcheck_trial_portal_session(body.session_id)
    except ClearCheckNoRecurringSubscriptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
            headers={"Cache-Control": "no-store"},
        ) from None
    except BillingStoreError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trial records are temporarily unavailable.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except StripeNotConfiguredError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing portal is not configured.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except StripeCheckoutInvalidSessionError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The payment provider returned an invalid portal session.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except stripe.StripeError:
        logger.warning("clearcheck trial portal provider error")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The payment provider is temporarily unavailable.",
            headers={"Cache-Control": "no-store"},
        ) from None
    if url is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No paid trial is on file for this session.",
            headers={"Cache-Control": "no-store"},
        )
    return TrialPortalResponse(url=url, portal_url=url)
