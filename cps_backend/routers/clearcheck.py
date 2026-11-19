"""
cps_backend.routers.clearcheck
=================================
Consumer-facing ClearCheck endpoints.

Flow:
  1. POST /api/clearcheck/preview   — run the deterministic checks, get a
     redacted preview (masked identifiers only) and a check_id.
  2. POST /api/clearcheck/checkout  — get a Stripe Checkout URL for the
     one-time unlock payment.
  3. Stripe calls /billing/webhook with checkout.session.completed, which
     marks the check unlocked on disk (signature-verified, idempotent).
  4. GET /api/clearcheck/report/{check_id} — 402 until unlocked, then the
     full findings breakdown.

No raw sensitive identifiers (account numbers, emails, SSN fragments,
names) are ever stored or returned — findings carry masked references
only, so even the paid report cannot leak what was submitted.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from cps_backend.schemas.clearcheck import (
    ClearCheckCheckoutRequest,
    ClearCheckCheckoutResponse,
    ClearCheckPreviewRequest,
    ClearCheckPreviewResponse,
    ClearCheckReportResponse,
    Finding,
)
from cps_backend.services import clearcheck_store
from cps_backend.services.clearcheck_engine import (
    NON_LEGAL_ADVICE_NOTICE,
    compute_check_id,
    jurisdiction_metadata,
    redacted_summary,
    run_checks,
)
from cps_backend.services.stripe_service import (
    StripeNotConfiguredError,
    create_clearcheck_checkout_session,
)
from cps_backend.utils.logging_setup import logger

router = APIRouter(prefix="/api/clearcheck", tags=["clearcheck"])


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


@router.get("/report/{check_id}", response_model=ClearCheckReportResponse)
def clearcheck_report(check_id: str) -> ClearCheckReportResponse:
    record = clearcheck_store.get_check(check_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown check_id. Run POST /api/clearcheck/preview first.",
        )
    if not record.get("unlocked"):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=(
                "This report is locked. Complete the one-time unlock "
                "payment via POST /api/clearcheck/checkout first."
            ),
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


@router.post("/checkout", response_model=ClearCheckCheckoutResponse)
def clearcheck_checkout(
    body: ClearCheckCheckoutRequest,
) -> ClearCheckCheckoutResponse:
    record = clearcheck_store.get_check(body.check_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown check_id. Run POST /api/clearcheck/preview first.",
        )
    if record.get("unlocked"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This check is already unlocked — fetch the report directly.",
        )
    try:
        url = create_clearcheck_checkout_session(
            check_id=body.check_id,
            customer_email=body.customer_email,
        )
    except StripeNotConfiguredError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        )
    return ClearCheckCheckoutResponse(checkout_url=url)
