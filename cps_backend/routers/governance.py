"""GovernanceCheck endpoints, independent of ClearCheck and billing."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Response, status

from cps_backend.schemas.governance import (
    ARCHITECTURE_VERSION,
    RECEIPT_ID_PATTERN,
    GovernanceCheckRequest,
    GovernanceCheckResponse,
)
from cps_backend.services import governance_store
from cps_backend.services.governance_engine import compute_receipt_id, run_checks

router = APIRouter(prefix="/api/governance", tags=["governance"])
ReceiptPath = Annotated[
    str, Path(min_length=68, max_length=68, pattern=RECEIPT_ID_PATTERN)
]


def _unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Governance records are temporarily unavailable.",
        headers={"Cache-Control": "no-store"},
    )


@router.post("/check", response_model=GovernanceCheckResponse)
def governance_check(body: GovernanceCheckRequest, response: Response) -> GovernanceCheckResponse:
    response.headers["Cache-Control"] = "no-store"
    receipt_id = compute_receipt_id(body)
    findings = run_checks(body)
    receipt = GovernanceCheckResponse(
        receipt_id=receipt_id,
        gate="HOLD" if findings else "PASS",
        architecture_version=ARCHITECTURE_VERSION,
        sha256_digest=receipt_id.removeprefix("gov_"),
        findings=findings,
        evaluated_at=datetime.now(timezone.utc),
    )
    try:
        return governance_store.save_check(receipt)
    except governance_store.GovernanceStoreError:
        raise _unavailable() from None


@router.get("/checks/{receipt_id}", response_model=GovernanceCheckResponse)
def governance_lookup(receipt_id: ReceiptPath, response: Response) -> GovernanceCheckResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        receipt = governance_store.get_check(receipt_id)
    except governance_store.GovernanceStoreError:
        raise _unavailable() from None
    if receipt is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown receipt_id. Run POST /api/governance/check first.",
            headers={"Cache-Control": "no-store"},
        )
    return receipt
