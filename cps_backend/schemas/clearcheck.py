"""
cps_backend.schemas.clearcheck
=================================
Request/response schemas for the ClearCheck consumer endpoints.

ClearCheck runs deterministic date/balance/status consistency checks
against account entries a consumer submits. The preview response is
always redacted — sensitive identifiers (account numbers, emails, SSN
fragments, names) never appear unmasked in any response body.
"""
from __future__ import annotations

from datetime import date
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AccountStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    PAID = "paid"
    CHARGED_OFF = "charged_off"
    IN_COLLECTION = "in_collection"
    DISPUTED = "disputed"


class ClearCheckAccountEntry(BaseModel):
    """One reported account/tradeline as the consumer sees it."""

    account_number: str = Field(min_length=1, max_length=64)
    creditor_name: str = Field(min_length=1, max_length=128)
    status: AccountStatus
    date_opened: date
    date_closed: date | None = None
    date_of_last_activity: date | None = None
    reported_balance: float = Field(ge=0)
    reported_past_due: float = Field(default=0, ge=0)
    credit_limit: float | None = Field(default=None, ge=0)


class ClearCheckPreviewRequest(BaseModel):
    consumer_name: str = Field(min_length=1, max_length=128)
    consumer_email: str | None = None
    ssn_last4: str | None = Field(default=None, min_length=4, max_length=4)
    jurisdiction: str = Field(default="US", min_length=2, max_length=16)
    report_date: date
    accounts: list[ClearCheckAccountEntry] = Field(min_length=1, max_length=100)


class Finding(BaseModel):
    """A single deterministic consistency finding. `account_ref` is
    always a masked account number — never the raw identifier."""

    code: str
    severity: str  # "high" | "medium" | "low"
    account_ref: str
    field: str
    description: str


class ClearCheckPreviewResponse(BaseModel):
    check_id: str
    findings_count: int
    redacted_summary: list[str]
    jurisdiction: str
    jurisdiction_metadata: dict[str, Any]
    notice: str
    unlock_required: bool


class ClearCheckReportResponse(BaseModel):
    check_id: str
    unlocked: bool
    findings_count: int
    findings: list[Finding]
    jurisdiction: str
    jurisdiction_metadata: dict[str, Any]
    notice: str


class ClearCheckCheckoutRequest(BaseModel):
    check_id: str = Field(strict=True)
    customer_email: str | None = None


class ClearCheckCheckoutResponse(BaseModel):
    checkout_url: str
