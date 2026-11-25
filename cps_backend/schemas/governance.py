"""GovernanceCheck's allowlisted request and receipt contracts."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    field_validator,
    model_validator,
)

ARCHITECTURE_VERSION = "PLATFORM-ARCHITECTURE-2026-V1"
RECEIPT_ID_PATTERN = r"^gov_[0-9a-f]{64}$"

FindingCode = Literal[
    "LOW_MODEL_CONFIDENCE",
    "UNSUPERVISED_HIGH_VALUE_ACTION",
    "MISSING_MODEL_PROVENANCE",
]
FINDING_REASONS: dict[str, str] = {
    "LOW_MODEL_CONFIDENCE": "Model confidence is below the policy minimum.",
    "UNSUPERVISED_HIGH_VALUE_ACTION": (
        "Transaction amount exceeds the unsupervised policy maximum without required human override."
    ),
    "MISSING_MODEL_PROVENANCE": "Model provenance is missing or unknown.",
}

Confidence = Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)]
Amount = Annotated[float, Field(strict=True, ge=0, allow_inf_nan=False)]
ReceiptId = Annotated[
    str, Field(strict=True, min_length=68, max_length=68, pattern=RECEIPT_ID_PATTERN)
]
Digest = Annotated[
    str, Field(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
]


class PolicyThresholds(BaseModel):
    """Only these two keys are accepted; omitted keys receive their defaults."""

    model_config = ConfigDict(extra="forbid")

    min_confidence: Confidence = 0.85
    max_unsupervised_amount: Amount = 10000.0


class GovernanceCheckRequest(BaseModel):
    """Strings are never echoed or persisted, including the redacted reference."""

    model_config = ConfigDict(extra="forbid")

    # Blank and trimmed/case-insensitive 'unknown' are valid inputs: they HOLD.
    model_id: StrictStr
    decision_domain: StrictStr
    proposed_action: StrictStr
    confidence_score: Confidence
    human_override_required: StrictBool
    policy_thresholds: PolicyThresholds = Field(default_factory=PolicyThresholds)
    transaction_amount: Amount = 0.0
    redacted_subject_ref: StrictStr


class GovernanceFinding(BaseModel):
    """Reasons are static rule text, not caller- or storage-controlled prose."""

    model_config = ConfigDict(extra="forbid")

    code: FindingCode
    reason: StrictStr

    @model_validator(mode="after")
    def require_static_reason(self) -> Self:
        if self.reason != FINDING_REASONS[self.code]:
            raise ValueError("Invalid finding reason")
        return self


class GovernanceCheckResponse(BaseModel):
    """A content-addressed receipt, not an authenticated cryptographic signature."""

    model_config = ConfigDict(extra="forbid")

    receipt_id: ReceiptId
    gate: Literal["PASS", "HOLD"]
    architecture_version: Literal["PLATFORM-ARCHITECTURE-2026-V1"]
    sha256_digest: Digest
    findings: list[GovernanceFinding] = Field(max_length=3)
    evaluated_at: AwareDatetime

    @field_validator("evaluated_at", mode="before")
    @classmethod
    def require_timestamp(cls, value: object) -> object:
        # Reject numeric epoch coercion in stored records.
        if not isinstance(value, (str, datetime)):
            raise ValueError("Invalid evaluation timestamp")
        return value

    @field_validator("evaluated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            raise ValueError("Evaluation timestamp must be UTC")
        return value

    @model_validator(mode="after")
    def require_consistent_receipt(self) -> Self:
        if self.receipt_id != f"gov_{self.sha256_digest}":
            raise ValueError("Receipt identifier and digest do not match")
        codes = [finding.code for finding in self.findings]
        expected_order = [code for code in FINDING_REASONS if code in codes]
        if codes != expected_order:
            raise ValueError("Findings must be unique and in rule order")
        if self.gate != ("HOLD" if self.findings else "PASS"):
            raise ValueError("Gate does not match findings")
        return self
