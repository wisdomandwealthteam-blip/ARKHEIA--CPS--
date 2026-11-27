"""Fail-closed contracts for the four additive platform checks.

Rule fields deliberately retain JSON types: invalid or missing evidence produces
HOLD findings rather than coercion or a request-validation error. Only declared
fields enter the canonical digest; optional subject references are masked first.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AwareDatetime, BaseModel, ConfigDict, Field, StrictStr,
    field_validator, model_validator,
)

from cps_backend.schemas.governance import ARCHITECTURE_VERSION, Digest
from cps_backend.utils.redaction import mask_value

FindingCode = Literal[
    "SPLIT_CONSERVATION_VIOLATION",
    "INVALID_GROSS_AMOUNT",
    "MISSING_PROVENANCE_HASH",
    "UNVERIFIED_RIGHTS_CHAIN",
    "INSUFFICIENT_QUORUM_SIGNATURES",
    "EXPIRED_OR_INACTIVE_CUSTODY_POLICY",
    "CUSTODY_LIMIT_EXCEEDED",
    "UNATTESTED_EDGE_NODE",
    "SENSOR_INVARIANT_BREACH",
    "MISSING_LOCAL_AUDIT_HASH",
]
FINDING_REASONS: dict[str, str] = {
    "SPLIT_CONSERVATION_VIOLATION": "Integer basis-point splits must sum to 10000.",
    "INVALID_GROSS_AMOUNT": "Gross amount must be a positive integer number of cents.",
    "MISSING_PROVENANCE_HASH": "ISRC and audio fingerprint hash must both be present.",
    "UNVERIFIED_RIGHTS_CHAIN": "Rights clearance must be explicitly verified.",
    "INSUFFICIENT_QUORUM_SIGNATURES": "Collected signatures must meet the required quorum.",
    "EXPIRED_OR_INACTIVE_CUSTODY_POLICY": "The custody policy window must be active.",
    "CUSTODY_LIMIT_EXCEEDED": "Release amount must not exceed the custody limit.",
    "UNATTESTED_EDGE_NODE": "The edge node must have a valid attestation.",
    "SENSOR_INVARIANT_BREACH": "Telemetry must remain within the permitted bounds.",
    "MISSING_LOCAL_AUDIT_HASH": "An offline queue audit hash must be present.",
}
RULE_ORDER: dict[str, tuple[FindingCode, ...]] = {
    "stl_": ("SPLIT_CONSERVATION_VIOLATION", "INVALID_GROSS_AMOUNT"),
    "prv_": ("MISSING_PROVENANCE_HASH", "UNVERIFIED_RIGHTS_CHAIN", "SPLIT_CONSERVATION_VIOLATION"),
    "cst_": ("INSUFFICIENT_QUORUM_SIGNATURES", "EXPIRED_OR_INACTIVE_CUSTODY_POLICY", "CUSTODY_LIMIT_EXCEEDED"),
    "edg_": ("UNATTESTED_EDGE_NODE", "SENSOR_INVARIANT_BREACH", "MISSING_LOCAL_AUDIT_HASH"),
}
ReceiptId = Annotated[
    str, Field(strict=True, min_length=68, max_length=68, pattern=r"^(stl|prv|cst|edg)_[0-9a-f]{64}$")
]


class PlatformCheckRequest(BaseModel):
    """Unknown fields are ignored, never echoed, logged, persisted or hashed."""

    model_config = ConfigDict(extra="ignore")
    redacted_subject_ref: Any = None

    @model_validator(mode="before")
    @classmethod
    def require_object_or_missing_evidence(cls, value: object) -> object:
        return value if isinstance(value, dict) else {}

    @field_validator("redacted_subject_ref", mode="before")
    @classmethod
    def mask_subject_reference(cls, value: object) -> str | None:
        return mask_value(value) if isinstance(value, str) else None


class SettlementCheckRequest(PlatformCheckRequest):
    splits_bps: Any = None
    gross_amount_cents: Any = None


class ProvenanceCheckRequest(PlatformCheckRequest):
    isrc: Any = None
    audio_fingerprint_sha256: Any = None
    rights_cleared: Any = None
    splits_bps: Any = None


class CustodyCheckRequest(PlatformCheckRequest):
    signatures_collected: Any = None
    quorum_required: Any = None
    policy_window_active: Any = None
    release_amount: Any = None
    custody_limit: Any = None


class EdgeCheckRequest(PlatformCheckRequest):
    node_attestation_valid: Any = None
    telemetry_within_bounds: Any = None
    offline_queue_hash: Any = None


class PlatformFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: FindingCode
    reason: StrictStr

    @model_validator(mode="after")
    def require_static_reason(self) -> Self:
        if self.reason != FINDING_REASONS[self.code]:
            raise ValueError("Invalid finding reason")
        return self


class PlatformCheckResponse(BaseModel):
    """Content-addressed PLATFORM receipt; not a signed DVE v1 receipt."""

    model_config = ConfigDict(extra="forbid")

    receipt_id: ReceiptId
    gate: Literal["PASS", "HOLD"]
    findings: list[PlatformFinding] = Field(max_length=3)
    sha256: Digest
    timestamp: AwareDatetime
    architecture_version: Literal["PLATFORM-ARCHITECTURE-2026-V1"] = ARCHITECTURE_VERSION

    @field_validator("timestamp", mode="before")
    @classmethod
    def require_timestamp(cls, value: object) -> object:
        if not isinstance(value, (str, datetime)):
            raise ValueError("Invalid evaluation timestamp")
        return value

    @field_validator("timestamp")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            raise ValueError("Evaluation timestamp must be UTC")
        return value

    @model_validator(mode="after")
    def require_consistent_receipt(self) -> Self:
        prefix = self.receipt_id[:4]
        if self.receipt_id != prefix + self.sha256:
            raise ValueError("Receipt identifier and digest do not match")
        codes = [finding.code for finding in self.findings]
        if codes != [code for code in RULE_ORDER[prefix] if code in codes]:
            raise ValueError("Findings must be unique and in rule order")
        if self.gate != ("HOLD" if self.findings else "PASS"):
            raise ValueError("Gate does not match findings")
        return self
