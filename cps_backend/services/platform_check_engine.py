"""Pure fixed-order checks, independent of billing, stores and clock reads."""
from __future__ import annotations

import math

from cps_backend.schemas.platform_checks import (
    FINDING_REASONS, CustodyCheckRequest, EdgeCheckRequest, FindingCode,
    PlatformCheckRequest, PlatformFinding, ProvenanceCheckRequest,
    SettlementCheckRequest,
)
from cps_backend.services.clearcheck_engine import compute_check_id


def compute_receipt_id(request: PlatformCheckRequest, prefix: str) -> str:
    """Reuse the existing sorted-key, compact JSON SHA-256 implementation."""
    return prefix + compute_check_id(request).removeprefix("chk_")


def _nonnegative_integer(value: object) -> bool:
    # bool is a subclass of int: exact types are essential for fail-closed rules.
    return type(value) is int and value >= 0


def _nonnegative_number(value: object) -> bool:
    if type(value) is int:
        return value >= 0
    return type(value) is float and math.isfinite(value) and value >= 0


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _conserved_splits(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(_nonnegative_integer(split) and split <= 10000 for split in value)
        and sum(value) == 10000
    )


def run_checks(request: PlatformCheckRequest) -> list[PlatformFinding]:
    """Every rule evaluates independently; findings contain only static text."""
    codes: list[FindingCode] = []
    if isinstance(request, SettlementCheckRequest):
        if not _conserved_splits(request.splits_bps):
            codes.append("SPLIT_CONSERVATION_VIOLATION")
        if type(request.gross_amount_cents) is not int or request.gross_amount_cents <= 0:
            codes.append("INVALID_GROSS_AMOUNT")
    elif isinstance(request, ProvenanceCheckRequest):
        if not (
            _nonempty_string(request.isrc)
            and _nonempty_string(request.audio_fingerprint_sha256)
        ):
            codes.append("MISSING_PROVENANCE_HASH")
        if request.rights_cleared is not True:
            codes.append("UNVERIFIED_RIGHTS_CHAIN")
        if not _conserved_splits(request.splits_bps):
            codes.append("SPLIT_CONSERVATION_VIOLATION")
    elif isinstance(request, CustodyCheckRequest):
        if not (
            _nonnegative_integer(request.signatures_collected)
            and _nonnegative_integer(request.quorum_required)
            and request.signatures_collected >= request.quorum_required
        ):
            codes.append("INSUFFICIENT_QUORUM_SIGNATURES")
        if request.policy_window_active is not True:
            codes.append("EXPIRED_OR_INACTIVE_CUSTODY_POLICY")
        if not (
            _nonnegative_number(request.release_amount)
            and _nonnegative_number(request.custody_limit)
            and request.release_amount <= request.custody_limit
        ):
            codes.append("CUSTODY_LIMIT_EXCEEDED")
    elif isinstance(request, EdgeCheckRequest):
        if request.node_attestation_valid is not True:
            codes.append("UNATTESTED_EDGE_NODE")
        if request.telemetry_within_bounds is not True:
            codes.append("SENSOR_INVARIANT_BREACH")
        if not _nonempty_string(request.offline_queue_hash):
            codes.append("MISSING_LOCAL_AUDIT_HASH")
    else:
        raise TypeError("Unsupported platform check request")
    return [PlatformFinding(code=code, reason=FINDING_REASONS[code]) for code in codes]
