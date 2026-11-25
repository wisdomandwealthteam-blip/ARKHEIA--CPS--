"""Fixed-order GovernanceCheck rules, with no I/O or clock reads.

ClearCheck provides a canonical SHA-256 content digest, not a receipt signer.
Reuse its existing implementation without adding signing keys or claiming an
authenticated signature. Hashing the validated model includes applied defaults;
evaluated_at is deliberately not part of that content-addressed identifier.
"""
from __future__ import annotations

from cps_backend.schemas.governance import (
    FINDING_REASONS,
    FindingCode,
    GovernanceCheckRequest,
    GovernanceFinding,
)
from cps_backend.services.clearcheck_engine import compute_check_id


def compute_receipt_id(request: GovernanceCheckRequest) -> str:
    """Use the same sorted-key, compact JSON digest as ClearCheck."""
    # compute_check_id only uses model_dump(mode="json"); no ClearCheck rules
    # or persistence are invoked. Preserve the full 64-character digest.
    return "gov_" + compute_check_id(request).removeprefix("chk_")


def run_checks(request: GovernanceCheckRequest) -> list[GovernanceFinding]:
    """Evaluate every rule in the published order; never include input text."""
    codes: list[FindingCode] = []
    if request.confidence_score < request.policy_thresholds.min_confidence:
        codes.append("LOW_MODEL_CONFIDENCE")
    if (
        request.transaction_amount > request.policy_thresholds.max_unsupervised_amount
        and not request.human_override_required
    ):
        codes.append("UNSUPERVISED_HIGH_VALUE_ACTION")
    if request.model_id.strip().casefold() in {"", "unknown"}:
        codes.append("MISSING_MODEL_PROVENANCE")
    return [GovernanceFinding(code=code, reason=FINDING_REASONS[code]) for code in codes]
