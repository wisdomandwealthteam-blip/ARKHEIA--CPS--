"""
cps_backend.services.receipt_gateway
=======================================
ARKHEIA DVE receipt client for cps_backend — VERIFY-ONLY.

Two responsibilities:

1. Mapping. ``clearcheck_verdict_payload()`` converts the deterministic
   ClearCheck engine output (findings + check_id) into the DVE schema
   v1.0.0 ``verdict_payload`` contract, so an upstream signing engine
   can issue the receipt. All scores are integers in basis points
   (0-10000) — floats are rejected at canonicalization, so signatures
   never depend on float formatting.

2. Gateway guard. cps_backend holds NO private signing keys. It only
   loads the published keyring (``ARKHEIA_TRUSTED_KEYS_FILE``) and
   verifies receipts. ``guard()`` wraps every upstream pass-through:
   a body is forwarded only if it is a valid receipt signed by a
   trusted key; anything else returns HTTP 502 and nothing is
   forwarded. Enforcement is fail-closed — if a signing seed is present
   in this service's environment, or the trusted keyring is missing or
   invalid, verification refuses to run (502 on the guard path).
"""
from __future__ import annotations

import os
import re
from typing import Any, Iterable, Mapping

from arkheia_receipt import Keyring, build_verdict_payload
from arkheia_receipt.gateway import handle_request, verify_upstream
from arkheia_receipt.jcs import canonical_bytes

GatewayResponse = tuple[int, list[tuple[str, str]], bytes]

# Identifies the deterministic rules in services/clearcheck_engine.py.
# Bump the version whenever a rule is added, removed, or changed.
CLEARCHECK_RULE_SET = {"id": "cps.clearcheck", "version": "1.0.0"}

BPS_SCALE = 10000  # 100% expressed in integer basis points

# Per-finding risk weight in basis points. Unknown severities weigh as
# the maximum, so a new severity can never silently lower the score.
_SEVERITY_WEIGHT_BPS = {"high": BPS_SCALE, "medium": 5000, "low": 2000}

_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
_CHECK_ID_PREFIX = "chk_"


class ReceiptGatewayError(RuntimeError):
    """Raised when the verify-only receipt gateway cannot operate safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# 1. ClearCheck -> verdict_payload mapping (client side; signing happens
#    upstream, never in this service).
# ---------------------------------------------------------------------------

def _finding_field(finding: Any, name: str) -> Any:
    # Findings arrive either as schemas.clearcheck.Finding models or as
    # the plain dicts persisted by services/clearcheck_store.py.
    if isinstance(finding, Mapping):
        return finding.get(name)
    return getattr(finding, name)


def check_id_evidence_digest(check_id: str) -> str:
    """The SHA-256 inside a ``chk_<sha256>`` check id, anchoring the
    legacy ClearCheck artifact under the receipt signature."""
    digest = str(check_id)
    if digest.startswith(_CHECK_ID_PREFIX):
        digest = digest[len(_CHECK_ID_PREFIX):]
    if not _SHA256_HEX.match(digest):
        raise ReceiptGatewayError(
            "EVIDENCE_DIGEST_INVALID",
            "check_id does not carry a SHA-256 hex digest",
        )
    return digest


def clearcheck_verdict_payload(check_id: str, findings: Iterable[Any]) -> dict[str, Any]:
    """Map a ClearCheck result to the DVE v1.0.0 verdict_payload contract.

    - verdict: CLEARED (no findings), BLOCKED (any high-severity finding)
      or REQUIRES_REVIEW (medium/low findings only).
    - reason_codes: the unique finding codes (already UPPER_SNAKE).
    - metrics: integers only; every score is in basis points (0-10000).
    - evidence_digests: the check_id's SHA-256, so the stored check
      record is anchored under the upstream signature.
    """
    rows = [
        (str(_finding_field(f, "code")), str(_finding_field(f, "severity")).lower())
        for f in findings
    ]
    total = len(rows)
    by_severity = {"high": 0, "medium": 0, "low": 0}
    for _, severity in rows:
        if severity in by_severity:
            by_severity[severity] += 1

    if total == 0:
        verdict = "CLEARED"
    elif by_severity["high"] > 0:
        verdict = "BLOCKED"
    else:
        verdict = "REQUIRES_REVIEW"

    if total == 0:
        risk_score_bps = 0
    else:
        weight_sum = sum(
            _SEVERITY_WEIGHT_BPS.get(severity, BPS_SCALE) for _, severity in rows
        )
        risk_score_bps = min(BPS_SCALE, weight_sum // total)

    def share_bps(count: int) -> int:
        return count * BPS_SCALE // total if total else 0

    metrics = {
        "findings_total": total,
        "findings_high": by_severity["high"],
        "findings_medium": by_severity["medium"],
        "findings_low": by_severity["low"],
        "risk_score_bps": risk_score_bps,
        "clean_confidence_bps": BPS_SCALE - risk_score_bps,
        "high_severity_share_bps": share_bps(by_severity["high"]),
        "medium_severity_share_bps": share_bps(by_severity["medium"]),
        "low_severity_share_bps": share_bps(by_severity["low"]),
    }
    return build_verdict_payload(
        verdict=verdict,
        reason_codes={code for code, _ in rows},
        rule_set=CLEARCHECK_RULE_SET,
        evidence_digests=[check_id_evidence_digest(check_id)],
        metrics=metrics,
    )


# ---------------------------------------------------------------------------
# 2. Gateway guard — verification only, no private keys, fail closed.
# ---------------------------------------------------------------------------

def _signing_seed_present() -> bool:
    return bool(os.environ.get("ARKHEIA_SIGNING_SEED_HEX", "").strip())


def load_keyring() -> Keyring:
    """Load the trusted public keyring. Refuses to operate if a private
    signing seed is configured for this service: cps_backend must never
    hold engine signing keys (it would collapse the engine/gateway
    separation the receipts rely on)."""
    if _signing_seed_present():
        raise ReceiptGatewayError(
            "GATEWAY_HOLDS_SIGNING_KEY",
            "cps_backend is verify-only; remove ARKHEIA_SIGNING_SEED_HEX from its environment",
        )
    path = os.environ.get("ARKHEIA_TRUSTED_KEYS_FILE", "").strip()
    if not path:
        raise ReceiptGatewayError(
            "TRUSTED_KEYS_NOT_CONFIGURED",
            "ARKHEIA_TRUSTED_KEYS_FILE is not set",
        )
    try:
        return Keyring.from_file(path)
    except ReceiptGatewayError:
        raise
    except Exception as exc:
        raise ReceiptGatewayError(
            "TRUSTED_KEYS_INVALID",
            f"trusted keyring could not be loaded: {type(exc).__name__}",
        ) from exc


def _error_response(status: int, body: dict[str, Any]) -> GatewayResponse:
    data = canonical_bytes(body)
    return status, [
        ("content-type", "application/json; charset=utf-8"),
        ("content-length", str(len(data))),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
    ], data


def guard(upstream_body: bytes) -> GatewayResponse:
    """Wrap EVERY backend pass-through with this: returns (status,
    headers, body) — 200 with the verified receipt, or 502 with an
    error. An unsigned, forged, or unverifiable body is never
    forwarded; misconfiguration also fails closed as 502."""
    try:
        keyring = load_keyring()
    except ReceiptGatewayError as exc:
        return _error_response(
            502, {"error_code": "UPSTREAM_RECEIPT_INVALID", "reason": exc.code}
        )
    return verify_upstream(upstream_body, keyring)


def verify_http(
    *, method: str, path: str, content_type: str | None, body: bytes
) -> GatewayResponse:
    """Serve the public verifier routes (/v1/verify-receipt and
    /v1/public-keys) through the toolkit's framework-neutral handler.
    Raises ReceiptGatewayError if the gateway is not safely configured."""
    return handle_request(
        method=method,
        path=path,
        content_type=content_type,
        body=body,
        keyring=load_keyring(),
    )
