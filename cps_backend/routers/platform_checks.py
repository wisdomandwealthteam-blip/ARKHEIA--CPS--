"""Four additive POST checks; no persistence, signing, billing or external I/O."""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response

from cps_backend.schemas.platform_checks import (
    CustodyCheckRequest, EdgeCheckRequest, PlatformCheckRequest,
    PlatformCheckResponse, ProvenanceCheckRequest, SettlementCheckRequest,
)
from cps_backend.services.platform_check_engine import compute_receipt_id, run_checks

router = APIRouter(prefix="/api", tags=["platform-checks"])


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _finite_float(value: str) -> float | None:
    number = float(value)
    return number if math.isfinite(number) else None


async def _check(
    request: Request, response: Response,
    request_type: type[PlatformCheckRequest], prefix: str,
) -> PlatformCheckResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        # Nonfinite values become missing evidence, retaining the appropriate
        # field finding without putting non-JSON constants into a digest.
        payload = json.loads(
            await request.body(), object_pairs_hook=_unique_object,
            parse_float=_finite_float, parse_constant=lambda _: None,
        )
    except (ValueError, UnicodeDecodeError, RecursionError):
        # Empty, invalid or ambiguous JSON cannot authorize any rule.
        payload = {}
    body = request_type.model_validate(payload)
    findings = run_checks(body)
    receipt_id = compute_receipt_id(body, prefix)
    return PlatformCheckResponse(
        receipt_id=receipt_id,
        gate="HOLD" if findings else "PASS",
        findings=findings,
        sha256=receipt_id.removeprefix(prefix),
        timestamp=datetime.now(timezone.utc),
    )


@router.post("/settlement/check", response_model=PlatformCheckResponse)
async def settlement_check(request: Request, response: Response) -> PlatformCheckResponse:
    return await _check(request, response, SettlementCheckRequest, "stl_")


@router.post("/provenance/check", response_model=PlatformCheckResponse)
async def provenance_check(request: Request, response: Response) -> PlatformCheckResponse:
    return await _check(request, response, ProvenanceCheckRequest, "prv_")


@router.post("/custody/check", response_model=PlatformCheckResponse)
async def custody_check(request: Request, response: Response) -> PlatformCheckResponse:
    return await _check(request, response, CustodyCheckRequest, "cst_")


@router.post("/edge/check", response_model=PlatformCheckResponse)
async def edge_check(request: Request, response: Response) -> PlatformCheckResponse:
    return await _check(request, response, EdgeCheckRequest, "edg_")
