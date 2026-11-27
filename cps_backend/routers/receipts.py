"""
cps_backend.routers.receipts
===============================
ARKHEIA DVE receipt verification endpoints (additive — no existing
route is replaced). cps_backend acts as a verify-only gateway here:

  POST /v1/verify-receipt — verify a DVE v1.0.0 receipt against the
      published keyring of trusted engine public keys.
  GET  /v1/public-keys    — the published keyring itself.

This service holds no private signing keys. If a signing seed is ever
configured, or the trusted keyring is absent, these routes fail closed
with 503 and the pass-through guard (services/receipt_gateway.guard)
fails closed with 502.
"""
from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from cps_backend.services.receipt_gateway import ReceiptGatewayError, verify_http
from cps_backend.utils.logging_setup import logger

router = APIRouter(tags=["receipts"])


async def _dispatch(request: Request) -> Response:
    try:
        status, headers, body = verify_http(
            method=request.method,
            path=request.url.path,
            content_type=request.headers.get("content-type"),
            body=await request.body(),
        )
    except ReceiptGatewayError as exc:
        logger.warning("receipt gateway unavailable error_code=%s", exc.code)
        return JSONResponse(
            status_code=503,
            content={"error_code": exc.code},
            headers={"Cache-Control": "no-store"},
        )
    return Response(content=body, status_code=status, headers=dict(headers))


@router.post("/v1/verify-receipt")
async def verify_receipt_endpoint(request: Request) -> Response:
    return await _dispatch(request)


@router.get("/v1/public-keys")
async def public_keys_endpoint(request: Request) -> Response:
    return await _dispatch(request)
