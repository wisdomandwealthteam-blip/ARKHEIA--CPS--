"""Additive raw-byte clearance endpoints with a dedicated signing key.

DVE receipt verification and ClearCheck/Stripe remain independent. Invalid or
missing configuration (including a corrupt ledger) disables only clearance
with a fixed opaque 503. One process/writer per JSONL ledger is required.
"""
from __future__ import annotations

import threading

from fastapi import APIRouter, Request, Response
from starlette.concurrency import run_in_threadpool

from arkheia_clearance.service import ClearanceService, ConfigError, engine_from_env, floor_ns_from_env
from cps_backend.utils.logging_setup import logger

router = APIRouter(tags=["clearance"])
_service: ClearanceService | None = None
_service_lock = threading.Lock()


def get_service() -> ClearanceService:
    global _service
    with _service_lock:
        if _service is None:
            try:
                _service = ClearanceService(engine_from_env(), floor_ns_from_env())
            except ConfigError as exc:
                logger.error("clearance engine disabled: %s", type(exc).__name__)
                _service = ClearanceService(None, 0)
        return _service


def set_service(service: ClearanceService | None) -> None:
    """Test / embedding hook; configuration changes otherwise require restart."""
    global _service
    with _service_lock:
        _service = service


def _service_dispatch(method: str, path: str, body: bytes, headers: dict[str, str]):
    return get_service().dispatch(method, path, body, headers)


async def _dispatch(request: Request, method: str) -> Response:
    # Do not let Pydantic coerce signed bytes (floats, duplicate keys, bools).
    body = await request.body() if method == "POST" else b""
    headers = {k.lower(): v for k, v in request.headers.items()}
    status, out_headers, payload = await run_in_threadpool(
        _service_dispatch, method, request.url.path, body, headers)
    return Response(content=payload, status_code=status,
                    headers={k: v for k, v in out_headers if k.lower() != "content-type"},
                    media_type="application/json")


@router.post("/api/mandate/verify")
async def mandate_verify(request: Request) -> Response:
    return await _dispatch(request, "POST")


@router.post("/api/aegis/evaluate")
async def aegis_evaluate(request: Request) -> Response:
    return await _dispatch(request, "POST")


@router.get("/api/clearance/head")
async def clearance_head(request: Request) -> Response:
    return await _dispatch(request, "GET")
