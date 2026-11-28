"""# telemetry test: creating a PR event for Scott's Law pipeline# telemetry test 2: closing without merge# telemetry test 3: absorbing state B (closed without merge)
cps_backend.main
===================
Application entry point. Run locally with:
    uvicorn cps_backend.main:app --reload

Or in production (see render.yaml):
    uvicorn cps_backend.main:app --host 0.0.0.0 --port $PORT
"""
from __future__ import annotations

import uuid
from typing import get_args

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.datastructures import MutableHeaders

from cps_backend.config import settings
from cps_backend.product_metadata import (
    PRODUCT_LICENSE,
    PRODUCT_PUBLISHER,
    PRODUCT_VERSION,
    PRODUCT_WEBSITE,
    commercial_metadata,
)
from cps_backend.routers import billing, clearcheck, governance, health, receipts, risk
from cps_backend.routers import clearance, platform_checks
from cps_backend.schemas.common import ErrorResponse
from cps_backend.utils.logging_setup import logger
from cps_backend.utils.redaction import safe_validation_errors

fastapi_app = FastAPI(
    title=settings.app_name,
    description=(
        "ARKHEIA 7™ is a deterministic pre-execution agent gate with Mandate "
        "verification and Aegis-Swarm evaluation. Also preserves the existing "
        "deterministic risk evaluation API for Auto and Housing contracts. "
        "Engine: ARKHEIA DVE™ | Architecture: PLATFORM-ARCHITECTURE-2026-V1 | "
        "Active modules: dve-clearcheck, dve-riskcheck."
    ),
    version=PRODUCT_VERSION,
    contact={"name": PRODUCT_PUBLISHER, "url": PRODUCT_WEBSITE},
    license_info={"name": PRODUCT_LICENSE},
)

# Production Frontend <-> Backend Integration
#
# Verified Production Flow:
# Frontend: https://fairnes.netlify.app
# Backend:  https://arkheia-cps-10.onrender.com
#
# CORS origins are normalized at startup to prevent issues caused by:
# - trailing whitespace
# - leading whitespace
# - newline characters
# - duplicate origin entries
#
# Required production origin:
# https://fairnes.netlify.app
#
# Verified flow:
# Step 1: Client-side PII masking/redaction
# Step 2: POST /api/clearcheck/preview
# Step 3: Full report access gated through
#         POST /api/clearcheck/checkout
#
# Health endpoint:
# GET /health
#
# Smoke-test verified:
# fairnes.netlify.app <-> arkheia-cps-10.onrender.com
fastapi_app.include_router(health.router)
fastapi_app.include_router(risk.router)
fastapi_app.include_router(billing.router)
fastapi_app.include_router(clearcheck.router)
fastapi_app.include_router(governance.router)
# ARKHEIA DVE verify-only receipt gateway (additive): /v1/verify-receipt,
# /v1/public-keys. The DVE gateway holds no DVE private signing key;
# clearance below uses a separate, domain-separated signing key.
fastapi_app.include_router(receipts.router)
fastapi_app.include_router(platform_checks.router)
# ARKHEIA Mandate / Aegis-Swarm pre-execution verification (additive):
# /api/mandate/verify, /api/aegis/evaluate, /api/clearance/head. 503 unless configured.
fastapi_app.include_router(clearance.router)

# Extend FastAPI's normal, cached schema rather than rebuilding route metadata.
# This retains schema visibility, security definitions, and operation IDs.
_default_openapi = fastapi_app.openapi


def product_openapi() -> dict:
    schema = _default_openapi()
    schema["info"]["x-commercial"] = commercial_metadata()
    return schema


fastapi_app.openapi = product_openapi


@fastapi_app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    try:
        response = await call_next(request)
    except Exception as exc:
        # Catch before Starlette's outer ServerErrorMiddleware: it otherwise
        # sends a 500 and re-raises, causing the ASGI server to log a raw
        # traceback and potentially sensitive exception message.
        response = await unhandled_exception_handler(request, exc)
    response.headers["X-Request-ID"] = request_id
    return response


def _validation_location_names(request: Request) -> set[str]:
    """Return schema-declared names; arbitrary input keys are never trusted."""
    names = {"body", "query", "path", "header", "cookie"}
    seen_types: set[object] = set()

    def add_type(annotation: object) -> None:
        # Annotations can contain unhashable metadata, such as FieldInfo.
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            if annotation in seen_types:
                return
            seen_types.add(annotation)
            names.add(annotation.__name__)
            for name, field in annotation.model_fields.items():
                names.add(name)
                if isinstance(field.alias, str):
                    names.add(field.alias)
                if isinstance(field.validation_alias, str):
                    names.add(field.validation_alias)
                add_type(field.annotation)
        for argument in get_args(annotation):
            add_type(argument)

    def add_dependant(dependant: object) -> None:
        for kind in ("body_params", "query_params", "path_params", "header_params", "cookie_params"):
            for field in getattr(dependant, kind, ()):
                names.add(field.name)
                if isinstance(field.alias, str):
                    names.add(field.alias)
                add_type(field.field_info.annotation)
        for dependency in getattr(dependant, "dependencies", ()):
            add_dependant(dependency)

    route = request.scope.get("route")
    add_dependant(getattr(route, "dependant", None))
    return names


@fastapi_app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", None)
    # Inputs, context, messages and arbitrary location keys can all carry
    # submitted values. Build a schema-based allowlisted representation.
    errors = safe_validation_errors(exc.errors(), _validation_location_names(request))
    logger.warning("validation error request_id=%s detail=%s", request_id, errors)
    is_checkout = (
        request.method == "POST" and request.url.path == "/api/clearcheck/checkout"
    )
    return JSONResponse(
        status_code=(status.HTTP_400_BAD_REQUEST if is_checkout else status.HTTP_422_UNPROCESSABLE_ENTITY),
        content=ErrorResponse(
            error="invalid_checkout_request" if is_checkout else "validation_error",
            detail=str(errors),
            request_id=request_id,
        ).model_dump(),
    )


@fastapi_app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    # Exception text and traceback may contain provider responses or PII.
    logger.error("unhandled exception request_id=%s exception_class=%s", request_id, type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="internal_error",
            detail="An unexpected error occurred.",
            request_id=request_id,
        ).model_dump(),
        headers={"X-Request-ID": request_id},
    )


class _CORSApplication(CORSMiddleware):
    """Outermost ASGI CORS wrapper with access to FastAPI's usual API."""

    def __getattr__(self, name: str):
        return getattr(self.app, name)

    async def send(self, message, send, request_headers):
        async def send_explicit_origin(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                # Browsers reject '*' for credentials='include', even if
                # the request did not happen to include a Cookie header.
                if (headers.get("access-control-allow-origin") == "*"
                        and headers.get("access-control-allow-credentials") == "true"):
                    headers["Access-Control-Allow-Origin"] = request_headers["origin"]
                    headers.add_vary_header("Origin")
            await send(message)

        await super().send(message, send_explicit_origin, request_headers)

    @property
    def dependency_overrides(self):
        return self.app.dependency_overrides

    @dependency_overrides.setter
    def dependency_overrides(self, value):
        self.app.dependency_overrides = value


# CORS must be outside the whole FastAPI/Starlette stack, including the
# server-error handler. Uvicorn and TestClient continue to use `app`.
app = _CORSApplication(
    fastapi_app,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)
