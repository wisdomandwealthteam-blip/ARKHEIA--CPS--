"""# telemetry test: creating a PR event for Scott's Law pipeline
cps_backend.main
===================
Application entry point. Run locally with:
    uvicorn cps_backend.main:app --reload

Or in production (see render.yaml):
    uvicorn cps_backend.main:app --host 0.0.0.0 --port $PORT
"""
from __future__ import annotations

import uuid

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from cps_backend.config import settings
from cps_backend.routers import billing, health, risk
from cps_backend.schemas.common import ErrorResponse
from cps_backend.utils.logging_setup import logger

app = FastAPI(
    title=settings.app_name,
    description="Deterministic risk evaluation API for Auto and Housing contracts.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(risk.router)
app.include_router(billing.router)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", None)
    logger.warning("validation error request_id=%s detail=%s", request_id, exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            error="validation_error",
            detail=str(exc.errors()),
            request_id=request_id,
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None)
    logger.error("unhandled exception request_id=%s error=%s", request_id, str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="internal_error",
            detail="An unexpected error occurred.",
            request_id=request_id,
        ).model_dump(),
    )
