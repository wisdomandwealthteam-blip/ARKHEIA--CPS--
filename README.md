# ARKHEIA-CPS Backend

A FastAPI backend for deterministic auto and housing risk evaluation, with subscription billing via Stripe.

## Structure

Backend code lives at the repository root in `cps_backend/`:

- `main.py` — FastAPI app assembly
- `config.py` — environment-driven settings
- `routers/` — `/health`, `/risk/auto`, `/risk/housing`, `/risk/aggregate`, `/billing/*` endpoints
- `services/` — risk evaluation logic, auth, rate limiting, billing, tier logic
- `schemas/` — Pydantic request/response models
- `models/` — data models
- `utils/` — logging, redaction, and shared utilities

Tests live in `tests/` and run with `pytest`.

## Security notes

- Tenant identifiers are opaque SHA-256 digests of API keys — raw keys are
  never stored in tenant IDs, log lines, or Stripe metadata.
- When `CPS_REQUIRE_AUTH` is false (dev mode), unauthenticated requests
  fall back to the FREE (most restricted) tier — never a privileged one.
- Sensitive request fields (`vin`, `customer_email`, API keys) are masked
  before appearing in logs or validation-error responses
  (see `cps_backend/utils/redaction.py`).

## Setup

See `requirements.txt` for dependencies and `02_render-1.yaml` for the
Render deployment configuration (service start command:
`uvicorn cps_backend.main:app --host 0.0.0.0 --port $PORT`).
