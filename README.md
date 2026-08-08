# ARKHEIA-CPS Backend

A FastAPI backend for deterministic auto and housing risk evaluation, with subscription billing via Stripe.

## Structure

Real backend code lives at `backend/cps_backend/`:

- `main.py` — FastAPI app assembly
- `config.py` — environment-driven settings
- `routers/` — `/health`, `/risk/auto`, `/risk/housing`, `/billing/*` endpoints
- `services/` — risk evaluation logic, auth, rate limiting, billing, tier logic
- `schemas/` — Pydantic request/response models
- `models/` — data models
- `utils/` — logging and shared utilities

## Setup

See `requirements.txt` for dependencies and `render.yaml` for deployment configuration.
