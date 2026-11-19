# ARKHEIA-CPS

A FastAPI backend for deterministic auto and housing risk evaluation, with
subscription billing via Stripe, plus the ClearCheck consumer frontend.

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

## ClearCheck frontend

The consumer-facing ClearCheck UI is a static site (no build step) in
`frontend/`, deployed to Netlify via `netlify.toml`. It drives the flow:

1. `POST /api/clearcheck/preview` — enter check details (with live, local
   masking previews mirroring `cps_backend/utils/redaction.py`), get the
   redacted preview: `check_id`, `findings_count`, `redacted_summary`,
   jurisdiction metadata, and the non-legal-advice notice.
2. Locked state — `POST /api/clearcheck/checkout` redirects to Stripe for
   the one-time unlock payment (`?clearcheck=success|cancelled` lands back
   on the page and auto-retries report retrieval).
3. `GET /api/clearcheck/report/{check_id}` — 402 while locked, full
   findings table once unlocked.

### API base resolution (`frontend/config.js`)

- `?api=<url>` query parameter (persisted to localStorage) — highest priority
- on `localhost` / `127.0.0.1` — `http://localhost:8000`
- anywhere else (the deployed Netlify site) — `https://arkheia-cps-10.onrender.com`

### Local testing

```bash
uvicorn cps_backend.main:app --reload            # API on :8000, CORS open by default
python -m http.server 5173 --directory frontend  # UI on http://localhost:5173
```

### Deployed configuration

On Render (see `02_render-1.yaml`), set:

- `CPS_ALLOWED_ORIGINS` — comma-separated list including the Netlify origin
  (e.g. `https://<your-site>.netlify.app`); the ClearCheck endpoints are
  called cross-origin from the browser.
- `CPS_FRONTEND_BASE_URL` — the Netlify site URL, so Stripe checkout
  success/cancel redirects land back on the ClearCheck page.

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
