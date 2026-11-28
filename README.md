# ARKHEIA 7™ — Deterministic Agent Gate

**Version 1.0.1 · Brand 7™ · Publisher ARKHEIA GROUP**

Website: [ericscott.ai](https://ericscott.ai).

A deterministic pre-execution agent gate providing Mandate verification and
Aegis-Swarm evaluation, exposed through the existing CPS FastAPI backend.
The backend also retains deterministic auto and housing risk evaluation,
subscription billing via Stripe, and the ClearCheck consumer frontend.

This is a public product-branding update, not a package or API migration.
Internal imports remain `cps_backend` and `arkheia_clearance`; existing
routes, CORS configuration, error handling, and Stripe/ClearCheck flows remain
compatible.

## Public API metadata

`GET /openapi.json` advertises the exact title
`ARKHEIA 7™ — Deterministic Agent Gate` and product version `1.0.1`.
Its `info.x-commercial` extension identifies the product, brand, version,
publisher, website, and proprietary license. The OpenAPI contact uses
ARKHEIA GROUP and the website above; no contact email or legal-document URL
is declared. Interactive API documentation remains at `GET /docs`.

### Existing endpoints

- Clearance: `POST /api/mandate/verify`, `POST /api/aegis/evaluate`,
  `GET /api/clearance/head`.
- Health and risk: `GET /health`, `POST /risk/auto`, `POST /risk/housing`,
  `POST /risk/aggregate`.
- Billing: `POST /billing/create-checkout-session`,
  `POST /billing/create-portal-session`, `GET /billing/status`,
  `POST /billing/webhook` (intentionally omitted from the public schema).
- ClearCheck: `POST /api/clearcheck/preview`, `POST /api/clearcheck/checkout`,
  `GET /api/clearcheck/report/{check_id}`, `GET /api/clearcheck/trial/status`,
  `POST /api/clearcheck/trial/portal`.
- Governance: `POST /api/governance/check`,
  `GET /api/governance/checks/{receipt_id}`.
- Receipt gateway: `POST /v1/verify-receipt`, `GET /v1/public-keys`.
- Platform checks: `POST /api/settlement/check`, `POST /api/provenance/check`,
  `POST /api/custody/check`, `POST /api/edge/check`.

## License

Proprietary commercial software. Copyright (c) Eric A. Scott / ARKHEIA GROUP.
All rights reserved. The public metadata does not grant an open-source license.

## Structure

Backend code lives at the repository root in `cps_backend/`:

- `main.py` — FastAPI app assembly
- `config.py` — environment-driven settings
- `product_metadata.py` — public title, brand, version, publisher, website, and license
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
