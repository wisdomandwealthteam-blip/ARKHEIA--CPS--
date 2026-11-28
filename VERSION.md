# ARKHEIA DVE™ — Version History

| Version | Milestone |
| ------- | --------- |
| v0.1 | Backend Deployed |
| v0.2 | ClearCheck™ Live Verification |
| v0.3 | Stripe Checkout & Report Unlock Gate |
| v0.4 | ARKHEIA DVE™ Positioning & Multi-Module Suite |
| Clearance v1.0.0 | Mandate/Aegis integration and live swarm handoff |
| Clearance v1.0.1 | 7™ branding, lease-capped signed permits and issuance-time expiry rejection |

## Deployment Notes

For ClearCheck payments on Render (`ARKHEIA--CPS---10`), configure:

- **Required:** `STRIPE_SECRET_KEY` is the Stripe API secret key, and
  `STRIPE_WEBHOOK_SECRET` is the signing secret for the specific webhook
  endpoint. Use matching test or live credentials for the environment;
  set them as secret environment variables and never commit their values.
- **Required for a deployed frontend:** `CPS_FRONTEND_BASE_URL` points to
  the frontend that receives the checkout return. Use an absolute HTTP(S)
  URL without a query string or fragment. Its local-development default is
  `http://localhost:5173`.
- **Optional:** `CPS_CLEARCHECK_PRICE_CENTS` sets the one-time USD price
  as a positive integer in cents; it defaults to `999`.
- **Optional locally; persistent storage required in production:**
  `CPS_CLEARCHECK_STORE_PATH` selects the ClearCheck JSON store, including
  unlock and processed-event records. Its default is
  `data/clearcheck_checks.json`; on Render, point it to the persistent disk.
  This file store is intended for a single backend instance.
- **Only required for subscription billing:** `STRIPE_PRICE_ID_PRO` and
  `STRIPE_PRICE_ID_ENTERPRISE` configure the corresponding subscription
  tiers; they are not required for the one-time ClearCheck checkout.
  `CPS_BILLING_STORE_PATH` selects the subscription store and should also
  be on persistent storage in production.

Configure Stripe to send webhook events to the backend's **`/billing/webhook`**
endpoint, and set `STRIPE_WEBHOOK_SECRET` to that endpoint's signing secret
(not the Stripe API key). Subscribe to both `checkout.session.completed` and
`checkout.session.async_payment_succeeded`: asynchronous payment methods may
complete checkout before payment succeeds. A verified webhook confirming
payment unlocks the report; a checkout return URL is not payment confirmation.
For subscription billing, also subscribe to `customer.subscription.created`,
`customer.subscription.updated`, `customer.subscription.deleted`, and
`invoice.payment_failed`.

Set `CPS_ALLOWED_ORIGINS` to the deployed frontend origin(s) for production
CORS. The default is permissive; the built-in production frontend origin is
always included.
