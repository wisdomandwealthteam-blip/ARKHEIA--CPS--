# ARKHEIA DVE™ — Version History

| Version | Milestone |
| ------- | --------- |
| v0.1 | Backend Deployed |
| v0.2 | ClearCheck™ Live Verification |
| v0.3 | Stripe Checkout & Report Unlock Gate |
| v0.4 | ARKHEIA DVE™ Positioning & Multi-Module Suite |

## Deployment Notes

Stripe integration on Render (`ARKHEIA--CPS---10`) requires the following environment variables:

- `STRIPE_SECRET_KEY=sk_test_...` — Stripe API secret key (test mode prefix shown; use `sk_live_...` in production).
- `STRIPE_WEBHOOK_SECRET=whsec_...` — signing secret for the Stripe webhook endpoint.

Webhook endpoint: `/api/stripe/webhook`, subscribed to the `checkout.session.completed` event.
