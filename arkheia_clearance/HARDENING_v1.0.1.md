# ARKHEIA 7™ — Deterministic Agent Gate v1.0.1

Validated on 2026-11-28 (UTC), on `feat/arkheia-clearance-v1`. This release resolves the permit/lease expiry blocker recorded in the historical v1.0.0 handoff. It does not merge `main`, deploy Render, or change `ericscott.ai` hosting.

## Bounded authority

The issuance tick is the actual next receipt Lamport clock: `max(engine.clock, request.lamport) + 1`. Every verified CUSTOS lease and A2A delegation must be live both at the request tick and at this issuance tick. A last-valid-request-tick that would issue an already expired permit is rejected with the existing opaque, signed-receipted 403. No permit or CLEARED receipt is emitted for that request.

The signed permit carries:

```text
lease_expires_at = min(root lease expiry, every delegation expiry, wire integer horizon)
expires_at = min(issued_lamport + permit_ttl, lease_expires_at)
not_after_lamport = expires_at
issued_lamport < expires_at <= lease_expires_at
```

`expires_at` and `lease_expires_at` are **exclusive Lamport ticks, not UTC timestamps**. Input leases retain the existing signed `lamport_issued` + `ttl` format. The existing `not_after_lamport` field is preserved as an equal alias, so internal module paths and caller field names are not renamed. Both added expiry fields are signed, not unsigned commercial metadata.

`verify_permit(permit, trusted_public_key, current_lamport=trusted_clock)` validates the signature, current version, signed bounds, expiry alias and live interval. The clock must be trusted, not supplied by the actor. The two-argument call remains usable for signed-bound verification, but cannot establish live expiry without a clock and is not standalone authorization. Consumers must still enforce operation/actor binding, revocation and replay before real effects.

## Version and upgrade behavior

Package version: `1.0.1`. Policy version: `arkheia.mandate-aegis/1.0.1`. The version-pinned golden transcript was intentionally regenerated for this authorized behavior change. Its SHA-256 is `eeb1216f691f4edbd104c8c1498294d346d26be02333252a66b8ddb0bb8a697c`.

The v1.0.0 vectors are archived unchanged as `tests/clearance/golden/clearance_vectors_v1.0.0.json` (SHA-256 `a27e79d5b7efcc6d4d2650180939fa64eb4def4158c8589b58901d4fcc163c05`). The old boundary assertion was updated to reject issuance at expiry while retaining its early, first, last-usable and expired-window checks. No existing test was removed or excluded.

Receipt schemas, domain tags, keys, persistence layout and state-replay effects are unchanged, so valid historical ledgers can be replayed with the same engine key. Quarantine must not be reset during upgrade. The v1.0.1 permit helper refuses legacy v1.0.0 permits without signed expiry bounds. Re-clear operations after upgrading; human releases must be freshly signed against the current policy version and exact quarantine receipt anchor.

## Public commercial identity

OpenAPI advertises title **ARKHEIA 7™ — Deterministic Agent Gate**, version `1.0.1`, and brand **7™**. `info.x-commercial` contains the product, brand, version, publisher (`ARKHEIA GROUP`), website (`https://ericscott.ai`) and proprietary license. Contact and license metadata use those same declared facts, without an invented email or legal URL. Internal `arkheia_clearance` and `cps_backend` imports remain unchanged.

All existing public operation/method pairs, hidden Stripe webhook behavior, CORS wrapper, request IDs, schema caching, validation/error handling, ClearCheck paid-report gating and Stripe handlers are preserved. This is API/product metadata branding, not a redesign of the existing consumer frontend.

## Verification

Full command: `pytest -q`.

**1181 passed, 110 warnings in 20.33s.** The retained 1123-test suite is supplemented by 27 permit-bound regression cases and 31 branding/route-compatibility cases. There are no failed, skipped or xfailed tests. Existing deprecation warnings are retained rather than hidden.

The new regressions cover capped and uncapped TTL, the last usable permit tick, expiry at/after issuance, stale request clocks, narrower A2A authority, expired delegation with a live root lease, trusted-clock permit expiry, re-signed invalid bounds, legacy-policy rejection, signed-field tampering, wire-integer horizon, raw-byte FastAPI behavior and public OpenAPI metadata.

The expanded real-Uvicorn mock campaign passes with **256 concurrent burst requests and 301 cryptographically verified chained receipts**. It now checks public 7™ metadata, a short-lease capped permit, and expired-at-issuance rejection over actual HTTP, alongside the existing drift/quarantine, absorbing state, restart, signed human release and full-chain attack checks.

Final live receipt head: `947f0f133622fffedf80b673c36fb1d6bf8e371a6339a47415ddcadd0348948d`.

Full logs and the live summary are committed under `docs/clearance-validation/v1.0.1/`. Downloadable evidence includes the full signed receipt chain and public trust/head metadata; private local test seeds and audit keys are excluded.

## Render deployment guardrails

Keep a dedicated production clearance seed, audit key and trust file, with the JSONL ledger on persistent storage. Run one engine/writer and one Uvicorn worker per ledger. Restart after upgrading so the current policy loads and the verified chain reconstructs the previous state. Configure `CPS_ALLOWED_ORIGINS` explicitly for the deployed frontend, including `https://ericscott.ai` if it calls this API; no origin policy was changed by this branding commit.

The previous limits still apply: Python timing is padded-work/latency-floor hardening, not instruction-level constant time; unauthenticated bad signatures cannot quarantine claimed identities; automatic step-up handle verification and external rollback anchors are not implemented. Passing this suite is not a blanket production security certification.
