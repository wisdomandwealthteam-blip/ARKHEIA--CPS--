# ARKHEIA Mandate™ + Aegis-Swarm™ — Clearance Engine v1.0.0

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Deterministic pre-execution verification for agent tool calls
(`POST /api/mandate/verify`) and the four-state swarm defense machine
(`POST /api/aegis/evaluate`). Implements *ARKHEIA_Mandate_Standalone_Product_Architecture_v1.0*
and *ARKHEIA_Aegis_Swarm_Defense_Specification_v1.0*.

The core here is framework-free (stdlib + `cryptography` + the vendored DVE `arkheia_receipt`
JCS/strict-JSON). `cps_backend/routers/clearance.py` and `server.py` are thin wrappers around it.

## Laws → code

| Spec | Enforcement | Module |
|---|---|---|
| Law I: canonical form, no floats (AX-1/2/4) | strict JSON (dup keys, floats, NaN, BOM rejected), closed schemas, MCP header/body match | `wire.py`, `schemas.py` |
| Law II: bounded ephemeral authority (CUSTOS, τ_G) | issuer-signed lease, `issued ≤ t < issued+Δt`, Δt bounded, Lamport skew bound, per-actor strict monotonic lamport, mandate-id replay set | `engine._eval_mandate` |
| Non-expansive A2A | every hop: `scope ⊆ parent`, `max_amount ≤ parent`, `[issued, expiry] ⊆ parent`; the signer of the expanding hop is quarantined | `engine._eval_mandate` |
| Law III / Aegis drift | integer `d_OP` in bps; Θ2 → THROTTLE, Θ3 → X*; N clean steps under integer Scott's-Law descent `d(t+1) ≤ d(t)` | `aegis.py` |
| Law IV: SPL-1 / CON-1 | `Σbps == 10000`; Hamilton largest remainder (rem DESC, id ASC); `Σamount == pool` checked before return; u128 without overflow | `conservation.py` |
| Law V: absorbing X* | `step()` is the identity on X*; the only exit is `release()` after a quorum-signed Release bound to the exact quarantine receipt hash, policy version and a passed invariant check; pre-quarantine leases are revoked | `aegis.py`, `engine._eval_release` |
| AX-6: receipt before effect | receipt signed, fsync'd, committed, *then* the response/permit is released; ledger fault → fixed 503 | `engine._commit`, `receipts.py` |
| Opaque constant-time rejection | one 403 body for every reason on both endpoints; Ed25519 work padded to a fixed count; integer-ns latency floor; reason stored only as an HMAC digest | `engine`, `timing.py` |

## State machine

```
            d ≥ Θ2                     hard ∨ d ≥ Θ3
  ALLOW ───────────▶ THROTTLE ─────────────────────────▶ QUARANTINE_X_STAR ◀─┐
    ▲   ◀────────────    │                                   │   (absorbing)    │
    │  N clean descending│                                   │ signed Release   │ hard ∨ d ≥ Θ3
    │  steps (d < Θ2)    │                                   ▼                  │
    └──────────── fresh-lease CLEAR / clean obs ──────── HUMAN_RELEASE ─────────┘
```

Hard triggers (when attributable to an authenticated principal): mandate replay, Lamport
regression, scope/budget/TTL escalation, action outside effective scope, conservation breach,
expired lease (spec default; `Policy.expired_lease_is_hard`), override attempt (a validly
signed Release from a non-authority, e.g. the agent itself or a swarm sibling), and hard
observation flags. **Unauthenticated garbage never quarantines anyone**, since the identity it
claims is unproven and doing so would let a swarm DoS legitimate agents.

## Receipt — `ARKHEIA/clearance/receipt/v1`

`seq, prev_hash, lamport, policy_version, endpoint, request_hash, decision, decision_core,
decision_core_hash, signature`. Signed bytes = `"ARKHEIA/clearance/receipt/v1" ‖ 0x00 ‖ JCS(receipt − signature)`;
`receipt_hash = SHA-256(JCS(receipt))`. Key id, JCS profile and hash convention match the DVE
toolkit; the distinct domain tag stops cross-protocol replay. Engine state is a fold over the
verified chain, so **a restart reproduces state exactly and X* survives reboots**. A corrupted
ledger refuses to load.

Wire integers are u64 ∩ [0, 2^53−1]; u128 amounts travel as canonical decimal strings.

## Run

```bash
export PYTHONPATH=.:vendor/arkheia-receipts/python
pytest tests/clearance -q                                     # golden suite
python -m arkheia_clearance.golden > tests/clearance/golden/clearance_vectors.json   # only on intentional policy change

# sidecar (own key; lets cps_backend stay verify-only)
ARKHEIA_CLEARANCE_SIGNING_SEED_FILE=secrets/clearance.seed \
ARKHEIA_CLEARANCE_AUDIT_KEY_FILE=secrets/clearance.audit \
ARKHEIA_CLEARANCE_TRUST_FILE=secrets/clearance-trust.json \
ARKHEIA_CLEARANCE_LEDGER=jsonl:var/arkheia-ledger/clearance.jsonl \
python -m arkheia_clearance.server --port 8090
```

`GET /api/clearance/head` returns the engine key, chain head and Lamport clock. CUSTOS issuers
need the clock to mint post-release leases (`lamport_issued` must exceed the quarantine lamport).

## Known limits

* Python can't guarantee instruction-level constant time. Signature work is padded and a
  latency floor is applied; the `#![no_std]` Rust port should keep the same structure.
* THROTTLE "step-up handle verification" from the spec table is not implemented. THROTTLE
  enforces deterministic rate shedding (one CLEARED mandate per `throttle_interval` ticks).
