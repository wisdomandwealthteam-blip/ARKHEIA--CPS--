# Clearance v1.0.0 integration and live swarm handoff

> Historical v1.0.0 evidence. The lease/permit blocker recorded below is corrected
> by [7™ v1.0.1 hardening](HARDENING_v1.0.1.md); its current versioned contract and
> validation results supersede the v1.0.0 release status.

## Status

**Integration and specified mock-campaign checks pass against the supplied implementation. This is not a production execution-authority certification.** The lease/permit boundary issue below remains a release blocker for using permits as standalone authorization.

Repository: `wisdomandwealthteam-blip/ARKHEIA--CPS--`

Feature branch: `feat/arkheia-clearance-v1`

Base commit: `529e1b4834d25c86d345513a5cb12d4af78ea08d`

Validation date: 2026-11-28 (UTC)

The delivered attachment was `arkheia-clearance-v1.0.0.patch`, not the initially mentioned ZIP. It applied cleanly with `git apply`. Attachment SHA-256: `f75ccb153259ebacc3a1a9413b5bd1467d1cafd41ac9762dc995f4d169a57529`. Its README, engine, stdlib sidecar, FastAPI router and golden vectors were inspected. No original architecture/specification documents beyond the supplied package were provided.

The active deployed app is `cps_backend.main:app`. `backend/cps_backend/` does not exist in this checkout. The outer CORS wrapper, request IDs, validation/error sanitization, existing routers, ClearCheck payment gating, Stripe signature verification and DVE gateway guard are preserved. The new routes are additive:

| Method | Path | Success contract |
|---|---|---|
| POST | `/api/mandate/verify` | `decision=CLEARED`; signed receipt and execution permit |
| POST | `/api/aegis/evaluate` | `decision=STATE_UPDATED` or `RELEASED`; explicit swarm `state` |
| GET | `/api/clearance/head` | Atomic public key, chain head, length, Lamport clock and policy version |

Missing/invalid clearance configuration disables only these routes with an opaque 503. Raw POST bytes bypass Pydantic normalization. Clearance signing uses its own seed file and domain tags; the existing DVE verifier remains verify-only, but the combined CPS **process** now holds the dedicated clearance private key. Use the supplied sidecar for stricter process/key isolation; an HTTP proxy to it is not included.

## Verification results

| Run | Result |
|---|---|
| Unmodified root `pytest -q` | 16 collection errors: root import path and duplicate receipt-test module names |
| Unmodified suite with `PYTHONPATH=.` and importlib mode | 921 passed, 110 warnings |
| Supplied clearance suite, before new tests | 191 passed, 1 warning; the supplied attachment collects 191, not 189 |
| Integrated suite before live/hardening additions | 1112 passed, 110 warnings |
| Final clearance suite | 202 passed, 1 warning |
| Final full suite (`pytest -q`, with JUnit output) | **1123 passed, 110 warnings in 19.45s** |
| Final standalone live campaign | **PASS: 256 concurrent burst requests, 299 signed chained receipts** |

All receipt-toolkit copies are still collected. Root `pytest.ini` uses `pythonpath=.` and importlib mode to avoid module-name collisions; no suite is excluded and no live test is skipped. Ten hardening regressions and one live campaign test were added. `httpx` and `jsonschema` are declared dependencies so HTTP and schema tests do not silently disappear. Existing deprecation warnings are retained in the full logs.

The live script launches a real single-worker Uvicorn process running `cps_backend.main:app` on loopback, checks readiness, issues real HTTP requests, restarts the process to verify persistence, and stops it in cleanup. It creates random local Ed25519 keys and an audit key in mode-0600 files, an explicit public trust set, and an isolated JSONL ledger. Stripe credentials are blanked; no provider payment calls are made. Signed sensor windows are controlled mock inputs, not a claim of automatic network telemetry collection.

The attack verifies baseline CLEARED mandates/ALLOW observations and signed SHA-256 receipts; drift of 3 → 4300 → 8000 bps producing ALLOW → THROTTLE → QUARANTINE_X_STAR; absorption under clean observations and mandates and across process restart; invalid/self-signed/wrong-anchor/failed-invariant releases; authority-signed HUMAN_RELEASE; old-lease revocation and a fresh-lease return to ALLOW; authenticated Lamport regression, mandate replay, budget escalation, action-scope violation and expanding A2A delegation; invalid signature rejection without spoofed quarantine; trusted sensor-reported signature-failure quarantine; and concurrent opaque rejection traffic without lost/duplicated receipt commits.

Every attack POST is matched to its durable receipt by receipt hash and exact request SHA-256. The complete chain is independently signature-checked using `cryptography`, then checked for contiguous sequence numbers, previous-hash links, strictly increasing Lamport clocks, decision-core hashes and policy binding. Deliberate receipt tampering is detected. Persisted state is reconstructed from the verified chain.

Final live head: `ba324c9b651d076340a46dd83b84764d0b7e8a512613e3b77017927adc0b4ca2`. Minimum observed rejection round-trip latency: 26,855,263 ns, above the configured 25,000,000 ns floor. These measurements are not a throughput benchmark or proof of instruction-level constant time.

## Integration hardening beyond the attachment

Bootstrap is serialized and moved into the worker threadpool rather than blocking the FastAPI event loop. Invalid trust members, corrupt ledgers and filesystem initialization faults become the documented opaque 503. Public head reads are atomic with receipt commits. Uncertain write/fsync/close failures latch the ledger unavailable until a verified restart, preventing a subsequent permit from extending stale in-memory state. Zero-progress writes cannot hang. MCP header mismatch still rejects execution, but no longer suppresses cryptographic attribution of a separate authenticated hard violation.

The supplied `Policy` values and golden vector file were not regenerated. Golden-vector SHA-256 remains `a27e79d5b7efcc6d4d2650180939fa64eb4def4158c8589b58901d4fcc163c05`.

## Pull into the friendly carnival Codespace

Open the existing Codespace for this repository, then run from its repository root:

```bash
git fetch origin feat/arkheia-clearance-v1 && git switch feat/arkheia-clearance-v1 && git pull --ff-only
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python tests/clearance/test_mock_swarm_attack.py \
  --output-dir "/tmp/arkheia-swarm-$(date +%s)" --burst-size 256
```

Do not discard existing Codespace changes to force a switch. If Git reports local changes, preserve them first. The script needs a fresh output directory, creates and tests its own local running server, and shuts it down afterward. It is intentionally not a remote-target attack tool. The regular full suite automatically runs a 64-request version on a separate local server.

## Start a local demo server manually

After running the script above, use that run's **local test-only** files, substituting the actual output directory:

```bash
RUN=/tmp/arkheia-swarm-<timestamp>
export ARKHEIA_CLEARANCE_SIGNING_SEED_FILE="$RUN/secrets/engine.seed"
export ARKHEIA_CLEARANCE_AUDIT_KEY_FILE="$RUN/secrets/audit.key"
export ARKHEIA_CLEARANCE_TRUST_FILE="$RUN/trust-public.json"
export ARKHEIA_CLEARANCE_LEDGER="jsonl:$RUN/receipts.jsonl"
export ARKHEIA_CLEARANCE_FLOOR_MS=25
uvicorn cps_backend.main:app --host 0.0.0.0 --port 8000 --workers 1
```

The existing attack ledger reconstructs its quarantines on startup. A fresh demo can use a different JSONL path. No seed or audit-key values are committed or included in the downloadable evidence archive. Create independent production keys and trust roots through an appropriate secret-management process; never deploy mock or golden keys.

## Contract distinctions and unresolved release blockers

1. **Unauthenticated signature failures do not quarantine a claimed actor.** They return the same opaque 403/X* body as other failures. Only attributable authenticated hard violations, including a trusted sensor's signed `signature_failures` observation, quarantine that subject. A body containing `code=X*` is not by itself proof that the claimed actor entered X*. This intentionally differs from a literal reading of the requested “any invalid signature immediately quarantines” condition and prevents identity-spoofed denial of service.

2. **Constant-time is bounded, not absolute.** Golden tests verify a fixed signature-verification count per endpoint (6 mandate slots, 5 Aegis slots); live tests verify a fixed-length rejection body modulo its receipt hash and the 25 ms latency floor. Python scheduling, JSON normalization, storage, body transfer and network round trips cannot guarantee instruction-level constant time. Timing distributions may still reveal work beyond the floor.

3. **Lease/permit boundary remains unresolved in the supplied version.** `test_lease_window_boundaries` explicitly expects a mandate at the last valid request Lamport tick to clear. Receipt/permit issuance advances the engine clock, and `not_after_lamport` is currently issuance + `permit_ttl`, not capped to the verified effective lease/delegation expiry. `verify_permit` checks the signature only. Do not use this permit alone to authorize real effects: downstream enforcement must also validate current clock, authority, lease bounds, revocation and replay, or apply an explicitly approved versioned contract correction. This handoff preserves the supplied golden behavior rather than silently changing it.

4. **Single writer only.** A JSONL ledger supports one engine/writer and one Uvicorn worker. Multiple workers/instances sharing a file are unsupported. A trusted external head is needed to detect valid-prefix rollback; this implementation only detects corruption within the supplied chain. There is no cross-process ledger lock or external anchor service.

5. **THROTTLE is tick-based rate shedding, not step-up handle verification.** This was already listed as unimplemented in the supplied README. Existing ClearCheck/Stripe routes are not automatically clearance-gated; wiring adds the requested clearance endpoints, not an interception layer over every existing operation.

## Evidence

Full pytest logs, JUnit XML, baseline logs, installation/environment details, live console/server logs, the attack transcript, public trust/head, and all 299 final receipts are delivered in the evidence archive. A corrected mock-payload setup failure is retained in the debug log; it occurred before attack requests and was not an engine failure. Private seeds and audit keys are excluded. Read-only review notes are included with their pre-fix provenance; this handoff describes which findings were corrected and which remain.
