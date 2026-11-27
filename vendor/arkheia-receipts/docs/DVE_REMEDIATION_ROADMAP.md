# ARKHEIA DVE Alignment & Remediation Roadmap — Receipt Schema v1.0.0

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
Source: Manus 2.0 audit (pinned commits below). Toolkit: `arkheia-receipts/` (this bundle).

> **Scope note.** The audit gives repo-level findings, not file contents. Patches below are
> complete, drop-in modules plus the exact call-site change for each repo. The one piece that
> can't be written blind is each engine's **result → `verdict_payload` mapping**, because it
> depends on that engine's output fields. Its contract is fixed (see §4) and the signer rejects
> any mapping that doesn't fit it.

---

## 1. Corrected language map (audit overrides the original brief)

| Repo | Brief said | Audit says | Toolkit used | Role |
|---|---|---|---|---|
| `ARKHEIA--CPS--bckend-1` | Node/TS | **Python** | `python/` | engine service → signs |
| `ARKHEIA--CPS--` | — | **Python** | `python/` | platform service → signs |
| `ARKHEIA-CPS-GATEWAY-` | Node/TS | **Python** | `python/` `gateway.py` | **verifies only, holds no private key** |
| `CUSTOS` | Rust | **Python** (+npm) | `python/` | proprietary engine → signs |
| `supreme_kernel` | Rust | **Python** | `python/` | proprietary engine → signs |
| `MusicGuard` | Node/TS | JavaScript | `node/` | wrapper-facing engine → signs |
| `SECURUS` | Node/TS | TypeScript | `node/` + `index.d.ts` | proprietary engine → signs |
| `Single-loop-harness-` | — | **Rust** | `rust/arkheia-receipt` | CreatorGuard sealing → signs |
| `Arkheia---cps---frontend-` | — | JavaScript (browser) | none (calls gateway) | display only |
| `bps-ledger` | — | **not accessible** | `ReceiptLedger` stub ×3 langs | persistence |

All three toolkits produce **byte-identical** receipts for identical inputs (proven by
`test-vectors/vectors.json`: same canonical bytes, same SHA-256, same Ed25519 signature).

## 2. Gap matrix (audit → required control)

Legend: ✅ present · ⚠️ partial / non-conforming · ❌ absent

| Repo @ commit | V1 envelope | JCS canon. | Schema gate before sign | Ed25519 | Hash chain | Ledger | Fail-closed egress |
|---|---|---|---|---|---|---|---|
| bckend-1 @ `eb4c978` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CPS-- @ `b214f2f` | ⚠️ `PLATFORM-ARCHITECTURE-2026-V1` (not DVE v1.0.0) | ❌ | ⚠️ unverified | ❌ | ❌ | ❌ | ❌ |
| GATEWAY- @ `c40f495` | ❌ (forwards raw JSON) | n/a | ❌ | ❌ verify | n/a | n/a | ❌ forwards unsigned |
| CUSTOS @ `0600a66` | ❌ | ❌ | ❌ | ⚠️ policy verify only | ❌ | ❌ | ❌ |
| supreme_kernel @ `e16c0da` | ❌ | ❌ | ❌ | ⚠️ verify only; signing delegated to SECURUS | ❌ | ❌ | ❌ |
| MusicGuard @ `1392b2c` | ❌ (v3.1.0 own schemas) | ❌ | ⚠️ own schemas | ❌ | ❌ | ❌ | ❌ |
| SECURUS @ `60098e7` | ❌ | ❌ | ❌ | ✅ signs ledger receipts | ⚠️ ledger-internal | ⚠️ own | ❌ |
| Single-loop-harness- @ `2b11d74` | ❌ (`creatorguard.manifest.v1`) | ❌ | ❌ | ✅ signs seals | ❌ | ❌ | ❌ |
| frontend @ `98369aa` | n/a | n/a | n/a | ❌ (SHA-256 only) | n/a | n/a | n/a |

**Two architectural findings beyond the per-repo gaps:**

1. **Engine coupling (violates invariant 1).** `supreme_kernel` hands its signing to SECURUS.
   That makes one proprietary engine depend at runtime on another, across languages (Python → TS).
   **Fix:** each engine signs its own receipts with its own key through the shared toolkit.
   SECURUS keeps its internal ledger signing; it just stops being supreme_kernel's signer.
2. **Gateway forwards unverified JSON.** That is the one place where an unsigned or forged verdict
   could reach a buyer. **Fix:** `verify_upstream()` — the gateway forwards a backend body only
   if it is a valid receipt from a trusted key; anything else returns **502** and nothing is forwarded.

## 3. Key & identity plan

| Repo | `ARKHEIA_ENGINE_ID` (proposed) | `wrapper_domain`(s) | Own key |
|---|---|---|---|
| bckend-1 | `cps_statute_engine` | `clearcheck` | yes |
| CPS-- | `cps_platform` | `clearcheck`, `settlementcheck` | yes |
| CUSTOS | `custos` | `governancecheck`, `riskcheck` | yes |
| supreme_kernel | `supreme_kernel` | `governancecheck`, `provenancecheck` | yes |
| SECURUS | `securus` | `governancecheck`, `riskcheck` | yes (new receipt key, separate from its ledger key) |
| MusicGuard | `musicguard_forensics` | `musicguard` | yes |
| Single-loop-harness- | `single_loop_harness` | `provenancecheck` ⚑ | yes |
| GATEWAY- | — (never signs) | — | **no private key**; holds `arkheia-public-keys.json` |

⚑ **Decision needed:** CreatorGuard has no wrapper domain in v1.0.0. I mapped seals to
`provenancecheck` (VERIFIED / UNVERIFIED / TAMPERED). If CreatorGuard should be its own buyer-facing
wrapper, add `creatorguard` to `$defs.wrapper_domain` with its verdict enum and cut schema **1.1.0**.
That's a schema change, so all three toolkits and the vectors must be regenerated together.

Keys: run `python -m arkheia_receipt.keygen --out-dir ./secrets` once per engine. Put the seed
in a Codespaces/Actions secret (`ARKHEIA_SIGNING_SEED_HEX`), and merge each engine's public
entry into the gateway's `arkheia-public-keys.json`. To rotate: add the new key as `active` and
flip the old one to `revoked` only once its receipts no longer need to verify, because revoked
keys fail verification.

## 4. The verdict_payload contract (what each mapping must produce)

```json
{
  "verdict": "<domain enum>",
  "reason_codes": ["UPPER_SNAKE", "..."],
  "rule_set": { "id": "lower.dotted", "version": "MAJOR.MINOR.PATCH" },
  "evidence_digests": ["<sha256 hex>", "..."],
  "metrics": { "lower_snake": 123 },
  "determinism": { "mode": "deterministic", "fallback_used": false }
}
```

- Use the `build_verdict_payload` / `buildVerdictPayload` builders. They sort the arrays and set `determinism`.
- **Integers only.** Express scores in basis points (`confidence_bps: 8125`, not `0.8125`).
  Floats are rejected at canonicalization in all three languages, so signatures never depend
  on float formatting.
- Put existing SHA-256 artifacts (MusicGuard reconciliation receipts, SECURUS ledger receipt
  hashes, CreatorGuard manifest digests, CPS-- legacy receipts) into `evidence_digests`.
  Nothing is thrown away; it gets anchored under the signature.
- `input_digest`: use `digest_bytes(raw_request_body)` at HTTP boundaries (it hashes exactly
  what was received). Use `digest_json(obj)` only for integer-only in-process inputs.

## 5. File-by-file patches

Every repo starts with the same step:

```bash
bash /path/to/arkheia-receipts/install_into_repo.sh <python|node|rust> . <engine_id>
cp .env.arkheia.example .env.arkheia-signing   # fill in the values; this file is git-ignored
```

That creates `vendor/arkheia-receipts/`, wires the dependency (`requirements.txt` /
`package.json` / `Cargo.toml`), and git-ignores secrets and the local ledger.

### 5.1 `ARKHEIA--CPS--bckend-1` (Python) — new file `cps_receipts.py`

```python
"""Signed egress for the CPS statute engine. Copyright (c) Eric A. Scott / ARKHEIA GROUP."""
from arkheia_receipt import build_verdict_payload, digest_bytes, signer_from_env
from arkheia_receipt.respond import signed_response

SIGNER = signer_from_env(env_file=".env.arkheia-signing")  # raises at import if misconfigured

def respond(raw_body: bytes, verdict: str, reason_codes: list[str], rule_version: str,
            evidence: list[str] = (), metrics: dict[str, int] | None = None):
    payload = build_verdict_payload(verdict=verdict, reason_codes=reason_codes,
                                    rule_set={"id": "cps.statutes", "version": rule_version},
                                    evidence_digests=evidence, metrics=metrics)
    return signed_response(SIGNER, wrapper_domain="clearcheck",
                           input_digest=digest_bytes(raw_body), verdict_payload=payload)
```

**Call site:** every place that returns a statute evaluation result (only `statutes.py` exists
today) returns `cps_receipts.respond(...)` instead of the raw dict. FastAPI:
`status, headers, body = respond(...); return Response(body, status, dict(headers))`.
**Tests:** add `pytest` to CI (`pip install -r requirements.txt && pytest vendor/arkheia-receipts/python`).
The audit found no tests at all.

### 5.2 `ARKHEIA--CPS--` (Python)

Same module as 5.1 with `ARKHEIA_ENGINE_ID=cps_platform`. Migration of the existing
`PLATFORM-ARCHITECTURE-2026-V1` responses:
- `rule_set = {"id": "platform.architecture", "version": "2026.1.0"}`
- the existing SHA-256 receipt → `evidence_digests=[legacy_sha256]`
- declare `pytest` in `requirements.txt` (the audit found it documented but undeclared; the installer adds it).

### 5.3 `ARKHEIA-CPS-GATEWAY-` (Python) — new file `gateway_receipts.py`

```python
"""Public verifier + upstream guard. The gateway holds NO private key.
Copyright (c) Eric A. Scott / ARKHEIA GROUP."""
from arkheia_receipt.gateway import (handle_request, load_keyring_from_env,
                                     make_asgi_app, make_wsgi_app, verify_upstream)

KEYRING = load_keyring_from_env()          # ARKHEIA_TRUSTED_KEYS_FILE; raises if unset
asgi_app = make_asgi_app(KEYRING)          # uvicorn gateway_receipts:asgi_app
wsgi_app = make_wsgi_app(KEYRING)          # gunicorn gateway_receipts:wsgi_app

def guard(upstream_body: bytes):
    """Wrap EVERY backend pass-through: returns (200, receipt) or (502, error). Never forwards unsigned."""
    return verify_upstream(upstream_body, KEYRING)
```

- **Forwarding path:** wherever the gateway currently relays backend JSON, relay
  `guard(backend_response_bytes)` instead.
- **If it's FastAPI**, add the routes directly, so there's no mount-path ambiguity:

```python
from fastapi import FastAPI, Request, Response
from gateway_receipts import KEYRING, handle_request
app = FastAPI()

@app.post("/v1/verify-receipt")
@app.get("/v1/public-keys")
async def receipts(request: Request) -> Response:
    status, headers, body = handle_request(method=request.method, path=request.url.path,
        content_type=request.headers.get("content-type"), body=await request.body(), keyring=KEYRING)
    return Response(content=body, status_code=status, headers=dict(headers))
```

- **No framework yet** (the audit found only a handshake script):
  `ARKHEIA_TRUSTED_KEYS_FILE=arkheia-public-keys.json python -m arkheia_receipt.gateway`.
- Set a reverse-proxy body limit of ≥256 KiB. The handler enforces 256 KiB itself.

### 5.4 `CUSTOS` (Python + npm)

Same module as 5.1 with `ARKHEIA_ENGINE_ID=custos` and `wrapper_domain="governancecheck"`
(`COMPLIANT`/`NON_COMPLIANT`/`REQUIRES_REVIEW`) or `"riskcheck"`. The existing Ed25519 *policy*
verification stays as is. Its policy-bundle SHA-256 goes into `evidence_digests`, so every
receipt pins the exact policy it was evaluated under.

### 5.5 `supreme_kernel` (Python) — remove the SECURUS signing dependency

Same module as 5.1 with `ARKHEIA_ENGINE_ID=supreme_kernel`. Replace the "pending SHA-256 digest
→ SECURUS signs" hand-off with a local `signed_response(...)`. The pending digest becomes
`input_digest` (if it's a digest of the request) or an `evidence_digests` entry (if it's a digest
of an intermediate artifact).

### 5.6 `MusicGuard` (JavaScript) — new file `src/receipts.mjs`

```js
// Signed egress for MusicGuard forensics. Copyright (c) Eric A. Scott / ARKHEIA GROUP.
import { signerFromEnv, buildVerdictPayload, digestBytes, respondWithReceipt, sendSignedOverWebSocket } from '@arkheia/receipt';

export const signer = signerFromEnv({ envFile: '.env.arkheia-signing' }); // throws at startup if misconfigured

export function musicguardPayload({ verdict, reasonCodes, rulesVersion, reconciliationSha256, metrics }) {
  return buildVerdictPayload({ verdict, reasonCodes, ruleSet: { id: 'musicguard.forensics', version: rulesVersion },
    evidenceDigests: reconciliationSha256 ? [reconciliationSha256] : [], metrics });
}

export const sendHttp = (res, rawBody, payload) =>
  respondWithReceipt(res, signer, { wrapperDomain: 'musicguard', inputDigest: digestBytes(rawBody), verdictPayload: payload });

export const sendWs = (ws, rawBody, payload) =>
  sendSignedOverWebSocket(ws, signer, { wrapperDomain: 'musicguard', inputDigest: digestBytes(rawBody), verdictPayload: payload });
```

**Call site:** the reconciliation step's `res.json(result)` becomes
`await sendHttp(res, rawBody, musicguardPayload({...}))`. Its SHA-256 receipt goes in as
`reconciliationSha256`. Express: capture raw bytes with `express.raw({ type: 'application/json' })`
on that route, or use the `verify` hook of `express.json`.

### 5.7 `SECURUS` (TypeScript) — new file `src/receipts.ts`

```ts
// Signed DVE v1 egress for SECURUS. Copyright (c) Eric A. Scott / ARKHEIA GROUP.
import { signerFromEnv, buildVerdictPayload, digestBytes, respondWithReceipt, type VerdictPayload, type WrapperDomain } from '@arkheia/receipt';
import type { ServerResponse } from 'node:http';

export const signer = signerFromEnv({ envFile: '.env.arkheia-signing' });

export function securusPayload(verdict: string, reasonCodes: string[], ledgerReceiptSha256: string, metrics: Record<string, number> = {}): VerdictPayload {
  return buildVerdictPayload({ verdict, reasonCodes, ruleSet: { id: 'securus.posture', version: '1.12.0' }, evidenceDigests: [ledgerReceiptSha256], metrics });
}

export function sendSigned(res: ServerResponse, rawBody: Buffer, domain: WrapperDomain, payload: VerdictPayload) {
  return respondWithReceipt(res, signer, { wrapperDomain: domain, inputDigest: digestBytes(rawBody), verdictPayload: payload });
}
```

SECURUS's internal Ed25519 ledger receipts stay as they are. Their SHA-256 becomes evidence inside
the outward-facing V1 receipt. Use a **separate** key for V1 receipts, so a ledger-key
compromise doesn't let anyone forge buyer receipts. `tsx` runs the toolkit's `.mjs` natively, and
types come from `index.d.ts`.

### 5.8 `Single-loop-harness-` (Rust)

```bash
bash install_into_repo.sh rust . single_loop_harness   # cargo add --path + regenerate Cargo.lock
git add Cargo.toml Cargo.lock vendor/arkheia-receipts && cargo test --locked
```

```rust
// src/receipts.rs — Copyright (c) Eric A. Scott / ARKHEIA GROUP.
use arkheia_receipt::{build_verdict_payload, digest_bytes, ReceiptError, ReceiptSigner, ReceiptSigningKey, JsonlFileLedger, Value};
use std::{path::Path, sync::Arc};

pub fn signer(commit_sha: &str) -> Result<ReceiptSigner, Box<dyn std::error::Error>> {
    let key = ReceiptSigningKey::from_env(Some(Path::new(".env.arkheia-signing")))?;
    let ledger = Arc::new(JsonlFileLedger::new("var/arkheia-ledger")?);
    Ok(ReceiptSigner::new(key, "single_loop_harness", commit_sha, ledger))
}

/// Wraps a CreatorGuard seal: the manifest digest is anchored as evidence.
pub fn sign_seal(s: &ReceiptSigner, raw_request: &[u8], manifest_sha256: &str, tampered: bool) -> Result<(Value, String), ReceiptError> {
    let verdict = if tampered { "TAMPERED" } else { "VERIFIED" };
    let payload = build_verdict_payload(verdict, &["CREATORGUARD_SEAL"], "creatorguard.manifest", "1.0.0", &[manifest_sha256], &[]);
    s.issue("provenancecheck", &digest_bytes(raw_request), &payload)
}
```

Pass `commit_sha` from `env!("ARKHEIA_ENGINE_COMMIT_SHA")` via `build.rs`, or read `GITHUB_SHA`
at runtime. The existing `creatorguard.manifest.v1` signature stays as is. This receipt is the
platform-level wrapper around it.

### 5.9 `Arkheia---cps---frontend-` (browser)

Don't verify locally with SHA-256, and never ship keys to the browser. POST each receipt to the
gateway's `/v1/verify-receipt` and show `valid` / `signer` / `receipt_hash` from the response.

## 6. `bps-ledger` plug point

Not found in the audit's accessible-repository inventory. All three toolkits ship the same
contract, plus a `BpsLedgerAdapter` that **raises `LEDGER_NOT_CONFIGURED`** on every call. A signer
pointed at it can't silently drop ledger writes. Until it exists, use `ARKHEIA_LEDGER=jsonl:<dir>`.

| Method | Contract |
|---|---|
| `head(chain_id)` | `{sequence, receipt_hash}` or null |
| `append(chain_id, receipt, receipt_hash, expected_prev_hash)` | **atomic compare-and-append**; raise `LedgerConflictError` if head ≠ `expected_prev_hash` (genesis = 64 zeros). Signers re-read and re-sign up to 3×, then fail. |
| `get(receipt_hash)` | receipt or null |

Implementation targets: Python `arkheia_receipt/ledger.py::BpsLedgerAdapter`, Node
`node/src/ledger.mjs::BpsLedgerAdapter`, Rust `rust/.../ledger.rs::BpsLedgerAdapter`.
Each is three methods. `chain_id` defaults to `<engine_id>:<public_key_id>`.

## 7. Rollout order

1. Generate one key per engine and publish the keyring to the gateway (§3).
2. Deploy the gateway verifier (`/v1/verify-receipt`, `/v1/public-keys`). It's additive and safe.
3. Migrate the signers: CUSTOS → supreme_kernel (which removes the SECURUS coupling) → SECURUS → MusicGuard → CPS-- → bckend-1 → Single-loop-harness-.
4. Turn on the gateway `guard()` for each upstream once that upstream signs. After that, unsigned responses get a 502.
5. Wire `bps-ledger` when access is restored: swap `ARKHEIA_LEDGER=bps:<url>`, with no code changes.
