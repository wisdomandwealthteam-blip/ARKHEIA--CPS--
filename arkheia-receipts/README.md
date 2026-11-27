# ARKHEIA DVE™ Canonical Receipts — v1.0.0

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Uniform, buyer-verifiable receipts for every ARKHEIA engine output: schema-gated, RFC 8785
canonical, Ed25519-signed, SHA-256 hash-chained. The toolkit comes in three byte-identical
implementations (Python, Node, Rust) plus a stateless public verifier.

```
schema/arkheia-receipt-schema-v1.json   single source of truth (copied into each toolkit; verify_all checks drift)
test-vectors/vectors.json               cross-language vectors (RFC 8032 TEST 1 seed — PUBLIC, TEST ONLY)
python/arkheia_receipt/                 CPS backend, CPS--, GATEWAY-, CUSTOS, supreme_kernel
  gateway.py                            /v1/verify-receipt + /v1/public-keys (WSGI, ASGI, stdlib server) + verify_upstream()
node/                                   MusicGuard (JS), SECURUS (TS: index.d.ts) — native node:crypto, zero deps
rust/arkheia-receipt/                   Single-loop-harness- — ed25519-dalek + sha2 only
docs/DVE_REMEDIATION_ROADMAP.md         audit gap matrix, per-repo patches, bps-ledger plug point
install_into_repo.sh                    vendors the toolkit into a repo and wires the dependency
verify_all.sh                           runs every suite + live HTTP smoke test
```

## Receipt

```json
{
  "schema_version": "1.0.0",
  "engine_id": "supreme_kernel",
  "commit_sha": "e16c0daa0814db8fb80115a0937436e80113d9a3",
  "wrapper_domain": "governancecheck",
  "timestamp_utc": "2026-11-25T12:00:02.000Z",
  "sequence": 2,
  "input_digest": "<sha256 hex>",
  "verdict_payload": { "verdict": "NON_COMPLIANT", "reason_codes": [...], "rule_set": {...},
                       "evidence_digests": [...], "metrics": {...},
                       "determinism": { "mode": "deterministic", "fallback_used": false } },
  "prev_receipt_hash": "<sha256 hex of previous full receipt; 64 zeros at sequence 0>",
  "signature": { "algorithm": "Ed25519", "public_key_id": "ed25519:<16 hex>", "value": "<128 hex>" }
}
```

| Rule | Definition |
|---|---|
| Canonical form | RFC 8785 JCS. Receipts are **integers-only** (safe range); fractions/exponents are rejected everywhere |
| Signed bytes | `UTF-8("arkheia.receipt.v1") ‖ 0x00 ‖ JCS(receipt without "signature")` |
| `receipt_hash` | `SHA-256(JCS(full signed receipt))` → next receipt's `prev_receipt_hash` |
| `public_key_id` | `"ed25519:" + first 16 hex of SHA-256(raw 32-byte public key)` |
| Genesis | `sequence == 0` ⇔ `prev_receipt_hash == 64 zeros` (schema-enforced) |
| Separation | `engine_id` can never be a wrapper name (schema `not`) |
| Determinism | `determinism.fallback_used` is `const false`; per-domain verdict enums |

**Fail-closed everywhere:** the signer validates against the schema before *and* after signing.
Boundary parsers reject duplicate keys, floats, NaN, lone surrogates, BOMs and deep nesting.
The egress helpers return a 500 / error frame instead of ever sending an unsigned verdict.
The schema interpreters reject unknown keywords rather than ignoring them.

## Quick start (Codespaces)

```bash
bash verify_all.sh                                        # everything, incl. live /v1/verify-receipt
python -m arkheia_receipt.keygen --out-dir ./secrets      # per-engine key (or node node/scripts/keygen.mjs)
ARKHEIA_TRUSTED_KEYS_FILE=secrets/arkheia-public-keys.json python -m arkheia_receipt.gateway
curl -s -X POST localhost:8080/v1/verify-receipt -H 'content-type: application/json' --data-binary @receipt.json
# -> {"chain_link_verified":false,"engine_id":"...","receipt_hash":"...","sequence":n,"signer":"ed25519:...","valid":true,"verified_at":"...","wrapper_domain":"..."}
```

To verify a chain link, POST `{"receipt": <r>, "previous_receipt": <r-1>}`. A bad receipt returns
`200 {"valid":false,"error_code":...}`. Codes: `SCHEMA_INVALID`, `TIMESTAMP_INVALID`, `UNKNOWN_SIGNER`,
`REVOKED_SIGNER`, `SIGNATURE_INVALID`, `PREVIOUS_RECEIPT_INVALID`, `CHAIN_LINK_MISMATCH`,
`CHAIN_SEQUENCE_GAP`, `CANONICALIZATION_ERROR`. A malformed request returns 4xx (`BODY_PARSE_ERROR`,
`UNSUPPORTED_MEDIA_TYPE`, `BODY_TOO_LARGE`, …).

Into a repo: `bash install_into_repo.sh <python|node|rust> <repo> <engine_id>`, then follow
`docs/DVE_REMEDIATION_ROADMAP.md` §5 for that repo.

## Per-suite commands

```bash
(cd node   && node --test test/*.test.mjs)
(cd python && pip install -e '.[dev]' && pytest -q)
(cd rust/arkheia-receipt && cargo test)
```
