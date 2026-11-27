# Additive platform checks

The four stateless POST endpoints are independent of existing governance, ClearCheck, CORS, authentication, receipt verification, and Stripe behavior. They return the new platform envelope with **exactly** `receipt_id`, `gate`, `findings`, `sha256`, `timestamp`, and `architecture_version`. The architecture version is `PLATFORM-ARCHITECTURE-2026-V1`. Findings contain only `code` and the fixed `reason` below. Any findings yield `HOLD`; otherwise the gate is `PASS`. Responses are HTTP 200 with `Cache-Control: no-store`, including malformed or missing evidence that produces HOLD.

| Endpoint | Prefix | Required evidence |
| --- | --- | --- |
| `POST /api/settlement/check` | `stl_` | `splits_bps`, `gross_amount_cents` |
| `POST /api/provenance/check` | `prv_` | `isrc`, `audio_fingerprint_sha256`, `rights_cleared`, `splits_bps` |
| `POST /api/custody/check` | `cst_` | `signatures_collected`, `quorum_required`, `policy_window_active`, `release_amount`, `custody_limit` |
| `POST /api/edge/check` | `edg_` | `node_attestation_valid`, `telemetry_within_bounds`, `offline_queue_hash` |

Splits are a nonempty array of exact JSON integers, each between 0 and 10000, summing to 10000. Booleans, decimal-valued basis points, numeric strings, negative allocations and non-array splits fail closed. Gross cents must be an exact integer greater than zero. Quorum counts are nonnegative exact integers and collected signatures must be at least the required quorum. Amounts are finite, nonnegative JSON numbers, with release amount at most the limit. Equality passes; zero quorum and zero amounts are permitted. Boolean evidence must be exactly `true`, never a truthy number or string. Provenance identifiers and audit hashes must be non-whitespace strings; their presence is checked, not their external authenticity or hash format.

Rules always evaluate independently in this order:

| Domain | Code | Exact reason |
| --- | --- | --- |
| Settlement, first; provenance, third | `SPLIT_CONSERVATION_VIOLATION` | Integer basis-point splits must sum to 10000. |
| Settlement, second | `INVALID_GROSS_AMOUNT` | Gross amount must be a positive integer number of cents. |
| Provenance, first | `MISSING_PROVENANCE_HASH` | ISRC and audio fingerprint hash must both be present. |
| Provenance, second | `UNVERIFIED_RIGHTS_CHAIN` | Rights clearance must be explicitly verified. |
| Custody, first | `INSUFFICIENT_QUORUM_SIGNATURES` | Collected signatures must meet the required quorum. |
| Custody, second | `EXPIRED_OR_INACTIVE_CUSTODY_POLICY` | The custody policy window must be active. |
| Custody, third | `CUSTODY_LIMIT_EXCEEDED` | Release amount must not exceed the custody limit. |
| Edge, first | `UNATTESTED_EDGE_NODE` | The edge node must have a valid attestation. |
| Edge, second | `SENSOR_INVARIANT_BREACH` | Telemetry must remain within the permitted bounds. |
| Edge, third | `MISSING_LOCAL_AUDIT_HASH` | An offline queue audit hash must be present. |

## Canonical content addressing

The existing `clearcheck_engine.compute_check_id` supplies the digest, replacing only its prefix. `sha256` is the full lowercase SHA-256 of UTF-8 `json.dumps(request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))`. The request model retains supplied evidence types, so integer and float inputs are not silently conflated. Omitted evidence defaults to null. Unknown fields are ignored and excluded from hashing, logging and responses. Every model also allows optional `redacted_subject_ref`: string values are passed through the existing `mask_value` helper before hashing, exposing at most the final four characters in the normalized model; non-string references become null. No reference is ever returned, stored or logged. Callers should still send pre-redacted references; hashing is not anonymization.

Nonfinite numeric evidence, including overflow and nonstandard constants, normalizes to null and fails its relevant rule. Missing bodies, non-object JSON, invalid JSON, malformed encoding, and duplicate keys normalize to entirely missing evidence and therefore produce all domain findings. No raw parser or payload values are echoed or logged.

The identifier covers the normalized request, not the receipt or clock. `timestamp` is aware UTC for each evaluation. Hashes, finding order and gates are stable for identical normalized content and reordered object keys; timestamps may differ. These checks do **not** persist receipts or implement GET lookups. They are content-addressed consistency checks, not authenticated signatures, authoritative rights verification, financial settlement execution, custody release authorization, or edge attestation verification. No private signing keys are introduced.

## Testing

Install with `python -m pip install -r requirements.txt httpx` and run `python -m pytest tests -q`. Platform coverage lives in `tests/test_platform_checks.py`. All tests use in-process clients, without a live service, browser, billing provider or production store.
