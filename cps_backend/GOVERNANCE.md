# GovernanceCheck backend contract

GovernanceCheck is separate from ClearCheck, CORS configuration, authentication scaffolding, and Stripe/billing. The only existing application change registers its router. It adds no payment flow or signing secret.

## Evaluation

`POST /api/governance/check` accepts this JSON object:

```json
{
  "model_id": "model-2026-v1",
  "decision_domain": "finance",
  "proposed_action": "approve-transfer",
  "confidence_score": 0.95,
  "human_override_required": false,
  "policy_thresholds": {
    "min_confidence": 0.85,
    "max_unsupervised_amount": 10000
  },
  "transaction_amount": 100,
  "redacted_subject_ref": "subject-redacted-0001"
}
```

`model_id`, `decision_domain`, `proposed_action`, and `redacted_subject_ref` must be strings. A blank/whitespace model ID or a trimmed, case-insensitive `unknown` is accepted and causes a HOLD; there is no external model registry or provenance authentication. Other model IDs are not normalized for hashing.

`confidence_score` and `min_confidence` are finite JSON numbers in `[0, 1]`. Amount fields are finite, nonnegative JSON numbers. Booleans and numeric strings are not accepted as numbers; JSON integers are accepted and validated as floats. `human_override_required` must be a JSON boolean, not `0`, `1`, or a string. Unknown fields are rejected both at the request level and inside `policy_thresholds` to avoid unplanned PII fields. Invalid inputs return sanitized 422 responses through the existing application handler.

`policy_thresholds` can be omitted or supplied partially. Its defaults are `min_confidence: 0.85` and `max_unsupervised_amount: 10000.0`. `transaction_amount` defaults to `0.0`. Null thresholds are not equivalent to omission.

Rules are evaluated in this fixed order:

1. `LOW_MODEL_CONFIDENCE` when confidence is **below** the minimum.
2. `UNSUPERVISED_HIGH_VALUE_ACTION` when amount is **above** the maximum and `human_override_required` is false.
3. `MISSING_MODEL_PROVENANCE` when the trimmed model ID is blank or case-insensitive `unknown`.

Threshold equality passes that rule. A human override suppresses only the unsupervised high-value finding, not other findings. Any finding yields `HOLD`; otherwise the gate is `PASS`. Each finding contains only `code` and static `reason` text, with no submitted values.

The response has exactly `receipt_id`, `gate`, `architecture_version`, `sha256_digest`, `findings`, and `evaluated_at`. The architecture version is `PLATFORM-ARCHITECTURE-2026-V1`. `evaluated_at` is an aware UTC timestamp from the first successful persisted evaluation. Responses carry `Cache-Control: no-store`.

## Content addressing, not signing

The existing `services/clearcheck_engine.py::compute_check_id` function is the shared canonical digest implementation. GovernanceCheck calls it with the validated GovernanceCheck request and replaces only the `chk_` prefix with `gov_`. No existing ClearCheck code is modified.

The digest is the full lowercase SHA-256 of UTF-8 encoded `json.dumps(request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))`. Validation applies numeric types and defaults before hashing; object key ordering does not affect the result. The receipt ID is `gov_` followed by all 64 digest characters, and `sha256_digest` contains those same 64 characters. Different validated content normally produces a different ID, even when findings are unchanged.

**This is a deterministic content-addressed digest, not an authenticated cryptographic signature.** There is no deterministic receipt signer in the existing repository. Neither the digest nor the receipt authenticates the caller, model provenance, issuing service, or integrity of an externally modified record. No signing secret, signature field, or claimed signature verification is introduced. The digest covers the validated request, not the timestamp or response, and the request is not retained for later rehashing.

Identical validated submissions return the entire first persisted receipt unchanged, including `evaluated_at`, without rewriting the file. On each POST replay, all deterministic fields of the stored receipt must agree with the newly evaluated candidate; only the original timestamp is preserved. A schema-valid record with contradictory gate or findings returns sanitized 503 without rewriting the file. A success response is returned only after the store is successfully persisted or a matching existing receipt is read. This recomputation does not authenticate standalone GET lookups or make storage tamper-proof.

## Lookup and storage

`GET /api/governance/checks/{receipt_id}` returns the same persisted response. A well-formed unknown ID returns sanitized 404; an ID not matching exactly `gov_[0-9a-f]{64}` returns sanitized 422. Lookup does not require resubmitting input and is not authenticated by possession of a cryptographic signature.

`services/governance_store.py` reads `CPS_GOVERNANCE_STORE_PATH` directly; no shared configuration is changed. The default is `/opt/render/project/src/data/governance_checks.json`. For local use, explicitly set a writable path, for example:

```sh
export CPS_GOVERNANCE_STORE_PATH="$PWD/data/governance_checks.json"
```

The JSON file contains only `{"checks": {"<receipt_id>": <response>}}`. No input payload or subject reference is persisted or echoed, even if a caller fails to redact a value in an allowed string field. Callers must still redact before submission; hashing is not encryption or anonymization and low-entropy inputs may be guessable.

Reads validate all persisted receipts, reject additional fields, ensure ID/digest parity and gate/finding consistency, require ordered unique finding codes and exact static reasons, and require UTC timestamps. Duplicate JSON keys, nonfinite constants, malformed UTF-8/JSON, and invalid structures are rejected. Corrupt or inaccessible stores return the same sanitized 503 (`Governance records are temporarily unavailable.`) without leaking paths, stored values, or underlying exceptions. The original file is not overwritten on corruption or failed writes. A missing store is considered new; lookup returns 404 without creating a file.

Writes use a process-local lock, a unique owner-only temporary file in the destination directory, file flush/fsync, and atomic POSIX replacement. Like ClearCheck's current JSON persistence, the lock protects **threads in one process only**, not multiple workers or replicas. Deploy only one writer process/instance; use a transactional database before scaling. Persistence across redeploys requires a persistent disk/volume at the configured path. Atomic replacement is not a backup or an authenticated tamper-proof ledger.

## Tests

Run `python -m pip install -r requirements.txt pytest httpx`, then `python -m pytest`. New tests use temporary paths and monkeypatch isolation; no live backend, browser, billing provider, or production store is contacted.
