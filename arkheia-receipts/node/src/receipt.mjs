// ARKHEIA DVE — receipt issuance and verification.
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

import { canonicalBytes, canonicalize } from './jcs.mjs';
import { validateReceiptSchema } from './schema.mjs';
import { sha256Hex, signBytes, verifyBytes } from './keys.mjs';
import { GENESIS_HASH, LedgerConflictError } from './ledger.mjs';

export const SCHEMA_VERSION = '1.0.0';
export const SIGNING_DOMAIN = Buffer.from('arkheia.receipt.v1\u0000', 'utf8');
export const WRAPPER_DOMAINS = Object.freeze(['clearcheck', 'musicguard', 'governancecheck', 'provenancecheck', 'settlementcheck', 'riskcheck']);
export const PLACEHOLDER_SIGNATURE = Object.freeze({ algorithm: 'Ed25519', public_key_id: 'ed25519:0000000000000000', value: '0'.repeat(128) });

export class ReceiptError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'ReceiptError';
    this.code = code;
    this.details = details;
  }
}

/** Deterministic ISO-8601 UTC with millisecond precision. */
export function formatTimestamp(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) throw new ReceiptError('TIMESTAMP_INVALID', 'invalid Date');
  return date.toISOString();
}

export function isValidTimestamp(ts) {
  if (typeof ts !== 'string' || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(ts)) return false;
  if (ts.startsWith('0000')) return false; // year 0 is not representable in Python/Rust validators
  const d = new Date(ts);
  return !Number.isNaN(d.getTime()) && d.toISOString() === ts; // rejects Feb 30, 24:00, etc.
}

export function digestBytes(bytes) {
  return sha256Hex(bytes);
}

/** SHA-256 of the JCS form of a JSON input (floats permitted per RFC 8785; Node-only reproducibility). */
export function digestJson(value, { allowFloats = false } = {}) {
  return sha256Hex(canonicalBytes(value, { allowFloats }));
}

/** Builds a verdict_payload with order-independent (sorted) arrays. */
export function buildVerdictPayload({ verdict, reasonCodes = [], ruleSet, evidenceDigests = [], metrics = {} }) {
  return {
    verdict,
    reason_codes: [...reasonCodes].sort(),
    rule_set: { id: ruleSet?.id, version: ruleSet?.version },
    evidence_digests: [...evidenceDigests].sort(),
    metrics: { ...metrics },
    determinism: { mode: 'deterministic', fallback_used: false },
  };
}

function stripSignature(receipt) {
  const { signature: _sig, ...unsigned } = receipt;
  return unsigned;
}

export function signingInput(receipt) {
  return Buffer.concat([SIGNING_DOMAIN, canonicalBytes(stripSignature(receipt))]);
}

export function receiptHash(receipt) {
  return sha256Hex(canonicalBytes(receipt));
}

function schemaCheck(receipt) {
  const r = validateReceiptSchema(receipt);
  if (!r.valid) throw new ReceiptError('SCHEMA_INVALID', 'receipt failed ARKHEIA DVE schema v1.0.0', r.errors);
  if (!isValidTimestamp(receipt.timestamp_utc)) throw new ReceiptError('TIMESTAMP_INVALID', 'timestamp_utc is not a real UTC instant');
}

/** Pure, ledger-free receipt construction (used by vectors and the signer). */
export function signReceipt(signingKey, fields) {
  const unsigned = {
    schema_version: SCHEMA_VERSION,
    engine_id: fields.engine_id,
    commit_sha: fields.commit_sha,
    wrapper_domain: fields.wrapper_domain,
    timestamp_utc: fields.timestamp_utc,
    sequence: fields.sequence,
    input_digest: fields.input_digest,
    verdict_payload: fields.verdict_payload,
    prev_receipt_hash: fields.prev_receipt_hash,
  };
  // Validate the full shape before signing (placeholder signature is schema-valid).
  schemaCheck({ ...unsigned, signature: PLACEHOLDER_SIGNATURE });
  const sig = signBytes(signingKey, signingInput(unsigned));
  const receipt = {
    ...unsigned,
    signature: { algorithm: 'Ed25519', public_key_id: signingKey.publicKeyId, value: sig.toString('hex') },
  };
  schemaCheck(receipt);
  return receipt;
}

export class ReceiptSigner {
  #key;
  #ledger;
  #clock;
  #queue = Promise.resolve();

  /**
   * @param {object} o
   * @param o.signingKey  from signingKeyFromSeedHex / loadSigningKeyFromEnv
   * @param o.engineId    proprietary engine id (never a wrapper name)
   * @param o.commitSha   40/64-hex git commit of the engine build
   * @param o.ledger      InMemoryLedger | JsonlFileLedger | BpsLedgerAdapter
   * @param o.chainId     defaults to `${engineId}:${publicKeyId}`
   * @param o.clock       () => Date  (inject for tests)
   */
  constructor({ signingKey, engineId, commitSha, ledger, chainId, clock = () => new Date() }) {
    if (!signingKey || !ledger) throw new ReceiptError('SIGNER_MISCONFIGURED', 'signingKey and ledger are required');
    this.#key = signingKey;
    this.#ledger = ledger;
    this.#clock = clock;
    this.engineId = engineId;
    this.commitSha = commitSha;
    this.chainId = chainId ?? `${engineId}:${signingKey.publicKeyId}`;
  }

  get publicKeyId() {
    return this.#key.publicKeyId;
  }

  /** Issues, validates, signs and ledgers one receipt. Serialized per signer. */
  issue({ wrapperDomain, inputDigest, verdictPayload }) {
    const run = async () => {
      for (let attempt = 0; attempt < 3; attempt++) {
        const head = await this.#ledger.head(this.chainId);
        const receipt = signReceipt(this.#key, {
          engine_id: this.engineId,
          commit_sha: this.commitSha,
          wrapper_domain: wrapperDomain,
          timestamp_utc: formatTimestamp(this.#clock()),
          sequence: head ? head.sequence + 1 : 0,
          input_digest: inputDigest,
          verdict_payload: verdictPayload,
          prev_receipt_hash: head ? head.receipt_hash : GENESIS_HASH,
        });
        const hash = receiptHash(receipt);
        try {
          await this.#ledger.append(this.chainId, { receipt, receipt_hash: hash, expected_prev_hash: receipt.prev_receipt_hash });
          return { receipt, receipt_hash: hash };
        } catch (e) {
          if (e instanceof LedgerConflictError && attempt < 2) continue; // another writer advanced the head; re-sign on new head
          throw e;
        }
      }
      throw new ReceiptError('LEDGER_CONFLICT', 'ledger head kept moving');
    };
    const p = this.#queue.then(run, run);
    this.#queue = p.catch(() => undefined);
    return p;
  }
}

/**
 * Verifies one receipt. Never throws for bad receipts; returns a result.
 * @param receipt parsed receipt (parse with parseStrictJson at boundaries)
 * @param keyring Keyring
 * @param previousReceipt optional — if supplied, the chain link is verified too
 */
export function verifyReceipt(receipt, keyring, { previousReceipt } = {}) {
  const fail = (error_code, extra = {}) => ({ valid: false, error_code, ...extra });
  try {
    const schema = validateReceiptSchema(receipt);
    if (!schema.valid) return fail('SCHEMA_INVALID', { errors: schema.errors });
    if (!isValidTimestamp(receipt.timestamp_utc)) return fail('TIMESTAMP_INVALID');
    const key = keyring.get(receipt.signature.public_key_id);
    if (!key) return fail('UNKNOWN_SIGNER');
    if (key.status !== 'active') return fail('REVOKED_SIGNER');
    const ok = verifyBytes(key, signingInput(receipt), Buffer.from(receipt.signature.value, 'hex'));
    if (!ok) return fail('SIGNATURE_INVALID');
    const hash = receiptHash(receipt);
    if (previousReceipt !== undefined) {
      const prev = verifyReceipt(previousReceipt, keyring);
      if (!prev.valid) return fail('PREVIOUS_RECEIPT_INVALID', { previous_error_code: prev.error_code });
      if (prev.receipt_hash !== receipt.prev_receipt_hash) return fail('CHAIN_LINK_MISMATCH');
      if (previousReceipt.sequence + 1 !== receipt.sequence) return fail('CHAIN_SEQUENCE_GAP');
    }
    return { valid: true, signer: key.publicKeyId, receipt_hash: hash };
  } catch (e) {
    return fail(e?.code === 'CANONICALIZATION_ERROR' ? 'CANONICALIZATION_ERROR' : 'VERIFICATION_ERROR');
  }
}

/** Verifies an ordered chain starting at genesis or at any anchored receipt. */
export function verifyChain(receipts, keyring) {
  for (let i = 0; i < receipts.length; i++) {
    const r = verifyReceipt(receipts[i], keyring, i > 0 ? { previousReceipt: receipts[i - 1] } : {});
    if (!r.valid) return { valid: false, index: i, error_code: r.error_code };
  }
  return { valid: true, length: receipts.length, head_hash: receipts.length ? receiptHash(receipts[receipts.length - 1]) : GENESIS_HASH };
}

export { canonicalize };
