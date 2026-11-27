// ARKHEIA DVE receipt toolkit — TypeScript declarations (SECURUS / MusicGuard).
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
import type { KeyObject } from 'node:crypto';
import type { ServerResponse } from 'node:http';

export type WrapperDomain = 'clearcheck' | 'musicguard' | 'governancecheck' | 'provenancecheck' | 'settlementcheck' | 'riskcheck';
export type Hex64 = string;

export interface VerdictPayload {
  verdict: string;
  reason_codes: string[];
  rule_set: { id: string; version: string };
  evidence_digests: Hex64[];
  metrics: Record<string, number>; // safe integers only
  determinism: { mode: 'deterministic'; fallback_used: false };
}

export interface ReceiptSignature { algorithm: 'Ed25519'; public_key_id: string; value: string }

export interface ArkheiaReceipt {
  schema_version: '1.0.0';
  engine_id: string;
  commit_sha: string;
  wrapper_domain: WrapperDomain;
  timestamp_utc: string;
  sequence: number;
  input_digest: Hex64;
  verdict_payload: VerdictPayload;
  prev_receipt_hash: Hex64;
  signature: ReceiptSignature;
}

export interface SigningKey { privateKey: KeyObject; publicKey: KeyObject; rawPublicKey: Buffer; publicKeyHex: string; publicKeyId: string }
export interface KeyringDoc { keys: { public_key_id: string; algorithm: 'Ed25519'; public_key_hex: string; status: 'active' | 'revoked' }[] }

export type VerifyErrorCode =
  | 'SCHEMA_INVALID' | 'TIMESTAMP_INVALID' | 'UNKNOWN_SIGNER' | 'REVOKED_SIGNER' | 'SIGNATURE_INVALID'
  | 'PREVIOUS_RECEIPT_INVALID' | 'CHAIN_LINK_MISMATCH' | 'CHAIN_SEQUENCE_GAP' | 'CANONICALIZATION_ERROR' | 'VERIFICATION_ERROR';

export type VerifyResult =
  | { valid: true; signer: string; receipt_hash: Hex64 }
  | { valid: false; error_code: VerifyErrorCode; errors?: { path: string; keyword: string }[]; previous_error_code?: VerifyErrorCode };

export interface LedgerHead { sequence: number; receipt_hash: Hex64 }
export interface ReceiptLedger {
  head(chainId: string): Promise<LedgerHead | null>;
  /** MUST be atomic compare-and-append; throw LedgerConflictError if head != expected_prev_hash. */
  append(chainId: string, entry: { receipt: ArkheiaReceipt; receipt_hash: Hex64; expected_prev_hash: Hex64 }): Promise<void>;
  get(receiptHash: Hex64): Promise<ArkheiaReceipt | null>;
}

export const SCHEMA_VERSION: '1.0.0';
export const SIGNING_DOMAIN: Buffer;
export const WRAPPER_DOMAINS: readonly WrapperDomain[];
export const GENESIS_HASH: Hex64;
export const RECEIPT_HASH_HEADER: 'x-arkheia-receipt-hash';
export const RECEIPT_SCHEMA: Record<string, unknown>;

export function canonicalize(value: unknown, opts?: { allowFloats?: boolean }): string;
export function canonicalBytes(value: unknown, opts?: { allowFloats?: boolean }): Buffer;
export function parseStrictJson(text: string, opts?: { integersOnly?: boolean }): unknown;
export function compileSchema(schema: object): (value: unknown) => { valid: boolean; errors: { path: string; keyword: string }[] };
export function validateReceiptSchema(value: unknown): { valid: boolean; errors: { path: string; keyword: string }[] };

export function sha256Hex(bytes: Buffer | Uint8Array): Hex64;
export function publicKeyId(rawPublicKey: Buffer): string;
export function signingKeyFromSeedHex(seedHex: string): SigningKey;
export function publicKeyFromHex(publicKeyHex: string): Omit<SigningKey, 'privateKey'>;
export function loadSigningKeyFromEnv(opts?: { envFile?: string; env?: Record<string, string | undefined> }): SigningKey;
export class Keyring {
  constructor(doc: KeyringDoc);
  static fromFile(path: string): Keyring;
  get(id: string): (Omit<SigningKey, 'privateKey'> & { status: 'active' | 'revoked' }) | null;
  toJSON(): KeyringDoc;
}

export function buildVerdictPayload(o: {
  verdict: string; reasonCodes?: string[]; ruleSet: { id: string; version: string }; evidenceDigests?: Hex64[]; metrics?: Record<string, number>;
}): VerdictPayload;
export function digestBytes(bytes: Buffer | Uint8Array): Hex64;
export function digestJson(value: unknown, opts?: { allowFloats?: boolean }): Hex64;
export function formatTimestamp(date: Date): string;
export function isValidTimestamp(ts: unknown): boolean;
export function signingInput(receipt: object): Buffer;
export function receiptHash(receipt: object): Hex64;
export function signReceipt(key: SigningKey, fields: Omit<ArkheiaReceipt, 'schema_version' | 'signature'>): ArkheiaReceipt;
export function verifyReceipt(receipt: unknown, keyring: Keyring, opts?: { previousReceipt?: unknown }): VerifyResult;
export function verifyChain(receipts: unknown[], keyring: Keyring):
  | { valid: true; length: number; head_hash: Hex64 }
  | { valid: false; index: number; error_code: VerifyErrorCode };

export class ReceiptSigner {
  constructor(o: { signingKey: SigningKey; engineId: string; commitSha: string; ledger: ReceiptLedger; chainId?: string; clock?: () => Date });
  readonly engineId: string;
  readonly commitSha: string;
  readonly chainId: string;
  readonly publicKeyId: string;
  issue(o: { wrapperDomain: WrapperDomain; inputDigest: Hex64; verdictPayload: VerdictPayload }): Promise<{ receipt: ArkheiaReceipt; receipt_hash: Hex64 }>;
}

export class InMemoryLedger implements ReceiptLedger {
  head(chainId: string): Promise<LedgerHead | null>;
  append(chainId: string, entry: { receipt: ArkheiaReceipt; receipt_hash: Hex64; expected_prev_hash: Hex64 }): Promise<void>;
  get(receiptHash: Hex64): Promise<ArkheiaReceipt | null>;
}
export class JsonlFileLedger extends InMemoryLedger { constructor(dir: string); }
export class BpsLedgerAdapter extends InMemoryLedger { constructor(config?: Record<string, unknown>); config: Record<string, unknown>; }

export function respondWithReceipt(res: ServerResponse, signer: ReceiptSigner, o: {
  wrapperDomain: WrapperDomain; inputDigest: Hex64; verdictPayload: VerdictPayload; status?: number;
}): Promise<{ ok: true; receipt: ArkheiaReceipt; receipt_hash: Hex64 } | { ok: false; error_code: string }>;
export function sendSignedOverWebSocket(ws: { send(data: string): void }, signer: ReceiptSigner, o: {
  wrapperDomain: WrapperDomain; inputDigest: Hex64; verdictPayload: VerdictPayload;
}): Promise<{ ok: true; receipt: ArkheiaReceipt; receipt_hash: Hex64 } | { ok: false; error_code: string }>;

export class CanonicalizationError extends Error { code: 'CANONICALIZATION_ERROR'; path: string }
export class StrictJsonError extends Error { code: 'BODY_PARSE_ERROR'; offset: number }
export class SchemaDefinitionError extends Error {}
export class KeyError extends Error { code: 'KEY_ERROR' }
export class ReceiptError extends Error { code: string; details?: unknown }
export class LedgerConflictError extends Error { code: 'LEDGER_CONFLICT' }
export class LedgerNotConfiguredError extends Error { code: 'LEDGER_NOT_CONFIGURED' }

export function ledgerFromEnv(env?: Record<string, string | undefined>): ReceiptLedger;
export function signerFromEnv(o?: { env?: Record<string, string | undefined>; envFile?: string }): ReceiptSigner;
