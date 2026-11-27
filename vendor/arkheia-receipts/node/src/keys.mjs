// ARKHEIA DVE — Ed25519 key handling via native node:crypto (no addons).
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//
// Keys are derived deterministically from a 32-byte RFC 8032 seed, so the same
// seed yields the same keypair in Node, Python (cryptography) and Rust
// (ed25519-dalek).

import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const HEX64 = /^[0-9a-f]{64}$/;

export class KeyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'KeyError';
    this.code = 'KEY_ERROR';
  }
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** public_key_id = "ed25519:" + first 16 hex chars of SHA-256(raw 32-byte public key). */
export function publicKeyId(rawPublicKey) {
  if (!Buffer.isBuffer(rawPublicKey) || rawPublicKey.length !== 32) throw new KeyError('raw public key must be 32 bytes');
  return `ed25519:${sha256Hex(rawPublicKey).slice(0, 16)}`;
}

export function signingKeyFromSeedHex(seedHex) {
  if (typeof seedHex !== 'string' || !HEX64.test(seedHex)) throw new KeyError('seed must be 64 lowercase hex characters');
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);
  const rawPublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(SPKI_ED25519_PREFIX.length);
  return Object.freeze({
    privateKey,
    publicKey,
    rawPublicKey: Buffer.from(rawPublicKey),
    publicKeyHex: Buffer.from(rawPublicKey).toString('hex'),
    publicKeyId: publicKeyId(Buffer.from(rawPublicKey)),
  });
}

export function publicKeyFromHex(publicKeyHex) {
  if (typeof publicKeyHex !== 'string' || !HEX64.test(publicKeyHex)) throw new KeyError('public key must be 64 lowercase hex characters');
  const raw = Buffer.from(publicKeyHex, 'hex');
  const publicKey = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: 'der', type: 'spki' });
  return Object.freeze({ publicKey, rawPublicKey: raw, publicKeyHex, publicKeyId: publicKeyId(raw) });
}

export function signBytes(signingKey, message) {
  return sign(null, message, signingKey.privateKey);
}

export function verifyBytes(publicKey, message, signature) {
  if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
  return verify(null, message, publicKey.publicKey, signature);
}

/**
 * Load the signing key from the environment. Optionally loads a .env file first
 * using Node's built-in process.loadEnvFile (no dotenv dependency).
 * Required: ARKHEIA_SIGNING_SEED_HEX. Optional cross-check: ARKHEIA_SIGNING_PUBLIC_KEY_ID.
 */
export function loadSigningKeyFromEnv({ envFile, env = process.env } = {}) {
  if (envFile) process.loadEnvFile(envFile);
  const seed = env.ARKHEIA_SIGNING_SEED_HEX;
  if (!seed) throw new KeyError('ARKHEIA_SIGNING_SEED_HEX is not set');
  const key = signingKeyFromSeedHex(seed.trim());
  const expectedId = env.ARKHEIA_SIGNING_PUBLIC_KEY_ID;
  if (expectedId && expectedId.trim() !== key.publicKeyId) {
    throw new KeyError(`seed does not match ARKHEIA_SIGNING_PUBLIC_KEY_ID (${expectedId} != ${key.publicKeyId})`);
  }
  return key;
}

/**
 * Keyring: { "keys": [ { "public_key_id", "algorithm": "Ed25519", "public_key_hex", "status": "active"|"revoked" } ] }
 * Every entry is re-derived and its id checked; mismatches throw.
 */
export class Keyring {
  #byId = new Map();

  constructor(doc) {
    if (!doc || !Array.isArray(doc.keys) || doc.keys.length === 0) throw new KeyError('keyring must contain a non-empty "keys" array');
    for (const entry of doc.keys) {
      if (entry.algorithm !== 'Ed25519') throw new KeyError('keyring entries must be Ed25519');
      if (entry.status !== 'active' && entry.status !== 'revoked') throw new KeyError('keyring status must be active or revoked');
      const pk = publicKeyFromHex(entry.public_key_hex);
      if (pk.publicKeyId !== entry.public_key_id) throw new KeyError(`keyring id mismatch for ${entry.public_key_id}`);
      if (this.#byId.has(pk.publicKeyId)) throw new KeyError(`duplicate keyring id ${pk.publicKeyId}`);
      this.#byId.set(pk.publicKeyId, { ...pk, status: entry.status });
    }
  }

  static fromFile(path) {
    return new Keyring(JSON.parse(readFileSync(path, 'utf8')));
  }

  get(id) {
    return this.#byId.get(id) ?? null;
  }

  toJSON() {
    return {
      keys: [...this.#byId.values()]
        .map((k) => ({ public_key_id: k.publicKeyId, algorithm: 'Ed25519', public_key_hex: k.publicKeyHex, status: k.status }))
        .sort((a, b) => (a.public_key_id < b.public_key_id ? -1 : 1)),
    };
  }
}
