#!/usr/bin/env node
// ARKHEIA DVE — Ed25519 signing key generation.
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//
// Usage:
//   node scripts/keygen.mjs [--out-dir DIR]            new random seed (OS CSPRNG)
//   node scripts/keygen.mjs --from-seed HEX [--out-dir DIR]   re-derive deterministically
//
// Writes:
//   DIR/.env.arkheia-signing      (mode 0600)  ARKHEIA_SIGNING_SEED_HEX + ARKHEIA_SIGNING_PUBLIC_KEY_ID
//   DIR/arkheia-public-keys.json  publishable keyring for /v1/verify-receipt
// Refuses to overwrite existing files.

import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { signingKeyFromSeedHex } from '../src/keys.mjs';

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const outDir = arg('--out-dir') ?? '.';
const seedHex = arg('--from-seed') ?? randomBytes(32).toString('hex');
const key = signingKeyFromSeedHex(seedHex);

const envPath = join(outDir, '.env.arkheia-signing');
const ringPath = join(outDir, 'arkheia-public-keys.json');
for (const p of [envPath, ringPath]) {
  if (existsSync(p)) {
    console.error(`refusing to overwrite ${p}`);
    process.exit(1);
  }
}
mkdirSync(outDir, { recursive: true });
writeFileSync(envPath, `ARKHEIA_SIGNING_SEED_HEX=${seedHex}\nARKHEIA_SIGNING_PUBLIC_KEY_ID=${key.publicKeyId}\n`, { mode: 0o600 });
writeFileSync(
  ringPath,
  `${JSON.stringify({ keys: [{ public_key_id: key.publicKeyId, algorithm: 'Ed25519', public_key_hex: key.publicKeyHex, status: 'active' }] }, null, 2)}\n`,
);
console.log(JSON.stringify({ public_key_id: key.publicKeyId, public_key_hex: key.publicKeyHex, env_file: envPath, keyring: ringPath }, null, 2));
console.error('Store the seed in your secret manager (Codespaces secret / GitHub Actions secret). Never commit .env.arkheia-signing.');
