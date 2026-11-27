// ARKHEIA DVE — env-driven signer bootstrap (fail closed on any misconfiguration).
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//
//   ARKHEIA_ENGINE_ID            engine id (never a wrapper name)
//   ARKHEIA_ENGINE_COMMIT_SHA    40/64-hex build commit (falls back to GITHUB_SHA)
//   ARKHEIA_LEDGER               memory | jsonl:<dir> | bps:<base_url>
//   ARKHEIA_SIGNING_SEED_HEX     (+ optional ARKHEIA_SIGNING_PUBLIC_KEY_ID)

import { loadSigningKeyFromEnv } from './keys.mjs';
import { InMemoryLedger, JsonlFileLedger, BpsLedgerAdapter } from './ledger.mjs';
import { ReceiptSigner, ReceiptError, WRAPPER_DOMAINS } from './receipt.mjs';

export function ledgerFromEnv(env = process.env) {
  const spec = (env.ARKHEIA_LEDGER ?? '').trim();
  if (spec === 'memory') return new InMemoryLedger();
  if (spec.startsWith('jsonl:') && spec.length > 6) return new JsonlFileLedger(spec.slice(6));
  if (spec.startsWith('bps:')) return new BpsLedgerAdapter({ baseUrl: spec.slice(4) || undefined, apiToken: env.ARKHEIA_BPS_LEDGER_TOKEN });
  throw new ReceiptError('SIGNER_MISCONFIGURED', 'ARKHEIA_LEDGER must be memory | jsonl:<dir> | bps:<url>');
}

export function signerFromEnv({ env = process.env, envFile } = {}) {
  if (envFile) process.loadEnvFile(envFile);
  const engineId = env.ARKHEIA_ENGINE_ID ?? '';
  const commitSha = env.ARKHEIA_ENGINE_COMMIT_SHA || env.GITHUB_SHA || '';
  if (WRAPPER_DOMAINS.includes(engineId) || !/^[a-z][a-z0-9_-]{1,63}$/.test(engineId)) {
    throw new ReceiptError('SIGNER_MISCONFIGURED', 'ARKHEIA_ENGINE_ID must be an engine id (never a wrapper name)');
  }
  if (!/^([0-9a-f]{40}|[0-9a-f]{64})$/.test(commitSha)) {
    throw new ReceiptError('SIGNER_MISCONFIGURED', 'ARKHEIA_ENGINE_COMMIT_SHA (or GITHUB_SHA) must be a 40/64-hex commit');
  }
  return new ReceiptSigner({ signingKey: loadSigningKeyFromEnv({ env }), engineId, commitSha, ledger: ledgerFromEnv(env) });
}
