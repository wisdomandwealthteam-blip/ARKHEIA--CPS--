// ARKHEIA DVE — receipt ledger interface (bps-ledger plug point).
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//
// Contract every ledger must honour:
//   head(chainId)  -> { sequence, receipt_hash } | null
//   append(chainId, { receipt, receipt_hash, expected_prev_hash })
//        MUST be atomic compare-and-append: throw LedgerConflictError if the
//        current head hash != expected_prev_hash (genesis: 64 zeros).
//   get(receipt_hash) -> receipt | null

import { appendFileSync, existsSync, mkdirSync, openSync, fsyncSync, closeSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

export const GENESIS_HASH = '0'.repeat(64);

export class LedgerConflictError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LedgerConflictError';
    this.code = 'LEDGER_CONFLICT';
  }
}

export class LedgerNotConfiguredError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LedgerNotConfiguredError';
    this.code = 'LEDGER_NOT_CONFIGURED';
  }
}

export class InMemoryLedger {
  #chains = new Map();
  #byHash = new Map();

  async head(chainId) {
    const c = this.#chains.get(chainId);
    return c && c.length ? { sequence: c.length - 1, receipt_hash: c[c.length - 1].receipt_hash } : null;
  }

  async append(chainId, { receipt, receipt_hash, expected_prev_hash }) {
    const c = this.#chains.get(chainId) ?? [];
    const currentHead = c.length ? c[c.length - 1].receipt_hash : GENESIS_HASH;
    if (currentHead !== expected_prev_hash) throw new LedgerConflictError(`head moved: ${currentHead} != ${expected_prev_hash}`);
    if (receipt.sequence !== c.length) throw new LedgerConflictError(`sequence ${receipt.sequence} != ${c.length}`);
    c.push({ receipt, receipt_hash });
    this.#chains.set(chainId, c);
    this.#byHash.set(receipt_hash, receipt);
  }

  async get(receiptHash) {
    return this.#byHash.get(receiptHash) ?? null;
  }
}

/**
 * Append-only JSONL ledger (one file per chain), fsync'd per write.
 * Single-process only. Use until bps-ledger is reachable.
 */
export class JsonlFileLedger {
  #dir;
  #cache = new Map();

  constructor(dir) {
    this.#dir = dir;
    mkdirSync(dir, { recursive: true });
  }

  #path(chainId) {
    if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(chainId)) throw new LedgerConflictError(`invalid chain id ${chainId}`);
    return `${this.#dir}/${chainId.replaceAll(':', '_')}.jsonl`;
  }

  #load(chainId) {
    if (this.#cache.has(chainId)) return this.#cache.get(chainId);
    const p = this.#path(chainId);
    const rows = existsSync(p)
      ? readFileSync(p, 'utf8').split('\n').filter((l) => l.length > 0).map((l) => JSON.parse(l))
      : [];
    this.#cache.set(chainId, rows);
    return rows;
  }

  async head(chainId) {
    const rows = this.#load(chainId);
    return rows.length ? { sequence: rows.length - 1, receipt_hash: rows[rows.length - 1].receipt_hash } : null;
  }

  async append(chainId, { receipt, receipt_hash, expected_prev_hash }) {
    const rows = this.#load(chainId);
    const currentHead = rows.length ? rows[rows.length - 1].receipt_hash : GENESIS_HASH;
    if (currentHead !== expected_prev_hash) throw new LedgerConflictError(`head moved: ${currentHead} != ${expected_prev_hash}`);
    const p = this.#path(chainId);
    mkdirSync(dirname(p), { recursive: true });
    appendFileSync(p, `${JSON.stringify({ receipt_hash, receipt })}\n`);
    const fd = openSync(p, 'r');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    rows.push({ receipt_hash, receipt });
  }

  async get(receiptHash) {
    for (const rows of this.#cache.values()) for (const r of rows) if (r.receipt_hash === receiptHash) return r.receipt;
    return null;
  }
}

/** bps-ledger adapter stub. Fails closed until wired to the real service. */
export class BpsLedgerAdapter {
  constructor(config = {}) {
    this.config = config; // e.g. { baseUrl, apiToken, timeoutMs }
  }

  async head(_chainId) {
    throw new LedgerNotConfiguredError('bps-ledger adapter not wired: implement head() against bps-ledger');
  }

  async append(_chainId, _entry) {
    throw new LedgerNotConfiguredError('bps-ledger adapter not wired: implement append() as atomic compare-and-append');
  }

  async get(_receiptHash) {
    throw new LedgerNotConfiguredError('bps-ledger adapter not wired: implement get()');
  }
}
