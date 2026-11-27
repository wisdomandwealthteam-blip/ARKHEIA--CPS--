// ARKHEIA DVE — egress helpers over real node:http.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import {
  ReceiptSigner, InMemoryLedger, BpsLedgerAdapter, signingKeyFromSeedHex, Keyring, verifyReceipt, parseStrictJson,
  buildVerdictPayload, digestJson, respondWithReceipt, sendSignedOverWebSocket, RECEIPT_HASH_HEADER,
} from '../src/index.mjs';

const V = JSON.parse(readFileSync(new URL('../../test-vectors/vectors.json', import.meta.url), 'utf8'));
const key = signingKeyFromSeedHex(V.rfc8032_kat.seed_hex);
const keyring = new Keyring(V.keyring);
const COMMIT = '1392b2c476b05ddc89ca56d757225b1cfc423d19';
const payload = buildVerdictPayload({ verdict: 'AI_ASSISTED', reasonCodes: ['STEM_SIGNATURE_MATCH'], ruleSet: { id: 'musicguard.forensics', version: '3.1.0' }, metrics: { confidence_bps: 8125 } });

async function serve(handler) {
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => srv.close(r)) };
}

test('HTTP: signed receipt body verifies and header carries its hash', async () => {
  const signer = new ReceiptSigner({ signingKey: key, engineId: 'musicguard_engine', commitSha: COMMIT, ledger: new InMemoryLedger() });
  const s = await serve((req, res) => respondWithReceipt(res, signer, { wrapperDomain: 'musicguard', inputDigest: digestJson({ track: 1 }), verdictPayload: payload }));
  try {
    const r = await fetch(s.url);
    const text = await r.text();
    assert.equal(r.status, 200);
    const receipt = parseStrictJson(text);
    const v = verifyReceipt(receipt, keyring);
    assert.equal(v.valid, true);
    assert.equal(r.headers.get(RECEIPT_HASH_HEADER), v.receipt_hash);
  } finally {
    await s.close();
  }
});

test('HTTP: issuance failure returns 500 with no verdict content', async () => {
  const signer = new ReceiptSigner({ signingKey: key, engineId: 'musicguard_engine', commitSha: COMMIT, ledger: new BpsLedgerAdapter() });
  const s = await serve((req, res) => respondWithReceipt(res, signer, { wrapperDomain: 'musicguard', inputDigest: digestJson({}), verdictPayload: payload }));
  try {
    const r = await fetch(s.url);
    assert.equal(r.status, 500);
    assert.deepEqual(await r.json(), { error_code: 'LEDGER_NOT_CONFIGURED' });
  } finally {
    await s.close();
  }
});

test('WebSocket: frames are signed receipts or bare error codes', async () => {
  const frames = [];
  const ws = { send: (f) => frames.push(JSON.parse(f)) };
  const ok = new ReceiptSigner({ signingKey: key, engineId: 'securus', commitSha: COMMIT, ledger: new InMemoryLedger() });
  await sendSignedOverWebSocket(ws, ok, { wrapperDomain: 'musicguard', inputDigest: digestJson({}), verdictPayload: payload });
  await sendSignedOverWebSocket(ws, ok, { wrapperDomain: 'clearcheck', inputDigest: digestJson({}), verdictPayload: payload }); // wrong verdict for domain
  assert.equal(frames[0].type, 'arkheia.receipt');
  assert.equal(verifyReceipt(frames[0].receipt, keyring).valid, true);
  assert.deepEqual(frames[1], { type: 'arkheia.error', error_code: 'SCHEMA_INVALID' });
});

test('signerFromEnv builds a working signer and fails closed on bad config', async () => {
  const { signerFromEnv, ReceiptError } = await import('../src/index.mjs');
  const base = { ARKHEIA_SIGNING_SEED_HEX: V.rfc8032_kat.seed_hex, ARKHEIA_ENGINE_ID: 'securus', ARKHEIA_ENGINE_COMMIT_SHA: COMMIT };
  const s = signerFromEnv({ env: { ...base, ARKHEIA_LEDGER: 'memory' } });
  const { receipt } = await s.issue({ wrapperDomain: 'musicguard', inputDigest: digestJson({}), verdictPayload: payload });
  assert.equal(verifyReceipt(receipt, keyring).valid, true);
  for (const bad of [base, { ...base, ARKHEIA_LEDGER: 'redis' }, { ...base, ARKHEIA_LEDGER: 'memory', ARKHEIA_ENGINE_ID: 'musicguard' }, { ...base, ARKHEIA_LEDGER: 'memory', ARKHEIA_ENGINE_COMMIT_SHA: 'abc' }]) {
    assert.throws(() => signerFromEnv({ env: bad }), ReceiptError);
  }
});
