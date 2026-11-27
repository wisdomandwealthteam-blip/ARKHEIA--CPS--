// ARKHEIA DVE — Node receipt suite. Run: node --test test/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, sign } from 'node:crypto';
import {
  canonicalize, parseStrictJson, signingKeyFromSeedHex, Keyring, verifyReceipt, verifyChain, receiptHash, signingInput,
  ReceiptSigner, InMemoryLedger, JsonlFileLedger, BpsLedgerAdapter, LedgerConflictError, LedgerNotConfiguredError,
  buildVerdictPayload, digestJson, loadSigningKeyFromEnv, compileSchema, SchemaDefinitionError, GENESIS_HASH,
} from '../src/index.mjs';

const here = new URL('.', import.meta.url);
const V = JSON.parse(readFileSync(new URL('../../test-vectors/vectors.json', here), 'utf8'));
const keyring = new Keyring(V.keyring);
const key = signingKeyFromSeedHex(V.rfc8032_kat.seed_hex);

test('schema copy is byte-identical to the root schema', () => {
  const a = readFileSync(new URL('../schema/arkheia-receipt-schema-v1.json', here));
  const b = readFileSync(new URL('../../schema/arkheia-receipt-schema-v1.json', here));
  assert.equal(createHash('sha256').update(a).digest('hex'), createHash('sha256').update(b).digest('hex'));
});

test('RFC 8032 TEST 1 known answer', () => {
  assert.equal(key.publicKeyHex, V.rfc8032_kat.public_key_hex);
  assert.equal(sign(null, Buffer.alloc(0), key.privateKey).toString('hex'), V.rfc8032_kat.empty_message_signature_hex);
});

test('JCS: RFC 8785 ordering, escaping, numbers', () => {
  assert.equal(canonicalize({ b: 1, a: [true, null, 'x'], '\u20ac': 1, '\r': 2, '\ud83d\ude00': 3, '\ufb33': 4 }),
    '{"\\r":2,"a":[true,null,"x"],"b":1,"\u20ac":1,"\ud83d\ude00":3,"\ufb33":4}');
  assert.equal(canonicalize({ x: -0 }), '{"x":0}');
  assert.equal(canonicalize('\u0001\u001f\u007f\u2028'), '"\\u0001\\u001f\u007f\u2028"');
  assert.equal(canonicalize({ n: 1e21, m: 0.000001 }, { allowFloats: true }), '{"m":0.000001,"n":1e+21}');
  assert.throws(() => canonicalize({ a: 1.5 }), /non-integer/);
  assert.throws(() => canonicalize({ a: NaN }, { allowFloats: true }), /non-finite/);
  assert.throws(() => canonicalize({ a: undefined }), /unsupported/);
  assert.throws(() => canonicalize({ a: new Date() }), /non-plain/);
  assert.throws(() => canonicalize('\ud800'), /lone surrogate/);
  assert.throws(() => canonicalize(2 ** 53), /safe range/);
});

test('strict JSON rejects every raw negative vector', () => {
  for (const c of V.raw_negative) {
    assert.throws(() => parseStrictJson(c.text), (e) => e.code === c.expected_error_code, c.name);
  }
  const o = parseStrictJson('{"__proto__":{"polluted":1}}');
  assert.equal(Object.getPrototypeOf(o), Object.prototype);
  assert.equal({}.polluted, undefined);
  assert.deepEqual(parseStrictJson(' {"a":[1,-2,0],"b":"\\u00e9\\ud83d\\ude00"} '), { a: [1, -2, 0], b: '\u00e9\ud83d\ude00' });
  assert.throws(() => parseStrictJson('\ufeff{}'));
  assert.throws(() => parseStrictJson('01'));
  assert.throws(() => parseStrictJson('['.repeat(100) + ']'.repeat(100)), /depth/);
});

test('vector chain reproduces byte-for-byte and verifies', () => {
  for (const step of V.chain) {
    assert.equal(canonicalize(step.input), step.input_canonical);
    assert.equal(digestJson(step.input), step.receipt.input_digest);
    assert.equal(canonicalize(step.receipt), step.receipt_canonical);
    assert.equal(signingInput(step.receipt).toString('hex'), step.signing_input_hex);
    assert.equal(receiptHash(step.receipt), step.receipt_hash);
    // Re-parse through the strict boundary parser, then verify.
    const parsed = parseStrictJson(JSON.stringify(step.receipt));
    const r = verifyReceipt(parsed, keyring);
    assert.equal(r.valid, true, JSON.stringify(r));
    assert.equal(r.signer, V.keyring.keys[0].public_key_id);
  }
  const chainResult = verifyChain(V.chain.map((s) => s.receipt), keyring);
  assert.deepEqual(chainResult, { valid: true, length: 3, head_hash: V.chain[2].receipt_hash });
});

test('every negative vector fails with its exact error code', () => {
  for (const n of V.negative) {
    const r = verifyReceipt(n.receipt, keyring);
    assert.equal(r.valid, false, n.name);
    assert.equal(r.error_code, n.expected_error_code, n.name);
  }
});

test('tamper: every single-bit flip of any verdict_payload or prev_receipt_hash byte fails', () => {
  const original = V.chain[1].receipt;
  const canonical = canonicalize(original);
  let checked = 0;
  for (const field of ['verdict_payload', 'prev_receipt_hash']) {
    const fieldJson = canonicalize(original[field]);
    const start = canonical.indexOf(`"${field}":`) + field.length + 3;
    assert.equal(canonical.slice(start, start + fieldJson.length), fieldJson);
    for (let i = 0; i < fieldJson.length; i++) {
      const c = fieldJson.charCodeAt(i);
      for (const bit of [0x01, 0x20]) {
        const mutatedField = fieldJson.slice(0, i) + String.fromCharCode(c ^ bit) + fieldJson.slice(i + 1);
        let parsed;
        try {
          parsed = parseStrictJson(canonical.slice(0, start) + mutatedField + canonical.slice(start + fieldJson.length));
        } catch {
          checked++; // structurally broken JSON is rejected at the boundary — also a fail-closed outcome
          continue;
        }
        const r = verifyReceipt(parsed, keyring);
        if (canonicalize(parsed) === canonical) continue; // flip produced an identical document (impossible, guarded)
        assert.equal(r.valid, false, `${field}[${i}]^${bit}`);
        checked++;
      }
    }
  }
  assert.ok(checked > 300, `checked ${checked} mutations`);
});

test('chain link: wrong previous receipt and sequence gap are detected', () => {
  const [r0, r1, r2] = V.chain.map((s) => s.receipt);
  assert.equal(verifyReceipt(r2, keyring, { previousReceipt: r1 }).valid, true);
  assert.equal(verifyReceipt(r2, keyring, { previousReceipt: r0 }).error_code, 'CHAIN_LINK_MISMATCH');
  assert.equal(verifyChain([r0, r2], keyring).error_code, 'CHAIN_LINK_MISMATCH');
  assert.equal(verifyChain([r1, r2], keyring).valid, true, 'anchored mid-chain verification');
});

test('revoked keys are rejected', () => {
  const ring = new Keyring({ keys: [{ ...V.keyring.keys[0], status: 'revoked' }] });
  assert.equal(verifyReceipt(V.chain[0].receipt, ring).error_code, 'REVOKED_SIGNER');
  assert.throws(() => new Keyring({ keys: [{ ...V.keyring.keys[0], public_key_id: 'ed25519:0000000000000000' }] }), /id mismatch/);
});

const COMMIT = 'c40f49580a627dfd8f9975ef4bd0905ece623346';
const payload = (verdict = 'CLEARED') =>
  buildVerdictPayload({ verdict, reasonCodes: ['Z_LAST', 'A_FIRST'], ruleSet: { id: 'clearcheck.rules', version: '1.0.0' }, metrics: { n: 1 } });

test('signer: issues a verifiable hash chain into the ledger; payload arrays sorted', async () => {
  const ledger = new InMemoryLedger();
  let t = Date.UTC(2026, 10, 25, 0, 0, 0);
  const signer = new ReceiptSigner({ signingKey: key, engineId: 'custos', commitSha: COMMIT, ledger, clock: () => new Date(t++) });
  const issued = [];
  for (let i = 0; i < 5; i++) issued.push(await signer.issue({ wrapperDomain: 'clearcheck', inputDigest: digestJson({ i }), verdictPayload: payload() }));
  assert.deepEqual(issued[0].receipt.verdict_payload.reason_codes, ['A_FIRST', 'Z_LAST']);
  assert.equal(issued[0].receipt.prev_receipt_hash, GENESIS_HASH);
  assert.equal(verifyChain(issued.map((x) => x.receipt), keyring).valid, true);
  assert.deepEqual(await ledger.head(signer.chainId), { sequence: 4, receipt_hash: issued[4].receipt_hash });
  assert.deepEqual(await ledger.get(issued[2].receipt_hash), issued[2].receipt);
});

test('signer: concurrent issue() calls stay strictly linear', async () => {
  const ledger = new InMemoryLedger();
  const signer = new ReceiptSigner({ signingKey: key, engineId: 'custos', commitSha: COMMIT, ledger });
  const results = await Promise.all(Array.from({ length: 25 }, (_, i) =>
    signer.issue({ wrapperDomain: 'riskcheck', inputDigest: digestJson({ i }), verdictPayload: payload('LOW') })));
  assert.deepEqual(results.map((r) => r.receipt.sequence), [...Array(25).keys()]);
  assert.equal(verifyChain(results.map((r) => r.receipt), keyring).valid, true);
});

test('signer: refuses to sign schema-invalid payloads (fail closed, nothing ledgered)', async () => {
  const ledger = new InMemoryLedger();
  const signer = new ReceiptSigner({ signingKey: key, engineId: 'custos', commitSha: COMMIT, ledger });
  await assert.rejects(signer.issue({ wrapperDomain: 'musicguard', inputDigest: digestJson({}), verdictPayload: payload('CLEARED') }), (e) => e.code === 'SCHEMA_INVALID');
  await assert.rejects(signer.issue({ wrapperDomain: 'clearcheck', inputDigest: 'nope', verdictPayload: payload() }), (e) => e.code === 'SCHEMA_INVALID');
  const bad = payload();
  bad.metrics.score = 0.5;
  await assert.rejects(signer.issue({ wrapperDomain: 'clearcheck', inputDigest: digestJson({}), verdictPayload: bad }));
  const wrapperAsEngine = new ReceiptSigner({ signingKey: key, engineId: 'clearcheck', commitSha: COMMIT, ledger });
  await assert.rejects(wrapperAsEngine.issue({ wrapperDomain: 'clearcheck', inputDigest: digestJson({}), verdictPayload: payload() }), (e) => e.code === 'SCHEMA_INVALID');
  assert.equal(await ledger.head(signer.chainId), null);
});

test('signer: re-signs on ledger conflict, then gives up after 3 attempts', async () => {
  const inner = new InMemoryLedger();
  let conflicts = 1;
  const flaky = {
    head: (c) => inner.head(c),
    get: (h) => inner.get(h),
    append: async (c, e) => {
      if (conflicts-- > 0) throw new LedgerConflictError('simulated');
      return inner.append(c, e);
    },
  };
  const s = new ReceiptSigner({ signingKey: key, engineId: 'custos', commitSha: COMMIT, ledger: flaky });
  assert.equal((await s.issue({ wrapperDomain: 'clearcheck', inputDigest: digestJson({}), verdictPayload: payload() })).receipt.sequence, 0);
  conflicts = 99;
  await assert.rejects(s.issue({ wrapperDomain: 'clearcheck', inputDigest: digestJson({}), verdictPayload: payload() }), LedgerConflictError);
});

test('JSONL ledger persists across instances; bps-ledger stub fails closed', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'arkheia-ledger-'));
  const s1 = new ReceiptSigner({ signingKey: key, engineId: 'securus', commitSha: COMMIT, ledger: new JsonlFileLedger(dir) });
  const a = await s1.issue({ wrapperDomain: 'governancecheck', inputDigest: digestJson({ a: 1 }), verdictPayload: payload('COMPLIANT') });
  const s2 = new ReceiptSigner({ signingKey: key, engineId: 'securus', commitSha: COMMIT, ledger: new JsonlFileLedger(dir) });
  const b = await s2.issue({ wrapperDomain: 'governancecheck', inputDigest: digestJson({ a: 2 }), verdictPayload: payload('COMPLIANT') });
  assert.equal(b.receipt.prev_receipt_hash, a.receipt_hash);
  const s3 = new ReceiptSigner({ signingKey: key, engineId: 'securus', commitSha: COMMIT, ledger: new BpsLedgerAdapter() });
  await assert.rejects(s3.issue({ wrapperDomain: 'governancecheck', inputDigest: digestJson({}), verdictPayload: payload('COMPLIANT') }), LedgerNotConfiguredError);
});

test('env loading and keygen script', () => {
  const dir = mkdtempSync(join(tmpdir(), 'arkheia-keys-'));
  const script = new URL('../scripts/keygen.mjs', here).pathname;
  const out = JSON.parse(execFileSync(process.execPath, [script, '--out-dir', dir, '--from-seed', V.rfc8032_kat.seed_hex], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
  assert.equal(out.public_key_hex, V.rfc8032_kat.public_key_hex);
  assert.equal(statSync(join(dir, '.env.arkheia-signing')).mode & 0o777, 0o600);
  assert.throws(() => execFileSync(process.execPath, [script, '--out-dir', dir], { stdio: 'ignore' }), 'refuses overwrite');
  const env = {};
  const loaded = loadSigningKeyFromEnv({ env: { ARKHEIA_SIGNING_SEED_HEX: V.rfc8032_kat.seed_hex, ARKHEIA_SIGNING_PUBLIC_KEY_ID: out.public_key_id } });
  assert.equal(loaded.publicKeyId, out.public_key_id);
  assert.throws(() => loadSigningKeyFromEnv({ env }), /not set/);
  assert.throws(() => loadSigningKeyFromEnv({ env: { ARKHEIA_SIGNING_SEED_HEX: V.rfc8032_kat.seed_hex, ARKHEIA_SIGNING_PUBLIC_KEY_ID: 'ed25519:0000000000000000' } }), /does not match/);
  assert.throws(() => signingKeyFromSeedHex('ABC'), /64 lowercase hex/);
  assert.deepEqual(Keyring.fromFile(join(dir, 'arkheia-public-keys.json')).toJSON(), V.keyring);
});

test('schema interpreter rejects unknown keywords (no silent ignore)', () => {
  assert.throws(() => compileSchema({ type: 'object', format: 'date-time' }), SchemaDefinitionError);
  assert.throws(() => compileSchema({ properties: { a: { oneOf: [] } } }), SchemaDefinitionError);
});
