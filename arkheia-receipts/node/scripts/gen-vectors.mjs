#!/usr/bin/env node
// ARKHEIA DVE — cross-language test vector generator.
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//
// Uses the PUBLIC RFC 8032 §7.1 TEST 1 seed. Never use it in production.
// Output is consumed by the Node, Python and Rust suites; all three must agree
// byte-for-byte (Ed25519 is deterministic, so signatures must match exactly).

import { writeFileSync } from 'node:fs';
import {
  signingKeyFromSeedHex, signReceipt, receiptHash, canonicalize, signingInput, buildVerdictPayload, digestJson, GENESIS_HASH,
} from '../src/index.mjs';

const out = process.argv[2];
if (!out) {
  console.error('usage: gen-vectors.mjs OUT.json');
  process.exit(1);
}

const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const key = signingKeyFromSeedHex(SEED);
const COMMIT = 'e16c0daa0814db8fb80115a0937436e80113d9a3';

const inputs = [
  { case_id: 'CC-0001', asset: 'track-01.wav', rights_holder: 'Example Holder', 'unicode_é中😀': 'ok\n\t"q"' },
  { case_id: 'MG-0002', bytes_sha256: 'a'.repeat(64), sample_rate_hz: 48000 },
  { policy: 'AC-2(3)', accounts: [3, 1, 2], nested: { b: 1, a: [true, false, null] } },
];

const steps = [
  ['clearcheck', 'CLEARED', ['CHAIN_OF_TITLE_COMPLETE', 'ALL_SPLITS_SIGNED'], { id: 'clearcheck.rules', version: '1.0.0' }, { splits_total_bps: 10000 }],
  ['musicguard', 'AI_ASSISTED', ['STEM_SIGNATURE_MATCH'], { id: 'musicguard.forensics', version: '3.1.0' }, { confidence_bps: 8125, segments_flagged: 3 }],
  ['governancecheck', 'NON_COMPLIANT', ['DORMANT_ACCOUNT_ACTIVE', 'AC_2_3_VIOLATION'], { id: 'custos.ac2', version: '1.0.0' }, { dormant_days: 91 }],
];

const chain = [];
let prev = GENESIS_HASH;
steps.forEach(([domain, verdict, reasons, ruleSet, metrics], i) => {
  const receipt = signReceipt(key, {
    engine_id: 'supreme_kernel',
    commit_sha: COMMIT,
    wrapper_domain: domain,
    timestamp_utc: `2026-11-25T12:00:0${i}.000Z`,
    sequence: i,
    input_digest: digestJson(inputs[i]),
    verdict_payload: buildVerdictPayload({ verdict, reasonCodes: reasons, ruleSet, evidenceDigests: [digestJson(inputs[i])], metrics }),
    prev_receipt_hash: prev,
  });
  const hash = receiptHash(receipt);
  chain.push({
    input: inputs[i],
    input_canonical: canonicalize(inputs[i]),
    receipt,
    signing_input_hex: signingInput(receipt).toString('hex'),
    receipt_canonical: canonicalize(receipt),
    receipt_hash: hash,
  });
  prev = hash;
});

const base = chain[1].receipt;
const clone = () => JSON.parse(JSON.stringify(base));
const flipHex = (h, idx) => h.slice(0, idx) + (h[idx] === '0' ? '1' : '0') + h.slice(idx + 1);

const negative = [];
const add = (name, mutate, expected) => {
  const r = clone();
  mutate(r);
  negative.push({ name, receipt: r, expected_error_code: expected });
};
add('verdict_payload_metric_changed_by_one', (r) => { r.verdict_payload.metrics.confidence_bps += 1; }, 'SIGNATURE_INVALID');
add('verdict_payload_reason_byte_flipped', (r) => { r.verdict_payload.reason_codes[0] = 'STEM_SIGNATURE_MATCI'; }, 'SIGNATURE_INVALID');
add('prev_receipt_hash_byte_flipped', (r) => { r.prev_receipt_hash = flipHex(r.prev_receipt_hash, 10); }, 'SIGNATURE_INVALID');
add('input_digest_byte_flipped', (r) => { r.input_digest = flipHex(r.input_digest, 0); }, 'SIGNATURE_INVALID');
add('signature_byte_flipped', (r) => { r.signature.value = flipHex(r.signature.value, 5); }, 'SIGNATURE_INVALID');
add('timestamp_changed', (r) => { r.timestamp_utc = '2026-11-25T12:00:01.001Z'; }, 'SIGNATURE_INVALID');
add('unknown_signer', (r) => { r.signature.public_key_id = 'ed25519:ffffffffffffffff'; }, 'UNKNOWN_SIGNER');
add('verdict_not_allowed_for_domain', (r) => { r.verdict_payload.verdict = 'CLEARED'; }, 'SCHEMA_INVALID');
add('engine_id_is_wrapper_name', (r) => { r.engine_id = 'musicguard'; }, 'SCHEMA_INVALID');
add('engine_id_trailing_newline', (r) => { r.engine_id = 'supreme_kernel\n'; }, 'SCHEMA_INVALID');
add('extra_top_level_field', (r) => { r.note = 'x'; }, 'SCHEMA_INVALID');
add('missing_signature', (r) => { delete r.signature; }, 'SCHEMA_INVALID');
add('fallback_used_true', (r) => { r.verdict_payload.determinism.fallback_used = true; }, 'SCHEMA_INVALID');
add('uppercase_hex_digest', (r) => { r.input_digest = r.input_digest.toUpperCase(); }, 'SCHEMA_INVALID');
add('sequence_negative', (r) => { r.sequence = -1; }, 'SCHEMA_INVALID');
add('year_zero_timestamp', (r) => { r.timestamp_utc = '0000-01-01T00:00:00.000Z'; }, 'TIMESTAMP_INVALID');
add('duplicate_reason_codes', (r) => { r.verdict_payload.reason_codes = ['A', 'A']; }, 'SCHEMA_INVALID');
add('genesis_rule_seq0_nonzero_prev', (r) => { r.sequence = 0; }, 'SCHEMA_INVALID');
add('genesis_rule_seq1_zero_prev', (r) => { r.prev_receipt_hash = GENESIS_HASH; }, 'SCHEMA_INVALID');
add('impossible_calendar_date', (r) => { r.timestamp_utc = '2026-02-30T12:00:00.000Z'; }, 'TIMESTAMP_INVALID');

const rawNegative = [
  { name: 'duplicate_key', text: '{"a":1,"a":2}', expected_error_code: 'BODY_PARSE_ERROR' },
  { name: 'fractional_number', text: '{"a":1.0}', expected_error_code: 'BODY_PARSE_ERROR' },
  { name: 'exponent_number', text: '{"a":1e3}', expected_error_code: 'BODY_PARSE_ERROR' },
  { name: 'lone_surrogate', text: '{"a":"\\ud800"}', expected_error_code: 'BODY_PARSE_ERROR' },
  { name: 'nan_literal', text: '{"a":NaN}', expected_error_code: 'BODY_PARSE_ERROR' },
  { name: 'trailing_data', text: '{"a":1} x', expected_error_code: 'BODY_PARSE_ERROR' },
  { name: 'unsafe_integer', text: '{"a":9007199254740992}', expected_error_code: 'BODY_PARSE_ERROR' },
];

const vectors = {
  description: 'ARKHEIA DVE receipt v1.0.0 cross-language vectors. RFC 8032 TEST 1 seed — PUBLIC, TEST ONLY.',
  rfc8032_kat: {
    seed_hex: SEED,
    public_key_hex: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    empty_message_signature_hex:
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },
  keyring: { keys: [{ public_key_id: key.publicKeyId, algorithm: 'Ed25519', public_key_hex: key.publicKeyHex, status: 'active' }] },
  chain,
  negative,
  raw_negative: rawNegative,
};

writeFileSync(out, `${JSON.stringify(vectors, null, 2)}\n`);
console.log(`wrote ${out}: ${chain.length} chain receipts, ${negative.length} negative receipts, ${rawNegative.length} raw parse cases`);
