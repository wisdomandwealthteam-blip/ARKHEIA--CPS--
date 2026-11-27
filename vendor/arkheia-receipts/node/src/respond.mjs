// ARKHEIA DVE — fail-closed HTTP / WebSocket egress for signed receipts.
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//
// Invariant: a verdict NEVER leaves the service unsigned. If issuance fails
// (schema, ledger, key), the caller gets a 500 / error frame with an error
// code and no verdict content.

import { canonicalize } from './jcs.mjs';

export const RECEIPT_HASH_HEADER = 'x-arkheia-receipt-hash';

function errorCode(e) {
  return typeof e?.code === 'string' && /^[A-Z_]{3,64}$/.test(e.code) ? e.code : 'RECEIPT_ISSUANCE_FAILED';
}

/**
 * Works with node:http ServerResponse and Express/Fastify-raw responses.
 * @returns {Promise<{ok: true, receipt, receipt_hash} | {ok: false, error_code}>}
 */
export async function respondWithReceipt(res, signer, { wrapperDomain, inputDigest, verdictPayload, status = 200 }) {
  let issued;
  try {
    issued = await signer.issue({ wrapperDomain, inputDigest, verdictPayload });
  } catch (e) {
    const code = errorCode(e);
    const body = canonicalize({ error_code: code });
    res.statusCode = 500;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.setHeader('content-length', Buffer.byteLength(body));
    res.setHeader('cache-control', 'no-store');
    res.end(body);
    return { ok: false, error_code: code };
  }
  const body = canonicalize(issued.receipt);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('content-length', Buffer.byteLength(body));
  res.setHeader('cache-control', 'no-store');
  res.setHeader(RECEIPT_HASH_HEADER, issued.receipt_hash);
  res.end(body);
  return { ok: true, ...issued };
}

/**
 * Sends a signed receipt frame over any WebSocket-like object with send(string).
 * Frame: {"type":"arkheia.receipt","receipt":{...}} or {"type":"arkheia.error","error_code":"..."}
 */
export async function sendSignedOverWebSocket(ws, signer, { wrapperDomain, inputDigest, verdictPayload }) {
  try {
    const issued = await signer.issue({ wrapperDomain, inputDigest, verdictPayload });
    ws.send(canonicalize({ type: 'arkheia.receipt', receipt: issued.receipt }));
    return { ok: true, ...issued };
  } catch (e) {
    const code = errorCode(e);
    ws.send(canonicalize({ type: 'arkheia.error', error_code: code }));
    return { ok: false, error_code: code };
  }
}
