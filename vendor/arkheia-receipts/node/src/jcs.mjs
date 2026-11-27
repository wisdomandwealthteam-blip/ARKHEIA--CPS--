// ARKHEIA DVE — RFC 8785 JSON Canonicalization Scheme (JCS)
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//
// Receipt canonicalization is integers-only (integersOnly: true) so that the
// Rust, Node and Python implementations produce byte-identical output.
// allowFloats is available ONLY for input digests of Node-native payloads and
// follows RFC 8785 / ECMAScript Number serialization exactly.

export class CanonicalizationError extends Error {
  constructor(message, path) {
    super(`${message} at ${path}`);
    this.name = 'CanonicalizationError';
    this.code = 'CANONICALIZATION_ERROR';
    this.path = path;
  }
}

const MAX_DEPTH = 64;

function isPlainObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function serialize(value, opts, path, depth) {
  if (depth > MAX_DEPTH) throw new CanonicalizationError('maximum nesting depth exceeded', path);
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number': {
      if (!Number.isFinite(value)) throw new CanonicalizationError('non-finite number', path);
      if (Number.isInteger(value)) {
        if (!Number.isSafeInteger(value) && !opts.allowFloats) throw new CanonicalizationError('integer outside safe range', path);
        return JSON.stringify(value); // -0 serializes as "0" per RFC 8785
      }
      if (!opts.allowFloats) throw new CanonicalizationError('non-integer number forbidden', path);
      return JSON.stringify(value); // ECMAScript Number.prototype.toString == RFC 8785 §3.2.2.3
    }
    case 'string':
      if (!value.isWellFormed()) throw new CanonicalizationError('string contains lone surrogate', path);
      return JSON.stringify(value); // ES JSON.stringify escaping == RFC 8785 §3.2.2.2
    case 'object': {
      if (Array.isArray(value)) {
        const parts = new Array(value.length);
        for (let i = 0; i < value.length; i++) {
          if (!(i in value)) throw new CanonicalizationError('sparse array', `${path}[${i}]`);
          parts[i] = serialize(value[i], opts, `${path}[${i}]`, depth + 1);
        }
        return `[${parts.join(',')}]`;
      }
      if (!isPlainObject(value)) throw new CanonicalizationError('non-plain object', path);
      if (Object.getOwnPropertySymbols(value).length > 0) throw new CanonicalizationError('symbol keys', path);
      // Default JS sort compares UTF-16 code units — exactly RFC 8785 §3.2.3.
      const keys = Object.keys(value).sort();
      const parts = [];
      for (const k of keys) {
        if (!k.isWellFormed()) throw new CanonicalizationError('key contains lone surrogate', path);
        parts.push(`${JSON.stringify(k)}:${serialize(value[k], opts, `${path}.${k}`, depth + 1)}`);
      }
      return `{${parts.join(',')}}`;
    }
    default:
      throw new CanonicalizationError(`unsupported type ${typeof value}`, path);
  }
}

/** Canonical JSON string. Throws CanonicalizationError; never silently coerces. */
export function canonicalize(value, { allowFloats = false } = {}) {
  return serialize(value, { allowFloats }, '$', 0);
}

/** Canonical UTF-8 bytes. */
export function canonicalBytes(value, opts) {
  return Buffer.from(canonicalize(value, opts), 'utf8');
}
