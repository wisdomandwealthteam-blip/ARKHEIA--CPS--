// ARKHEIA DVE — strict JSON parser for boundary inputs.
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//
// JSON.parse silently keeps the LAST duplicate key, which lets an attacker
// present two different documents to two different parsers. This parser
// rejects: duplicate keys, lone surrogates, non-integer numbers (when
// integersOnly), leading BOM, trailing data, and nesting deeper than 64.

export class StrictJsonError extends Error {
  constructor(message, offset) {
    super(`${message} at offset ${offset}`);
    this.name = 'StrictJsonError';
    this.code = 'BODY_PARSE_ERROR';
    this.offset = offset;
  }
}

const MAX_DEPTH = 64;

export function parseStrictJson(text, { integersOnly = true } = {}) {
  if (typeof text !== 'string') throw new StrictJsonError('input must be a string', 0);
  let i = 0;
  const n = text.length;

  const fail = (msg) => {
    throw new StrictJsonError(msg, i);
  };
  const ws = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const expectLiteral = (lit, val) => {
    if (text.startsWith(lit, i)) {
      i += lit.length;
      return val;
    }
    return fail('invalid literal');
  };

  const parseString = () => {
    i++; // opening quote
    let out = '';
    let chunkStart = i;
    while (true) {
      if (i >= n) fail('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(chunkStart, i);
        i++;
        break;
      }
      if (c < 0x20) fail('unescaped control character');
      if (c === 0x5c) {
        out += text.slice(chunkStart, i);
        i++;
        const e = text[i];
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            const hex = text.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('invalid unicode escape');
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            fail('invalid escape');
        }
        i++;
        chunkStart = i;
        continue;
      }
      i++;
    }
    if (!out.isWellFormed()) fail('lone surrogate in string');
    return out;
  };

  const parseNumber = () => {
    const start = i;
    const re = /-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
    re.lastIndex = i;
    const m = re.exec(text);
    if (!m || m[0].length === 0) fail('invalid number');
    if (integersOnly && (m[2] !== undefined || m[3] !== undefined)) fail('non-integer number forbidden');
    i = start + m[0].length;
    const v = Number(m[0]);
    if (!Number.isFinite(v)) fail('number out of range');
    if (integersOnly && !Number.isSafeInteger(v)) fail('integer outside safe range');
    return v;
  };

  const parseValue = (depth) => {
    if (depth > MAX_DEPTH) fail('maximum nesting depth exceeded');
    ws();
    if (i >= n) fail('unexpected end of input');
    const c = text[i];
    if (c === '{') {
      i++;
      const obj = {};
      const seen = new Set();
      ws();
      if (text[i] === '}') {
        i++;
        return obj;
      }
      while (true) {
        ws();
        if (text[i] !== '"') fail('expected object key');
        const key = parseString();
        if (seen.has(key)) fail(`duplicate key "${key}"`);
        seen.add(key);
        ws();
        if (text[i] !== ':') fail('expected colon');
        i++;
        const val = parseValue(depth + 1);
        // defineProperty: a "__proto__" key becomes an own property, never a prototype.
        Object.defineProperty(obj, key, { value: val, enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === '}') {
          i++;
          return obj;
        }
        fail('expected comma or closing brace');
      }
    }
    if (c === '[') {
      i++;
      const arr = [];
      ws();
      if (text[i] === ']') {
        i++;
        return arr;
      }
      while (true) {
        arr.push(parseValue(depth + 1));
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === ']') {
          i++;
          return arr;
        }
        fail('expected comma or closing bracket');
      }
    }
    if (c === '"') return parseString();
    if (c === 't') return expectLiteral('true', true);
    if (c === 'f') return expectLiteral('false', false);
    if (c === 'n') return expectLiteral('null', null);
    if (c === '-' || (c >= '0' && c <= '9')) return parseNumber();
    return fail('unexpected character');
  };

  if (n > 0 && text.charCodeAt(0) === 0xfeff) fail('byte order mark not allowed');
  const value = parseValue(0);
  ws();
  if (i !== n) fail('trailing data');
  return value;
}
