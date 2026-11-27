// ARKHEIA DVE — closed-subset JSON Schema (draft 2020-12) interpreter.
// Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//
// The schema file is the single source of truth: this module interprets it
// directly. Any keyword outside the supported set throws at load time, so a
// schema edit can never be silently ignored.

import { readFileSync } from 'node:fs';
import { canonicalize } from './jcs.mjs';

const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description']);
const ASSERTIONS = new Set([
  'type', 'const', 'enum', 'minLength', 'maxLength', 'pattern', 'not', '$ref',
  'additionalProperties', 'required', 'properties', 'allOf', 'if', 'then', 'else',
  'minimum', 'maximum', 'maxItems', 'uniqueItems', 'items', 'maxProperties',
  'propertyNames', '$defs',
]);

export class SchemaDefinitionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SchemaDefinitionError';
  }
}

function assertSupported(node, path) {
  if (typeof node === 'boolean') return;
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    throw new SchemaDefinitionError(`schema node at ${path} must be an object or boolean`);
  }
  for (const k of Object.keys(node)) {
    if (!ANNOTATIONS.has(k) && !ASSERTIONS.has(k)) {
      throw new SchemaDefinitionError(`unsupported schema keyword "${k}" at ${path}`);
    }
  }
  for (const k of ['not', 'if', 'then', 'else', 'items', 'propertyNames']) {
    if (k in node) assertSupported(node[k], `${path}/${k}`);
  }
  if (node.additionalProperties !== undefined) assertSupported(node.additionalProperties, `${path}/additionalProperties`);
  for (const group of ['properties', '$defs']) {
    if (node[group]) for (const [k, v] of Object.entries(node[group])) assertSupported(v, `${path}/${group}/${k}`);
  }
  if (node.allOf) node.allOf.forEach((s, i) => assertSupported(s, `${path}/allOf/${i}`));
  if (node.pattern !== undefined) new RegExp(node.pattern); // compile check
}

function jsonType(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v; // string | boolean | object
}

function typeMatches(expected, v) {
  const t = jsonType(v);
  if (expected === 'number') return t === 'number' || t === 'integer';
  return expected === t;
}

function deepEqual(a, b) {
  try {
    return canonicalize(a, { allowFloats: true }) === canonicalize(b, { allowFloats: true });
  } catch {
    return false;
  }
}

const codePointLength = (s) => {
  let c = 0;
  for (const _ of s) c++;
  return c;
};

export function compileSchema(root) {
  assertSupported(root, '#');
  const regexCache = new Map();
  const re = (p) => {
    let r = regexCache.get(p);
    if (!r) {
      r = new RegExp(p);
      regexCache.set(p, r);
    }
    return r;
  };
  const resolve = (ref) => {
    if (!ref.startsWith('#/')) throw new SchemaDefinitionError(`only local refs supported: ${ref}`);
    let node = root;
    for (const part of ref.slice(2).split('/')) {
      node = node?.[part];
      if (node === undefined) throw new SchemaDefinitionError(`unresolvable ref ${ref}`);
    }
    return node;
  };

  function validate(schema, value, path, errors) {
    if (schema === true) return;
    if (schema === false) {
      errors.push({ path, keyword: 'false' });
      return;
    }
    const before = errors.length;
    if (schema.$ref !== undefined) validate(resolve(schema.$ref), value, path, errors);
    if (schema.type !== undefined && !typeMatches(schema.type, value)) {
      errors.push({ path, keyword: 'type' });
      return; // remaining keywords are type-specific
    }
    if ('const' in schema && !deepEqual(schema.const, value)) errors.push({ path, keyword: 'const' });
    if (schema.enum !== undefined && !schema.enum.some((e) => deepEqual(e, value))) errors.push({ path, keyword: 'enum' });
    if (schema.not !== undefined) {
      const sub = [];
      validate(schema.not, value, path, sub);
      if (sub.length === 0) errors.push({ path, keyword: 'not' });
    }
    if (schema.allOf) for (const s of schema.allOf) validate(s, value, path, errors);
    if (schema.if !== undefined) {
      const sub = [];
      validate(schema.if, value, path, sub);
      if (sub.length === 0) {
        if (schema.then !== undefined) validate(schema.then, value, path, errors);
      } else if (schema.else !== undefined) {
        validate(schema.else, value, path, errors);
      }
    }

    const t = jsonType(value);
    if (t === 'string') {
      const len = codePointLength(value);
      if (schema.minLength !== undefined && len < schema.minLength) errors.push({ path, keyword: 'minLength' });
      if (schema.maxLength !== undefined && len > schema.maxLength) errors.push({ path, keyword: 'maxLength' });
      if (schema.pattern !== undefined && !re(schema.pattern).test(value)) errors.push({ path, keyword: 'pattern' });
    }
    if (t === 'integer' || t === 'number') {
      if (schema.minimum !== undefined && value < schema.minimum) errors.push({ path, keyword: 'minimum' });
      if (schema.maximum !== undefined && value > schema.maximum) errors.push({ path, keyword: 'maximum' });
    }
    if (t === 'array') {
      if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push({ path, keyword: 'maxItems' });
      if (schema.uniqueItems === true) {
        const seen = new Set();
        for (const item of value) {
          let key;
          try {
            key = canonicalize(item, { allowFloats: true });
          } catch {
            errors.push({ path, keyword: 'uniqueItems' });
            break;
          }
          if (seen.has(key)) {
            errors.push({ path, keyword: 'uniqueItems' });
            break;
          }
          seen.add(key);
        }
      }
      if (schema.items !== undefined) value.forEach((item, idx) => validate(schema.items, item, `${path}[${idx}]`, errors));
    }
    if (t === 'object') {
      const keys = Object.keys(value);
      if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) errors.push({ path, keyword: 'maxProperties' });
      if (schema.required) for (const r of schema.required) if (!Object.hasOwn(value, r)) errors.push({ path: `${path}.${r}`, keyword: 'required' });
      if (schema.propertyNames !== undefined) for (const k of keys) validate(schema.propertyNames, k, `${path}{${k}}`, errors);
      const props = schema.properties || {};
      for (const k of keys) {
        if (Object.hasOwn(props, k)) validate(props[k], value[k], `${path}.${k}`, errors);
        else if (schema.additionalProperties !== undefined) validate(schema.additionalProperties, value[k], `${path}.${k}`, errors);
      }
    }
    return errors.length === before;
  }

  return function validateRoot(value) {
    const errors = [];
    validate(root, value, '$', errors);
    return { valid: errors.length === 0, errors };
  };
}

const SCHEMA_URL = new URL('../schema/arkheia-receipt-schema-v1.json', import.meta.url);
export const RECEIPT_SCHEMA = JSON.parse(readFileSync(SCHEMA_URL, 'utf8'));
export const validateReceiptSchema = compileSchema(RECEIPT_SCHEMA);
