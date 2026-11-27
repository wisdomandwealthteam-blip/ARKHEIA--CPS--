//! RFC 8785 JSON Canonicalization (integers-only profile).
//! Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

use crate::json::{Value, MAX_DEPTH, MAX_SAFE_INTEGER};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalizationError(pub String);

impl fmt::Display for CanonicalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "canonicalization error: {}", self.0)
    }
}
impl std::error::Error for CanonicalizationError {}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(v: &Value, out: &mut String, depth: usize) -> Result<(), CanonicalizationError> {
    if depth > MAX_DEPTH {
        return Err(CanonicalizationError("maximum nesting depth exceeded".into()));
    }
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => {
            if i.abs() > MAX_SAFE_INTEGER {
                return Err(CanonicalizationError("integer outside safe range".into()));
            }
            out.push_str(&i.to_string());
        }
        Value::Str(s) => escape(s, out),
        Value::Array(a) => {
            out.push('[');
            for (idx, item) in a.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write(item, out, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut entries: Vec<&(String, Value)> = m.iter().collect();
            // RFC 8785 §3.2.3: sort by UTF-16 code units.
            entries.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            for w in entries.windows(2) {
                if w[0].0 == w[1].0 {
                    return Err(CanonicalizationError(format!("duplicate key {}", w[0].0)));
                }
            }
            out.push('{');
            for (idx, (k, val)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                escape(k, out);
                out.push(':');
                write(val, out, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

pub fn canonicalize(v: &Value) -> Result<String, CanonicalizationError> {
    let mut out = String::new();
    write(v, &mut out, 0)?;
    Ok(out)
}

pub fn canonical_bytes(v: &Value) -> Result<Vec<u8>, CanonicalizationError> {
    canonicalize(v).map(String::into_bytes)
}
