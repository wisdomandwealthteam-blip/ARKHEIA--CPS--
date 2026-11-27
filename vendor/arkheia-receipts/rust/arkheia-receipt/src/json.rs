//! Strict JSON value + parser (integers only, duplicate keys rejected).
//! Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

use std::fmt;

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Value>),
    /// Insertion-ordered; keys are unique (enforced by parser and `obj`).
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }
    /// Returns a copy without `key` (objects only).
    pub fn without(&self, key: &str) -> Value {
        match self {
            Value::Object(m) => Value::Object(m.iter().filter(|(k, _)| k != key).cloned().collect()),
            other => other.clone(),
        }
    }
    /// Returns a copy with `key` set (replacing any existing value).
    pub fn with(&self, key: &str, v: Value) -> Value {
        match self {
            Value::Object(m) => {
                let mut out: Vec<(String, Value)> = m.iter().filter(|(k, _)| k != key).cloned().collect();
                out.push((key.to_string(), v));
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
}

/// Builds an object; panics on duplicate keys (programmer error, never input-driven).
pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut out: Vec<(String, Value)> = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        assert!(!out.iter().any(|(e, _)| e == k), "duplicate key {k}");
        out.push((k.to_string(), v));
    }
    Value::Object(out)
}

pub fn s(v: &str) -> Value {
    Value::Str(v.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    pub message: String,
    pub offset: usize,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at offset {}", self.message, self.offset)
    }
}
impl std::error::Error for JsonError {}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn err<T>(&self, m: &str) -> Result<T, JsonError> {
        Err(JsonError { message: m.to_string(), offset: self.i })
    }
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn literal(&mut self, lit: &[u8], v: Value) -> Result<Value, JsonError> {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            Ok(v)
        } else {
            self.err("invalid literal")
        }
    }
    fn hex4(&mut self) -> Result<u32, JsonError> {
        if self.i + 4 > self.b.len() {
            return self.err("invalid unicode escape");
        }
        let mut v = 0u32;
        for k in 0..4 {
            let c = self.b[self.i + k];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return self.err("invalid unicode escape"),
            };
            v = v * 16 + d as u32;
        }
        self.i += 4;
        Ok(v)
    }
    fn string(&mut self) -> Result<String, JsonError> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => return self.err("unterminated string"),
            };
            match c {
                b'"' => {
                    self.i += 1;
                    break;
                }
                0x00..=0x1f => return self.err("unescaped control character"),
                b'\\' => {
                    self.i += 1;
                    let e = match self.peek() {
                        Some(e) => e,
                        None => return self.err("unterminated escape"),
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if !self.b[self.i..].starts_with(b"\\u") {
                                    return self.err("lone surrogate in string");
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return self.err("lone surrogate in string");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return self.err("lone surrogate in string");
                            } else {
                                hi
                            };
                            let ch = match char::from_u32(cp) {
                                Some(ch) => ch,
                                None => return self.err("invalid code point"),
                            };
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return self.err("invalid escape"),
                    }
                }
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        // Input was &str and escapes produce valid UTF-8, so this cannot fail.
        String::from_utf8(out).or_else(|_| self.err("invalid UTF-8"))
    }
    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return self.err("invalid number"),
        }
        if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E')) {
            return self.err("non-integer number forbidden");
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).unwrap_or("x");
        match text.parse::<i64>() {
            Ok(v) if v.abs() <= MAX_SAFE_INTEGER => Ok(Value::Int(v)),
            _ => self.err("integer outside safe range"),
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return self.err("maximum nesting depth exceeded");
        }
        self.ws();
        match self.peek() {
            None => self.err("unexpected end of input"),
            Some(b'{') => {
                self.i += 1;
                let mut m: Vec<(String, Value)> = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Value::Object(m));
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        return self.err("expected object key");
                    }
                    let k = self.string()?;
                    if m.iter().any(|(e, _)| *e == k) {
                        return self.err(&format!("duplicate key \"{k}\""));
                    }
                    self.ws();
                    if self.peek() != Some(b':') {
                        return self.err("expected colon");
                    }
                    self.i += 1;
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Object(m));
                        }
                        _ => return self.err("expected comma or closing brace"),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Value::Array(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Array(a));
                        }
                        _ => return self.err("expected comma or closing bracket"),
                    }
                }
            }
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            _ => self.err("unexpected character"),
        }
    }
}

/// Strict parse: duplicate keys, fractions/exponents, unsafe integers, lone
/// surrogates, BOM, trailing data and depth > 64 are all errors.
pub fn parse_strict(text: &str) -> Result<Value, JsonError> {
    if text.starts_with('\u{feff}') {
        return Err(JsonError { message: "byte order mark not allowed".into(), offset: 0 });
    }
    let mut p = Parser { b: text.as_bytes(), i: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return p.err("trailing data");
    }
    Ok(v)
}

/// Strict parse of raw bytes (must be valid UTF-8).
pub fn parse_strict_bytes(bytes: &[u8]) -> Result<Value, JsonError> {
    let text = std::str::from_utf8(bytes).map_err(|e| JsonError { message: "invalid UTF-8".into(), offset: e.valid_up_to() })?;
    parse_strict(text)
}
