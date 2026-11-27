//! Ed25519 keys via ed25519-dalek; SHA-256 via sha2.
//! Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

use crate::json::{parse_strict, s, Value};
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(pub String);
impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key error: {}", self.0)
    }
}
impl std::error::Error for KeyError {}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn to_hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0x0f) as usize] as char);
    }
    out
}

/// Lowercase-hex decoder; rejects uppercase and odd lengths.
pub fn from_hex(h: &str) -> Result<Vec<u8>, KeyError> {
    if h.len() % 2 != 0 {
        return Err(KeyError("odd-length hex".into()));
    }
    let val = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(KeyError("hex must be lowercase [0-9a-f]".into())),
    };
    h.as_bytes().chunks(2).map(|p| Ok(val(p[0])? << 4 | val(p[1])?)).collect()
}

fn hex32(h: &str, what: &str) -> Result<[u8; 32], KeyError> {
    let v = from_hex(h)?;
    v.try_into().map_err(|_| KeyError(format!("{what} must be 32 bytes / 64 hex chars")))
}

pub fn sha256_hex(data: &[u8]) -> String {
    to_hex(&sha256(data))
}

/// "ed25519:" + first 16 hex chars of SHA-256(raw public key).
pub fn public_key_id(raw: &[u8; 32]) -> String {
    format!("ed25519:{}", &sha256_hex(raw)[..16])
}

pub struct ReceiptSigningKey {
    inner: DalekSigningKey,
}

impl ReceiptSigningKey {
    /// Deterministic RFC 8032 derivation from a 32-byte seed.
    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, KeyError> {
        Ok(Self { inner: DalekSigningKey::from_bytes(&hex32(seed_hex, "seed")?) })
    }
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }
    pub fn public_key_hex(&self) -> String {
        to_hex(&self.public_key_bytes())
    }
    pub fn public_key_id(&self) -> String {
        public_key_id(&self.public_key_bytes())
    }
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.inner.sign(msg).to_bytes()
    }
    /// Reads ARKHEIA_SIGNING_SEED_HEX (and optional ARKHEIA_SIGNING_PUBLIC_KEY_ID cross-check),
    /// optionally merging KEY=VALUE pairs from a .env file (process env wins).
    pub fn from_env(env_file: Option<&Path>) -> Result<Self, KeyError> {
        let mut vars: BTreeMap<String, String> = BTreeMap::new();
        if let Some(p) = env_file {
            vars.extend(parse_env_file(p)?);
        }
        for k in ["ARKHEIA_SIGNING_SEED_HEX", "ARKHEIA_SIGNING_PUBLIC_KEY_ID"] {
            if let Ok(v) = std::env::var(k) {
                vars.insert(k.to_string(), v);
            }
        }
        Self::from_vars(&vars)
    }
    pub fn from_vars(vars: &BTreeMap<String, String>) -> Result<Self, KeyError> {
        let seed = vars.get("ARKHEIA_SIGNING_SEED_HEX").ok_or_else(|| KeyError("ARKHEIA_SIGNING_SEED_HEX is not set".into()))?;
        let key = Self::from_seed_hex(seed.trim())?;
        if let Some(expected) = vars.get("ARKHEIA_SIGNING_PUBLIC_KEY_ID") {
            if expected.trim() != key.public_key_id() {
                return Err(KeyError(format!("seed does not match ARKHEIA_SIGNING_PUBLIC_KEY_ID ({} != {})", expected.trim(), key.public_key_id())));
            }
        }
        Ok(key)
    }
}

pub fn parse_env_file(path: &Path) -> Result<BTreeMap<String, String>, KeyError> {
    let text = std::fs::read_to_string(path).map_err(|e| KeyError(format!("{}: {e}", path.display())))?;
    let mut out = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (k, v) = l.split_once('=').ok_or_else(|| KeyError(format!("{}:{}: expected KEY=VALUE", path.display(), n + 1)))?;
        let v = v.trim();
        let v = if v.len() >= 2 && (v.starts_with('"') && v.ends_with('"') || v.starts_with('\'') && v.ends_with('\'')) { &v[1..v.len() - 1] } else { v };
        out.insert(k.trim().to_string(), v.to_string());
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Revoked,
}

pub struct TrustedKey {
    pub id: String,
    pub raw: [u8; 32],
    pub status: KeyStatus,
    vk: VerifyingKey,
}

impl TrustedKey {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let arr: [u8; 64] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.vk.verify_strict(msg, &Signature::from_bytes(&arr)).is_ok()
    }
}

pub struct Keyring {
    keys: Vec<TrustedKey>,
}

impl Keyring {
    pub fn from_value(doc: &Value) -> Result<Self, KeyError> {
        let entries = doc.get("keys").and_then(Value::as_array).filter(|a| !a.is_empty()).ok_or_else(|| KeyError("keyring must contain a non-empty \"keys\" array".into()))?;
        let mut keys: Vec<TrustedKey> = Vec::new();
        for e in entries {
            if e.get("algorithm").and_then(Value::as_str) != Some("Ed25519") {
                return Err(KeyError("keyring entries must be Ed25519".into()));
            }
            let status = match e.get("status").and_then(Value::as_str) {
                Some("active") => KeyStatus::Active,
                Some("revoked") => KeyStatus::Revoked,
                _ => return Err(KeyError("keyring status must be active or revoked".into())),
            };
            let raw = hex32(e.get("public_key_hex").and_then(Value::as_str).unwrap_or(""), "public_key_hex")?;
            let vk = VerifyingKey::from_bytes(&raw).map_err(|_| KeyError("invalid Ed25519 public key".into()))?;
            let id = public_key_id(&raw);
            if e.get("public_key_id").and_then(Value::as_str) != Some(id.as_str()) {
                return Err(KeyError(format!("keyring id mismatch for {id}")));
            }
            if keys.iter().any(|k| k.id == id) {
                return Err(KeyError(format!("duplicate keyring id {id}")));
            }
            keys.push(TrustedKey { id, raw, status, vk });
        }
        Ok(Self { keys })
    }
    pub fn from_file(path: &Path) -> Result<Self, KeyError> {
        let text = std::fs::read_to_string(path).map_err(|e| KeyError(format!("{}: {e}", path.display())))?;
        Self::from_value(&parse_strict(&text).map_err(|e| KeyError(e.to_string()))?)
    }
    pub fn get(&self, id: &str) -> Option<&TrustedKey> {
        self.keys.iter().find(|k| k.id == id)
    }
    pub fn to_value(&self) -> Value {
        let mut ks: Vec<&TrustedKey> = self.keys.iter().collect();
        ks.sort_by(|a, b| a.id.cmp(&b.id));
        Value::Object(vec![(
            "keys".into(),
            Value::Array(
                ks.into_iter()
                    .map(|k| {
                        Value::Object(vec![
                            ("public_key_id".into(), s(&k.id)),
                            ("algorithm".into(), s("Ed25519")),
                            ("public_key_hex".into(), s(&to_hex(&k.raw))),
                            ("status".into(), s(if k.status == KeyStatus::Active { "active" } else { "revoked" })),
                        ])
                    })
                    .collect(),
            ),
        )])
    }
}
