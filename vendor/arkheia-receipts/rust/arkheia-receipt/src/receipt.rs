//! Receipt issuance and verification.
//! Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

use crate::jcs::{canonical_bytes, CanonicalizationError};
use crate::json::{obj, s, Value};
use crate::keys::{from_hex, sha256_hex, to_hex, KeyStatus, Keyring, ReceiptSigningKey};
use crate::ledger::{LedgerError, ReceiptLedger, GENESIS_HASH};
use crate::schema::{validate_receipt_schema, SchemaViolation};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: &str = "1.0.0";
pub const SIGNING_DOMAIN: &[u8] = b"arkheia.receipt.v1\x00";
pub const WRAPPER_DOMAINS: [&str; 6] = ["clearcheck", "musicguard", "governancecheck", "provenancecheck", "settlementcheck", "riskcheck"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    Schema(Vec<SchemaViolation>),
    Timestamp(String),
    Canonicalization(String),
    Ledger(LedgerError),
}

impl ReceiptError {
    pub fn code(&self) -> &'static str {
        match self {
            ReceiptError::Schema(_) => "SCHEMA_INVALID",
            ReceiptError::Timestamp(_) => "TIMESTAMP_INVALID",
            ReceiptError::Canonicalization(_) => "CANONICALIZATION_ERROR",
            ReceiptError::Ledger(e) => e.code(),
        }
    }
}
impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}
impl std::error::Error for ReceiptError {}
impl From<CanonicalizationError> for ReceiptError {
    fn from(e: CanonicalizationError) -> Self {
        ReceiptError::Canonicalization(e.0)
    }
}
impl From<LedgerError> for ReceiptError {
    fn from(e: LedgerError) -> Self {
        ReceiptError::Ledger(e)
    }
}

// ---------- timestamps (no chrono) ----------

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Milliseconds since the Unix epoch -> "YYYY-MM-DDTHH:MM:SS.mmmZ".
pub fn format_timestamp_millis(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", sod / 3600, (sod % 3600) / 60, sod % 60, ms % 1000)
}

pub fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub fn is_valid_timestamp(ts: &str) -> bool {
    let b = ts.as_bytes();
    if b.len() != 24 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'.' || b[23] != b'Z' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = &ts[r];
        if part.bytes().all(|c| c.is_ascii_digit()) { part.parse().ok() } else { None }
    };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(sec), Some(_ms)) =
        (num(0..4), num(5..7), num(8..10), num(11..13), num(14..16), num(17..19), num(20..23))
    else {
        return false;
    };
    let dim = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => return false,
    };
    y >= 1 && d >= 1 && d <= dim && h < 24 && mi < 60 && sec < 60
}

// ---------- payloads, digests, hashes ----------

pub fn digest_bytes(data: &[u8]) -> String {
    sha256_hex(data)
}

pub fn digest_json(v: &Value) -> Result<String, ReceiptError> {
    Ok(sha256_hex(&canonical_bytes(v)?))
}

/// Builds a verdict_payload with sorted (order-independent) arrays.
pub fn build_verdict_payload(verdict: &str, reason_codes: &[&str], rule_set_id: &str, rule_set_version: &str, evidence_digests: &[&str], metrics: &[(&str, i64)]) -> Value {
    let mut rc: Vec<&str> = reason_codes.to_vec();
    rc.sort_unstable();
    let mut ev: Vec<&str> = evidence_digests.to_vec();
    ev.sort_unstable();
    obj(vec![
        ("verdict", s(verdict)),
        ("reason_codes", Value::Array(rc.into_iter().map(s).collect())),
        ("rule_set", obj(vec![("id", s(rule_set_id)), ("version", s(rule_set_version))])),
        ("evidence_digests", Value::Array(ev.into_iter().map(s).collect())),
        ("metrics", Value::Object(metrics.iter().map(|(k, v)| (k.to_string(), Value::Int(*v))).collect())),
        ("determinism", obj(vec![("mode", s("deterministic")), ("fallback_used", Value::Bool(false))])),
    ])
}

pub fn signing_input(receipt: &Value) -> Result<Vec<u8>, ReceiptError> {
    let mut out = SIGNING_DOMAIN.to_vec();
    out.extend(canonical_bytes(&receipt.without("signature"))?);
    Ok(out)
}

pub fn receipt_hash(receipt: &Value) -> Result<String, ReceiptError> {
    Ok(sha256_hex(&canonical_bytes(receipt)?))
}

fn schema_check(receipt: &Value) -> Result<(), ReceiptError> {
    let errs = validate_receipt_schema(receipt);
    if !errs.is_empty() {
        return Err(ReceiptError::Schema(errs));
    }
    let ts = receipt.get("timestamp_utc").and_then(Value::as_str).unwrap_or("");
    if !is_valid_timestamp(ts) {
        return Err(ReceiptError::Timestamp(ts.to_string()));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ReceiptFields {
    pub engine_id: String,
    pub commit_sha: String,
    pub wrapper_domain: String,
    pub timestamp_utc: String,
    pub sequence: i64,
    pub input_digest: String,
    pub verdict_payload: Value,
    pub prev_receipt_hash: String,
}

fn placeholder_signature() -> Value {
    obj(vec![("algorithm", s("Ed25519")), ("public_key_id", s("ed25519:0000000000000000")), ("value", s(&"0".repeat(128)))])
}

/// Pure, ledger-free construction: validate -> sign -> validate.
pub fn sign_receipt(key: &ReceiptSigningKey, f: &ReceiptFields) -> Result<Value, ReceiptError> {
    let unsigned = obj(vec![
        ("schema_version", s(SCHEMA_VERSION)),
        ("engine_id", s(&f.engine_id)),
        ("commit_sha", s(&f.commit_sha)),
        ("wrapper_domain", s(&f.wrapper_domain)),
        ("timestamp_utc", s(&f.timestamp_utc)),
        ("sequence", Value::Int(f.sequence)),
        ("input_digest", s(&f.input_digest)),
        ("verdict_payload", f.verdict_payload.clone()),
        ("prev_receipt_hash", s(&f.prev_receipt_hash)),
    ]);
    schema_check(&unsigned.with("signature", placeholder_signature()))?;
    let sig = key.sign(&signing_input(&unsigned)?);
    let receipt = unsigned.with(
        "signature",
        obj(vec![("algorithm", s("Ed25519")), ("public_key_id", s(&key.public_key_id())), ("value", s(&to_hex(&sig)))]),
    );
    schema_check(&receipt)?;
    Ok(receipt)
}

// ---------- signer ----------

pub struct ReceiptSigner {
    key: ReceiptSigningKey,
    ledger: Arc<dyn ReceiptLedger>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    lock: Mutex<()>,
    pub engine_id: String,
    pub commit_sha: String,
    pub chain_id: String,
}

impl ReceiptSigner {
    pub fn new(key: ReceiptSigningKey, engine_id: &str, commit_sha: &str, ledger: Arc<dyn ReceiptLedger>) -> Self {
        let chain_id = format!("{engine_id}:{}", key.public_key_id());
        Self { key, ledger, clock: Box::new(now_millis), lock: Mutex::new(()), engine_id: engine_id.into(), commit_sha: commit_sha.into(), chain_id }
    }

    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    pub fn with_chain_id(mut self, chain_id: &str) -> Self {
        self.chain_id = chain_id.into();
        self
    }

    pub fn public_key_id(&self) -> String {
        self.key.public_key_id()
    }

    /// validate -> sign -> compare-and-append. Serialized per signer; re-signs on
    /// ledger conflict up to 3 attempts; every failure is returned, never swallowed.
    pub fn issue(&self, wrapper_domain: &str, input_digest: &str, verdict_payload: &Value) -> Result<(Value, String), ReceiptError> {
        let _g = self.lock.lock().map_err(|_| ReceiptError::Ledger(LedgerError::Io("poisoned signer lock".into())))?;
        let mut last = None;
        for _ in 0..3 {
            let head = self.ledger.head(&self.chain_id)?;
            let receipt = sign_receipt(
                &self.key,
                &ReceiptFields {
                    engine_id: self.engine_id.clone(),
                    commit_sha: self.commit_sha.clone(),
                    wrapper_domain: wrapper_domain.into(),
                    timestamp_utc: format_timestamp_millis((self.clock)()),
                    sequence: head.as_ref().map_or(0, |h| h.sequence + 1),
                    input_digest: input_digest.into(),
                    verdict_payload: verdict_payload.clone(),
                    prev_receipt_hash: head.map_or(GENESIS_HASH.to_string(), |h| h.receipt_hash),
                },
            )?;
            let h = receipt_hash(&receipt)?;
            let prev = receipt.get("prev_receipt_hash").and_then(Value::as_str).unwrap_or(GENESIS_HASH).to_string();
            match self.ledger.append(&self.chain_id, &receipt, &h, &prev) {
                Ok(()) => return Ok((receipt, h)),
                Err(e @ LedgerError::Conflict(_)) => last = Some(e),
                Err(e) => return Err(e.into()),
            }
        }
        Err(ReceiptError::Ledger(last.unwrap_or(LedgerError::Conflict("ledger head kept moving".into()))))
    }
}

// ---------- verification ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub valid: bool,
    pub error_code: Option<&'static str>,
    pub signer: Option<String>,
    pub receipt_hash: Option<String>,
}

impl VerifyResult {
    fn fail(code: &'static str) -> Self {
        Self { valid: false, error_code: Some(code), signer: None, receipt_hash: None }
    }
}

pub fn verify_receipt(receipt: &Value, keyring: &Keyring, previous: Option<&Value>) -> VerifyResult {
    if !validate_receipt_schema(receipt).is_empty() {
        return VerifyResult::fail("SCHEMA_INVALID");
    }
    let field = |path: &[&str]| -> &str {
        let mut v = receipt;
        for p in path {
            match v.get(p) {
                Some(n) => v = n,
                None => return "",
            }
        }
        v.as_str().unwrap_or("")
    };
    if !is_valid_timestamp(field(&["timestamp_utc"])) {
        return VerifyResult::fail("TIMESTAMP_INVALID");
    }
    let key = match keyring.get(field(&["signature", "public_key_id"])) {
        Some(k) => k,
        None => return VerifyResult::fail("UNKNOWN_SIGNER"),
    };
    if key.status != KeyStatus::Active {
        return VerifyResult::fail("REVOKED_SIGNER");
    }
    let (msg, sig) = match (signing_input(receipt), from_hex(field(&["signature", "value"]))) {
        (Ok(m), Ok(s)) => (m, s),
        (Err(_), _) => return VerifyResult::fail("CANONICALIZATION_ERROR"),
        _ => return VerifyResult::fail("SIGNATURE_INVALID"),
    };
    if !key.verify(&msg, &sig) {
        return VerifyResult::fail("SIGNATURE_INVALID");
    }
    let h = match receipt_hash(receipt) {
        Ok(h) => h,
        Err(_) => return VerifyResult::fail("CANONICALIZATION_ERROR"),
    };
    if let Some(prev) = previous {
        let pr = verify_receipt(prev, keyring, None);
        if !pr.valid {
            return VerifyResult::fail("PREVIOUS_RECEIPT_INVALID");
        }
        if pr.receipt_hash.as_deref() != Some(field(&["prev_receipt_hash"])) {
            return VerifyResult::fail("CHAIN_LINK_MISMATCH");
        }
        let seq = |v: &Value| v.get("sequence").and_then(Value::as_i64);
        if seq(prev).map(|p| p + 1) != seq(receipt) {
            return VerifyResult::fail("CHAIN_SEQUENCE_GAP");
        }
    }
    VerifyResult { valid: true, error_code: None, signer: Some(key.id.clone()), receipt_hash: Some(h) }
}

/// Ok(head_hash) or Err((index, error_code)).
pub fn verify_chain(receipts: &[Value], keyring: &Keyring) -> Result<String, (usize, &'static str)> {
    let mut head = GENESIS_HASH.to_string();
    for (i, r) in receipts.iter().enumerate() {
        let res = verify_receipt(r, keyring, if i > 0 { Some(&receipts[i - 1]) } else { None });
        if !res.valid {
            return Err((i, res.error_code.unwrap_or("VERIFICATION_ERROR")));
        }
        head = res.receipt_hash.unwrap_or_default();
    }
    Ok(head)
}
