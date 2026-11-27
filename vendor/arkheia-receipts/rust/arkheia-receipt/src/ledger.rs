//! Receipt ledger trait (bps-ledger plug point) + in-memory and JSONL impls.
//! Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//!
//! `append` MUST be an atomic compare-and-append: return `LedgerError::Conflict`
//! when the head hash != `expected_prev_hash` (genesis = 64 zeros).

use crate::jcs::canonicalize;
use crate::json::{parse_strict, Value};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    Conflict(String),
    NotConfigured(String),
    Io(String),
}

impl LedgerError {
    pub fn code(&self) -> &'static str {
        match self {
            LedgerError::Conflict(_) => "LEDGER_CONFLICT",
            LedgerError::NotConfigured(_) => "LEDGER_NOT_CONFIGURED",
            LedgerError::Io(_) => "LEDGER_IO",
        }
    }
}
impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for LedgerError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerHead {
    pub sequence: i64,
    pub receipt_hash: String,
}

pub trait ReceiptLedger: Send + Sync {
    fn head(&self, chain_id: &str) -> Result<Option<LedgerHead>, LedgerError>;
    fn append(&self, chain_id: &str, receipt: &Value, receipt_hash: &str, expected_prev_hash: &str) -> Result<(), LedgerError>;
    fn get(&self, receipt_hash: &str) -> Result<Option<Value>, LedgerError>;
}

#[derive(Default)]
pub struct InMemoryLedger {
    inner: Mutex<(HashMap<String, Vec<(String, Value)>>, HashMap<String, Value>)>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReceiptLedger for InMemoryLedger {
    fn head(&self, chain_id: &str) -> Result<Option<LedgerHead>, LedgerError> {
        let g = self.inner.lock().map_err(|_| LedgerError::Io("poisoned lock".into()))?;
        Ok(g.0.get(chain_id).and_then(|c| c.last().map(|(h, _)| LedgerHead { sequence: c.len() as i64 - 1, receipt_hash: h.clone() })))
    }
    fn append(&self, chain_id: &str, receipt: &Value, receipt_hash: &str, expected_prev_hash: &str) -> Result<(), LedgerError> {
        let mut g = self.inner.lock().map_err(|_| LedgerError::Io("poisoned lock".into()))?;
        let chain = g.0.entry(chain_id.to_string()).or_default();
        let current = chain.last().map(|(h, _)| h.as_str()).unwrap_or(GENESIS_HASH);
        if current != expected_prev_hash {
            return Err(LedgerError::Conflict(format!("head moved: {current} != {expected_prev_hash}")));
        }
        if receipt.get("sequence").and_then(Value::as_i64) != Some(chain.len() as i64) {
            return Err(LedgerError::Conflict("sequence mismatch".into()));
        }
        chain.push((receipt_hash.to_string(), receipt.clone()));
        g.1.insert(receipt_hash.to_string(), receipt.clone());
        Ok(())
    }
    fn get(&self, receipt_hash: &str) -> Result<Option<Value>, LedgerError> {
        let g = self.inner.lock().map_err(|_| LedgerError::Io("poisoned lock".into()))?;
        Ok(g.1.get(receipt_hash).cloned())
    }
}

/// Append-only JSONL (canonical JSON per line), fsync'd. Single-process only.
pub struct JsonlFileLedger {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl JsonlFileLedger {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, LedgerError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| LedgerError::Io(e.to_string()))?;
        Ok(Self { dir, lock: Mutex::new(()) })
    }
    fn path(&self, chain_id: &str) -> Result<PathBuf, LedgerError> {
        let ok = !chain_id.is_empty() && chain_id.len() <= 128 && chain_id.chars().all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c));
        if !ok {
            return Err(LedgerError::Conflict(format!("invalid chain id {chain_id}")));
        }
        Ok(self.dir.join(format!("{}.jsonl", chain_id.replace(':', "_"))))
    }
    fn rows(&self, chain_id: &str) -> Result<Vec<(String, Value)>, LedgerError> {
        let p = self.path(chain_id)?;
        if !p.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&p).map_err(|e| LedgerError::Io(e.to_string()))?;
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let row = parse_strict(l).map_err(|e| LedgerError::Io(e.to_string()))?;
                let h = row.get("receipt_hash").and_then(Value::as_str).ok_or_else(|| LedgerError::Io("corrupt row".into()))?.to_string();
                let r = row.get("receipt").cloned().ok_or_else(|| LedgerError::Io("corrupt row".into()))?;
                Ok((h, r))
            })
            .collect()
    }
}

impl ReceiptLedger for JsonlFileLedger {
    fn head(&self, chain_id: &str) -> Result<Option<LedgerHead>, LedgerError> {
        let _g = self.lock.lock().map_err(|_| LedgerError::Io("poisoned lock".into()))?;
        let rows = self.rows(chain_id)?;
        Ok(rows.last().map(|(h, _)| LedgerHead { sequence: rows.len() as i64 - 1, receipt_hash: h.clone() }))
    }
    fn append(&self, chain_id: &str, receipt: &Value, receipt_hash: &str, expected_prev_hash: &str) -> Result<(), LedgerError> {
        let _g = self.lock.lock().map_err(|_| LedgerError::Io("poisoned lock".into()))?;
        let rows = self.rows(chain_id)?;
        let current = rows.last().map(|(h, _)| h.as_str()).unwrap_or(GENESIS_HASH);
        if current != expected_prev_hash {
            return Err(LedgerError::Conflict(format!("head moved: {current} != {expected_prev_hash}")));
        }
        let row = Value::Object(vec![("receipt_hash".into(), Value::Str(receipt_hash.into())), ("receipt".into(), receipt.clone())]);
        let line = canonicalize(&row).map_err(|e| LedgerError::Io(e.to_string()))?;
        let mut f = OpenOptions::new().create(true).append(true).open(self.path(chain_id)?).map_err(|e| LedgerError::Io(e.to_string()))?;
        f.write_all(format!("{line}\n").as_bytes()).map_err(|e| LedgerError::Io(e.to_string()))?;
        f.sync_all().map_err(|e| LedgerError::Io(e.to_string()))
    }
    fn get(&self, receipt_hash: &str) -> Result<Option<Value>, LedgerError> {
        let _g = self.lock.lock().map_err(|_| LedgerError::Io("poisoned lock".into()))?;
        for entry in fs::read_dir(&self.dir).map_err(|e| LedgerError::Io(e.to_string()))? {
            let p = entry.map_err(|e| LedgerError::Io(e.to_string()))?.path();
            if p.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let chain = p.file_stem().and_then(|x| x.to_str()).unwrap_or_default().to_string();
            for (h, r) in self.rows(&chain)? {
                if h == receipt_hash {
                    return Ok(Some(r));
                }
            }
        }
        Ok(None)
    }
}

/// bps-ledger stub — fails closed until wired to the real service.
pub struct BpsLedgerAdapter {
    pub base_url: Option<String>,
}

impl ReceiptLedger for BpsLedgerAdapter {
    fn head(&self, _chain_id: &str) -> Result<Option<LedgerHead>, LedgerError> {
        Err(LedgerError::NotConfigured("bps-ledger adapter not wired: implement head()".into()))
    }
    fn append(&self, _c: &str, _r: &Value, _h: &str, _p: &str) -> Result<(), LedgerError> {
        Err(LedgerError::NotConfigured("bps-ledger adapter not wired: implement append() as atomic compare-and-append".into()))
    }
    fn get(&self, _receipt_hash: &str) -> Result<Option<Value>, LedgerError> {
        Err(LedgerError::NotConfigured("bps-ledger adapter not wired: implement get()".into()))
    }
}
