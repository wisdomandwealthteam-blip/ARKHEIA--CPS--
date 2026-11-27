//! ARKHEIA DVE canonical receipts (schema v1.0.0).
//! Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//!
//! Dependencies: ed25519-dalek (signing) and sha2 (hashing) only. JSON parsing,
//! RFC 8785 canonicalization and schema validation are in-crate so behaviour is
//! byte-identical to the Node and Python toolkits and duplicate keys are rejected.

pub mod jcs;
pub mod json;
pub mod keys;
pub mod ledger;
pub mod pattern;
pub mod receipt;
pub mod schema;

pub use jcs::{canonical_bytes, canonicalize, CanonicalizationError};
pub use json::{obj, parse_strict, parse_strict_bytes, s, JsonError, Value};
pub use keys::{public_key_id, sha256_hex, KeyError, KeyStatus, Keyring, ReceiptSigningKey};
pub use ledger::{BpsLedgerAdapter, InMemoryLedger, JsonlFileLedger, LedgerError, LedgerHead, ReceiptLedger, GENESIS_HASH};
pub use receipt::{
    build_verdict_payload, digest_bytes, digest_json, format_timestamp_millis, is_valid_timestamp, now_millis, receipt_hash,
    sign_receipt, signing_input, verify_chain, verify_receipt, ReceiptError, ReceiptFields, ReceiptSigner, VerifyResult,
    SCHEMA_VERSION, SIGNING_DOMAIN, WRAPPER_DOMAINS,
};
pub use schema::{validate_receipt_schema, CompiledSchema, SchemaDefinitionError, SchemaViolation};
