//! ARKHEIA DVE — Rust receipt suite. Run: cargo test
use arkheia_receipt::*;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("data").join(name)
}

fn vectors() -> Value {
    parse_strict(&std::fs::read_to_string(data("vectors.json")).expect("vectors.json")).expect("vectors parse strictly")
}

fn st<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("missing {k}"))
}

fn keyring(v: &Value) -> Keyring {
    Keyring::from_value(v.get("keyring").unwrap()).unwrap()
}

fn seed(v: &Value) -> String {
    st(v.get("rfc8032_kat").unwrap(), "seed_hex").to_string()
}

const COMMIT: &str = "2b11d74b6812b2930c82073916b93376ea03232a";

#[test]
fn schema_copy_matches_root_schema() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schema/arkheia-receipt-schema-v1.json");
    if let Ok(root_bytes) = std::fs::read(&root) {
        assert_eq!(sha256_hex(&root_bytes), sha256_hex(schema::RECEIPT_SCHEMA_JSON.as_bytes()), "schema copy drifted");
    }
}

#[test]
fn rfc8032_known_answer() {
    let v = vectors();
    let kat = v.get("rfc8032_kat").unwrap();
    let key = ReceiptSigningKey::from_seed_hex(st(kat, "seed_hex")).unwrap();
    assert_eq!(key.public_key_hex(), st(kat, "public_key_hex"));
    assert_eq!(keys::to_hex(&key.sign(b"")), st(kat, "empty_message_signature_hex"));
}

#[test]
fn jcs_rules() {
    let v = parse_strict("{\"b\":1,\"a\":[true,null,\"x\"],\"\u{20ac}\":1,\"\\r\":2,\"\u{1f600}\":3,\"\u{fb33}\":4}").unwrap();
    assert_eq!(canonicalize(&v).unwrap(), "{\"\\r\":2,\"a\":[true,null,\"x\"],\"b\":1,\"\u{20ac}\":1,\"\u{1f600}\":3,\"\u{fb33}\":4}");
    assert_eq!(canonicalize(&s("\u{1}\u{1f}\u{7f}\u{2028}")).unwrap(), "\"\\u0001\\u001f\u{7f}\u{2028}\"");
    assert!(canonicalize(&Value::Int(9_007_199_254_740_992)).is_err());
}

#[test]
fn strict_parser_rejects_raw_negatives() {
    let v = vectors();
    for c in v.get("raw_negative").unwrap().as_array().unwrap() {
        assert!(parse_strict(st(c, "text")).is_err(), "{}", st(c, "name"));
    }
    assert!(parse_strict("\u{feff}{}").is_err());
    assert!(parse_strict("01").is_err());
    assert!(parse_strict(&format!("{}{}", "[".repeat(100), "]".repeat(100))).is_err());
    assert!(parse_strict_bytes(b"{\"a\":\"\xff\"}").is_err());
    assert_eq!(parse_strict(r#"{"b":"\u00e9\ud83d\ude00"}"#).unwrap().get("b").unwrap().as_str(), Some("é😀"));
}

#[test]
fn vector_chain_is_byte_identical_and_signatures_reproduce() {
    let v = vectors();
    let ring = keyring(&v);
    let key = ReceiptSigningKey::from_seed_hex(&seed(&v)).unwrap();
    let mut receipts = Vec::new();
    for step in v.get("chain").unwrap().as_array().unwrap() {
        let r = step.get("receipt").unwrap();
        assert_eq!(canonicalize(step.get("input").unwrap()).unwrap(), st(step, "input_canonical"));
        assert_eq!(digest_json(step.get("input").unwrap()).unwrap(), st(r, "input_digest"));
        assert_eq!(canonicalize(r).unwrap(), st(step, "receipt_canonical"));
        assert_eq!(keys::to_hex(&signing_input(r).unwrap()), st(step, "signing_input_hex"));
        assert_eq!(receipt_hash(r).unwrap(), st(step, "receipt_hash"));
        let fields = ReceiptFields {
            engine_id: st(r, "engine_id").into(),
            commit_sha: st(r, "commit_sha").into(),
            wrapper_domain: st(r, "wrapper_domain").into(),
            timestamp_utc: st(r, "timestamp_utc").into(),
            sequence: r.get("sequence").unwrap().as_i64().unwrap(),
            input_digest: st(r, "input_digest").into(),
            verdict_payload: r.get("verdict_payload").unwrap().clone(),
            prev_receipt_hash: st(r, "prev_receipt_hash").into(),
        };
        let resigned = sign_receipt(&key, &fields).unwrap();
        assert_eq!(canonicalize(&resigned).unwrap(), st(step, "receipt_canonical"), "Rust signature must equal Node/Python byte-for-byte");
        let res = verify_receipt(r, &ring, None);
        assert!(res.valid, "{res:?}");
        assert_eq!(res.receipt_hash.as_deref(), Some(st(step, "receipt_hash")));
        receipts.push(r.clone());
    }
    assert_eq!(verify_chain(&receipts, &ring).unwrap(), st(&v.get("chain").unwrap().as_array().unwrap()[2], "receipt_hash"));
    assert_eq!(verify_chain(&[receipts[0].clone(), receipts[2].clone()], &ring), Err((1, "CHAIN_LINK_MISMATCH")));
}

#[test]
fn negative_vectors_fail_with_exact_code() {
    let v = vectors();
    let ring = keyring(&v);
    for n in v.get("negative").unwrap().as_array().unwrap() {
        let res = verify_receipt(n.get("receipt").unwrap(), &ring, None);
        assert!(!res.valid, "{}", st(n, "name"));
        assert_eq!(res.error_code, Some(st(n, "expected_error_code")), "{}", st(n, "name"));
    }
}

#[test]
fn tamper_every_bit_flip_in_verdict_payload_and_prev_hash_fails() {
    let v = vectors();
    let ring = keyring(&v);
    let original = v.get("chain").unwrap().as_array().unwrap()[1].get("receipt").unwrap().clone();
    let canonical = canonicalize(&original).unwrap();
    let mut checked = 0;
    for field in ["verdict_payload", "prev_receipt_hash"] {
        let fj = canonicalize(original.get(field).unwrap()).unwrap();
        let start = canonical.find(&format!("\"{field}\":")).unwrap() + field.len() + 3;
        assert_eq!(&canonical[start..start + fj.len()], fj);
        for i in 0..fj.len() {
            for bit in [0x01u8, 0x20u8] {
                let mut bytes = canonical.clone().into_bytes();
                bytes[start + i] ^= bit;
                checked += 1;
                let Ok(parsed) = parse_strict_bytes(&bytes) else { continue }; // boundary rejection = fail closed
                assert!(!verify_receipt(&parsed, &ring, None).valid, "{field}[{i}]^{bit:#x}");
            }
        }
    }
    assert!(checked > 300);
}

fn payload(verdict: &str) -> Value {
    build_verdict_payload(verdict, &["Z_LAST", "A_FIRST"], "clearcheck.rules", "1.0.0", &[], &[("n", 1)])
}

fn clock() -> impl Fn() -> u64 + Send + Sync + 'static {
    let t = Arc::new(AtomicU64::new(1_795_000_000_000));
    move || t.fetch_add(1, Ordering::SeqCst)
}

#[test]
fn signer_chain_concurrency_and_fail_closed() {
    let v = vectors();
    let ring = keyring(&v);
    let ledger = Arc::new(InMemoryLedger::new());
    let signer = Arc::new(ReceiptSigner::new(ReceiptSigningKey::from_seed_hex(&seed(&v)).unwrap(), "single_loop_harness", COMMIT, ledger.clone()).with_clock(clock()));
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let s = signer.clone();
            std::thread::spawn(move || (0..5).map(|i| s.issue("riskcheck", &digest_json(&Value::Int(t * 10 + i)).unwrap(), &payload("LOW")).unwrap().0).collect::<Vec<_>>())
        })
        .collect();
    let mut all: Vec<Value> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    all.sort_by_key(|r| r.get("sequence").unwrap().as_i64().unwrap());
    assert_eq!(all.iter().map(|r| r.get("sequence").unwrap().as_i64().unwrap()).collect::<Vec<_>>(), (0..40).collect::<Vec<_>>());
    assert_eq!(st(&all[0], "prev_receipt_hash"), GENESIS_HASH);
    assert_eq!(all[0].get("verdict_payload").unwrap().get("reason_codes").unwrap(), &Value::Array(vec![s("A_FIRST"), s("Z_LAST")]));
    assert!(verify_chain(&all, &ring).is_ok());
    assert!(format_timestamp_millis(1_795_000_000_000).ends_with(".000Z"));

    let fresh = Arc::new(InMemoryLedger::new());
    let s2 = ReceiptSigner::new(ReceiptSigningKey::from_seed_hex(&seed(&v)).unwrap(), "single_loop_harness", COMMIT, fresh.clone());
    let d = digest_json(&Value::Null).unwrap();
    assert_eq!(s2.issue("musicguard", &d, &payload("CLEARED")).unwrap_err().code(), "SCHEMA_INVALID");
    assert_eq!(s2.issue("clearcheck", "nope", &payload("CLEARED")).unwrap_err().code(), "SCHEMA_INVALID");
    assert_eq!(s2.issue("clearcheck", &d, &payload("CLEARED").with("extra", Value::Int(1))).unwrap_err().code(), "SCHEMA_INVALID");
    let wrapper_as_engine = ReceiptSigner::new(ReceiptSigningKey::from_seed_hex(&seed(&v)).unwrap(), "clearcheck", COMMIT, fresh.clone());
    assert_eq!(wrapper_as_engine.issue("clearcheck", &d, &payload("CLEARED")).unwrap_err().code(), "SCHEMA_INVALID");
    assert_eq!(fresh.head(&s2.chain_id).unwrap(), None);
}

#[test]
fn jsonl_ledger_persists_and_bps_stub_fails_closed() {
    let v = vectors();
    let dir = std::env::temp_dir().join(format!("arkheia-ledger-{}-{}", std::process::id(), now_millis()));
    let mk = || ReceiptSigner::new(ReceiptSigningKey::from_seed_hex(&seed(&v)).unwrap(), "single_loop_harness", COMMIT, Arc::new(JsonlFileLedger::new(&dir).unwrap()));
    let (_r1, h1) = mk().issue("provenancecheck", &digest_json(&Value::Int(1)).unwrap(), &payload("VERIFIED")).unwrap();
    let (r2, _) = mk().issue("provenancecheck", &digest_json(&Value::Int(2)).unwrap(), &payload("VERIFIED")).unwrap();
    assert_eq!(st(&r2, "prev_receipt_hash"), h1);
    assert!(JsonlFileLedger::new(&dir).unwrap().get(&h1).unwrap().is_some());
    let stub = ReceiptSigner::new(ReceiptSigningKey::from_seed_hex(&seed(&v)).unwrap(), "single_loop_harness", COMMIT, Arc::new(BpsLedgerAdapter { base_url: None }));
    assert_eq!(stub.issue("provenancecheck", &digest_json(&Value::Int(3)).unwrap(), &payload("VERIFIED")).unwrap_err().code(), "LEDGER_NOT_CONFIGURED");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn env_vars_keyring_and_revocation() {
    let v = vectors();
    let mut vars = BTreeMap::new();
    assert!(ReceiptSigningKey::from_vars(&vars).is_err());
    vars.insert("ARKHEIA_SIGNING_SEED_HEX".to_string(), seed(&v));
    let key = ReceiptSigningKey::from_vars(&vars).unwrap();
    vars.insert("ARKHEIA_SIGNING_PUBLIC_KEY_ID".to_string(), key.public_key_id());
    assert!(ReceiptSigningKey::from_vars(&vars).is_ok());
    vars.insert("ARKHEIA_SIGNING_PUBLIC_KEY_ID".to_string(), "ed25519:0000000000000000".into());
    assert!(ReceiptSigningKey::from_vars(&vars).is_err());
    assert!(ReceiptSigningKey::from_seed_hex("ABC").is_err());

    let ring = keyring(&v);
    assert_eq!(canonicalize(&ring.to_value()).unwrap(), canonicalize(v.get("keyring").unwrap()).unwrap());
    let revoked_doc = parse_strict(&canonicalize(v.get("keyring").unwrap()).unwrap().replace("\"active\"", "\"revoked\"")).unwrap();
    let revoked = Keyring::from_value(&revoked_doc).unwrap();
    let r0 = v.get("chain").unwrap().as_array().unwrap()[0].get("receipt").unwrap();
    assert_eq!(verify_receipt(r0, &revoked, None).error_code, Some("REVOKED_SIGNER"));
}

#[test]
fn schema_interpreter_rejects_unknown_keywords() {
    assert!(CompiledSchema::compile(parse_strict(r#"{"type":"object","format":"date-time"}"#).unwrap()).is_err());
    assert!(is_valid_timestamp("2024-02-29T00:00:00.000Z"));
    assert!(!is_valid_timestamp("2026-02-29T00:00:00.000Z"));
    assert!(!is_valid_timestamp("2026-11-25T24:00:00.000Z"));
}
