"""ARKHEIA DVE receipt toolkit (schema v1.0.0, RFC 8785 JCS, Ed25519).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
"""

from .jcs import CanonicalizationError, canonical_bytes, canonicalize
from .keys import (
    Keyring,
    PublicKey,
    ReceiptKeyError,
    SigningKey,
    generate_seed_hex,
    load_env_file,
    load_signing_key_from_env,
    public_key_from_hex,
    public_key_id,
    sha256_hex,
    signing_key_from_seed_hex,
)
from .ledger import (
    GENESIS_HASH,
    BpsLedgerAdapter,
    InMemoryLedger,
    JsonlFileLedger,
    LedgerConflictError,
    LedgerNotConfiguredError,
    ReceiptLedger,
)
from .receipt import (
    SCHEMA_VERSION,
    SIGNING_DOMAIN,
    WRAPPER_DOMAINS,
    ReceiptError,
    ReceiptSigner,
    build_verdict_payload,
    digest_bytes,
    digest_json,
    format_timestamp,
    is_valid_timestamp,
    ledger_from_env,
    signer_from_env,
    receipt_hash,
    sign_receipt,
    signing_input,
    verify_chain,
    verify_receipt,
)
from .schema import RECEIPT_SCHEMA, SchemaDefinitionError, compile_schema, validate_receipt_schema
from .strict_json import StrictJsonError, parse_strict_json

__all__ = [name for name in dir() if not name.startswith("_")]
