"""ARKHEIA Mandate + Aegis-Swarm deterministic pre-execution verification engine.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Proprietary core — framework-free. Customer-facing wrappers (the CPS FastAPI
router, the stdlib sidecar, the playground) depend on this package; it never
depends on them.
"""
from .aegis import ALLOW, HUMAN_RELEASE, STATES, THROTTLE, X_STAR
from .engine import AEGIS_EP, MANDATE_EP, ClearanceEngine, Response, decode_reason, opaque_rejection, verify_permit
from .policy import POLICY_VERSION, Policy
from .receipts import GENESIS, SCHEMA as RECEIPT_SCHEMA, receipt_hash, verify_chain
from .service import ClearanceService, ConfigError, engine_from_env
from .wire import Signer

__all__ = [
    "AEGIS_EP", "ALLOW", "ClearanceEngine", "ClearanceService", "ConfigError", "GENESIS", "HUMAN_RELEASE",
    "MANDATE_EP", "POLICY_VERSION", "Policy", "RECEIPT_SCHEMA", "Response", "STATES", "Signer", "THROTTLE",
    "X_STAR", "decode_reason", "engine_from_env", "opaque_rejection", "receipt_hash", "verify_chain", "verify_permit",
]
__version__ = "1.0.0"
