"""Bit-identical reproducibility (Kernel 7): the pinned golden transcript must match exactly.

Regenerate ONLY on an intentional policy/schema change (and bump policy_version):
    python -m arkheia_clearance.golden > tests/clearance/golden/clearance_vectors.json
"""
from __future__ import annotations

import json
from pathlib import Path

from arkheia_clearance import artifacts as A
from arkheia_clearance.engine import AEGIS_EP
from arkheia_clearance.golden import World, vectors
from arkheia_clearance.receipts import verify_chain
from arkheia_clearance.wire import sha256_hex

VECTORS = Path(__file__).parent / "golden" / "clearance_vectors.json"
PINNED = json.loads(VECTORS.read_text(encoding="utf-8"))

EXPECTED_WALK = [
    ("01_allow_clear", 200, "ALLOW"),
    ("02_drift_into_throttle", 200, "THROTTLE"),
    ("03_throttled_within_interval", 403, "THROTTLE"),
    ("04_throttle_interval_elapsed", 200, "THROTTLE"),
    ("05_clean_descent_0", 200, "THROTTLE"),
    ("05_clean_descent_1", 200, "THROTTLE"),
    ("05_clean_descent_2", 200, "ALLOW"),
    ("06_scope_escalation_quarantines_delegator", 403, "QUARANTINE_X_STAR"),
    ("07_x_star_absorbs_clean_observation", 200, "QUARANTINE_X_STAR"),
    ("08_x_star_rejects_mandate", 403, "QUARANTINE_X_STAR"),
    ("09_self_release_is_override_attempt", 403, "QUARANTINE_X_STAR"),
    ("10_release_wrong_quarantine_hash", 403, "QUARANTINE_X_STAR"),
    ("11_signed_human_release", 200, "HUMAN_RELEASE"),
    ("12_pre_quarantine_lease_revoked", 403, "HUMAN_RELEASE"),
    ("13_fresh_lease_returns_to_allow", 200, "ALLOW"),
    ("14_release_replay_rejected", 403, "ALLOW"),
]


def test_walk_covers_all_four_states_in_spec_order():
    assert [(s["step"], s["status"], s["state_after"]) for s in PINNED["steps"]] == EXPECTED_WALK


def test_regenerated_transcript_is_byte_identical_to_pinned():
    assert vectors() == PINNED


def test_pinned_requests_replay_to_identical_responses():
    """Cross-implementation contract: feed the pinned request bytes to a fresh engine."""
    e = World().engine()
    for s in PINNED["steps"]:
        raw = A.to_bytes(s["request"])
        r = e.evaluate_aegis(raw) if s["endpoint"] == AEGIS_EP else e.verify_mandate(raw)
        assert (r.status, sha256_hex(r.body), r.receipt_hash) == (s["status"], s["response_sha256"], s["receipt_hash"]), s["step"]
    assert e.head_hash == PINNED["head_hash"]
    assert verify_chain(e.records(), {PINNED["engine_public_key_id"]: PINNED["engine_public_key"]})["valid"]
