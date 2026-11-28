"""Hash-chained Ed25519 receipts (ARKHEIA/clearance/receipt/v1): integrity, durability, permits."""
from __future__ import annotations

import copy
import json

import pytest

from arkheia_clearance import artifacts as A
from arkheia_clearance.engine import verify_permit
from arkheia_clearance.golden import golden_signer, run_scenario
from arkheia_clearance.receipts import GENESIS, LedgerError, receipt_hash, verify_chain
from arkheia_clearance.wire import sha256_hex, jcs


@pytest.fixture
def chain(h):
    run_scenario(h.w, h.e)
    return h, h.e.records()


def test_full_scenario_chain_verifies(chain):
    h, recs = chain
    rep = verify_chain(recs, h.e.trusted_keys())
    assert rep == {"valid": True, "length": len(recs), "head_hash": h.e.head_hash}
    assert recs[0]["prev_hash"] == GENESIS and recs[0]["seq"] == 0
    for i in range(1, len(recs)):
        assert recs[i]["prev_hash"] == receipt_hash(recs[i - 1])
        assert recs[i]["lamport"] > recs[i - 1]["lamport"]
        assert recs[i]["decision_core_hash"] == sha256_hex(jcs(recs[i]["decision_core"]))


def test_every_receipt_is_signed_under_the_clearance_domain(chain):
    h, recs = chain
    for r in recs:
        assert r["schema"] == "ARKHEIA/clearance/receipt/v1"
        assert r["signature"]["public_key_id"] == h.e.public_key_id


def _flip(v, a, b):
    return b if v == a else a


TAMPERS = {
    "decision": lambda r: r.__setitem__("decision", _flip(r["decision"], "CLEARED", "REJECTED")),
    "core_state": lambda r: r["decision_core"].__setitem__(
        "state_after", _flip(r["decision_core"]["state_after"], "ALLOW", "QUARANTINE_X_STAR")),
    "core_hash_resync": lambda r: (
        r["decision_core"].__setitem__("state_after", _flip(r["decision_core"]["state_after"], "ALLOW", "QUARANTINE_X_STAR")),
        r.__setitem__("decision_core_hash", sha256_hex(jcs(r["decision_core"])))),
    "lamport": lambda r: r.__setitem__("lamport", r["lamport"] + 1),
    "request_hash": lambda r: r.__setitem__("request_hash", "0" * 64),
    "signature": lambda r: r["signature"].__setitem__("value", "0" * 128),
    "extra_field": lambda r: r.__setitem__("note", "x"),
}


@pytest.mark.parametrize("name", sorted(TAMPERS))
@pytest.mark.parametrize("index", [0, 7, -1])
def test_any_mutation_is_detected_at_its_index(chain, name, index):
    h, recs = chain
    recs = copy.deepcopy(recs)
    i = index % len(recs)
    TAMPERS[name](recs[i])
    rep = verify_chain(recs, h.e.trusted_keys())
    assert rep["valid"] is False and rep["index"] <= i + 1


def test_reorder_drop_and_splice_are_detected(chain):
    h, recs = chain
    k = h.e.trusted_keys()
    assert verify_chain(recs[:3] + recs[4:], k)["error_code"] == "SEQUENCE_GAP"
    swapped = list(recs)
    swapped[2], swapped[3] = swapped[3], swapped[2]
    assert verify_chain(swapped, k)["valid"] is False
    assert verify_chain(recs[1:], k)["valid"] is False


def test_foreign_signer_is_rejected(chain):
    h, recs = chain
    assert verify_chain(recs, {golden_signer("x").key_id: golden_signer("x").public_hex})["error_code"] == "UNKNOWN_SIGNER"


def test_jsonl_ledger_roundtrip_resume_and_corruption(tmp_path, make_harness, world):
    path = tmp_path / "chain.jsonl"
    h1 = make_harness(ledger_path=path)
    run_scenario(world, h1.e)
    n, head = len(h1.e.records()), h1.e.head_hash
    h2 = make_harness(ledger_path=path)
    assert (len(h2.e.records()), h2.e.head_hash, h2.e.clock) == (n, head, h1.e.clock)
    h2.e.verify_mandate(b"{}")                             # resumes the same chain
    assert h2.e.records()[-1]["seq"] == n and h2.e.records()[-1]["prev_hash"] == head
    lines = path.read_bytes().splitlines(keepends=True)
    lines[5] = lines[5].replace(b'"REJECTED"', b'"CLEARED"').replace(b'"STATE_UPDATED"', b'"CLEARED"')
    path.write_bytes(b"".join(lines))
    with pytest.raises(LedgerError):
        make_harness(ledger_path=path)                     # fail closed: refuses to start


def test_restart_reproduces_identical_state(tmp_path, make_harness, world):
    path = tmp_path / "chain.jsonl"
    h1 = make_harness(ledger_path=path)
    run_scenario(world, h1.e)
    h2 = make_harness(ledger_path=path)
    for attr in ("_mem", "_qhash", "_floor", "_used_mandates", "_used_nonces", "_last_cleared", "_last_obs", "_clock"):
        assert getattr(h2.e, attr) == getattr(h1.e, attr), attr


def test_cleared_response_carries_verifiable_permit_bound_to_receipt(h):
    w, a = h.w, h.w.agent("alpha")
    r, _ = h.mandate(w.mandate(a, w.lease(a, issued=0), t=h.t(), tag="p"))
    body = json.loads(r.body)
    permit = body["permit"]
    assert permit["receipt_hash"] == body["receipt_hash"] == receipt_hash(body["receipt"])
    assert permit["allocations_digest"] == sha256_hex(jcs(body["allocations"]))
    assert permit["not_after_lamport"] - permit["issued_lamport"] == h.e.policy.permit_ttl
    assert verify_permit(permit, h.e.public_key_hex)
    assert not verify_permit(dict(permit, pool="1"), h.e.public_key_hex)
    assert body["receipt"] == h.e.records()[-1], "receipt committed before the permit was released"
