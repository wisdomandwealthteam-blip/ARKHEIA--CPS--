"""Golden proofs: QUARANTINE_X_STAR is absorbing; only a valid signed HUMAN_RELEASE exits it."""
from __future__ import annotations

import itertools
import random

import pytest

from arkheia_clearance import aegis
from arkheia_clearance import artifacts as A
from arkheia_clearance.aegis import ALLOW, HUMAN_RELEASE, STATES, THROTTLE, X_STAR, Mem
from arkheia_clearance.policy import Policy

P = Policy().validate()
DRIFTS = (0, 1, P.theta2_bps - 1, P.theta2_bps, P.theta3_bps - 1, P.theta3_bps, 10_000)
LAST = (None, 0, P.theta2_bps - 1, P.theta2_bps, 10_000)


# ---------------------------------------------------------------- pure machine: exhaustive
def all_mems():
    for state, clean, last in itertools.product(STATES, range(P.recover_steps + 1), LAST):
        yield Mem(state, clean, last)


@pytest.mark.parametrize("mem", list(all_mems()), ids=str)
def test_transition_table_is_total_and_matches_spec(mem):
    for d, hard in itertools.product(DRIFTS, (False, True)):
        nxt = aegis.step(mem, d, hard, P)
        assert nxt.state in STATES
        if mem.state == X_STAR:
            assert nxt == mem, "X* must be absorbing under every observation"
        elif hard or d >= P.theta3_bps:
            assert nxt.state == X_STAR
        elif mem.state in (ALLOW, HUMAN_RELEASE):
            assert nxt.state == (THROTTLE if d >= P.theta2_bps else ALLOW)
        else:  # THROTTLE
            if d >= P.theta2_bps or (mem.last_drift is not None and d > mem.last_drift):
                assert nxt == Mem(THROTTLE, 0, d)
            elif mem.clean_steps + 1 >= P.recover_steps:
                assert nxt.state == ALLOW
            else:
                assert nxt == Mem(THROTTLE, mem.clean_steps + 1, d)
        assert nxt.state != HUMAN_RELEASE, "step() can never produce HUMAN_RELEASE"


def test_release_is_the_only_exit_and_only_from_x_star():
    assert aegis.release(Mem(X_STAR, 0, 9_000)) == Mem(HUMAN_RELEASE, 0, None)
    for s in (ALLOW, THROTTLE, HUMAN_RELEASE):
        with pytest.raises(ValueError):
            aegis.release(Mem(s))
    with pytest.raises(ValueError):
        aegis.after_clear(Mem(X_STAR))


def test_random_walks_never_self_heal():
    rng = random.Random(20261128)
    for _ in range(2_000):
        m = Mem(X_STAR, rng.randrange(4), rng.choice(LAST))
        for _ in range(50):
            m = aegis.step(m, rng.randrange(10_001), rng.random() < 0.5, P)
            assert m.state == X_STAR


def test_throttle_requires_n_consecutive_descending_steps():
    m = Mem(THROTTLE, 0, 5_000)
    m = aegis.step(m, 1_000, False, P)
    m = aegis.step(m, 1_200, False, P)        # integrity energy rose: counter resets
    assert m == Mem(THROTTLE, 0, 1_200)
    for _ in range(P.recover_steps - 1):
        m = aegis.step(m, 1_200, False, P)
        assert m.state == THROTTLE
    assert aegis.step(m, 1_100, False, P).state == ALLOW


# ---------------------------------------------------------------- engine-level absorption
def test_every_hard_observation_flag_quarantines(h):
    for flag in ("scope_violations", "signature_failures", "override_attempts"):
        agent = h.w.agent("flag-" + flag)
        r, _ = h.aegis(h.w.observe(agent, t=h.t(), **{flag: 1}))
        assert r.status == 200 and h.state(agent) == X_STAR


def test_drift_breach_quarantines(h):
    agent = h.w.agent("drift")
    # reject 100% (5000) + rate saturated (3000) = 8000 = Θ3
    h.aegis(h.w.observe(agent, t=h.t(), request_count=1_000, reject_count=1_000))
    assert h.state(agent) == X_STAR


def test_engine_x_star_absorbs_a_long_adversarial_campaign(h):
    w, rng = h.w, random.Random(7)
    a, b = w.agent("alpha"), w.agent("bravo")
    lease_a = w.lease(a, issued=0)
    h.quarantine(a)
    for i in range(150):
        kind = rng.randrange(5)
        if kind == 0:   # perfectly clean telemetry
            h.aegis(w.observe(a, t=h.t(), request_count=1))
        elif kind == 1:  # valid-looking mandate under the pre-quarantine lease
            h.mandate(w.mandate(a, lease_a, t=h.t(), tag=f"camp-{i}"))
        elif kind == 2:  # self-signed "release"
            h.aegis(w.release(a, h.e.quarantine_receipt_hash(a.public_hex), t=h.t(), tag=f"self-{i}", approvers=[a]))
        elif kind == 3:  # sibling agent attempts override
            h.aegis(w.release(a, h.e.quarantine_receipt_hash(a.public_hex), t=h.t(), tag=f"sib-{i}", approvers=[b]))
        else:  # unauthenticated garbage
            h.raw_aegis(b'{"type":"HUMAN_RELEASE"}')
        assert h.state(a) == X_STAR, f"self-healed at iteration {i}"
    assert h.state(b) == X_STAR, "sibling override attempt must quarantine the sibling"


def _bad_releases(h, a, qhash):
    w = h.w
    t = h.t()
    good = w.release(a, qhash, t=t, tag="good")
    tampered = dict(good, subject=w.agent("other").public_hex)
    wrong_sig = dict(good, approvals=[dict(good["approvals"][0], sig="00" * 64)])
    return {
        "QUARANTINE_HASH_MISMATCH": w.release(a, "ab" * 32, t=t, tag="h"),
        "OVERRIDE_ATTEMPT": w.release(a, qhash, t=t, tag="self", approvers=[a]),
        "APPROVAL_SIG": wrong_sig,
        "AUTHORITY_DUPLICATE": w.release(a, qhash, t=t, tag="dup", approvers=[w.humans[0], w.humans[0]]),
        "POLICY_MISMATCH": w.release(a, qhash, t=t, tag="pv", policy_version="arkheia.mandate-aegis/0.9.0"),
        "INVARIANT_CHECK_FAILED": w.release(a, qhash, t=t, tag="inv", passed=False),
        "LAMPORT_SKEW": w.release(a, qhash, t=h.e.clock + h.e.policy.max_lamport_skew + 1_000, tag="skew"),
        "TAMPERED_SUBJECT": tampered,
        "STRUCT": dict(good, approvals=[]),
    }


def test_every_invalid_release_is_rejected_and_x_star_holds(h):
    a = h.w.agent("alpha")
    qhash = h.quarantine(a)
    for expected, obj in _bad_releases(h, a, qhash).items():
        r, reason = h.aegis(obj)
        assert r.status == 403, expected
        if expected != "TAMPERED_SUBJECT":
            assert reason == expected
        assert h.state(a) == X_STAR
        assert h.e.quarantine_receipt_hash(a.public_hex) == qhash


def test_quorum_policy(make_harness):
    h = make_harness(policy=Policy(release_quorum=2))
    a = h.w.agent("alpha")
    qhash = h.quarantine(a)
    r, reason = h.aegis(h.w.release(a, qhash, t=h.t(), tag="q1", approvers=h.w.humans[:1]))
    assert (r.status, reason, h.state(a)) == (403, "QUORUM_NOT_MET", X_STAR)
    r, reason = h.aegis(h.w.release(a, qhash, t=h.t(), tag="q2", approvers=h.w.humans[:2]))
    assert (r.status, reason, h.state(a)) == (200, "OK", HUMAN_RELEASE)


def test_valid_release_then_requarantine_invalidates_old_artifact(h):
    w, a = h.w, h.w.agent("alpha")
    q1 = h.quarantine(a)
    rel = w.release(a, q1, t=h.t(), tag="r1")
    assert h.aegis(rel)[0].status == 200 and h.state(a) == HUMAN_RELEASE
    q2 = h.quarantine(a)
    assert q2 != q1
    r, reason = h.aegis(rel)                                  # verbatim replay
    assert r.status == 403 and h.state(a) == X_STAR
    r, reason = h.aegis(w.release(a, q1, t=h.t(), tag="r1b"))  # fresh nonce, stale hash
    assert (r.status, reason) == (403, "QUARANTINE_HASH_MISMATCH") and h.state(a) == X_STAR
    assert h.aegis(w.release(a, q2, t=h.t(), tag="r2"))[0].status == 200


def test_release_does_not_reinstate_old_lease_and_fresh_lease_restores_allow(h):
    w, a = h.w, h.w.agent("alpha")
    old = w.lease(a, issued=0)
    assert h.mandate(w.mandate(a, old, t=h.t(), tag="pre"))[0].status == 200
    q = h.quarantine(a)
    h.aegis(w.release(a, q, t=h.t(), tag="rel"))
    r, reason = h.mandate(w.mandate(a, old, t=h.t(), tag="old"))
    assert (r.status, reason, h.state(a)) == (403, "LEASE_REVOKED", HUMAN_RELEASE)
    fresh = w.lease(a, issued=h.t())
    r, reason = h.mandate(w.mandate(a, fresh, t=h.t(), tag="fresh"))
    assert (r.status, reason, h.state(a)) == (200, "OK", ALLOW)


def test_human_release_back_to_x_star_on_breach(h):
    a = h.w.agent("alpha")
    q = h.quarantine(a)
    h.aegis(h.w.release(a, q, t=h.t(), tag="rel"))
    h.aegis(h.w.observe(a, t=h.t(), signature_failures=1))
    assert h.state(a) == X_STAR


def test_x_star_survives_restart(tmp_path, make_harness, world):
    path = tmp_path / "ledger.jsonl"
    h1 = make_harness(ledger_path=path)
    a = world.agent("alpha")
    q = h1.quarantine(a)
    h2 = make_harness(ledger_path=path)   # "reboot"
    assert h2.state(a) == X_STAR
    assert h2.e.quarantine_receipt_hash(a.public_hex) == q
    assert h2.aegis(world.observe(a, t=h2.t(), request_count=1))[0].status == 200
    assert h2.state(a) == X_STAR
    assert h2.aegis(world.release(a, q, t=h2.t(), tag="after-reboot"))[0].status == 200
    assert make_harness(ledger_path=path).state(a) == HUMAN_RELEASE


def test_quarantined_delegator_poisons_its_downstream_chain(h):
    w = h.w
    a, c = w.agent("alpha"), w.agent("charlie")
    lease_a = w.lease(a, issued=0)
    hop = A.delegation(a, delegate=c.public_hex, lease_id=lease_a["lease_id"], scopes=["payments.transfer"],
                       max_amount=10 ** 20, lamport_issued=0, ttl=4_000)
    assert h.mandate(w.mandate(c, lease_a, t=h.t(), tag="ok", delegations=[hop]))[0].status == 200
    h.quarantine(a)
    r, reason = h.mandate(w.mandate(c, lease_a, t=h.t(), tag="poisoned", delegations=[hop]))
    assert (r.status, reason) == (403, "SUBJECT_QUARANTINED")
    assert h.state(c) == ALLOW, "the innocent delegate is blocked, not quarantined"
