"""Law II: Lamport-bounded CUSTOS leases and non-expansive A2A delegation."""
from __future__ import annotations

import pytest

from arkheia_clearance import artifacts as A
from arkheia_clearance.aegis import ALLOW, X_STAR
from arkheia_clearance.golden import golden_signer
from arkheia_clearance.policy import Policy


def test_lease_window_boundaries(make_harness, world):
    a = world.agent("alpha")
    h = make_harness(policy=Policy(expired_lease_is_hard=False))
    lease = world.lease(a, issued=5, ttl=10)                         # valid for 5 <= t < 15
    assert h.mandate(world.mandate(a, lease, t=4, tag="early"))[1] == "LEASE_EXPIRED"
    assert h.mandate(world.mandate(a, lease, t=5, tag="first"))[0].status == 200
    assert h.mandate(world.mandate(a, lease, t=13, tag="last-usable"))[0].status == 200
    # v1.0.1: request tick 14 would issue the receipt/permit at expired tick 15.
    assert h.mandate(world.mandate(a, lease, t=14, tag="last"))[1] == "LEASE_EXPIRED"
    assert h.mandate(world.mandate(a, lease, t=15, tag="expired"))[1] == "LEASE_EXPIRED"
    assert h.state(a) == ALLOW  # soft when the policy says so


def test_expired_lease_is_hard_by_default(h):
    a = h.w.agent("alpha")
    lease = h.w.lease(a, issued=0, ttl=1)
    r, reason = h.mandate(h.w.mandate(a, lease, t=5, tag="exp"))
    assert (reason, h.state(a)) == ("LEASE_EXPIRED", X_STAR)


@pytest.mark.parametrize("ttl", [0, Policy().max_lease_ttl + 1])
def test_ttl_bounds_are_structural(h, ttl):
    a = h.w.agent("alpha")
    assert h.mandate(h.w.mandate(a, h.w.lease(a, issued=0, ttl=ttl), t=1, tag="ttl"))[1] == "STRUCT"


def test_unknown_issuer_and_tampering_are_unauthenticated(h):
    w, a = h.w, h.w.agent("alpha")
    rogue = golden_signer("rogue-issuer")
    assert h.mandate(w.mandate(a, w.lease(a, issued=0, issuer=rogue), t=1, tag="r"))[1] == "LEASE_ISSUER_UNKNOWN"
    lease = w.lease(a, issued=0)
    widened = dict(lease, scopes=sorted(lease["scopes"] + ["treasury.sweep"]))
    assert h.mandate(w.mandate(a, widened, t=1, tag="w"))[1] == "LEASE_SIG"
    stolen = w.mandate(w.agent("mallory"), lease, t=1, tag="s")   # someone else's lease
    assert h.mandate(stolen)[1] == "CHAIN_LINK"
    forged = dict(w.mandate(a, lease, t=1, tag="f"), pool="999")
    assert h.mandate(forged)[1] == "REQUEST_SIG"
    assert h.state(a) == ALLOW, "unauthenticated failures never quarantine the claimed identity"


def test_lamport_skew_bound(h):
    w, a = h.w, h.w.agent("alpha")
    lease = w.lease(a, issued=0, ttl=50_000)
    far = h.e.clock + h.e.policy.max_lamport_skew + 1
    assert h.mandate(w.mandate(a, lease, t=far, tag="far"))[1] == "LAMPORT_SKEW"
    before = h.e.clock
    h.mandate(w.mandate(a, lease, t=far + 10_000, tag="far2"))
    assert h.e.clock == before + 1, "an out-of-bound lamport cannot drag the engine clock forward"


def test_replay_and_regression_are_hard(h):
    w = h.w
    a, b = w.agent("alpha"), w.agent("bravo")
    la, lb = w.lease(a, issued=0), w.lease(b, issued=0)
    m = w.mandate(a, la, t=h.t(), tag="once")
    assert h.mandate(m)[0].status == 200
    assert (h.mandate(m)[1], h.state(a)) == ("MANDATE_REPLAY", X_STAR)
    t = h.t()
    assert h.mandate(w.mandate(b, lb, t=t, tag="b1"))[0].status == 200
    assert (h.mandate(w.mandate(b, lb, t=t, tag="b2"))[1], h.state(b)) == ("LAMPORT_REGRESSION", X_STAR)


def _chain(w, a, c, d, **over):
    lease = w.lease(a, issued=0, ttl=5_000, max_amount=10 ** 20)
    hop1 = A.delegation(a, delegate=c.public_hex, lease_id=lease["lease_id"], scopes=["payments.transfer"],
                        max_amount=over.get("m1", 10 ** 19), lamport_issued=over.get("i1", 1), ttl=over.get("t1", 4_000))
    hop2 = A.delegation(c, delegate=d.public_hex, lease_id=lease["lease_id"], scopes=over.get("s2", ["payments.transfer"]),
                        max_amount=over.get("m2", 10 ** 18), lamport_issued=over.get("i2", 2), ttl=over.get("t2", 3_000))
    return lease, [hop1, hop2]


def test_two_hop_narrowing_chain_clears(h):
    w = h.w
    a, c, d = w.agent("alpha"), w.agent("charlie"), w.agent("delta")
    lease, hops = _chain(w, a, c, d)
    assert h.mandate(w.mandate(d, lease, t=h.t(10), tag="ok", delegations=hops))[0].status == 200


@pytest.mark.parametrize("over,reason", [
    ({"s2": ["payments.transfer", "treasury.sweep"]}, "SCOPE_ESCALATION"),
    ({"m2": 10 ** 19 + 1}, "BUDGET_ESCALATION"),
    ({"t2": 4_000}, "TTL_ESCALATION"),          # 2 + 4000 > 1 + 4000: outlives its parent (renewal)
    ({"i2": 0}, "TTL_ESCALATION"),              # predates its parent
])
def test_expansion_quarantines_exactly_the_signer_of_the_expanding_hop(h, over, reason):
    w = h.w
    a, c, d = w.agent("alpha"), w.agent("charlie"), w.agent("delta")
    lease, hops = _chain(w, a, c, d, **over)
    r, got = h.mandate(w.mandate(d, lease, t=h.t(10), tag="x", delegations=hops))
    assert (r.status, got) == (403, reason)
    assert (h.state(a), h.state(c), h.state(d)) == (ALLOW, X_STAR, ALLOW)


def test_action_and_amount_outside_effective_authority(h):
    w = h.w
    a, c, d = w.agent("alpha"), w.agent("charlie"), w.agent("delta")
    lease, hops = _chain(w, a, c, d)
    assert h.mandate(w.mandate(d, lease, t=h.t(10), tag="q", mcp_name="payments.quote", delegations=hops))[1] == "ACTION_OUT_OF_SCOPE"
    assert h.state(d) == X_STAR
    e = w.agent("echo")
    lease2, hops2 = _chain(w, a, c, e)
    assert h.mandate(w.mandate(e, lease2, t=h.t(10), tag="big", pool=10 ** 18 + 1, delegations=hops2))[1] == "BUDGET_ESCALATION"
    assert h.state(e) == X_STAR


def test_chain_structure_rules(h):
    w = h.w
    a, c = w.agent("alpha"), w.agent("charlie")
    lease = w.lease(a, issued=0)
    cycle = [A.delegation(a, delegate=c.public_hex, lease_id=lease["lease_id"], scopes=["payments.transfer"],
                          max_amount=10, lamport_issued=0, ttl=100),
             A.delegation(c, delegate=a.public_hex, lease_id=lease["lease_id"], scopes=["payments.transfer"],
                          max_amount=10, lamport_issued=0, ttl=100)]
    assert h.mandate(w.mandate(a, lease, t=h.t(), tag="cyc", pool=1, delegations=cycle))[1] == "CHAIN_CYCLE"
    wrong_lease = [A.delegation(a, delegate=c.public_hex, lease_id="ff" * 16, scopes=["payments.transfer"],
                                max_amount=10, lamport_issued=0, ttl=100)]
    assert h.mandate(w.mandate(c, lease, t=h.t(), tag="wl", pool=1, delegations=wrong_lease))[1] == "CHAIN_LINK"
    deep = [cycle[0]] * (h.e.policy.max_delegation_depth + 1)
    assert h.mandate(w.mandate(c, lease, t=h.t(), tag="deep", pool=1, delegations=deep))[1] == "STRUCT"


def test_mcp_header_body_mismatch(h):
    w, a = h.w, h.w.agent("alpha")
    m = w.mandate(a, w.lease(a, issued=0), t=h.t(), tag="hdr")
    assert h.mandate(m, {"Mcp-Name": "payments.quote"})[1] == "MCP_HEADER_MISMATCH"
    assert h.mandate(m, {"MCP-Protocol-Version": "2025-06-18"})[1] == "MCP_HEADER_MISMATCH"
    ok = {"Mcp-Method": "tools/call", "Mcp-Name": "payments.transfer", "MCP-Protocol-Version": "2026-07-28"}
    assert h.mandate(m, ok)[0].status == 200
