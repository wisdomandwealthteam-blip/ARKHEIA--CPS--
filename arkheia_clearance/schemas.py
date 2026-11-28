"""ARKHEIA Clearance — closed request schemas (Zone I canonical IR).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Wire shapes (all keys required, no others allowed; u128 = decimal string):

CUSTOS lease  (signed by a trusted CUSTOS issuer, domain ARKHEIA/custos/lease/v1)
  {lease_id:hex16, issuer:pub, holder:pub, swarm_id:ident, scopes:[scope..],
   max_amount:u128, lamport_issued:u64, ttl:u64, sig:hex64}

A2A delegation hop  (signed by its delegator, domain ARKHEIA/a2a/delegation/v1)
  {delegator:pub, delegate:pub, lease_id:hex16, scopes:[scope..], max_amount:u128,
   lamport_issued:u64, ttl:u64, sig:hex64}

Mandate request  (signed by the acting agent, domain ARKHEIA/mandate/request/v1)
  {type:"MANDATE", mandate_id:hex16, lamport:u64,
   tool_call:{mcp_method:"tools/call", mcp_name:scope},
   pool:u128, allocations:[{recipient:ident, bps:u64}..],
   lease:<lease>, delegations:[<hop>..], actor:pub, sig:hex64}

Aegis observation  (signed by a trusted sensor, domain ARKHEIA/aegis/observation/v1)
  {type:"OBSERVATION", subject:pub, lamport:u64, sensor:pub, sig:hex64,
   window:{request_count, reject_count, fanout, scope_violations,
           signature_failures, override_attempts}}

Human Release artifact  (each approval signs domain ARKHEIA/aegis/human-release/v1
                         over the artifact minus "approvals")
  {type:"HUMAN_RELEASE", subject:pub, quarantine_receipt_hash:hex32,
   policy_version:str, invariant_check:{passed:bool, evidence_digest:hex32},
   lamport:u64, nonce:hex16, approvals:[{authority:pub, sig:hex64}..]}
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import wire
from .aegis import Window
from .policy import MCP_METHOD, Policy

LEASE_KEYS = frozenset({"lease_id", "issuer", "holder", "swarm_id", "scopes", "max_amount", "lamport_issued", "ttl", "sig"})
HOP_KEYS = frozenset({"delegator", "delegate", "lease_id", "scopes", "max_amount", "lamport_issued", "ttl", "sig"})
MANDATE_KEYS = frozenset({"type", "mandate_id", "lamport", "tool_call", "pool", "allocations", "lease",
                          "delegations", "actor", "sig"})
TOOL_KEYS = frozenset({"mcp_method", "mcp_name"})
ALLOC_KEYS = frozenset({"recipient", "bps"})
OBS_KEYS = frozenset({"type", "subject", "lamport", "sensor", "sig", "window"})
WINDOW_KEYS = frozenset({"request_count", "reject_count", "fanout", "scope_violations",
                         "signature_failures", "override_attempts"})
RELEASE_KEYS = frozenset({"type", "subject", "quarantine_receipt_hash", "policy_version", "invariant_check",
                          "lamport", "nonce", "approvals"})
CHECK_KEYS = frozenset({"passed", "evidence_digest"})
APPROVAL_KEYS = frozenset({"authority", "sig"})


@dataclass(frozen=True)
class SigCheck:
    public_hex: str
    sig_hex: str
    message: bytes


@dataclass(frozen=True)
class Grant:
    """Common shape of a lease and a delegation hop: a bounded, expiring authority."""

    grantor: str          # lease issuer, or hop delegator
    grantee: str          # lease holder, or hop delegate
    lease_id: str
    scopes: frozenset[str]
    max_amount: int
    lamport_issued: int
    ttl: int
    check: SigCheck

    @property
    def expiry(self) -> int:
        return self.lamport_issued + self.ttl


@dataclass(frozen=True)
class Mandate:
    mandate_id: str
    lamport: int
    mcp_name: str
    pool: int
    allocations: tuple[tuple[str, int], ...]
    lease: Grant
    swarm_id: str
    hops: tuple[Grant, ...]
    actor: str
    check: SigCheck


@dataclass(frozen=True)
class Observation:
    subject: str
    lamport: int
    sensor: str
    window: Window
    check: SigCheck


@dataclass(frozen=True)
class Approval:
    authority: str
    check: SigCheck


@dataclass(frozen=True)
class Release:
    subject: str
    quarantine_receipt_hash: str
    policy_version: str
    invariant_passed: bool
    lamport: int
    nonce: str
    approvals: tuple[Approval, ...]


def _ttl(v: object, p: Policy) -> int:
    t = wire.count(v)
    if t < 1 or t > p.max_lease_ttl:
        raise wire.Malformed()
    return t


def parse_lease(v: object, p: Policy) -> tuple[Grant, str]:
    o = wire.closed(v, LEASE_KEYS)
    g = Grant(
        grantor=wire.hexstr(o["issuer"], 32),
        grantee=wire.hexstr(o["holder"], 32),
        lease_id=wire.hexstr(o["lease_id"], 16),
        scopes=wire.scope_set(o["scopes"], p.max_scopes),
        max_amount=wire.amount(o["max_amount"]),
        lamport_issued=wire.lamport(o["lamport_issued"]),
        ttl=_ttl(o["ttl"], p),
        check=SigCheck(o["issuer"], wire.hexstr(o["sig"], 64), wire.signing_input(wire.DOMAIN_LEASE, o, "sig")),
    )
    return g, wire.ident(o["swarm_id"])


def parse_hop(v: object, p: Policy) -> Grant:
    o = wire.closed(v, HOP_KEYS)
    return Grant(
        grantor=wire.hexstr(o["delegator"], 32),
        grantee=wire.hexstr(o["delegate"], 32),
        lease_id=wire.hexstr(o["lease_id"], 16),
        scopes=wire.scope_set(o["scopes"], p.max_scopes),
        max_amount=wire.amount(o["max_amount"]),
        lamport_issued=wire.lamport(o["lamport_issued"]),
        ttl=_ttl(o["ttl"], p),
        check=SigCheck(o["delegator"], wire.hexstr(o["sig"], 64), wire.signing_input(wire.DOMAIN_DELEGATION, o, "sig")),
    )


def parse_mandate(body: Any, p: Policy) -> Mandate:
    o = wire.closed(body, MANDATE_KEYS)
    wire.literal(o["type"], "MANDATE")
    tool = wire.closed(o["tool_call"], TOOL_KEYS)
    wire.literal(tool["mcp_method"], MCP_METHOD)
    allocs = o["allocations"]
    if type(allocs) is not list or not allocs or len(allocs) > p.max_allocations:
        raise wire.Malformed()
    entries = []
    for a in allocs:
        a = wire.closed(a, ALLOC_KEYS)
        entries.append((wire.ident(a["recipient"]), wire.count(a["bps"])))
    hops_raw = o["delegations"]
    if type(hops_raw) is not list or len(hops_raw) > p.max_delegation_depth:
        raise wire.Malformed()
    lease, swarm_id = parse_lease(o["lease"], p)
    return Mandate(
        mandate_id=wire.hexstr(o["mandate_id"], 16),
        lamport=wire.lamport(o["lamport"]),
        mcp_name=wire.scope(tool["mcp_name"]),
        pool=wire.amount(o["pool"]),
        allocations=tuple(entries),
        lease=lease,
        swarm_id=swarm_id,
        hops=tuple(parse_hop(h, p) for h in hops_raw),
        actor=wire.hexstr(o["actor"], 32),
        check=SigCheck(o["actor"], wire.hexstr(o["sig"], 64), wire.signing_input(wire.DOMAIN_MANDATE, o, "sig")),
    )


def parse_observation(o: dict[str, Any]) -> Observation:
    o = wire.closed(o, OBS_KEYS)
    w = wire.closed(o["window"], WINDOW_KEYS)
    window = Window(**{k: wire.count(w[k]) for k in sorted(WINDOW_KEYS)})
    if window.reject_count > window.request_count:
        raise wire.Malformed()
    return Observation(
        subject=wire.hexstr(o["subject"], 32),
        lamport=wire.lamport(o["lamport"]),
        sensor=wire.hexstr(o["sensor"], 32),
        window=window,
        check=SigCheck(o["sensor"], wire.hexstr(o["sig"], 64), wire.signing_input(wire.DOMAIN_OBSERVATION, o, "sig")),
    )


def parse_release(o: dict[str, Any], p: Policy) -> Release:
    o = wire.closed(o, RELEASE_KEYS)
    chk = wire.closed(o["invariant_check"], CHECK_KEYS)
    if type(chk["passed"]) is not bool:
        raise wire.Malformed()
    wire.hexstr(chk["evidence_digest"], 32)
    if type(o["policy_version"]) is not str:
        raise wire.Malformed()
    raw = o["approvals"]
    if type(raw) is not list or not raw or len(raw) > p.max_approvals:
        raise wire.Malformed()
    message = wire.signing_input(wire.DOMAIN_RELEASE, o, "approvals")
    approvals = []
    for a in raw:
        a = wire.closed(a, APPROVAL_KEYS)
        pub = wire.hexstr(a["authority"], 32)
        approvals.append(Approval(pub, SigCheck(pub, wire.hexstr(a["sig"], 64), message)))
    return Release(
        subject=wire.hexstr(o["subject"], 32),
        quarantine_receipt_hash=wire.hexstr(o["quarantine_receipt_hash"], 32),
        policy_version=o["policy_version"],
        invariant_passed=chk["passed"],
        lamport=wire.lamport(o["lamport"]),
        nonce=wire.hexstr(o["nonce"], 16),
        approvals=tuple(approvals),
    )
