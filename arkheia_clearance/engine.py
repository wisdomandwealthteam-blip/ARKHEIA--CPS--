"""ARKHEIA Mandate + Aegis-Swarm — deterministic pre-execution verification engine.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Two entry points, both strictly serialized under one lock:

* ``verify_mandate(raw, headers)``  — POST /api/mandate/verify
* ``evaluate_aegis(raw, headers)``  — POST /api/aegis/evaluate

Pipeline per request (Aegis-Swarm §4 stages 1–5):

1. Zone U → Zone I: strict JSON, closed schemas, no floats, MCP header/body match.
2. CUSTOS lease + A2A delegation verification, Lamport-bounded and non-expansive.
3. Aegis drift / state-machine evaluation (pure, integer).
4. bps-ledger conservation (SPL-1, CON-1) and X* gate.
5. Receipt commit (fsync) — and only then is any decision released (AX-6).

State model
-----------
Engine state is *derived*: it is the left fold of ``_apply`` over the verified
receipt chain. Live commits call the same ``_apply`` on the receipt they just
appended, and a restart replays the ledger through it. Consequently a
quarantine survives restarts — there is no self-healing by reboot either.

Opacity
-------
Every rejection, on both endpoints and for every reason, returns the same
status (403) and the same body shape whose only variable is a 64-hex receipt
hash. Ed25519 verification work is padded to a fixed count per endpoint so
signature checks cost the same whether the request was garbage or nearly
valid; the transport adds a fixed latency floor on top (see ``timing``). The
reason is recorded only as an HMAC digest under an audit key the caller never
sees.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from . import aegis, wire
from .aegis import ALLOW, HUMAN_RELEASE, THROTTLE, X_STAR, Mem
from .conservation import ConservationError, Share, allocate
from .policy import MCP_METHOD, MCP_PROTOCOL_VERSION, Policy
from .receipts import Ledger, LedgerError, receipt_hash, sign_receipt
from .schemas import (Mandate, Observation, Release, SigCheck, parse_mandate, parse_observation,
                      parse_release)
from .u import WIRE_INT_MAX, format_u128

MANDATE_EP = "/api/mandate/verify"
AEGIS_EP = "/api/aegis/evaluate"
PERMIT_SCHEMA = "ARKHEIA/mandate/permit/v1"
REJECTION_SCHEMA = "ARKHEIA/clearance/rejection/v1"

# Priority order: the first code present becomes the receipt's (HMAC-digested) primary reason.
REASONS = (
    "OVERSIZE", "STRUCT", "MCP_HEADER_MISMATCH",
    "LEASE_ISSUER_UNKNOWN", "LEASE_SIG", "HOP_SIG", "REQUEST_SIG", "CHAIN_LINK", "CHAIN_CYCLE",
    "SENSOR_UNKNOWN", "SENSOR_SIG",
    "AUTHORITY_DUPLICATE", "AUTHORITY_UNKNOWN", "OVERRIDE_ATTEMPT", "APPROVAL_SIG", "QUORUM_NOT_MET",
    "SUBJECT_QUARANTINED", "LAMPORT_SKEW", "MANDATE_REPLAY", "LAMPORT_REGRESSION", "OBS_REGRESSION",
    "LEASE_REVOKED", "LEASE_EXPIRED", "SCOPE_ESCALATION", "BUDGET_ESCALATION", "TTL_ESCALATION",
    "ACTION_OUT_OF_SCOPE", "CONSERVATION_BREACH", "THROTTLED",
    "POLICY_MISMATCH", "INVARIANT_CHECK_FAILED", "NOT_QUARANTINED", "QUARANTINE_HASH_MISMATCH",
    "RELEASE_REPLAY", "INTERNAL_FAULT", "OK",
)
_RANK = {code: i for i, code in enumerate(REASONS)}

# Hard invariant breaches: when attributable to an authenticated principal, that
# principal enters the absorbing QUARANTINE_X_STAR state.
HARD_BASE = frozenset({
    "MANDATE_REPLAY", "LAMPORT_REGRESSION", "SCOPE_ESCALATION", "BUDGET_ESCALATION",
    "TTL_ESCALATION", "ACTION_OUT_OF_SCOPE", "CONSERVATION_BREACH", "OVERRIDE_ATTEMPT",
})

Failure = tuple[str, "str | None"]  # (reason code, culprit public key or None)


def _blank_effects() -> dict[str, Any]:
    return {
        "mandate_id": None, "actor": None, "actor_lamport": None, "mcp_name": None, "pool": None,
        "allocations": [], "quarantined": [], "subject_mem": None, "obs_lamport": None,
        "drift_bps": None, "release_nonce": None,
    }


def _mem_json(m: Mem) -> dict[str, Any]:
    return {"state": m.state, "clean_steps": m.clean_steps, "last_drift": m.last_drift}


@dataclass
class Decision:
    endpoint: str
    decision: str
    reason: str
    subject: str = ""
    state_before: str = "NONE"
    state_after: str = "NONE"
    clock_input: int | None = None
    effects: dict[str, Any] = field(default_factory=_blank_effects)
    shares: tuple[Share, ...] = ()
    mandate: Mandate | None = None
    drift: int | None = None


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    receipt_hash: str


def _keyset(name: str, keys: Iterable[str]) -> frozenset[str]:
    out = frozenset(keys)
    for k in out:
        try:
            wire.hexstr(k, 32)
        except wire.Malformed as exc:
            raise ValueError(f"{name}: public keys must be 64 lowercase hex") from exc
    return out


class ClearanceEngine:
    def __init__(
        self,
        *,
        signer: wire.Signer,
        audit_key: bytes,
        custos_issuers: Iterable[str],
        sensors: Iterable[str],
        release_authorities: Iterable[str],
        policy: Policy | None = None,
        ledger_path=None,
    ) -> None:
        self.policy = (policy or Policy()).validate()
        if type(audit_key) is not bytes or len(audit_key) < 32:
            raise ValueError("audit_key must be >= 32 bytes")
        self._signer = signer
        self._audit_key = audit_key
        self.custos_issuers = _keyset("custos_issuers", custos_issuers)
        self.sensors = _keyset("sensors", sensors)
        self.release_authorities = _keyset("release_authorities", release_authorities)
        if signer.public_hex in self.custos_issuers | self.sensors | self.release_authorities:
            raise ValueError("engine signing key must not double as an issuer, sensor or release authority")
        self._hard = HARD_BASE | ({"LEASE_EXPIRED"} if self.policy.expired_lease_is_hard else frozenset())
        self._lock = threading.Lock()
        dummy = wire.Signer.from_seed(bytes.fromhex(wire.sha256_hex(b"ARKHEIA/clearance/dummy-verifier")))
        dmsg = b"ARKHEIA/clearance/dummy\x00"
        self._dummy = SigCheck(dummy.public_hex, dummy.sign_hex(dmsg), dmsg)
        self.sig_verifications = 0  # instrumentation: proves constant verification work
        # derived state
        self._clock = 0
        self._mem: dict[str, Mem] = {}
        self._qhash: dict[str, str] = {}
        self._floor: dict[str, int] = {}
        self._used_mandates: set[str] = set()
        self._used_nonces: set[str] = set()
        self._last_cleared: dict[str, int] = {}
        self._last_obs: dict[str, int] = {}
        self._ledger = Ledger(trusted={signer.key_id: signer.public_hex}, path=ledger_path)
        for r in self._ledger.records:  # fail-closed recovery: state is a fold over the verified chain
            self._apply(r, receipt_hash(r))

    # ------------------------------------------------------------------ read-only views
    @property
    def public_key_hex(self) -> str:
        return self._signer.public_hex

    @property
    def public_key_id(self) -> str:
        return self._signer.key_id

    @property
    def clock(self) -> int:
        return self._clock

    @property
    def head_hash(self) -> str:
        return self._ledger.head_hash

    def records(self) -> list[dict[str, Any]]:
        return list(self._ledger.records)

    def trusted_keys(self) -> dict[str, str]:
        return {self._signer.key_id: self._signer.public_hex}

    def head_snapshot(self) -> dict[str, Any]:
        """One coherent public snapshot, serialized with receipt commits."""
        with self._lock:
            return {
                "engine_public_key": self.public_key_hex, "public_key_id": self.public_key_id,
                "head_hash": self._ledger.head_hash, "length": self._ledger.next_seq,
                "lamport": self._clock, "policy_version": self.policy.policy_version,
            }

    def state_of(self, subject: str) -> str:
        return self._mem_of(subject).state

    def quarantine_receipt_hash(self, subject: str) -> str | None:
        return self._qhash.get(subject)

    def _mem_of(self, subject: str) -> Mem:
        return self._mem.get(subject, Mem())

    # ------------------------------------------------------------------ public entry points
    def verify_mandate(self, raw: bytes, headers: Mapping[str, str] | None = None) -> Response:
        return self._run(MANDATE_EP, raw, headers, self._eval_mandate)

    def evaluate_aegis(self, raw: bytes, headers: Mapping[str, str] | None = None) -> Response:
        return self._run(AEGIS_EP, raw, headers, self._eval_aegis)

    def _run(self, endpoint: str, raw: bytes, headers: Mapping[str, str] | None,
             evaluator: Callable[[bytes, dict[str, str]], Decision]) -> Response:
        if type(raw) is not bytes:
            raw = b""
        hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        with self._lock:
            request_hash = wire.sha256_hex(raw)
            try:
                decision = evaluator(raw, hdrs)
            except Exception:  # noqa: BLE001 — fail closed: an unexpected fault is a *recorded* rejection
                decision = Decision(endpoint, "REJECTED", "INTERNAL_FAULT")
            receipt, h = self._commit(decision, request_hash)  # ledger faults propagate: no unreceipted output
            return self._respond(decision, receipt, h)

    # ------------------------------------------------------------------ signature padding
    def _verify_padded(self, checks: list[SigCheck], slots: int) -> list[bool]:
        if len(checks) > slots:
            raise ValueError("more signatures than slots")
        plan = checks + [self._dummy] * (slots - len(checks))
        results = [wire.ed25519_verify(c.public_hex, c.sig_hex, c.message) for c in plan]
        self.sig_verifications += len(plan)
        return results[: len(checks)]

    def _skew_ok(self, t: int) -> bool:
        return t <= self._clock + self.policy.max_lamport_skew

    # ------------------------------------------------------------------ /api/mandate/verify
    def _eval_mandate(self, raw: bytes, headers: dict[str, str]) -> Decision:
        p = self.policy
        fails: list[Failure] = []
        m: Mandate | None = None
        if len(raw) > p.max_body_bytes:
            fails.append(("OVERSIZE", None))
        else:
            try:
                m = parse_mandate(wire.parse_body(raw), p)
            except wire.Malformed:
                fails.append(("STRUCT", None))
        checks = [] if m is None else [m.lease.check, *(h.check for h in m.hops), m.check]
        results = self._verify_padded(checks, 2 + p.max_delegation_depth)
        if m is None:
            return self._reject(MANDATE_EP, fails, hard_effects=False, subject="", clock_input=None)

        lease, hops, actor, t = m.lease, m.hops, m.actor, m.lamport
        chain = (lease, *hops)

        # Stage 1/2 — authentication & linkage
        if headers.get("mcp-method", MCP_METHOD) != MCP_METHOD or \
                headers.get("mcp-name", m.mcp_name) != m.mcp_name or \
                headers.get("mcp-protocol-version", MCP_PROTOCOL_VERSION) != MCP_PROTOCOL_VERSION:
            fails.append(("MCP_HEADER_MISMATCH", None))
        if lease.grantor not in self.custos_issuers:
            fails.append(("LEASE_ISSUER_UNKNOWN", None))
        if not results[0]:
            fails.append(("LEASE_SIG", None))
        for i in range(len(hops)):
            if not results[1 + i]:
                fails.append(("HOP_SIG", None))
        if not results[1 + len(hops)]:
            fails.append(("REQUEST_SIG", None))
        for parent, hop in zip(chain, chain[1:]):
            if hop.grantor != parent.grantee or hop.lease_id != lease.lease_id:
                fails.append(("CHAIN_LINK", None))
        if actor != chain[-1].grantee:
            fails.append(("CHAIN_LINK", None))
        members = [g.grantee for g in chain]
        if len(set(members)) != len(members):
            fails.append(("CHAIN_CYCLE", None))
        # Transport metadata mismatch rejects execution but does not erase
        # cryptographic attribution of an otherwise valid signed chain.
        authenticated = not any(code != "MCP_HEADER_MISMATCH" for code, _ in fails)

        # Stage 2/3 — Lamport causality, revocation, non-expansive authority
        if any(self._mem_of(s).state == X_STAR for s in members):
            fails.append(("SUBJECT_QUARANTINED", None))
        if not self._skew_ok(t):
            fails.append(("LAMPORT_SKEW", None))
        if m.mandate_id in self._used_mandates:
            fails.append(("MANDATE_REPLAY", actor))
        last = self._last_cleared.get(actor)
        if last is not None and t <= last:
            fails.append(("LAMPORT_REGRESSION", actor))
        for g in chain:
            for party in (g.grantor, g.grantee):
                floor = self._floor.get(party)
                if floor is not None and g.lamport_issued <= floor:
                    fails.append(("LEASE_REVOKED", None))
        for parent, g in zip((None, *chain), chain):
            if parent is not None:
                if not g.scopes <= parent.scopes:
                    fails.append(("SCOPE_ESCALATION", g.grantor))
                if g.max_amount > parent.max_amount:
                    fails.append(("BUDGET_ESCALATION", g.grantor))
                if g.lamport_issued < parent.lamport_issued or g.expiry > parent.expiry:
                    fails.append(("TTL_ESCALATION", g.grantor))
            if not g.lamport_issued <= t < g.expiry:
                fails.append(("LEASE_EXPIRED", actor))
        effective = chain[-1]
        if m.mcp_name not in effective.scopes:
            fails.append(("ACTION_OUT_OF_SCOPE", actor))
        if m.pool > effective.max_amount:
            fails.append(("BUDGET_ESCALATION", actor))

        # Stage 4 — bps-ledger conservation
        shares: tuple[Share, ...] = ()
        try:
            shares = allocate(m.pool, m.allocations, p.max_allocations)
        except ConservationError:
            fails.append(("CONSERVATION_BREACH", actor))

        actor_mem = self._mem_of(actor)
        if actor_mem.state == THROTTLE and last is not None and t - last < p.throttle_interval:
            fails.append(("THROTTLED", None))

        if fails:
            return self._reject(MANDATE_EP, fails, hard_effects=authenticated,
                                subject=actor if authenticated else "",
                                clock_input=t if authenticated and self._skew_ok(t) else None)

        after = aegis.after_clear(actor_mem)
        eff = _blank_effects()
        eff.update({
            "mandate_id": m.mandate_id, "actor": actor, "actor_lamport": t, "mcp_name": m.mcp_name,
            "pool": format_u128(m.pool),
            "allocations": [{"recipient": s.recipient, "bps": s.bps, "amount": format_u128(s.amount)} for s in shares],
            "subject_mem": _mem_json(after),
        })
        return Decision(MANDATE_EP, "CLEARED", "OK", subject=actor, state_before=actor_mem.state,
                        state_after=after.state, clock_input=t, effects=eff, shares=shares, mandate=m)

    # ------------------------------------------------------------------ /api/aegis/evaluate
    def _eval_aegis(self, raw: bytes, headers: dict[str, str]) -> Decision:
        p = self.policy
        fails: list[Failure] = []
        obs: Observation | None = None
        rel: Release | None = None
        if len(raw) > p.max_body_bytes:
            fails.append(("OVERSIZE", None))
        else:
            try:
                body = wire.parse_body(raw)
                kind = body.get("type") if type(body) is dict else None
                if kind == "OBSERVATION":
                    obs = parse_observation(body)
                elif kind == "HUMAN_RELEASE":
                    rel = parse_release(body, p)
                else:
                    raise wire.Malformed()
            except wire.Malformed:
                fails.append(("STRUCT", None))
        if obs is not None:
            checks = [obs.check]
        elif rel is not None:
            checks = [a.check for a in rel.approvals]
        else:
            checks = []
        results = self._verify_padded(checks, p.max_approvals)
        if obs is not None:
            return self._eval_observation(obs, results[0])
        if rel is not None:
            return self._eval_release(rel, results)
        return self._reject(AEGIS_EP, fails, hard_effects=False, subject="", clock_input=None)

    def _eval_observation(self, obs: Observation, sig_ok: bool) -> Decision:
        fails: list[Failure] = []
        if obs.sensor not in self.sensors:
            fails.append(("SENSOR_UNKNOWN", None))
        if not sig_ok:
            fails.append(("SENSOR_SIG", None))
        if not self._skew_ok(obs.lamport):
            fails.append(("LAMPORT_SKEW", None))
        last = self._last_obs.get(obs.subject)
        if last is not None and obs.lamport <= last:
            fails.append(("OBS_REGRESSION", None))
        if fails:
            return self._reject(AEGIS_EP, fails, hard_effects=False, subject="", clock_input=None)
        before = self._mem_of(obs.subject)
        d = aegis.drift_bps(obs.window, self.policy)
        after = aegis.step(before, d, aegis.is_hard(obs.window), self.policy)
        eff = _blank_effects()
        eff.update({
            "subject_mem": _mem_json(after), "obs_lamport": obs.lamport, "drift_bps": d,
            "quarantined": [obs.subject] if after.state == X_STAR and before.state != X_STAR else [],
        })
        return Decision(AEGIS_EP, "STATE_UPDATED", "OK", subject=obs.subject, state_before=before.state,
                        state_after=after.state, clock_input=obs.lamport, effects=eff, drift=d)

    def _eval_release(self, rel: Release, results: list[bool]) -> Decision:
        p = self.policy
        fails: list[Failure] = []
        seen: set[str] = set()
        valid = 0
        for a, ok in zip(rel.approvals, results):
            if a.authority in seen:
                fails.append(("AUTHORITY_DUPLICATE", None))
                continue
            seen.add(a.authority)
            if a.authority not in self.release_authorities:
                # A *validly signed* release from a non-authority (e.g. the quarantined agent itself,
                # or a sibling in its swarm) is an override attempt (NO_EXTERNAL_OVERRIDE, Kernel 9).
                fails.append(("OVERRIDE_ATTEMPT", a.authority) if ok else ("AUTHORITY_UNKNOWN", None))
                continue
            if not ok:
                fails.append(("APPROVAL_SIG", None))
                continue
            valid += 1
        if valid < p.release_quorum:
            fails.append(("QUORUM_NOT_MET", None))
        if rel.policy_version != p.policy_version:
            fails.append(("POLICY_MISMATCH", None))
        if not rel.invariant_passed:
            fails.append(("INVARIANT_CHECK_FAILED", None))
        if not self._skew_ok(rel.lamport):
            fails.append(("LAMPORT_SKEW", None))
        before = self._mem_of(rel.subject)
        if before.state != X_STAR:
            fails.append(("NOT_QUARANTINED", None))
        q = self._qhash.get(rel.subject)
        if q is None or not wire.ct_equal(q, rel.quarantine_receipt_hash):
            fails.append(("QUARANTINE_HASH_MISMATCH", None))
        if rel.nonce in self._used_nonces:
            fails.append(("RELEASE_REPLAY", None))
        if fails:
            return self._reject(AEGIS_EP, fails, hard_effects=True, subject="", clock_input=None)
        after = aegis.release(before)
        eff = _blank_effects()
        eff.update({"subject_mem": _mem_json(after), "release_nonce": rel.nonce})
        return Decision(AEGIS_EP, "RELEASED", "OK", subject=rel.subject, state_before=before.state,
                        state_after=after.state, clock_input=rel.lamport, effects=eff)

    # ------------------------------------------------------------------ rejection
    def _reject(self, endpoint: str, fails: list[Failure], *, hard_effects: bool, subject: str,
                clock_input: int | None) -> Decision:
        reason = min((code for code, _ in fails), key=_RANK.__getitem__)
        quarantined: list[str] = []
        if hard_effects:
            quarantined = sorted({c for code, c in fails
                                  if c is not None and code in self._hard and self._mem_of(c).state != X_STAR})
        eff = _blank_effects()
        eff["quarantined"] = quarantined
        before = self._mem_of(subject).state if subject else "NONE"
        after = X_STAR if subject and subject in quarantined else before
        return Decision(endpoint, "REJECTED", reason, subject=subject, state_before=before,
                        state_after=after, clock_input=clock_input, effects=eff)

    # ------------------------------------------------------------------ commit (AX-6)
    def _commit(self, d: Decision, request_hash: str) -> tuple[dict[str, Any], str]:
        base = self._clock if d.clock_input is None or d.clock_input < self._clock else d.clock_input
        lamport = base + 1
        if lamport > WIRE_INT_MAX:
            raise LedgerError("Lamport clock exhausted")
        seq = self._ledger.next_seq
        reason_digest = wire.hmac_hex(
            self._audit_key, wire.DOMAIN_REASON + b"\x00" + d.reason.encode("ascii") + b"\x00" + str(seq).encode("ascii"))
        core = {"subject": d.subject, "state_before": d.state_before, "state_after": d.state_after,
                "reason_digest": reason_digest, "effects": d.effects}
        receipt = sign_receipt(self._signer, seq=seq, prev_hash=self._ledger.head_hash, lamport=lamport,
                               policy_version=self.policy.policy_version, endpoint=d.endpoint,
                               request_hash=request_hash, decision=d.decision, decision_core=core)
        h = self._ledger.append(receipt)
        self._apply(receipt, h)
        return receipt, h

    def _apply(self, r: Mapping[str, Any], h: str) -> None:
        """The single state-transition function, shared by live commits and ledger replay."""
        core = r["decision_core"]
        eff = core["effects"]
        subject = core["subject"]
        self._clock = r["lamport"]
        if eff["mandate_id"] is not None:
            self._used_mandates.add(eff["mandate_id"])
            self._last_cleared[eff["actor"]] = eff["actor_lamport"]
        if eff["subject_mem"] is not None:
            sm = eff["subject_mem"]
            self._mem[subject] = Mem(sm["state"], sm["clean_steps"], sm["last_drift"])
        if eff["obs_lamport"] is not None:
            self._last_obs[subject] = eff["obs_lamport"]
        if eff["release_nonce"] is not None:
            self._used_nonces.add(eff["release_nonce"])
            self._qhash.pop(subject, None)
        for s in eff["quarantined"]:
            self._mem[s] = aegis.quarantine(self._mem_of(s))
            self._floor[s] = r["lamport"]
            self._qhash[s] = h

    # ------------------------------------------------------------------ responses
    def _respond(self, d: Decision, receipt: dict[str, Any], h: str) -> Response:
        if d.decision == "REJECTED":
            return Response(403, opaque_rejection(h), h)
        if d.decision == "CLEARED":
            m = d.mandate
            permit = {
                "schema": PERMIT_SCHEMA,
                "policy_version": self.policy.policy_version,
                "mandate_id": m.mandate_id,
                "actor": m.actor,
                "mcp_name": m.mcp_name,
                "pool": format_u128(m.pool),
                "allocations_digest": wire.sha256_hex(wire.jcs(d.effects["allocations"])),
                "receipt_hash": h,
                "issued_lamport": receipt["lamport"],
                "not_after_lamport": receipt["lamport"] + self.policy.permit_ttl,
            }
            permit["signature"] = {"algorithm": "Ed25519", "public_key_id": self._signer.key_id,
                                   "value": self._signer.sign_hex(wire.signing_input(wire.DOMAIN_PERMIT, permit, "signature"))}
            body = {"schema": "ARKHEIA/mandate/verify/response/v1", "decision": "CLEARED",
                    "mandate_id": m.mandate_id, "allocations": d.effects["allocations"],
                    "permit": permit, "receipt": receipt, "receipt_hash": h}
            return Response(200, wire.jcs(body), h)
        body = {"schema": "ARKHEIA/aegis/evaluate/response/v1", "decision": d.decision,
                "subject": d.subject, "state": d.state_after, "drift_bps": d.drift,
                "receipt": receipt, "receipt_hash": h}
        return Response(200, wire.jcs(body), h)


def opaque_rejection(receipt_hash_hex: str) -> bytes:
    """The one and only rejection body. Fixed length; the receipt hash is its sole variable."""
    return wire.jcs({"code": "X*", "decision": "REJECTED", "receipt_hash": receipt_hash_hex,
                     "schema": REJECTION_SCHEMA})


def verify_permit(permit: Mapping[str, Any], public_hex: str) -> bool:
    if type(permit) is not dict or type(permit.get("signature")) is not dict:
        return False
    sig = permit["signature"].get("value")
    if type(sig) is not str or len(sig) != 128:
        return False
    return wire.ed25519_verify(public_hex, sig, wire.signing_input(wire.DOMAIN_PERMIT, permit, "signature"))


def decode_reason(receipt: Mapping[str, Any], audit_key: bytes) -> str | None:
    """Auditor-side: recover a receipt's primary reason code. Requires the HMAC audit key."""
    seq = str(receipt["seq"]).encode("ascii")
    digest = receipt["decision_core"]["reason_digest"]
    for code in REASONS:
        if wire.ct_equal(wire.hmac_hex(audit_key, wire.DOMAIN_REASON + b"\x00" + code.encode("ascii") + b"\x00" + seq), digest):
            return code
    return None
