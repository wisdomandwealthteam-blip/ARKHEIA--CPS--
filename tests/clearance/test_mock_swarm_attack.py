"""Live FastAPI swarm campaign (real Uvicorn process; no TestClient shortcuts).

Run directly: python tests/clearance/test_mock_swarm_attack.py --output-dir /tmp/swarm-run
Or run automatically with the full suite: pytest -q

Only local disposable test servers are started. Random seeds and audit keys are
written mode 0600 below the output directory's secrets/ subdirectory. Never use
these keys in production or include that subdirectory in a handoff archive.

Bad signatures cannot authenticate a claimed actor: they are rejected, not used
as an unauthenticated quarantine oracle. A trusted sensor's signed report of a
signature failure is the attributable hard trigger that immediately enters X*.
Python constant-time claims are limited to padded signature work (golden tests)
and the live latency floor/opaque response shape, not instruction-level timing.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arkheia_clearance import artifacts as A, wire
from arkheia_clearance.aegis import ALLOW, HUMAN_RELEASE, THROTTLE, X_STAR
from arkheia_clearance.engine import AEGIS_EP, MANDATE_EP, decode_reason, verify_permit
from arkheia_clearance.policy import Policy
from arkheia_clearance.receipts import receipt_hash, receipt_signing_input, verify_chain
from arkheia_clearance.service import engine_from_env

REJECTION_RE = re.compile(
    rb'\{"code":"X\*","decision":"REJECTED","receipt_hash":"[0-9a-f]{64}",'
    rb'"schema":"ARKHEIA/clearance/rejection/v1"\}')


def dump(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


class LiveCampaign:
    def __init__(self, output: Path, *, floor_ms: int = 25) -> None:
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.private = self.output / "secrets"
        self.private.mkdir(mode=0o700)
        self.ledger = self.output / "receipts.jsonl"
        self.floor_ms = floor_ms
        self.policy = Policy().validate()
        self.signers: dict[str, wire.Signer] = {}
        for label in ("engine", "issuer", "sensor", "human"):
            seed = secrets.token_bytes(32)
            path = self.private / (label + ".seed")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(seed.hex() + "\n")
            self.signers[label] = wire.Signer.from_seed(seed)
        self.audit = secrets.token_bytes(32)
        audit_path = self.private / "audit.key"
        fd = os.open(audit_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(self.audit.hex() + "\n")
        trust = {"custos_issuers": [self.signers["issuer"].public_hex],
                 "sensors": [self.signers["sensor"].public_hex],
                 "release_authorities": [self.signers["human"].public_hex]}
        dump(self.output / "trust-public.json", trust)
        self.env = os.environ.copy()
        for key in ("ARKHEIA_SIGNING_SEED_HEX", "ARKHEIA_TRUSTED_KEYS_FILE"):
            self.env.pop(key, None)
        self.env.update({
            "PYTHONPATH": str(ROOT), "CPS_ENV": "development", "CPS_REQUIRE_AUTH": "false",
            "CPS_RATE_LIMIT_ENABLED": "false", "STRIPE_SECRET_KEY": "", "STRIPE_WEBHOOK_SECRET": "",
            "CPS_BILLING_STORE_PATH": str(self.output / "billing.json"),
            "CPS_CLEARCHECK_STORE_PATH": str(self.output / "clearcheck.json"),
            "ARKHEIA_CLEARANCE_SIGNING_SEED_FILE": str(self.private / "engine.seed"),
            "ARKHEIA_CLEARANCE_AUDIT_KEY_FILE": str(audit_path),
            "ARKHEIA_CLEARANCE_TRUST_FILE": str(self.output / "trust-public.json"),
            "ARKHEIA_CLEARANCE_LEDGER": "jsonl:" + str(self.ledger),
            "ARKHEIA_CLEARANCE_FLOOR_MS": str(floor_ms),
        })
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.client = httpx.Client(base_url=self.base, timeout=15, trust_env=False)
        self.process: subprocess.Popen | None = None
        self.server_log = None
        self.transcript: list[dict] = []
        self.lock = threading.Lock()
        self.log_lines: list[str] = []
        self.id_counter = 0

    def say(self, message: str) -> None:
        self.log_lines.append(message)
        print(message, flush=True)

    def start(self) -> None:
        self.server_log = (self.output / "server.log").open("a")
        self.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "cps_backend.main:app", "--host", "127.0.0.1",
             "--port", str(self.port), "--workers", "1", "--no-access-log"],
            cwd=ROOT, env=self.env, stdout=self.server_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError("Uvicorn exited: see server.log")
            try:
                if self.client.get("/health").status_code == 200:
                    head = self.head()
                    assert head["engine_public_key"] == self.signers["engine"].public_hex
                    return
            except httpx.TransportError:
                pass
            time.sleep(0.05)
        raise AssertionError("Uvicorn readiness timeout: see server.log")

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
        if self.server_log is not None:
            self.server_log.close()
            self.server_log = None

    def head(self) -> dict:
        r = self.client.get("/api/clearance/head")
        assert r.status_code == 200, r.text
        assert r.headers["cache-control"] == "no-store"
        return r.json()

    def t(self) -> int:
        return self.head()["lamport"] + 1

    def ident(self, label: str) -> str:
        self.id_counter += 1
        return hashlib.sha256(f"live/{label}/{self.id_counter}".encode()).hexdigest()[:32]

    def agent(self) -> wire.Signer:
        return wire.Signer.from_seed(secrets.token_bytes(32))

    def lease(self, actor: wire.Signer, *, issued: int | None = None,
              scopes=("payments.transfer",), max_amount=1_000_000) -> dict:
        return A.lease(self.signers["issuer"], holder=actor.public_hex, lease_id=self.ident("lease"),
                       scopes=scopes, max_amount=max_amount,
                       lamport_issued=self.t() if issued is None else issued, ttl=50_000)

    def mandate(self, actor: wire.Signer, lease: dict, *, t: int | None = None,
                pool=100, tool="payments.transfer", delegations=()) -> dict:
        return A.mandate(actor, mandate_id=self.ident("mandate"), lamport=self.t() if t is None else t,
                         mcp_name=tool, pool=pool, allocations=(("ops", 4000), ("treasury", 6000)),
                         lease_obj=lease, delegations=delegations)

    def records(self) -> list[dict]:
        if not self.ledger.exists():
            return []
        return [wire.parse_body(line) for line in self.ledger.read_bytes().splitlines() if line.strip()]

    def last_record(self, body: dict) -> dict:
        records = self.records()
        found = next(r for r in records if receipt_hash(r) == body["receipt_hash"])
        # This is present on disk before the HTTP output is acted upon (AX-6).
        self.verify_receipt(found)
        return found

    def verify_receipt(self, rec: dict) -> None:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.signers["engine"].public_hex))
        pub.verify(bytes.fromhex(rec["signature"]["value"]), receipt_signing_input(rec))
        assert hashlib.sha256(wire.jcs(rec["decision_core"])).hexdigest() == rec["decision_core_hash"]
        assert rec["signature"]["algorithm"] == "Ed25519"
        assert rec["policy_version"] == self.policy.policy_version

    def post(self, endpoint: str, obj: Any, label: str, *, expected=200) -> dict:
        raw = obj if isinstance(obj, bytes) else A.to_bytes(obj)
        start = time.perf_counter_ns()
        r = self.client.post(endpoint, content=raw, headers={"Content-Type": "application/json"})
        elapsed = time.perf_counter_ns() - start
        assert r.status_code == expected, (label, r.status_code, r.text)
        assert r.headers["cache-control"] == "no-store"
        body = r.json()
        if expected == 403:
            assert REJECTION_RE.fullmatch(r.content), (label, r.text)
            assert elapsed >= self.floor_ms * 1_000_000, (label, elapsed)
        else:
            self.verify_receipt(body["receipt"])
            assert receipt_hash(body["receipt"]) == body["receipt_hash"]
        row = {"label": label, "endpoint": endpoint, "status": r.status_code, "elapsed_ns": elapsed,
               "request_hash": hashlib.sha256(raw).hexdigest(), "receipt_hash": body["receipt_hash"],
               "decision": body["decision"], "state": body.get("state")}
        with self.lock:
            self.transcript.append(row)
        return body

    def observe(self, actor: wire.Signer, label: str, *, state: str, **window) -> dict:
        obj = A.observation(self.signers["sensor"], subject=actor.public_hex, lamport=self.t(), **window)
        body = self.post(AEGIS_EP, obj, label)
        assert body["state"] == state, (label, body)
        return body

    def release(self, actor: wire.Signer, qhash: str, *, approver=None, passed=True, policy=None) -> dict:
        return A.human_release([approver or self.signers["human"]], subject=actor.public_hex,
                              quarantine_receipt_hash=qhash, lamport=self.t(), nonce=self.ident("release"),
                              evidence_digest=hashlib.sha256(b"local-test-invariant-evidence").hexdigest(),
                              passed=passed, policy_version=policy or self.policy.policy_version)

    def reject(self, obj: dict, label: str, reason: str, *, endpoint=MANDATE_EP) -> dict:
        body = self.post(endpoint, obj, label, expected=403)
        rec = self.last_record(body)
        assert decode_reason(rec, self.audit) == reason, (label, decode_reason(rec, self.audit))
        return rec

    def campaign(self, burst_size: int) -> dict:
        self.start()
        self.say("LIVE MOCK SWARM: cps_backend.main:app; real loopback HTTP; dedicated random Ed25519 keys")
        self.say(f"Policy {self.policy.policy_version}; latency floor {self.floor_ms} ms; single Uvicorn worker")
        # Legacy routes remain live. Stripe is deliberately unconfigured: no provider calls/payments.
        legacy = self.client.post("/api/clearcheck/preview", json={
            "consumer_name": "Mock Consumer", "jurisdiction": "US-CA", "report_date": "2026-11-01", "accounts": [{
                "account_number": "MOCK-1234", "creditor_name": "Mock Bank", "status": "open", "date_opened": "2020-01-01",
                "reported_balance": 100}]})
        assert legacy.status_code == 200, legacy.text
        assert self.client.get("/api/clearcheck/report/" + legacy.json()["check_id"]).status_code == 402
        assert self.client.post("/billing/webhook", content=b"{}").status_code == 503
        assert self.client.get("/v1/public-keys").status_code == 503
        self.say("PASS legacy health / ClearCheck preview+locked report / Stripe fail-closed / DVE verify-only routes")

        info = self.client.get("/openapi.json").json()["info"]
        assert info["title"] == "ARKHEIA 7™ — Deterministic Agent Gate"
        assert info["version"] == "1.0.1" and info["x-commercial"]["brand"] == "7™"
        capped_actor = self.agent()
        capped_lease = A.lease(self.signers["issuer"], holder=capped_actor.public_hex,
                               lease_id=self.ident("capped-lease"), scopes=("payments.transfer",),
                               max_amount=1_000_000, lamport_issued=self.t(), ttl=4)
        capped = self.post(MANDATE_EP, self.mandate(capped_actor, capped_lease), "live-permit-ttl-cap")
        permit = capped["permit"]
        assert permit["expires_at"] == permit["lease_expires_at"] == capped_lease["lamport_issued"] + 4
        assert verify_permit(permit, self.signers["engine"].public_hex, current_lamport=permit["issued_lamport"])
        expired_actor = self.agent()
        expiring = A.lease(self.signers["issuer"], holder=expired_actor.public_hex,
                           lease_id=self.ident("expired-at-issue"), scopes=("payments.transfer",),
                           max_amount=1_000_000, lamport_issued=self.t(), ttl=1)
        self.reject(self.mandate(expired_actor, expiring), "live-lease-expired-at-issuance", "LEASE_EXPIRED")
        self.say("PASS 7™ v1.0.1 OpenAPI branding; signed permit TTL cap; expired-at-issuance lease => opaque 403")

        main = self.agent()
        old = self.lease(main)
        for i in range(3):
            body = self.post(MANDATE_EP, self.mandate(main, old), f"baseline-mandate-{i}")
            permit = body["permit"]
            assert body["decision"] == "CLEARED" and verify_permit(
                permit, self.signers["engine"].public_hex, current_lamport=permit["issued_lamport"])
            assert permit["issued_lamport"] < permit["expires_at"] <= permit["lease_expires_at"]
            assert sum(int(x["amount"]) for x in body["allocations"]) == 100
        clean = self.observe(main, "baseline-observation", state=ALLOW, request_count=1)
        mid = self.observe(main, "drift-throttle", state=THROTTLE, request_count=100, reject_count=80)
        high = self.observe(main, "burst-quarantine", state=X_STAR, request_count=1000, reject_count=1000)
        assert clean["drift_bps"] < self.policy.theta2_bps
        assert self.policy.theta2_bps <= mid["drift_bps"] < self.policy.theta3_bps
        assert high["drift_bps"] == self.policy.theta3_bps
        qhash = high["receipt_hash"]
        self.say(f"PASS ALLOW -> THROTTLE -> X*: drift {clean['drift_bps']} / {mid['drift_bps']} / {high['drift_bps']} bps")
        for i in range(12):
            self.observe(main, f"absorbed-clean-{i}", state=X_STAR, request_count=1)
        self.reject(self.mandate(main, old), "absorbed-mandate", "SUBJECT_QUARANTINED")
        before_restart = self.head()
        self.stop()
        self.start()
        assert self.head() == before_restart
        self.observe(main, "absorbed-after-process-restart", state=X_STAR, request_count=1)
        self.say("PASS X* absorbs 12 clean windows and clean mandate; survives full Uvicorn process restart")

        self.reject(self.release(main, qhash, approver=main), "self-release", "OVERRIDE_ATTEMPT", endpoint=AEGIS_EP)
        self.reject(self.release(main, "ab" * 32), "wrong-anchor-release", "QUARANTINE_HASH_MISMATCH", endpoint=AEGIS_EP)
        self.reject(self.release(main, qhash, passed=False), "failed-invariant-release", "INVARIANT_CHECK_FAILED", endpoint=AEGIS_EP)
        tampered = self.release(main, qhash)
        tampered["approvals"][0]["sig"] = "00" * 64
        self.reject(tampered, "invalid-release-signature", "APPROVAL_SIG", endpoint=AEGIS_EP)
        self.observe(main, "still-absorbed-after-bad-releases", state=X_STAR)
        rel = self.release(main, qhash)
        body = self.post(AEGIS_EP, rel, "authorized-human-release")
        assert body["decision"] == "RELEASED" and body["state"] == HUMAN_RELEASE
        self.reject(self.mandate(main, old), "revoked-pre-quarantine-lease", "LEASE_REVOKED")
        fresh = self.lease(main)
        clear = self.post(MANDATE_EP, self.mandate(main, fresh), "fresh-post-release-mandate")
        assert clear["receipt"]["decision_core"]["state_after"] == ALLOW
        self.say("PASS only valid authority-signed HUMAN_RELEASE exits X*; stale lease remains revoked; fresh lease restores ALLOW")

        reg = self.agent()
        lease = self.lease(reg)
        first = self.mandate(reg, lease)
        self.post(MANDATE_EP, first, "regression-baseline")
        rec = self.reject(self.mandate(reg, lease, t=first["lamport"]), "lamport-regression", "LAMPORT_REGRESSION")
        assert rec["decision_core"]["state_after"] == X_STAR
        self.observe(reg, "regression-absorbed", state=X_STAR)
        replay = self.agent()
        replay_mandate = self.mandate(replay, self.lease(replay))
        self.post(MANDATE_EP, replay_mandate, "replay-baseline")
        rec = self.reject(replay_mandate, "mandate-replay", "MANDATE_REPLAY")
        assert rec["decision_core"]["state_after"] == X_STAR
        budget = self.agent()
        rec = self.reject(self.mandate(budget, self.lease(budget, max_amount=10), pool=11),
                          "budget-escalation", "BUDGET_ESCALATION")
        assert rec["decision_core"]["state_after"] == X_STAR
        scope = self.agent()
        rec = self.reject(self.mandate(scope, self.lease(scope), tool="treasury.sweep"),
                          "action-out-of-scope", "ACTION_OUT_OF_SCOPE")
        assert rec["decision_core"]["state_after"] == X_STAR
        # Non-expansive A2A: quarantine the authenticated expanding delegator, not an innocent delegate.
        delegator, delegate = self.agent(), self.agent()
        parent = self.lease(delegator)
        hop = A.delegation(delegator, delegate=delegate.public_hex, lease_id=parent["lease_id"],
                           scopes=("payments.transfer", "treasury.sweep"), max_amount=100,
                           lamport_issued=parent["lamport_issued"], ttl=40_000)
        rec = self.reject(self.mandate(delegate, parent, delegations=(hop,)), "a2a-scope-escalation", "SCOPE_ESCALATION")
        assert rec["decision_core"]["effects"]["quarantined"] == [delegator.public_hex]
        self.observe(delegator, "expanding-delegator-absorbed", state=X_STAR)
        self.observe(delegate, "innocent-delegate-not-quarantined", state=ALLOW)
        self.say("PASS immediate X* on authenticated Lamport regression, replay, budget/action violations and A2A scope expansion")

        victim = self.agent()
        victim_lease = self.lease(victim)
        invalid = self.mandate(victim, victim_lease)
        invalid["sig"] = "00" * 64
        rec = self.reject(invalid, "unauthenticated-invalid-signature", "REQUEST_SIG")
        assert rec["decision_core"]["effects"]["quarantined"] == []
        self.observe(victim, "no-spoofed-quarantine", state=ALLOW)
        self.observe(victim, "trusted-signature-failure", state=X_STAR, signature_failures=1)
        self.reject(self.mandate(victim, victim_lease), "signature-failure-absorbed", "SUBJECT_QUARANTINED")
        self.say("PASS invalid signature => opaque 403; no spoofed identity quarantine; signed trusted signature-failure => immediate X*")

        start_length = self.head()["length"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, burst_size)) as pool:
            tasks = [pool.submit(self.post, MANDATE_EP if i % 2 == 0 else AEGIS_EP,
                                 b"{}", f"concurrent-garbage-{i}", expected=403) for i in range(burst_size)]
            for task in tasks:
                task.result()
        assert self.head()["length"] == start_length + burst_size
        self.observe(victim, "still-absorbed-after-concurrent-burst", state=X_STAR, request_count=1)
        self.say(f"PASS {burst_size} concurrent burst rejections: no lost/duplicate receipt commits, X* unchanged")

        head = self.head()
        records = self.records()
        trusted = {head["public_key_id"]: head["engine_public_key"]}
        report = verify_chain(records, trusted)
        assert report["valid"] and report["length"] == len(self.transcript) == head["length"]
        assert report["head_hash"] == head["head_hash"]
        by_hash = {receipt_hash(rec): rec for rec in records}
        assert len(by_hash) == len(records)
        for row in self.transcript:
            rec = by_hash[row["receipt_hash"]]
            self.verify_receipt(rec)
            assert rec["request_hash"] == row["request_hash"] and rec["endpoint"] == row["endpoint"]
            row["seq"] = rec["seq"]
            row["audit_reason"] = decode_reason(rec, self.audit)
        recovered = engine_from_env(self.env)
        assert recovered.head_hash == head["head_hash"] and recovered.state_of(victim.public_hex) == X_STAR
        corrupt = json.loads(json.dumps(records))
        corrupt[len(corrupt) // 2]["decision_core"]["state_after"] = "TAMPERED"
        assert not verify_chain(corrupt, trusted)["valid"]
        self.say(f"PASS full chain: {len(records)} receipts, contiguous seq, strictly increasing Lamport, SHA-256 and Ed25519; tampering detected")
        rejected_ns = sorted(row["elapsed_ns"] for row in self.transcript if row["status"] == 403)
        summary = {"result": "PASS", "policy_version": self.policy.policy_version,
                   "receipt_count": len(records), "head_hash": head["head_hash"], "chain": report,
                   "burst_size": burst_size, "workers": 1, "floor_ms": self.floor_ms,
                   "rejection_latency_ns": {"min": rejected_ns[0], "median": rejected_ns[len(rejected_ns) // 2],
                                            "max": rejected_ns[-1]},
                   "limits": ["Python is not instruction-level constant time; floor and padded work are tested separately.",
                              "Unauthenticated bad signatures do not quarantine claimed identities; trusted reports do.",
                              "JSONL engine supports a single process/worker; not a distributed ledger."]}
        dump(self.output / "summary.json", summary)
        dump(self.output / "head-public.json", head)
        self.say("MOCK SWARM ATTACK: PASS")
        return summary

    def finish(self) -> None:
        self.stop()
        self.client.close()
        rows = sorted(self.transcript, key=lambda r: r.get("seq", -1))
        (self.output / "attack-transcript.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
        (self.output / "mock-swarm-attack.log").write_text("\n".join(self.log_lines) + "\n")


def run_attack(output: Path, *, burst_size=64, floor_ms=25) -> dict:
    assert 1 <= burst_size <= 1000 and 0 <= floor_ms <= 1000
    run = LiveCampaign(output, floor_ms=floor_ms)
    try:
        return run.campaign(burst_size)
    except Exception as exc:
        run.say(f"MOCK SWARM ATTACK: FAIL ({type(exc).__name__})")
        raise
    finally:
        run.finish()


@pytest.mark.live
def test_mock_swarm_attack(tmp_path):
    summary = run_attack(tmp_path / "live-swarm")
    assert summary["result"] == "PASS"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path, help="Fresh local run directory (contains private secrets/)")
    parser.add_argument("--burst-size", type=int, default=64)
    parser.add_argument("--floor-ms", type=int, default=25)
    args = parser.parse_args()
    run_attack(args.output_dir, burst_size=args.burst_size, floor_ms=args.floor_ms)
