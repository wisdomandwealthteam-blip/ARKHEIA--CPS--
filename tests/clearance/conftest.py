"""Shared fixtures for the ARKHEIA Mandate / Aegis-Swarm golden suite."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "vendor" / "arkheia-receipts" / "python"):
    if str(p) not in sys.path:  # works with or without `pip install -e`
        sys.path.insert(0, str(p))

import pytest  # noqa: E402

from arkheia_clearance import artifacts as A  # noqa: E402
from arkheia_clearance.engine import decode_reason  # noqa: E402
from arkheia_clearance.golden import World  # noqa: E402


class Harness:
    """A World plus a live engine and convenience senders that return (response, reason)."""

    def __init__(self, world: World, ledger_path=None, policy=None) -> None:
        self.w = world
        self.e = world.engine(ledger_path=ledger_path, policy=policy)

    def t(self, ahead: int = 1) -> int:
        return self.e.clock + ahead

    def mandate(self, obj, headers=None):
        r = self.e.verify_mandate(A.to_bytes(obj), headers)
        return r, decode_reason(self.e.records()[-1], self.w.audit_key)

    def aegis(self, obj, headers=None):
        r = self.e.evaluate_aegis(A.to_bytes(obj), headers)
        return r, decode_reason(self.e.records()[-1], self.w.audit_key)

    def raw_mandate(self, raw: bytes):
        r = self.e.verify_mandate(raw)
        return r, decode_reason(self.e.records()[-1], self.w.audit_key)

    def raw_aegis(self, raw: bytes):
        r = self.e.evaluate_aegis(raw)
        return r, decode_reason(self.e.records()[-1], self.w.audit_key)

    def state(self, signer) -> str:
        return self.e.state_of(signer.public_hex)

    def quarantine(self, agent) -> str:
        """Drive ``agent`` into X* via a hard observation; return the quarantine receipt hash."""
        r, _ = self.aegis(self.w.observe(agent, t=self.t(), scope_violations=1))
        assert r.status == 200 and self.state(agent) == "QUARANTINE_X_STAR"
        return r.receipt_hash


@pytest.fixture
def world() -> World:
    return World()


@pytest.fixture
def h(world) -> Harness:
    return Harness(world)


@pytest.fixture
def make_harness(world):
    def _make(**kw) -> Harness:
        return Harness(world, **kw)
    return _make
