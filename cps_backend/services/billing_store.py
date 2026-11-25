"""
cps_backend.services.billing_store
=====================================
Persists subscription records: which tenant has which Stripe customer/
subscription ID, what tier they're on, and whether their subscription is
currently active.

WHY A JSON FILE: you asked for "a simple database or JSON file," and for
a single-instance deployment this is genuinely fine — it's durable across
restarts (unlike the in-memory rate limiter), requires no separate
service to run, and is trivial to inspect/debug by just opening the
file. It will NOT work correctly across multiple server instances or
concurrent writers (see the file-locking caveat below) — that's the
signal you've outgrown this and need a real database (Postgres, etc.).

SWAP-IN PATH: every other module talks to this file only through the
five functions below (`get_subscription`, `upsert_subscription`,
`delete_subscription`, `all_subscriptions`, `is_active`). Replace this
module's internals with real database calls and nothing else in the
codebase needs to change.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from cps_backend.config import settings
from cps_backend.services.tiers import Tier
from cps_backend.utils.logging_setup import logger

# A single process-wide lock. This makes concurrent requests within ONE
# process safe. It does NOT make concurrent writes safe across multiple
# processes/instances — see module docstring.
_lock = threading.Lock()


@dataclass
class SubscriptionRecord:
    tenant_id: str
    stripe_customer_id: str | None
    stripe_subscription_id: str | None
    tier: str  # Tier value, stored as plain str for JSON-friendliness
    status: str  # Stripe subscription status: "active", "past_due", "canceled", etc.
    current_period_end: str | None  # ISO 8601 timestamp, or None if unknown
    updated_at: str

    def is_active(self) -> bool:
        """A subscription counts as active if Stripe says its status is
        one of the "usable" states. `past_due` is intentionally excluded —
        per your requirement to reject unpaid subscriptions, a payment
        that's failed should downgrade access, not silently continue it."""
        return self.status in {"active", "trialing"}


def _ensure_store_file() -> None:
    path = settings.billing_store_path
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump({}, f)


def _read_all() -> dict[str, dict]:
    _ensure_store_file()
    with open(settings.billing_store_path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            logger.error("billing store file is corrupt; treating as empty")
            return {}


def _write_all(data: dict[str, dict]) -> None:
    path = settings.billing_store_path
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)  # atomic on POSIX — avoids a half-written file


def get_subscription(tenant_id: str) -> SubscriptionRecord | None:
    with _lock:
        data = _read_all()
        record = data.get(tenant_id)
        return SubscriptionRecord(**record) if record else None


def upsert_subscription(record: SubscriptionRecord) -> None:
    record.updated_at = datetime.now(timezone.utc).isoformat()
    with _lock:
        data = _read_all()
        data[record.tenant_id] = asdict(record)
        _write_all(data)
    logger.info(
        "subscription upserted tenant=%s tier=%s status=%s",
        record.tenant_id,
        record.tier,
        record.status,
    )


def delete_subscription(tenant_id: str) -> None:
    with _lock:
        data = _read_all()
        if tenant_id in data:
            del data[tenant_id]
            _write_all(data)
    logger.info("subscription deleted tenant=%s", tenant_id)


def all_subscriptions() -> list[SubscriptionRecord]:
    with _lock:
        data = _read_all()
        return [SubscriptionRecord(**v) for v in data.values()]


def is_active(tenant_id: str) -> bool:
    """Free-tier tenants (no Stripe subscription at all) are always
    'active' at the free tier — this only governs paid subscriptions."""
    record = get_subscription(tenant_id)
    if record is None:
        return True  # no paid subscription = free tier, which is always usable
    return record.is_active()


def effective_tier(tenant_id: str) -> Tier:
    """The tier to actually enforce for this tenant right now. A tenant
    with an inactive (past_due/canceled) paid subscription is downgraded
    to FREE rather than losing access entirely."""
    record = get_subscription(tenant_id)
    if record is None:
        return Tier.FREE
    if not record.is_active():
        return Tier.FREE
    try:
        return Tier(record.tier)
    except ValueError:
        logger.warning(
            "unknown tier %r stored for tenant=%s, defaulting to FREE",
            record.tier,
            tenant_id,
        )
        return Tier.FREE


class BillingStoreError(Exception):
    """Trial persistence is unavailable; callers must fail closed."""


@dataclass(frozen=True)
class TrialRecord:
    session_id: str
    stripe_customer_id: str
    stripe_subscription_id: str | None
    status: str
    trial_expires_at: int

    def is_active(self) -> bool:
        return (
            self.status == "trial_active"
            and datetime.now(timezone.utc).timestamp() < self.trial_expires_at
        )


@contextmanager
def _trial_db():
    # Keep trial records separate from legacy tenant JSON. SQLite transactions
    # also protect session idempotency and cancellation across worker processes.
    connection = None
    try:
        path = f"{settings.billing_store_path}.trials.sqlite3"
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        connection = sqlite3.connect(path, timeout=5)
        os.chmod(path, 0o600)
        connection.row_factory = sqlite3.Row
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS trials (
                    session_id TEXT PRIMARY KEY,
                    stripe_customer_id TEXT NOT NULL,
                    stripe_subscription_id TEXT,
                    status TEXT NOT NULL,
                    trial_expires_at INTEGER NOT NULL
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS revoked_trial_subscriptions (
                    subscription_id TEXT PRIMARY KEY
                )
            """)
            yield connection
    except (OSError, sqlite3.Error):
        raise BillingStoreError("Trial records are temporarily unavailable.") from None
    finally:
        if connection is not None:
            connection.close()


def get_trial(session_id: str) -> TrialRecord | None:
    with _trial_db() as db:
        row = db.execute("SELECT * FROM trials WHERE session_id = ?", (session_id,)).fetchone()
        return TrialRecord(**dict(row)) if row is not None else None


def record_paid_trial(
    session_id: str,
    stripe_customer_id: str,
    stripe_subscription_id: str | None,
    trial_expires_at: int,
) -> None:
    with _trial_db() as db:
        # Reserve the write lock before reading revocations so a simultaneous
        # cancellation cannot race the paid checkout into reactivation.
        db.execute("BEGIN IMMEDIATE")
        revoked = stripe_subscription_id and db.execute(
            "SELECT 1 FROM revoked_trial_subscriptions WHERE subscription_id = ?",
            (stripe_subscription_id,),
        ).fetchone()
        db.execute(
            "INSERT OR IGNORE INTO trials VALUES (?, ?, ?, ?, ?)",
            (session_id, stripe_customer_id, stripe_subscription_id,
             "canceled" if revoked else "trial_active", trial_expires_at),
        )
        # INSERT OR IGNORE means replayed events cannot extend seven days or
        # overwrite a cancellation. Only a different, paid session is a new trial.


def revoke_trial_subscription(subscription_id: str) -> None:
    with _trial_db() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "INSERT OR IGNORE INTO revoked_trial_subscriptions VALUES (?)",
            (subscription_id,),
        )
        db.execute(
            "UPDATE trials SET status = 'canceled' WHERE stripe_subscription_id = ?",
            (subscription_id,),
        )
