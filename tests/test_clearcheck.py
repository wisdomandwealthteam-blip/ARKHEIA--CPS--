"""Tests for the ClearCheck consumer endpoints:

1. Deterministic output — identical submissions produce identical
   check_ids, findings, and redacted summaries.
2. Preview redaction — raw sensitive identifiers (account numbers,
   emails, SSN fragments, names) never appear in any response body.
3. Locked vs. unlocked report access — 402 until the Stripe
   checkout.session.completed webhook marks the check unlocked on disk,
   then the full findings breakdown is returned.
4. Webhook signature verification and event-ID idempotency.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

from cps_backend.config import settings
from cps_backend.main import app
from cps_backend.services import clearcheck_store

client = TestClient(app, raise_server_exceptions=False)

SECRET_ACCOUNT = "ACCT-SECRET-99881234"
SECRET_EMAIL = "superprivate@example.com"
SECRET_NAME = "Jane Q. Consumer"
WEBHOOK_SECRET = "whsec_test_clearcheck"


@pytest.fixture(autouse=True)
def isolated_store(tmp_path):
    """Point the clearcheck store at a fresh temp file per test.
    settings is a frozen dataclass, so bypass __setattr__ directly."""
    original = settings.clearcheck_store_path
    object.__setattr__(
        settings, "clearcheck_store_path", str(tmp_path / "clearcheck_checks.json")
    )
    yield
    object.__setattr__(settings, "clearcheck_store_path", original)


@pytest.fixture
def stripe_configured():
    originals = (settings.stripe_secret_key, settings.stripe_webhook_secret)
    object.__setattr__(settings, "stripe_secret_key", "sk_test_clearcheck")
    object.__setattr__(settings, "stripe_webhook_secret", WEBHOOK_SECRET)
    yield
    object.__setattr__(settings, "stripe_secret_key", originals[0])
    object.__setattr__(settings, "stripe_webhook_secret", originals[1])


def sample_payload() -> dict:
    """A submission with known, deliberate inconsistencies:
    account 1: closed date before opened date  -> DATE_CLOSED_BEFORE_OPENED
               nonzero balance while closed    -> BALANCE_ON_CLOSED_ACCOUNT
    account 2: open but carries a closed date  -> OPEN_WITH_CLOSED_DATE
               past due exceeds balance        -> PAST_DUE_EXCEEDS_BALANCE
    """
    return {
        "consumer_name": SECRET_NAME,
        "consumer_email": SECRET_EMAIL,
        "ssn_last4": "6789",
        "jurisdiction": "US-CA",
        "report_date": "2025-06-01",
        "accounts": [
            {
                "account_number": SECRET_ACCOUNT,
                "creditor_name": "First Example Bank",
                "status": "closed",
                "date_opened": "2020-05-01",
                "date_closed": "2019-01-01",
                "reported_balance": 1500.0,
            },
            {
                "account_number": "4111-2222-3333-5555",
                "creditor_name": "Second Example Card",
                "status": "open",
                "date_opened": "2018-03-15",
                "date_closed": "2024-01-01",
                "reported_balance": 100.0,
                "reported_past_due": 250.0,
                "credit_limit": 5000.0,
            },
        ],
    }


EXPECTED_CODES = {
    "DATE_CLOSED_BEFORE_OPENED",
    "BALANCE_ON_CLOSED_ACCOUNT",
    "OPEN_WITH_CLOSED_DATE",
    "PAST_DUE_EXCEEDS_BALANCE",
}


def _signed_webhook_headers(payload: bytes, secret: str = WEBHOOK_SECRET) -> dict:
    """Builds a genuine Stripe-Signature header so the webhook route's
    real signature verification passes."""
    ts = int(time.time())
    signed = f"{ts}.".encode() + payload
    mac = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return {"stripe-signature": f"t={ts},v1={mac}"}


def _checkout_completed_event(check_id: str, event_id: str = "evt_test_1") -> bytes:
    return json.dumps(
        {
            "id": event_id,
            "object": "event",
            "api_version": "2024-06-20",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_1",
                    "object": "checkout.session",
                    "metadata": {
                        "purpose": "clearcheck_unlock",
                        "check_id": check_id,
                    },
                }
            },
        }
    ).encode()


def _unlock_via_webhook(check_id: str, event_id: str = "evt_test_1"):
    payload = _checkout_completed_event(check_id, event_id)
    return client.post(
        "/billing/webhook",
        content=payload,
        headers=_signed_webhook_headers(payload),
    )


# ------------------------------------------------------------ determinism

def test_preview_is_deterministic():
    first = client.post("/api/clearcheck/preview", json=sample_payload())
    second = client.post("/api/clearcheck/preview", json=sample_payload())
    assert first.status_code == 200 and second.status_code == 200
    a, b = first.json(), second.json()
    assert a["check_id"] == b["check_id"]
    assert a["findings_count"] == b["findings_count"]
    assert a["redacted_summary"] == b["redacted_summary"]


def test_different_input_yields_different_check_id():
    first = client.post("/api/clearcheck/preview", json=sample_payload())
    changed = sample_payload()
    changed["accounts"][0]["reported_balance"] = 0.0
    second = client.post("/api/clearcheck/preview", json=changed)
    assert first.json()["check_id"] != second.json()["check_id"]


def test_preview_detects_expected_findings():
    resp = client.post("/api/clearcheck/preview", json=sample_payload())
    body = resp.json()
    assert body["findings_count"] == len(EXPECTED_CODES)
    assert len(body["redacted_summary"]) == len(EXPECTED_CODES)


def test_clean_submission_has_zero_findings():
    payload = {
        "consumer_name": "Clean Consumer",
        "report_date": "2025-06-01",
        "accounts": [
            {
                "account_number": "CLEAN-0001",
                "creditor_name": "Clean Bank",
                "status": "open",
                "date_opened": "2020-01-01",
                "reported_balance": 100.0,
                "credit_limit": 1000.0,
            }
        ],
    }
    resp = client.post("/api/clearcheck/preview", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["findings_count"] == 0
    assert body["redacted_summary"] == []


# -------------------------------------------------------------- redaction

def test_preview_never_exposes_unmasked_identifiers():
    resp = client.post("/api/clearcheck/preview", json=sample_payload())
    assert resp.status_code == 200
    assert SECRET_ACCOUNT not in resp.text
    assert SECRET_EMAIL not in resp.text
    assert SECRET_NAME not in resp.text
    assert "6789" not in json.dumps(resp.json()["redacted_summary"])
    # masked account suffix is still usable for correlation
    assert any("1234" in line for line in resp.json()["redacted_summary"])


def test_preview_attaches_notice_and_jurisdiction_metadata():
    resp = client.post("/api/clearcheck/preview", json=sample_payload())
    body = resp.json()
    assert body["unlock_required"] is True
    assert "not legal advice" in body["notice"]
    assert body["jurisdiction"] == "US-CA"
    assert "California" in body["jurisdiction_metadata"]["name"]


def test_unknown_jurisdiction_gets_fallback_metadata():
    payload = sample_payload()
    payload["jurisdiction"] = "ZZ"
    body = client.post("/api/clearcheck/preview", json=payload).json()
    assert body["jurisdiction_metadata"]["primary_statute"] is None
    assert "note" in body["jurisdiction_metadata"]


def test_validation_error_does_not_leak_account_number():
    payload = sample_payload()
    del payload["report_date"]  # whole body attaches as the error 'input'
    resp = client.post("/api/clearcheck/preview", json=payload)
    assert resp.status_code == 422
    assert SECRET_ACCOUNT not in resp.text
    assert SECRET_EMAIL not in resp.text


def test_stored_check_record_contains_no_raw_identifiers():
    check_id = client.post(
        "/api/clearcheck/preview", json=sample_payload()
    ).json()["check_id"]
    raw = json.dumps(clearcheck_store.get_check(check_id))
    assert SECRET_ACCOUNT not in raw
    assert SECRET_EMAIL not in raw
    assert SECRET_NAME not in raw


# ------------------------------------------------- locked/unlocked report

def test_report_unknown_check_id_is_404():
    resp = client.get("/api/clearcheck/report/chk_does_not_exist")
    assert resp.status_code == 404


def test_report_locked_until_paid_returns_402():
    check_id = client.post(
        "/api/clearcheck/preview", json=sample_payload()
    ).json()["check_id"]
    resp = client.get(f"/api/clearcheck/report/{check_id}")
    assert resp.status_code == 402
    assert "locked" in resp.text.lower()


def test_report_unlocked_after_webhook(stripe_configured):
    check_id = client.post(
        "/api/clearcheck/preview", json=sample_payload()
    ).json()["check_id"]

    webhook_resp = _unlock_via_webhook(check_id)
    assert webhook_resp.status_code == 200

    resp = client.get(f"/api/clearcheck/report/{check_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["unlocked"] is True
    assert body["findings_count"] == len(EXPECTED_CODES)
    assert {f["code"] for f in body["findings"]} == EXPECTED_CODES
    # the full paid report is still masked — raw identifiers never leave disk
    assert SECRET_ACCOUNT not in resp.text


def test_preview_after_unlock_reports_no_unlock_required(stripe_configured):
    check_id = client.post(
        "/api/clearcheck/preview", json=sample_payload()
    ).json()["check_id"]
    _unlock_via_webhook(check_id)
    # identical re-submission maps to the same, already-unlocked check
    body = client.post("/api/clearcheck/preview", json=sample_payload()).json()
    assert body["check_id"] == check_id
    assert body["unlock_required"] is False
    # and the report stays unlocked
    assert client.get(f"/api/clearcheck/report/{check_id}").status_code == 200


# ----------------------------------------------------------------- webhook

def test_webhook_rejects_invalid_signature(stripe_configured):
    payload = _checkout_completed_event("chk_x")
    resp = client.post(
        "/billing/webhook",
        content=payload,
        headers=_signed_webhook_headers(payload, secret="whsec_wrong"),
    )
    assert resp.status_code == 400


def test_webhook_is_idempotent_on_event_id(stripe_configured):
    check_id = client.post(
        "/api/clearcheck/preview", json=sample_payload()
    ).json()["check_id"]

    first = _unlock_via_webhook(check_id, event_id="evt_dup")
    second = _unlock_via_webhook(check_id, event_id="evt_dup")
    assert first.status_code == 200
    assert second.status_code == 200  # redelivery acknowledged, not re-processed

    record = clearcheck_store.get_check(check_id)
    assert record["unlocked"] is True
    assert record["unlock_event_id"] == "evt_dup"
    assert clearcheck_store.was_event_processed("evt_dup")

    with open(settings.clearcheck_store_path) as f:
        store = json.load(f)
    assert list(store["processed_events"].keys()) == ["evt_dup"]


def test_duplicate_event_does_not_relock_or_mutate_record(stripe_configured):
    check_id = client.post(
        "/api/clearcheck/preview", json=sample_payload()
    ).json()["check_id"]
    _unlock_via_webhook(check_id, event_id="evt_a")
    before = clearcheck_store.get_check(check_id)
    _unlock_via_webhook(check_id, event_id="evt_a")
    after = clearcheck_store.get_check(check_id)
    assert before == after


def test_webhook_for_unknown_check_is_acknowledged_but_noop(stripe_configured):
    resp = _unlock_via_webhook("chk_never_created", event_id="evt_orphan")
    assert resp.status_code == 200
    # the event was NOT burned — a later redelivery after the check
    # exists could still succeed
    assert not clearcheck_store.was_event_processed("evt_orphan")


def test_webhook_without_clearcheck_metadata_is_noop(stripe_configured):
    payload = json.dumps(
        {
            "id": "evt_sub_checkout",
            "object": "event",
            "type": "checkout.session.completed",
            "data": {"object": {"id": "cs_sub", "object": "checkout.session"}},
        }
    ).encode()
    resp = client.post(
        "/billing/webhook",
        content=payload,
        headers=_signed_webhook_headers(payload),
    )
    assert resp.status_code == 200
    assert not clearcheck_store.was_event_processed("evt_sub_checkout")


# ---------------------------------------------------------------- checkout

def test_checkout_unknown_check_is_404():
    resp = client.post(
        "/api/clearcheck/checkout", json={"check_id": "chk_nope"}
    )
    assert resp.status_code == 404


def test_checkout_returns_stripe_url(stripe_configured, monkeypatch):
    check_id = client.post(
        "/api/clearcheck/preview", json=sample_payload()
    ).json()["check_id"]

    captured: dict = {}

    class FakeSession:
        id = "cs_test_fake"
        url = "https://checkout.stripe.com/pay/cs_test_fake"

    def fake_create(**kwargs):
        captured.update(kwargs)
        return FakeSession()

    import stripe

    monkeypatch.setattr(stripe.checkout.Session, "create", fake_create)

    resp = client.post(
        "/api/clearcheck/checkout",
        json={"check_id": check_id, "customer_email": SECRET_EMAIL},
    )
    assert resp.status_code == 200
    assert resp.json()["checkout_url"] == FakeSession.url
    assert captured["mode"] == "payment"
    assert captured["metadata"] == {
        "purpose": "clearcheck_unlock",
        "check_id": check_id,
    }


def test_checkout_already_unlocked_is_400(stripe_configured):
    check_id = client.post(
        "/api/clearcheck/preview", json=sample_payload()
    ).json()["check_id"]
    _unlock_via_webhook(check_id)
    resp = client.post("/api/clearcheck/checkout", json={"check_id": check_id})
    assert resp.status_code == 400


def test_checkout_without_stripe_configured_is_503():
    check_id = client.post(
        "/api/clearcheck/preview", json=sample_payload()
    ).json()["check_id"]
    assert settings.stripe_secret_key == ""  # default dev environment
    resp = client.post("/api/clearcheck/checkout", json={"check_id": check_id})
    assert resp.status_code == 503
