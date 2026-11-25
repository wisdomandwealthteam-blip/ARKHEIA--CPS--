"""Security and reliability regressions for ClearCheck checkout and webhooks."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import stripe
from fastapi.testclient import TestClient

from cps_backend.config import settings
from cps_backend.main import app
from cps_backend.services import billing_store, clearcheck_store, stripe_service


client = TestClient(app, raise_server_exceptions=False)
WEBHOOK_SECRET = "whsec_safety_test"
CHECK_ID = "chk_safety"


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    updates = {
        "clearcheck_store_path": str(tmp_path / "checks.json"),
        "billing_store_path": str(tmp_path / "subscriptions.json"),
        "stripe_secret_key": "sk_test_fake",
        "stripe_webhook_secret": WEBHOOK_SECRET,
        "frontend_base_url": "https://frontend.example/app/",
        "clearcheck_price_cents": 999,
    }
    original = {key: getattr(settings, key) for key in updates}
    for key, value in updates.items():
        object.__setattr__(settings, key, value)
    monkeypatch.setattr(stripe, "api_key", None)
    yield
    for key, value in original.items():
        object.__setattr__(settings, key, value)


def save_check(check_id=CHECK_ID):
    clearcheck_store.save_check({"check_id": check_id, "findings": [], "findings_count": 0})


def make_event(
    *, event_id="evt_safety", event_type="checkout.session.completed",
    check_id=CHECK_ID, mode="payment", payment_status="paid", metadata=None,
):
    if metadata is None:
        metadata = {"purpose": "clearcheck_unlock", "check_id": check_id}
    return json.dumps({
        "id": event_id,
        "object": "event",
        "type": event_type,
        "data": {"object": {
            "id": "cs_test_safe",
            "object": "checkout.session",
            "mode": mode,
            "payment_status": payment_status,
            "metadata": metadata,
        }},
    }).encode("utf-8")


def signed_headers(payload, secret=WEBHOOK_SECRET):
    timestamp = int(time.time())
    signature = hmac.new(
        secret.encode(), str(timestamp).encode() + b"." + payload, hashlib.sha256
    ).hexdigest()
    return {"Stripe-Signature": f"t={timestamp},v1={signature}"}


def send(payload, secret=WEBHOOK_SECRET):
    return client.post("/billing/webhook", content=payload, headers=signed_headers(payload, secret))


def test_real_signature_paid_completed_unlocks_without_api_key():
    save_check()
    object.__setattr__(settings, "stripe_secret_key", "")
    response = send(make_event())
    assert response.status_code == 200
    assert clearcheck_store.get_check(CHECK_ID)["unlocked"] is True
    assert clearcheck_store.was_event_processed("evt_safety")


def test_bad_signature_never_unlocks_or_leaks_payload():
    save_check()
    payload = make_event()
    response = send(payload, secret="whsec_wrong")
    assert response.status_code == 400
    assert CHECK_ID not in response.text
    assert clearcheck_store.get_check(CHECK_ID)["unlocked"] is False
    assert not clearcheck_store.was_event_processed("evt_safety")


@pytest.mark.parametrize("secret", ["", " \t\n"])
@pytest.mark.parametrize("with_signature", [False, True])
def test_missing_webhook_secret_is_503_even_without_signature(secret, with_signature):
    object.__setattr__(settings, "stripe_webhook_secret", secret)
    payload = make_event()
    response = client.post(
        "/billing/webhook", content=payload,
        headers=signed_headers(payload) if with_signature else {},
    )
    assert response.status_code == 503
    assert WEBHOOK_SECRET not in response.text


def test_missing_signature_is_400_when_secret_present():
    assert client.post("/billing/webhook", content=make_event()).status_code == 400


@pytest.mark.parametrize("payment_status", ["unpaid", "no_payment_required", "", None])
def test_completed_without_paid_status_does_not_unlock(payment_status):
    save_check()
    response = send(make_event(payment_status=payment_status))
    assert response.status_code == 200
    assert not clearcheck_store.get_check(CHECK_ID)["unlocked"]
    assert not clearcheck_store.was_event_processed("evt_safety")


@pytest.mark.parametrize("event_type", ["checkout.session.completed", "checkout.session.async_payment_succeeded"])
@pytest.mark.parametrize("mode", ["subscription", "setup", "", None])
def test_paid_wrong_mode_does_not_unlock(event_type, mode):
    save_check()
    assert send(make_event(event_type=event_type, mode=mode)).status_code == 200
    assert not clearcheck_store.get_check(CHECK_ID)["unlocked"]
    assert not clearcheck_store.was_event_processed("evt_safety")


def test_paid_async_success_unlocks_and_failed_event_never_unlocks():
    save_check()
    failure = make_event(event_id="evt_failure", event_type="checkout.session.async_payment_failed")
    assert send(failure).status_code == 200
    assert not clearcheck_store.get_check(CHECK_ID)["unlocked"]
    assert not clearcheck_store.was_event_processed("evt_failure")
    success = make_event(event_id="evt_success", event_type="checkout.session.async_payment_succeeded")
    assert send(success).status_code == 200
    assert clearcheck_store.get_check(CHECK_ID)["unlocked"]
    assert clearcheck_store.was_event_processed("evt_success")


def test_unpaid_async_success_is_ignored():
    save_check()
    payload = make_event(event_type="checkout.session.async_payment_succeeded", payment_status="unpaid")
    assert send(payload).status_code == 200
    assert not clearcheck_store.get_check(CHECK_ID)["unlocked"]
    assert not clearcheck_store.was_event_processed("evt_safety")


def test_paid_replay_is_acknowledged_without_mutation():
    save_check()
    payload = make_event()
    assert send(payload).status_code == 200
    before = clearcheck_store.get_check(CHECK_ID)
    assert send(payload).status_code == 200
    assert clearcheck_store.get_check(CHECK_ID) == before
    with open(settings.clearcheck_store_path, encoding="utf-8") as f:
        assert list(json.load(f)["processed_events"]) == ["evt_safety"]


def test_unknown_check_is_retryable_and_redelivery_succeeds_when_available():
    payload = make_event()
    assert send(payload).status_code == 503
    assert not clearcheck_store.was_event_processed("evt_safety")
    save_check()
    assert send(payload).status_code == 200
    assert clearcheck_store.get_check(CHECK_ID)["unlocked"]
    assert clearcheck_store.was_event_processed("evt_safety")


@pytest.mark.parametrize("error_type", [
    clearcheck_store.ClearCheckStoreUnavailableError,
    clearcheck_store.ClearCheckStoreCorruptError,
])
def test_store_errors_are_retryable_and_details_are_not_exposed(error_type, monkeypatch, caplog):
    secret_details = "sensitive-value secret-key example@example.com"

    def fail(*args, **kwargs):
        raise error_type(secret_details)

    monkeypatch.setattr(clearcheck_store, "mark_unlocked", fail)
    response = send(make_event())
    assert response.status_code == 503
    assert secret_details not in response.text
    assert secret_details not in caplog.text


@pytest.mark.parametrize("payload", [b'{"private":"example@example.com",', b'\xffprivate=example@example.com'])
def test_signed_malformed_json_and_utf8_are_400_without_payload_leak(payload, caplog):
    response = send(payload)
    assert response.status_code == 400
    assert "example@example.com" not in response.text
    assert "example@example.com" not in caplog.text


def test_non_clearcheck_checkout_is_ignored():
    save_check()
    assert send(make_event(metadata={"purpose": "subscription"})).status_code == 200
    assert not clearcheck_store.get_check(CHECK_ID)["unlocked"]


@pytest.mark.parametrize("payload", [b"{}", b"[]", b"null", b'{"id":"evt", "type":"bad", "data":{}}'])
def test_signed_malformed_event_shape_is_400(payload):
    assert send(payload).status_code == 400


def test_signed_subscription_events_still_update_and_cancel_subscription():
    event = {
        "id": "evt_sub_create",
        "object": "event",
        "type": "customer.subscription.created",
        "data": {"object": {
            "id": "sub_test",
            "object": "subscription",
            "metadata": {"tenant_id": "tenant-test"},
            "customer": "cus_test",
            "status": "active",
            "items": {"data": []},
        }},
    }
    assert send(json.dumps(event).encode()).status_code == 200
    record = billing_store.get_subscription("tenant-test")
    assert record.stripe_subscription_id == "sub_test"
    assert record.status == "active"
    event["id"] = "evt_sub_delete"
    event["type"] = "customer.subscription.deleted"
    assert send(json.dumps(event).encode()).status_code == 200
    assert billing_store.get_subscription("tenant-test").status == "canceled"


def fake_session(monkeypatch, url="https://checkout.stripe.com/c/pay?token=abc"):
    captured = []

    def create(**kwargs):
        captured.append(kwargs)
        return type("Session", (), {"id": "cs_fake", "url": url})()

    monkeypatch.setattr(stripe.checkout.Session, "create", create)
    return captured


def test_callback_urls_encode_both_frontend_contracts_and_preserve_path(monkeypatch):
    captured = fake_session(monkeypatch)
    object.__setattr__(settings, "frontend_base_url", "https://frontend.example/app///")
    check_id = "chk_a&checkout=evil ?#ü"
    result = stripe_service.create_clearcheck_checkout_session(check_id, "private@example.com")
    assert result == "https://checkout.stripe.com/c/pay?token=abc"
    call = captured[0]
    assert call["mode"] == "payment"
    assert call["client_reference_id"] == check_id
    assert call["metadata"] == {"purpose": "clearcheck_unlock", "check_id": check_id}
    assert call["customer_email"] == "private@example.com"
    assert call["line_items"][0]["price_data"]["unit_amount"] == 999
    for key, outcome in [("success_url", "success"), ("cancel_url", "cancelled")]:
        parsed = urlsplit(call[key])
        assert (parsed.scheme, parsed.netloc, parsed.path, parsed.fragment) == (
            "https", "frontend.example", "/app/", ""
        )
        assert parse_qs(parsed.query) == {
            "clearcheck": [outcome], "checkout": [outcome], "check_id": [check_id]
        }


@pytest.mark.parametrize("url", [
    "http://localhost:5173", "https://frontend.example", "https://frontend.example/app/",
    "https://[::1]:8443/app", "https://fairnes.netlify.app", "Https://fairnes.netlify.app",
])
def test_valid_frontend_urls_are_accepted(url, monkeypatch):
    captured = fake_session(monkeypatch)
    object.__setattr__(settings, "frontend_base_url", url)
    stripe_service.create_clearcheck_checkout_session(CHECK_ID)
    assert len(captured) == 1


@pytest.mark.parametrize("url", [
    "", " ", "frontend.example/app", "//frontend.example", "ftp://frontend.example",
    "https:///path", "https://user:password@frontend.example", "https://@frontend.example",
    "https://frontend.example/?q=x", "https://frontend.example/?",
    "https://frontend.example/#fragment", "https://frontend.example/#",
    "https://frontend.example\\@evil.example", "https://frontend.example/has space",
    "https://frontend.example:99999", "https://frontend.example:notaport",
    "https://[::1", "https://bad%2fhost.example", "https://.",
])
def test_invalid_frontend_urls_are_rejected_before_stripe_call(url, monkeypatch):
    captured = fake_session(monkeypatch)
    object.__setattr__(settings, "frontend_base_url", url)
    with pytest.raises(stripe_service.StripeCheckoutConfigurationError):
        stripe_service.create_clearcheck_checkout_session(CHECK_ID)
    assert not captured


@pytest.mark.parametrize("url", [
    None, "", " ", "http://checkout.stripe.com/pay", "//checkout.stripe.com/pay",
    "https:///pay", "https://user:pass@checkout.stripe.com/pay", "https://@checkout.stripe.com",
    "https://checkout.stripe.com\\@evil.example", "https://bad%2fhost.example",
    "https://checkout.stripe.com:bad", "https://checkout.stripe.com/has space",
])
def test_invalid_returned_session_urls_are_rejected(url, monkeypatch):
    fake_session(monkeypatch, url=url)
    with pytest.raises(stripe_service.StripeCheckoutInvalidSessionError):
        stripe_service.create_clearcheck_checkout_session(CHECK_ID)


@pytest.mark.parametrize("secret", ["", " \n\t"])
def test_blank_api_key_is_rejected_before_call(secret, monkeypatch):
    captured = fake_session(monkeypatch)
    object.__setattr__(settings, "stripe_secret_key", secret)
    with pytest.raises(stripe_service.StripeNotConfiguredError):
        stripe_service.create_clearcheck_checkout_session(CHECK_ID)
    assert not captured


@pytest.mark.parametrize("price", [0, -1, None, "999", 1.5, True])
def test_invalid_price_is_rejected_before_call(price, monkeypatch):
    captured = fake_session(monkeypatch)
    object.__setattr__(settings, "clearcheck_price_cents", price)
    with pytest.raises(stripe_service.StripeCheckoutConfigurationError):
        stripe_service.create_clearcheck_checkout_session(CHECK_ID)
    assert not captured


def test_invalid_checkout_configuration_returns_safe_503(monkeypatch):
    save_check()
    fake_session(monkeypatch)
    object.__setattr__(settings, "frontend_base_url", "https://user:secret@example.com/?x=1")
    response = client.post("/api/clearcheck/checkout", json={"check_id": CHECK_ID})
    assert response.status_code == 503
    assert "secret" not in response.text


def test_invalid_stripe_session_returns_safe_502(monkeypatch):
    save_check()
    fake_session(monkeypatch, url="https://user:secret@example.com/")
    response = client.post("/api/clearcheck/checkout", json={"check_id": CHECK_ID})
    assert response.status_code == 502
    assert "secret" not in response.text


@pytest.mark.parametrize("raw,expected", [(None, "999"), ("123", "123"), ("0", "0"), ("not-a-number", "None"), ("12.3", "None"), ("", "None")])
def test_price_environment_parsing_does_not_crash_startup(raw, expected):
    env = os.environ.copy()
    if raw is None:
        env.pop("CPS_CLEARCHECK_PRICE_CENTS", None)
    else:
        env["CPS_CLEARCHECK_PRICE_CENTS"] = raw
    result = subprocess.run(
        [sys.executable, "-c", "from cps_backend.main import app; from cps_backend.config import settings; print(settings.clearcheck_price_cents)"],
        env=env, capture_output=True, text=True, check=True,
    )
    assert result.stdout.strip() == expected
