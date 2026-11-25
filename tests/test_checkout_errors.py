"""Checkout contract tests. All persistence and Stripe calls are isolated."""
from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, quote, urlsplit
from uuid import UUID

import pytest
import stripe
from fastapi.testclient import TestClient

from cps_backend.config import settings
from cps_backend.main import app
from cps_backend.routers import clearcheck as clearcheck_router
from cps_backend.services import clearcheck_store, stripe_service


CHECKOUT = "/api/clearcheck/checkout"
CHECK_ID = "chk_checkout_test"
EMAIL = "private-customer@example.invalid"
KEY = "sk_test_secret_checkout_key"
PROVIDER_MESSAGE = f"provider private details: {EMAIL} {KEY}"


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path):
    """Do not use a shared store or rely on developer environment settings."""
    overrides = {
        "clearcheck_store_path": str(tmp_path / "checks.json"),
        "stripe_secret_key": KEY,
        "frontend_base_url": "https://frontend.example.invalid",
        "clearcheck_price_cents": 999,
    }
    originals = {name: getattr(settings, name) for name in overrides}
    original_stripe_key = stripe.api_key
    for name, value in overrides.items():
        object.__setattr__(settings, name, value)
    try:
        yield
    finally:
        for name, value in originals.items():
            object.__setattr__(settings, name, value)
        stripe.api_key = original_stripe_key


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def stripe_create(monkeypatch):
    """Unexpected Stripe API calls fail locally instead of reaching the network."""
    create = Mock(side_effect=AssertionError("Unexpected Stripe API call"))
    monkeypatch.setattr(stripe.checkout.Session, "create", create)
    return create


@pytest.fixture
def saved_check():
    clearcheck_store.save_check(
        {"check_id": CHECK_ID, "jurisdiction": "US", "findings": [],
         "findings_count": 0, "redacted_summary": []}
    )
    return CHECK_ID


def assert_error(response, status, code, *secrets):
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"error", "detail", "request_id"}
    assert body["error"] == code
    assert isinstance(body["detail"], str) and body["detail"].strip()
    assert isinstance(body["request_id"], str)
    UUID(body["request_id"])
    assert body["request_id"] == response.headers["X-Request-ID"]
    for secret in secrets:
        assert secret not in response.text


def test_checkout_success_uses_mocked_stripe_sdk(client, stripe_create, saved_check):
    url = "https://checkout.stripe.com/pay/cs_test_checkout"
    stripe_create.side_effect = None
    stripe_create.return_value = SimpleNamespace(id="cs_test_checkout", url=url)

    response = client.post(
        CHECKOUT, json={"check_id": saved_check, "customer_email": EMAIL}
    )

    assert response.status_code == 200, response.text
    assert response.json() == {"checkout_url": url}
    stripe_create.assert_called_once()
    kwargs = stripe_create.call_args.kwargs
    assert kwargs["mode"] == "payment"
    assert kwargs["customer_email"] == EMAIL
    assert kwargs["client_reference_id"] == saved_check
    assert kwargs["metadata"] == {
        "purpose": "clearcheck_unlock", "check_id": saved_check
    }
    assert kwargs["line_items"][0]["price_data"]["unit_amount"] == 999
    for key, result in (("success_url", "success"), ("cancel_url", "cancelled")):
        callback = urlsplit(kwargs[key])
        assert (callback.scheme, callback.netloc, callback.path) == (
            "https", "frontend.example.invalid", "/"
        )
        assert parse_qs(callback.query)["clearcheck"] == [result]


@pytest.mark.parametrize("key", [None, "", "   ", "\t\n"])
def test_missing_or_blank_key_is_503_without_sdk_call(
    client, stripe_create, saved_check, key
):
    object.__setattr__(settings, "stripe_secret_key", key)
    response = client.post(CHECKOUT, json={"check_id": saved_check})
    assert_error(response, 503, "stripe_not_configured", KEY, EMAIL)
    stripe_create.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"check_id": None},
        {"check_id": 0},
        {"check_id": 1.5},
        {"check_id": True},
        {"check_id": []},
        {"check_id": {}},
        {"check_id": ""},
        {"check_id": " \t\n"},
        {"check_id": "\u2003"},
    ],
)
def test_invalid_check_id_is_400_before_store_or_sdk(
    client, monkeypatch, stripe_create, payload
):
    lookup = Mock(side_effect=AssertionError("Unexpected store lookup"))
    monkeypatch.setattr(clearcheck_store, "get_check", lookup)
    response = client.post(CHECKOUT, json={**payload, "customer_email": EMAIL})
    assert_error(response, 400, "invalid_checkout_request", EMAIL, KEY)
    lookup.assert_not_called()
    stripe_create.assert_not_called()


@pytest.mark.parametrize("content", [b"", b"null", b"[]", b"{broken json"])
def test_malformed_body_is_400_before_store_or_sdk(
    client, monkeypatch, stripe_create, content
):
    lookup = Mock(side_effect=AssertionError("Unexpected store lookup"))
    monkeypatch.setattr(clearcheck_store, "get_check", lookup)
    response = client.post(
        CHECKOUT, content=content, headers={"Content-Type": "application/json"}
    )
    assert_error(response, 400, "invalid_checkout_request")
    lookup.assert_not_called()
    stripe_create.assert_not_called()


def test_invalid_customer_email_type_is_safe_validation_error(client, stripe_create):
    response = client.post(
        CHECKOUT, json={"check_id": CHECK_ID, "customer_email": {"secret": EMAIL}}
    )
    assert_error(response, 400, "invalid_checkout_request", EMAIL)
    stripe_create.assert_not_called()


@pytest.mark.parametrize(
    "check_id", ["chk_unknown", "legacy-malformed-id", "../not-a-uuid", " notblank "]
)
def test_nonempty_unknown_ids_are_404_not_format_errors(client, stripe_create, check_id):
    response = client.post(CHECKOUT, json={"check_id": check_id})
    assert_error(response, 404, "check_not_found", check_id)
    stripe_create.assert_not_called()


def test_nonempty_legacy_id_is_looked_up_without_normalization(client, stripe_create):
    check_id = " legacy id "
    clearcheck_store.save_check({"check_id": check_id})
    stripe_create.side_effect = None
    stripe_create.return_value = SimpleNamespace(id="cs_legacy", url="https://stripe.example/cs")
    response = client.post(CHECKOUT, json={"check_id": check_id})
    assert response.status_code == 200, response.text
    assert stripe_create.call_args.kwargs["metadata"]["check_id"] == check_id


def test_report_accepts_encoded_legacy_path_separator(client):
    check_id = " legacy/id "
    clearcheck_store.save_check({"check_id": check_id, "jurisdiction": "US", "findings": []})
    clearcheck_store.mark_unlocked(check_id, "evt_legacy")
    response = client.get(f"/api/clearcheck/report/{quote(check_id, safe='')}")
    assert response.status_code == 200, response.text
    assert response.json()["check_id"] == check_id
    assert response.json()["unlocked"] is True


@pytest.mark.parametrize("check_id", [".", ".."])
def test_report_accepts_encoded_separator_for_dot_segment_ids(client, check_id):
    clearcheck_store.save_check({"check_id": check_id, "jurisdiction": "US", "findings": []})
    clearcheck_store.mark_unlocked(check_id, "evt_dot")
    response = client.get(f"/api/clearcheck/report%2F{quote(check_id, safe='')}")
    assert response.status_code == 200, response.text
    assert response.json()["check_id"] == check_id
    assert response.json()["unlocked"] is True


def test_unlocked_check_is_400_without_sdk_call(client, stripe_create, saved_check):
    assert clearcheck_store.mark_unlocked(saved_check, "evt_checkout_test") == clearcheck_store.UNLOCKED
    response = client.post(CHECKOUT, json={"check_id": saved_check})
    assert_error(response, 400, "check_already_unlocked")
    stripe_create.assert_not_called()


@pytest.mark.parametrize(
    ("exception_name", "code"),
    [
        ("ClearCheckStoreError", "check_store_unavailable"),
        ("ClearCheckStoreUnavailableError", "check_store_unavailable"),
        ("ClearCheckStoreCorruptError", "check_store_corrupt"),
    ],
)
def test_store_lookup_errors_are_mapped_and_do_not_leak(
    client, monkeypatch, stripe_create, caplog, exception_name, code
):
    caplog.set_level(logging.INFO, logger="cps_backend")
    error = getattr(clearcheck_store, exception_name)(PROVIDER_MESSAGE)
    lookup = Mock(side_effect=error)
    monkeypatch.setattr(clearcheck_store, "get_check", lookup)
    response = client.post(CHECKOUT, json={"check_id": CHECK_ID, "customer_email": EMAIL})
    assert_error(response, 503, code, PROVIDER_MESSAGE, EMAIL, KEY)
    assert PROVIDER_MESSAGE not in caplog.text
    assert EMAIL not in caplog.text
    assert KEY not in caplog.text
    lookup.assert_called_once_with(CHECK_ID)
    stripe_create.assert_not_called()


def test_corrupt_store_file_is_503_not_unknown_check(client, stripe_create, tmp_path):
    (tmp_path / "checks.json").write_text("{invalid json", encoding="utf-8")
    response = client.post(CHECKOUT, json={"check_id": CHECK_ID})
    assert_error(response, 503, "check_store_corrupt")
    stripe_create.assert_not_called()


def test_unreadable_store_path_is_503_not_unknown_check(client, stripe_create, tmp_path):
    path = tmp_path / "store-directory"
    path.mkdir()
    object.__setattr__(settings, "clearcheck_store_path", str(path))
    response = client.post(CHECKOUT, json={"check_id": CHECK_ID})
    assert_error(response, 503, "check_store_unavailable")
    stripe_create.assert_not_called()


@pytest.mark.parametrize(
    ("exception_name", "status", "code"),
    [
        ("StripeNotConfiguredError", 503, "stripe_not_configured"),
        ("StripeCheckoutConfigurationError", 503, "checkout_config_invalid"),
        ("StripeCheckoutInvalidSessionError", 502, "stripe_invalid_session"),
    ],
)
def test_stripe_service_errors_are_safely_mapped(
    client, monkeypatch, stripe_create, saved_check, caplog, exception_name, status, code
):
    caplog.set_level(logging.INFO, logger="cps_backend")
    service = Mock(side_effect=getattr(stripe_service, exception_name)(PROVIDER_MESSAGE))
    monkeypatch.setattr(clearcheck_router, "create_clearcheck_checkout_session", service)
    response = client.post(
        CHECKOUT, json={"check_id": saved_check, "customer_email": EMAIL}
    )
    assert_error(response, status, code, PROVIDER_MESSAGE, EMAIL, KEY)
    assert PROVIDER_MESSAGE not in caplog.text
    assert EMAIL not in caplog.text
    assert KEY not in caplog.text
    service.assert_called_once_with(check_id=saved_check, customer_email=EMAIL)
    stripe_create.assert_not_called()


@pytest.mark.parametrize(
    "exception",
    [
        stripe.StripeError(PROVIDER_MESSAGE),
        stripe.APIConnectionError(PROVIDER_MESSAGE),
        stripe.AuthenticationError(PROVIDER_MESSAGE),
        stripe.InvalidRequestError(PROVIDER_MESSAGE, "field"),
        stripe.RateLimitError(PROVIDER_MESSAGE),
        stripe.CardError(PROVIDER_MESSAGE, "card", "declined"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_sdk_errors_are_502_and_never_expose_provider_details(
    client, stripe_create, saved_check, caplog, exception
):
    caplog.set_level(logging.INFO, logger="cps_backend")
    stripe_create.side_effect = exception
    response = client.post(
        CHECKOUT, json={"check_id": saved_check, "customer_email": EMAIL}
    )
    assert_error(response, 502, "stripe_upstream_error", PROVIDER_MESSAGE, EMAIL, KEY)
    assert f"stripe_error_class={type(exception).__name__}" in caplog.text
    assert PROVIDER_MESSAGE not in caplog.text
    assert EMAIL not in caplog.text
    assert KEY not in caplog.text
    stripe_create.assert_called_once()


@pytest.mark.parametrize(
    "url",
    [None, "", " \t\n", "http://stripe.example/", "https://user:private-token@example.com/"],
)
def test_invalid_checkout_session_is_502(client, stripe_create, saved_check, url):
    stripe_create.side_effect = None
    stripe_create.return_value = SimpleNamespace(id="cs_bad", url=url)
    response = client.post(CHECKOUT, json={"check_id": saved_check})
    assert_error(response, 502, "stripe_invalid_session", "private-token")
    stripe_create.assert_called_once()


@pytest.mark.parametrize("price", [0, -1])
def test_invalid_price_configuration_is_503_without_sdk_call(
    client, stripe_create, saved_check, price
):
    object.__setattr__(settings, "clearcheck_price_cents", price)
    response = client.post(CHECKOUT, json={"check_id": saved_check})
    assert_error(response, 503, "checkout_config_invalid")
    stripe_create.assert_not_called()


def test_error_request_ids_match_header_and_are_unique(client):
    first = client.post(CHECKOUT, json={"check_id": "unknown"})
    second = client.post(CHECKOUT, json={"check_id": "unknown"})
    assert_error(first, 404, "check_not_found")
    assert_error(second, 404, "check_not_found")
    assert first.json()["request_id"] != second.json()["request_id"]
