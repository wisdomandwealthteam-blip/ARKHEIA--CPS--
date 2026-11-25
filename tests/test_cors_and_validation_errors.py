"""Regression tests for CORS on errors and safe validation diagnostics."""
from __future__ import annotations

import logging
import uuid

import pytest
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient

from cps_backend.config import FRONTEND_ORIGIN
from cps_backend.main import _CORSApplication, app, fastapi_app
from cps_backend.routers import clearcheck


ORIGIN = FRONTEND_ORIGIN


@pytest.fixture
def client():
    # Explicitly keep raise_server_exceptions=True: a handled 500 should not
    # propagate to an ASGI server and trigger raw exception logging.
    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client


def _assert_cors(response):
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"


def _assert_request_id(response):
    request_id = response.headers["x-request-id"]
    assert str(uuid.UUID(request_id)) == request_id
    return request_id


def test_preflight_allows_checkout_and_request_headers(client):
    response = client.options(
        "/api/clearcheck/checkout",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-api-key",
        },
    )
    assert response.status_code == 200
    _assert_cors(response)
    assert "POST" in response.headers["access-control-allow-methods"]
    assert response.headers["access-control-allow-headers"] == "content-type,x-api-key"


def test_normal_cors_exposes_request_id_and_preserves_fastapi_internals(client):
    response = client.get("/health", headers={"Origin": ORIGIN})
    assert response.status_code == 200
    _assert_cors(response)
    _assert_request_id(response)
    assert "x-request-id" in response.headers["access-control-expose-headers"].lower()
    assert app.app is fastapi_app
    assert app.routes is fastapi_app.routes
    assert app.openapi()["paths"]["/api/clearcheck/checkout"]
    assert client.get("/openapi.json").status_code == 200


def test_disallowed_origin_is_not_granted_cors():
    # Isolate this check from the environment's optional wildcard origin.
    restricted = _CORSApplication(
        fastapi_app,
        allow_origins=[ORIGIN],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )
    with TestClient(restricted) as restricted_client:
        response = restricted_client.get(
            "/health", headers={"Origin": "https://not-allowed.example"}
        )
        preflight = restricted_client.options(
            "/api/clearcheck/checkout",
            headers={
                "Origin": "https://not-allowed.example",
                "Access-Control-Request-Method": "POST",
            },
        )
    assert "access-control-allow-origin" not in response.headers
    assert preflight.status_code == 400
    assert "access-control-allow-origin" not in preflight.headers


def test_wildcard_credentials_still_returns_an_explicit_origin():
    wildcard = _CORSApplication(
        fastapi_app,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )
    with TestClient(wildcard) as wildcard_client:
        response = wildcard_client.get("/health", headers={"Origin": ORIGIN})
    _assert_cors(response)
    assert "origin" in response.headers["vary"].lower()


def test_unhandled_500_has_cors_and_matching_id_without_provider_details(
    client, monkeypatch, caplog
):
    secret = "sk_test_private_and_person@example.test"

    def fail(_check_id):
        raise RuntimeError(f"provider returned private information {secret}")

    monkeypatch.setattr(clearcheck.clearcheck_store, "get_check", fail)
    caplog.set_level(logging.ERROR, logger="cps_backend")
    response = client.post(
        "/api/clearcheck/checkout",
        json={"check_id": "chk_failure"},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 500
    _assert_cors(response)
    assert "x-request-id" in response.headers["access-control-expose-headers"].lower()
    request_id = _assert_request_id(response)
    assert response.json() == {
        "error": "internal_error",
        "detail": "An unexpected error occurred.",
        "request_id": request_id,
    }
    assert request_id in caplog.text
    assert "RuntimeError" in caplog.text
    assert secret not in response.text
    assert secret not in caplog.text
    assert "provider returned private information" not in caplog.text


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"check_id": None},
        {"check_id": 123},
        {"check_id": ["private-check-id"]},
        ["private-whole-body"],
    ],
)
def test_checkout_validation_is_400_and_request_ids_match(client, payload):
    response = client.post(
        "/api/clearcheck/checkout", json=payload, headers={"Origin": ORIGIN}
    )
    assert response.status_code == 400
    _assert_cors(response)
    request_id = _assert_request_id(response)
    body = response.json()
    assert body["error"] == "invalid_checkout_request"
    assert isinstance(body["detail"], str) and body["detail"]
    assert body["request_id"] == request_id
    assert "private-check-id" not in response.text
    assert "private-whole-body" not in response.text
    if isinstance(payload, dict):
        assert "check_id" in body["detail"]


@pytest.mark.parametrize("content", ["null", '{"check_id":"PRIVATE-BROKEN-JSON"'])
def test_checkout_null_or_malformed_json_is_a_safe_400(client, caplog, content):
    caplog.set_level(logging.WARNING, logger="cps_backend")
    response = client.post(
        "/api/clearcheck/checkout",
        content=content,
        headers={"Origin": ORIGIN, "Content-Type": "application/json"},
    )
    assert response.status_code == 400
    _assert_cors(response)
    assert response.json()["error"] == "invalid_checkout_request"
    assert response.json()["request_id"] == _assert_request_id(response)
    assert "PRIVATE-BROKEN-JSON" not in response.text
    assert "PRIVATE-BROKEN-JSON" not in caplog.text


def test_other_validation_errors_keep_existing_422_envelope(client):
    response = client.post(
        "/api/clearcheck/preview", json={}, headers={"Origin": ORIGIN}
    )
    assert response.status_code == 422
    _assert_cors(response)
    body = response.json()
    assert set(body) == {"error", "detail", "request_id"}
    assert body["error"] == "validation_error"
    assert body["request_id"] == _assert_request_id(response)
    assert "missing" in body["detail"]
    assert "consumer_name" in body["detail"]
    assert "Field required" in body["detail"]


def test_validation_never_echoes_body_strings_lists_and_extra_values(client, caplog):
    secrets = [
        "Person-PRIVATE-Alpha",
        "private-date@example.test",
        "LIST-PRIVATE-Beta",
        "EXTRA-PRIVATE-Gamma",
        "ACCOUNT-PRIVATE-Delta",
        "STATUS-PRIVATE-Epsilon",
    ]
    caplog.set_level(logging.WARNING, logger="cps_backend")
    response = client.post(
        "/api/clearcheck/preview",
        json={
            "consumer_name": secrets[0],
            "report_date": secrets[1],
            "accounts": [secrets[2], {"account_number": secrets[4], "status": secrets[5]}],
            "an_extra_field": {"nested": [secrets[3]]},
        },
    )
    assert response.status_code == 422
    assert "accounts" in response.json()["detail"]
    assert "report_date" in response.json()["detail"]
    for secret in secrets:
        assert secret not in response.text
        assert secret not in caplog.text
    assert "'input':" not in response.json()["detail"]
    assert "'ctx':" not in response.json()["detail"]


def test_validation_rejects_untrusted_error_messages_context_keys_and_codes(
    client, caplog, monkeypatch
):
    secrets = [
        "user@example.test",
        "RAW-LIST-PRIVATE",
        "RAW-CONTEXT-PRIVATE",
        "RAW-EXTRA-PRIVATE",
        "RAW-CODE-PRIVATE",
    ]
    synthetic_errors = [
        {
            "type": "value_error",
            "loc": ("body", "check_id", secrets[0]),
            "msg": f"Value error, {secrets[0]}",
            "input": [secrets[1]],
            "ctx": {"error": ValueError(secrets[2])},
            "unexpected": secrets[3],
        },
        {
            "type": secrets[4],
            "loc": ("body", secrets[0]),
            "msg": secrets[0],
            "input": {secrets[3]: secrets[1]},
            "ctx": {"anything": secrets[2]},
        },
    ]
    monkeypatch.setattr(RequestValidationError, "errors", lambda self: synthetic_errors)
    caplog.set_level(logging.WARNING, logger="cps_backend")
    response = client.post("/api/clearcheck/checkout", json={})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "value_error" in detail
    assert "check_id" in detail
    assert "Invalid value" in detail
    assert "[REDACTED]" in detail
    for secret in secrets:
        assert secret not in response.text
        assert secret not in caplog.text
    assert "'input':" not in detail
    assert "'ctx':" not in detail
