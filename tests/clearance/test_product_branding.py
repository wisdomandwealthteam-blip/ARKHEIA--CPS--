"""Public product branding must not migrate APIs or internal clearance imports."""
from __future__ import annotations

import importlib
import uuid

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Match

from cps_backend.config import FRONTEND_ORIGIN, settings
from cps_backend.main import _CORSApplication, app, fastapi_app


# Public schema paths use OpenAPI's normalized template syntax; the report
# route retains its existing Starlette :path converter in the mounted router.
EXPECTED_PUBLIC_ROUTES = (
    ("/health", "get"),
    ("/risk/auto", "post"),
    ("/risk/housing", "post"),
    ("/risk/aggregate", "post"),
    ("/billing/create-checkout-session", "post"),
    ("/billing/create-portal-session", "post"),
    ("/billing/status", "get"),
    ("/api/clearcheck/preview", "post"),
    ("/api/clearcheck/report/{check_id}", "get"),
    ("/api/clearcheck/checkout", "post"),
    ("/api/clearcheck/trial/status", "get"),
    ("/api/clearcheck/trial/portal", "post"),
    ("/api/governance/check", "post"),
    ("/api/governance/checks/{receipt_id}", "get"),
    ("/v1/verify-receipt", "post"),
    ("/v1/public-keys", "get"),
    ("/api/settlement/check", "post"),
    ("/api/provenance/check", "post"),
    ("/api/custody/check", "post"),
    ("/api/edge/check", "post"),
    ("/api/mandate/verify", "post"),
    ("/api/aegis/evaluate", "post"),
    ("/api/clearance/head", "get"),
)


def _route_is_mounted(path: str, method: str) -> bool:
    # ASGI matching supports both flattened routes and lazy included routers.
    # It does not execute handlers or trigger Stripe, stores, or clearance.
    scope = {"type": "http", "path": path, "root_path": "", "method": method.upper()}
    return any(route.matches(scope)[0] == Match.FULL for route in app.routes)


@pytest.fixture(scope="module")
def client():
    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def schema(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    return response.json()


def test_openapi_has_exact_public_product_identity_and_commercial_metadata(schema):
    info = schema["info"]
    assert info["title"] == "ARKHEIA 7™ — Deterministic Agent Gate"
    assert info["version"] == "1.0.1"
    assert info["x-commercial"] == {
        "product": "ARKHEIA 7™ — Deterministic Agent Gate",
        "brand": "7™",
        "version": "1.0.1",
        "publisher": "ARKHEIA GROUP",
        "website": "https://ericscott.ai",
        "license": "Proprietary",
    }


def test_openapi_contact_and_license_do_not_invent_email_or_legal_urls(schema):
    info = schema["info"]
    # FastAPI's OpenAPI contact model normalizes a bare origin with a slash.
    assert info["contact"] == {
        "name": "ARKHEIA GROUP",
        "url": "https://ericscott.ai/",
    }
    assert info["license"] == {"name": "Proprietary"}


def test_docs_remains_available_with_branded_title(client):
    response = client.get("/docs")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "ARKHEIA 7™ — Deterministic Agent Gate - Swagger UI" in response.text
    assert "url: '/openapi.json'" in response.text


@pytest.mark.parametrize("path,method", EXPECTED_PUBLIC_ROUTES)
def test_all_existing_legacy_and_clearance_paths_remain_documented_and_mounted(
    schema, path, method
):
    assert method in schema["paths"][path]
    concrete_path = path.replace("{check_id}", "chk_branding").replace(
        "{receipt_id}", "branding_receipt"
    )
    assert _route_is_mounted(concrete_path, method)


def test_hidden_stripe_webhook_and_report_path_converter_are_preserved(schema):
    assert "/billing/webhook" not in schema["paths"]
    assert _route_is_mounted("/billing/webhook", "POST")
    assert _route_is_mounted("/api/clearcheck/report/chk_branding/legacy", "GET")


@pytest.mark.parametrize("path", ("/openapi.json", "/docs"))
def test_public_metadata_keeps_outer_cors_wrapper_and_request_ids(client, path):
    response = client.get(path, headers={"Origin": FRONTEND_ORIGIN})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == FRONTEND_ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"
    assert "x-request-id" in response.headers["access-control-expose-headers"].lower()
    assert str(uuid.UUID(response.headers["x-request-id"])) == response.headers["x-request-id"]
    assert isinstance(app, _CORSApplication)
    assert app.app is fastapi_app
    assert app.routes is fastapi_app.routes
    assert app.allow_origins == settings.allowed_origins


def test_commercial_extension_preserves_fastapi_schema_cache(client, schema):
    assert app.openapi() is fastapi_app.openapi_schema
    assert client.get("/openapi.json").json() == schema


def test_internal_arkheia_clearance_imports_remain_compatible():
    core = importlib.import_module("arkheia_clearance")
    engine = importlib.import_module("arkheia_clearance.engine")
    service = importlib.import_module("arkheia_clearance.service")
    policy = importlib.import_module("arkheia_clearance.policy")
    wire = importlib.import_module("arkheia_clearance.wire")
    router = importlib.import_module("cps_backend.routers.clearance")

    assert core.__name__ == "arkheia_clearance"
    assert core.ClearanceEngine is engine.ClearanceEngine
    assert core.ClearanceService is service.ClearanceService
    assert core.Policy is policy.Policy
    assert core.Signer is wire.Signer
    assert router.ClearanceService is core.ClearanceService
    assert router.engine_from_env is core.engine_from_env
    assert {"ClearanceEngine", "ClearanceService", "Policy", "Signer"} <= set(core.__all__)
