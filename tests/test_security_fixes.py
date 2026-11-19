"""Tests for the security/fail-closed fixes:

1. Raw API keys never appear in tenant ids (SHA-256 digest instead).
2. Unauthenticated dev-mode fallback is the FREE tier (fail-closed).
3. Sensitive identifiers (vin, customer_email) are masked before
   logging / error (preview) responses.
"""
from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from cps_backend.config import settings
from cps_backend.main import app
from cps_backend.services.auth import resolve_api_key, tenant_id_for_key
from cps_backend.services.tiers import Tier
from cps_backend.utils.redaction import (
    REDACTED,
    mask_email,
    mask_vin,
    redact_validation_errors,
)

client = TestClient(app, raise_server_exceptions=False)

DEMO_KEY = settings.valid_api_keys[0]


# ---------------------------------------------------------------- tenant id

def test_tenant_id_is_sha256_digest_not_raw_key():
    tenant_id = tenant_id_for_key(DEMO_KEY)
    expected = hashlib.sha256(DEMO_KEY.encode("utf-8")).hexdigest()
    assert tenant_id == f"tenant:{expected}"
    assert DEMO_KEY not in tenant_id


def test_tenant_id_is_deterministic():
    assert tenant_id_for_key(DEMO_KEY) == tenant_id_for_key(DEMO_KEY)


def test_resolve_api_key_context_never_embeds_raw_key_in_tenant_id():
    ctx = resolve_api_key(DEMO_KEY)
    assert DEMO_KEY not in ctx.tenant_id


def test_resolve_api_key_rejects_unknown_key():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        resolve_api_key("not-a-real-key")
    assert exc_info.value.status_code == 401


# ------------------------------------------------------------- fail-closed

def test_unauthenticated_dev_fallback_is_free_tier():
    assert settings.require_auth is False  # dev-mode default
    resp = client.get("/billing/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == Tier.FREE.value
    assert body["tier"] != Tier.ENTERPRISE.value


def test_unauthenticated_dev_fallback_denies_paid_modules():
    # housing is a PRO+ module; a keyless dev-mode caller must be refused
    resp = client.post(
        "/risk/housing",
        json={
            "address": "1 Test Street",
            "year_built": 1990,
            "home_value": 250000,
            "location_risk_tier": 2,
            "structural_score": 80,
        },
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------- masking

def test_mask_vin_hides_all_but_last_four():
    masked = mask_vin("1HGCM82633A004352")
    assert masked.endswith("4352")
    assert "1HGCM82633A00" not in masked


def test_mask_email_hides_local_part():
    masked = mask_email("johndoe@example.com")
    assert masked == "j***@example.com"
    assert mask_email(None) == REDACTED
    assert mask_email("not-an-email") == REDACTED


def test_redact_validation_errors_masks_sensitive_field_input():
    errors = [
        {
            "loc": ("body", "vin"),
            "msg": "String should have at least 1 character",
            "input": "SECRET-VIN-123",
        },
        {
            "loc": ("body", "driver_age"),
            "msg": "Input should be a valid integer",
            "input": "abc",
        },
    ]
    scrubbed = redact_validation_errors(errors)
    assert scrubbed[0]["input"] == REDACTED
    assert scrubbed[1]["input"] == "abc"  # non-sensitive values preserved


def test_redact_validation_errors_scrubs_sensitive_keys_in_whole_body_input():
    # pydantic attaches the whole body as 'input' for missing-field errors
    errors = [
        {
            "loc": ("body", "driver_age"),
            "msg": "Field required",
            "input": {"vin": "SECRET-VIN-123", "vehicle_value": 20000},
        }
    ]
    scrubbed = redact_validation_errors(errors)
    assert scrubbed[0]["input"]["vin"] == REDACTED
    assert scrubbed[0]["input"]["vehicle_value"] == 20000


def test_validation_error_response_does_not_leak_vin():
    secret_vin = "SECRETVIN0004352"
    # driver_age missing -> whole body attached as the error 'input'
    resp = client.post(
        "/risk/auto",
        json={"vin": secret_vin, "vehicle_value": 20000},
    )
    assert resp.status_code == 422
    assert secret_vin not in resp.text


def test_validation_error_response_does_not_leak_customer_email():
    secret_email = "superprivate@example.com"
    resp = client.post(
        "/billing/create-checkout-session",
        json={"customer_email": secret_email},  # 'tier' missing
    )
    assert resp.status_code == 422
    assert secret_email not in resp.text
