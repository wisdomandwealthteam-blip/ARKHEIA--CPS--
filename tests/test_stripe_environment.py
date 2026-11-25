"""Stripe environment settings are normalized before the SDK is configured."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    ("raw_key", "raw_webhook", "expected_key", "expected_webhook"),
    [
        (None, None, "", ""),
        (" \t\n", "\r\n ", "", ""),
        (" \t synthetic-api-key\n", "\r\nsynthetic-signing-secret \t", "synthetic-api-key", "synthetic-signing-secret"),
        ("\u2003synthetic-api-key\u00a0", "\u00a0synthetic-signing-secret\u2003", "synthetic-api-key", "synthetic-signing-secret"),
        ("synthetic-api-key", "synthetic-signing-secret", "synthetic-api-key", "synthetic-signing-secret"),
        ("synthetic key", "synthetic secret", "synthetic key", "synthetic secret"),
    ],
)
def test_stripe_environment_is_trimmed_and_sdk_uses_default_base(
    raw_key, raw_webhook, expected_key, expected_webhook
):
    env = os.environ.copy()
    for name, value in (("STRIPE_SECRET_KEY", raw_key), ("STRIPE_WEBHOOK_SECRET", raw_webhook)):
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    script = """
import json
import sys
from cps_backend.config import settings
from cps_backend.services import stripe_service
expected = json.load(sys.stdin)
assert settings.stripe_secret_key == expected["key"]
assert settings.stripe_webhook_secret == expected["webhook"]
assert stripe_service.stripe.api_key == settings.stripe_secret_key
assert stripe_service.stripe.api_base == "https://api.stripe.com"
"""
    subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps({"key": expected_key, "webhook": expected_webhook}),
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
