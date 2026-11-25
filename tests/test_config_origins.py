"""Tests for CPS_ALLOWED_ORIGINS parsing and the always-allowed frontend
origin (https://fairnes.netlify.app)."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from cps_backend.config import FRONTEND_ORIGIN, _allowed_origins, _env_list


def test_env_list_strips_whitespace_and_newlines(monkeypatch):
    monkeypatch.setenv("CPS_ALLOWED_ORIGINS", "  https://a.com ,\nhttps://b.com\n ")
    assert _env_list("CPS_ALLOWED_ORIGINS", ["*"]) == [
        "https://a.com",
        "https://b.com",
    ]


def test_env_list_whitespace_only_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("CPS_ALLOWED_ORIGINS", " \n\t ")
    assert _env_list("CPS_ALLOWED_ORIGINS", ["*"]) == ["*"]


def test_frontend_origin_always_included(monkeypatch):
    monkeypatch.setenv("CPS_ALLOWED_ORIGINS", "https://other.example.com")
    origins = _allowed_origins()
    assert FRONTEND_ORIGIN in origins
    assert "https://other.example.com" in origins


def test_frontend_origin_not_duplicated(monkeypatch):
    monkeypatch.setenv("CPS_ALLOWED_ORIGINS", f" {FRONTEND_ORIGIN} \n")
    origins = _allowed_origins()
    assert origins.count(FRONTEND_ORIGIN) == 1


def test_frontend_origin_included_when_env_unset(monkeypatch):
    monkeypatch.delenv("CPS_ALLOWED_ORIGINS", raising=False)
    origins = _allowed_origins()
    assert FRONTEND_ORIGIN in origins


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "http://localhost:5173"),
        ("https://fairnes.netlify.app", "https://fairnes.netlify.app"),
        (" \t\nhttps://fairnes.netlify.app\r\n ", "https://fairnes.netlify.app"),
        ("\u2003https://fairnes.netlify.app\u00a0", "https://fairnes.netlify.app"),
        ("https://fairnes.netlify.app/has space", "https://fairnes.netlify.app/has space"),
        ("\u200bhttps://fairnes.netlify.app\u200b", "\u200bhttps://fairnes.netlify.app\u200b"),
        ("", ""),
    ],
)
def test_frontend_base_url_strips_surrounding_whitespace_at_startup(raw, expected):
    env = os.environ.copy()
    if raw is None:
        env.pop("CPS_FRONTEND_BASE_URL", None)
    else:
        env["CPS_FRONTEND_BASE_URL"] = raw
    result = subprocess.run(
        [sys.executable, "-c", "import json; from cps_backend.config import settings; print(json.dumps(settings.frontend_base_url))"],
        env=env, capture_output=True, text=True, check=True,
    )
    assert json.loads(result.stdout) == expected
