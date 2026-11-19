"""Tests for CPS_ALLOWED_ORIGINS parsing and the always-allowed frontend
origin (https://fairnes.netlify.app)."""
from __future__ import annotations

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
