"""Tests for security modules.

The authentication half is local: this build has no password of its own, and takes the identity
oauth2-proxy established plus the HMAC signature it puts on every request it forwards. These tests
are what keep that property from quietly regressing - a change that made `requires_admin` accept an
unsigned request would be invisible in a browser and fatal in production.
"""
import base64
import hashlib
import hmac
import os

import pytest
from fastapi import HTTPException

from app.security.basic_auth import get_current_user, requires_admin
from app.security.csrf import generate_csrf_token, validate_csrf_token
from app.security.proxy_signature import SIGNATURE_HEADERS, verify


class _Url:
    def __init__(self, path, query="", fragment=""):
        self.path = path
        self.query = query
        self.fragment = fragment


class _Headers(dict):
    """Enough of Starlette's Headers for the code under test: case-insensitive, with getlist."""

    def __init__(self, values):
        super().__init__({k.lower(): v for k, v in values.items()})

    def get(self, name, default=""):
        return super().get(name.lower(), default)

    def getlist(self, name):
        value = super().get(name.lower())
        return [value] if value else []


class _Request:
    def __init__(self, headers, method="GET", path="/", query=""):
        self.headers = _Headers(headers)
        self.method = method
        self.url = _Url(path, query)


# --------------------------------------------------------------------------- identity


def test_identity_prefers_email():
    req = _Request({"X-Forwarded-Email": "someone@example.com", "X-Forwarded-User": "someone"})
    assert requires_admin(req) == "someone@example.com"


def test_identity_falls_back_to_user():
    req = _Request({"X-Forwarded-User": "someone"})
    assert requires_admin(req) == "someone"


def test_no_identity_is_rejected():
    with pytest.raises(HTTPException) as raised:
        requires_admin(_Request({}))
    assert raised.value.status_code == 401


def test_get_current_user_is_none_without_identity():
    assert get_current_user(_Request({})) is None


# --------------------------------------------------------------------------- signature


def _sign(key, req, body=b""):
    """The same string oauth2-proxy signs, built independently of the code under test."""
    lines = [req.method]
    for name in SIGNATURE_HEADERS:
        lines.append(req.headers.get(name, ""))
    path = req.url.path + (("?" + req.url.query) if req.url.query else "")
    lines.append(path)
    lines.append("")
    mac = hmac.new(key.encode(), "\n".join(lines).encode(), hashlib.sha256)
    mac.update(body)
    return "sha256 " + base64.b64encode(mac.digest()).decode()


@pytest.fixture
def signing_key(monkeypatch):
    monkeypatch.setenv("GAP_SIGNATURE_KEY", "sha256:a-test-key")
    return "a-test-key"


def test_unconfigured_key_means_not_checked(monkeypatch):
    monkeypatch.delenv("GAP_SIGNATURE_KEY", raising=False)
    assert verify(_Request({"GAP-Signature": "sha256 whatever"})) is None


def test_good_signature_verifies(signing_key):
    req = _Request({"X-Forwarded-Email": "someone@example.com"}, path="/rooms")
    req.headers["gap-signature"] = _sign(signing_key, req)
    assert verify(req) is True


def test_signature_covers_the_query_string(signing_key):
    req = _Request({"X-Forwarded-Email": "someone@example.com"}, path="/rooms", query="page=1")
    req.headers["gap-signature"] = _sign(signing_key, req)
    assert verify(req) is True


def test_changing_the_identity_breaks_the_signature(signing_key):
    """The point of the whole mechanism: the asserted identity is part of what is signed."""
    req = _Request({"X-Forwarded-Email": "someone@example.com"}, path="/rooms")
    signature = _sign(signing_key, req)
    req.headers["x-forwarded-email"] = "attacker@example.com"
    req.headers["gap-signature"] = signature
    assert verify(req) is False


def test_missing_signature_is_not_a_pass(signing_key):
    assert verify(_Request({"X-Forwarded-Email": "someone@example.com"})) is False


def test_wrong_key_does_not_verify(signing_key):
    req = _Request({"X-Forwarded-Email": "someone@example.com"}, path="/rooms")
    req.headers["gap-signature"] = _sign("a-different-key", req)
    assert verify(req) is False


def test_enforcing_rejects_an_unsigned_request(signing_key, monkeypatch):
    monkeypatch.setenv("GAP_SIGNATURE_ENFORCE", "true")
    with pytest.raises(HTTPException) as raised:
        requires_admin(_Request({"X-Forwarded-Email": "someone@example.com"}))
    assert raised.value.status_code == 401


def test_not_enforcing_only_logs(signing_key, monkeypatch):
    monkeypatch.setenv("GAP_SIGNATURE_ENFORCE", "false")
    assert requires_admin(_Request({"X-Forwarded-Email": "someone@example.com"})) == "someone@example.com"


# --------------------------------------------------------------------------- csrf


def test_csrf_token_generation():
    token = generate_csrf_token()
    assert token is not None
    assert len(token) > 0
    assert isinstance(token, str)


def test_csrf_token_validation():
    token = generate_csrf_token()
    assert validate_csrf_token(token) is True


def test_csrf_token_invalid():
    assert validate_csrf_token("invalid-token") is False
    assert validate_csrf_token("") is False


def test_csrf_token_uniqueness():
    assert generate_csrf_token() != generate_csrf_token()
