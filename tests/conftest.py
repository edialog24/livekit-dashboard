"""Pytest configuration and fixtures"""
import os
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    """Setup test environment variables"""
    # Set test environment variables
    os.environ["LIVEKIT_URL"] = "http://localhost:7880"
    os.environ["LIVEKIT_API_KEY"] = "test-key"
    os.environ["LIVEKIT_API_SECRET"] = "test-secret"
    # No ADMIN_USERNAME/ADMIN_PASSWORD: this build has no password of its own. Identity comes
    # from oauth2-proxy's headers (see app/security/basic_auth.py).
    os.environ["APP_SECRET_KEY"] = "test-secret-key"
    os.environ["DEBUG"] = "true"
    os.environ["ENABLE_SIP"] = "false"


@pytest.fixture
def client():
    """Create a test client"""
    from app.main import app
    
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers():
    """The headers oauth2-proxy puts on a request once it has signed someone in.

    GAP_SIGNATURE_KEY is deliberately left unset for the suite, so signature verification is not
    configured and these headers alone are accepted - the same as running without --signature-key.
    test_security.py covers the signed path on its own.
    """
    return {"X-Forwarded-Email": "tester@example.com", "X-Forwarded-User": "tester"}

