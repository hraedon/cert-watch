"""Test configuration and fixtures for cert-watch."""

import pytest
from fastapi.testclient import TestClient

from cert_watch.web.app_factory import create_app
from cert_watch.core.config import Settings


@pytest.fixture
def settings():
    """Create test settings with temporary database."""
    return Settings(
        database_url="sqlite:///:memory:",
        debug=True,
        smtp_host="localhost",
        smtp_port=1025,
    )


@pytest.fixture
def app(settings):
    """Create test FastAPI application."""
    return create_app(settings)


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)
