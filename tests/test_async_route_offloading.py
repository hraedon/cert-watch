"""Regression tests for synchronous network work in async request handlers."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient

from cert_watch.auth import AuthResult


def _spy_to_thread(monkeypatch) -> list[Callable[..., Any]]:
    """Record functions submitted to the real asyncio worker pool."""
    original = asyncio.to_thread
    submitted: list[Callable[..., Any]] = []

    async def spy(func, /, *args, **kwargs):
        submitted.append(func)
        return await original(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", spy)
    return submitted


def test_login_authentication_is_offloaded(reload_app, monkeypatch):
    class FailingProvider:
        provider_name = "ldap"
        provider_label = "LDAP"
        supports_form_login = True

        def authenticate(self, username: str, password: str) -> AuthResult:
            return AuthResult(success=False, error="login failed")

    app_mod = reload_app()
    provider = FailingProvider()
    with TestClient(app_mod.app) as client:
        app_mod.app.state.auth_provider = provider
        submitted = _spy_to_thread(monkeypatch)
        response = client.post(
            "/login",
            data={"username": "alice", "password": "wrong"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert provider.authenticate in submitted


def test_smtp_connection_is_offloaded(reload_app, monkeypatch):
    import smtplib

    from cert_watch.routes.settings import smtp as smtp_routes

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: int = 10) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self) -> None:
            pass

        def send_message(self, msg) -> None:
            pass

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(
        "cert_watch.http_client.validate_smtp_host", lambda *args, **kwargs: None
    )
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        submitted = _spy_to_thread(monkeypatch)
        response = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "smtp.example.com",
                "smtp_port": "587",
                "alert_from": "cert-watch@example.com",
                "alert_recipients": "ops@example.com",
            },
        )

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert smtp_routes._send_smtp_test in submitted


def test_webhook_test_delivery_is_offloaded(reload_app, monkeypatch):
    from cert_watch.routes.api import insights

    def fake_send_webhook(*args, **kwargs) -> bool:
        return True

    monkeypatch.setattr("cert_watch.http_client.validate_webhook_url", lambda *a, **k: None)
    monkeypatch.setattr(insights, "send_webhook", fake_send_webhook)
    app_mod = reload_app(ALERT_WEBHOOK_URL="https://hooks.example.com/cert-watch")
    with TestClient(app_mod.app) as client:
        submitted = _spy_to_thread(monkeypatch)
        response = client.post("/api/webhook/test")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert fake_send_webhook in submitted
