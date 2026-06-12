"""Integration tests for alert webhook delivery against a local server."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler

from cert_watch.alerts import WebhookConfig, send_webhook
from cert_watch.database import Alert
from cert_watch.http_client import validate_webhook_url
from tests._integration_servers import allow_loopback_transport, http_server, server_url


class _WebhookServer:
    def __init__(self) -> None:
        self.requests: list[dict] = []

    def __call__(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(length)
        self.requests.append({
            "path": handler.path,
            "headers": dict(handler.headers),
            "body": body,
        })
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", "2")
        handler.end_headers()
        handler.wfile.write(b"{}")


def _alert() -> Alert:
    return Alert(
        cert_id="cert-123",
        alert_type="expiry_warning",
        status="pending",
        message="Certificate expires soon",
        threshold_days=7,
        hostname="web.example.com",
        subject="CN=web.example.com",
        created_at=datetime.now(UTC),
    )


def test_validate_webhook_url_allows_local_with_transport_override(monkeypatch):
    """Loopback webhook URL passes validation with the transport override."""
    router = _WebhookServer()
    with allow_loopback_transport(monkeypatch), http_server(router) as srv:
        url = server_url(srv, path="/webhook")
        assert validate_webhook_url(url, allow_private=True) is None


def test_validate_webhook_url_blocks_local_by_default():
    """Loopback webhook URL is blocked without the transport override."""
    router = _WebhookServer()
    with http_server(router) as srv:
        url = server_url(srv, path="/webhook")
        err = validate_webhook_url(url, allow_private=True)
        assert err is not None


def test_send_webhook_delivers_generic_json_to_local_server(monkeypatch):
    router = _WebhookServer()
    with allow_loopback_transport(monkeypatch), http_server(router) as srv:
        url = server_url(srv, path="/webhook")
        config = WebhookConfig(url=url, kind="generic", allow_private=True)
        alert = _alert()
        assert send_webhook(alert, config) is True
        assert len(router.requests) == 1
        payload = json.loads(router.requests[0]["body"])
        assert payload["alert_type"] == "expiry_warning"
        assert payload["cert_id"] == "cert-123"


def test_send_webhook_blocked_when_loopback_always_blocked(monkeypatch):
    """Loopback is always blocked; webhook delivery fails without transport override."""
    router = _WebhookServer()
    with http_server(router) as srv:
        url = server_url(srv, path="/webhook")
        config = WebhookConfig(url=url, kind="generic", allow_private=True)
        alert = _alert()
        assert send_webhook(alert, config) is False
        assert "SSRF" in (alert.error_message or "")
        assert len(router.requests) == 0
