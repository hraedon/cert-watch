"""Integration tests for SIEM HEC export against a local server."""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler

import pytest

from cert_watch.siem import SiemExporter, reset_exporter
from tests._integration_servers import allow_loopback_transport, http_server, server_url


class _HECRouter:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.events: list[dict] = []

    def __call__(self, handler: BaseHTTPRequestHandler) -> None:
        assert handler.path == "/services/collector/event"
        length = int(handler.headers.get("Content-Length", 0))
        body = json.loads(handler.rfile.read(length))
        self.events.append(body)

        if self.status == 200:
            response = json.dumps({"text": "Success", "code": 0}).encode()
        else:
            response = b"Internal Server Error"
        handler.send_response(self.status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(response)))
        handler.end_headers()
        handler.wfile.write(response)


@pytest.fixture(autouse=True)
def _reset_siem_exporter():
    reset_exporter()
    yield
    reset_exporter()


def test_siem_hec_posts_successfully(monkeypatch, caplog):
    """SiemExporter._to_hec POSTs an event and succeeds on HTTP 200."""
    caplog.set_level(logging.WARNING, logger="cert_watch.siem")

    router = _HECRouter(status=200)
    with allow_loopback_transport(monkeypatch), http_server(router) as srv:
        url = server_url(srv, path="/services/collector/event")
        monkeypatch.setenv("CERT_WATCH_HEC_URL", url)
        monkeypatch.setenv("CERT_WATCH_HEC_TOKEN", "test-token")
        exporter = SiemExporter()
        exporter._to_hec({"action": "test"})

    assert len(router.events) == 1
    assert router.events[0]["event"] == {"action": "test"}
    assert "non-2xx" not in caplog.text
    assert "HEC export failed" not in caplog.text


def test_siem_hec_logs_non_2xx(monkeypatch, caplog):
    """SiemExporter._to_hec logs a warning on a non-2xx response without raising."""
    caplog.set_level(logging.WARNING, logger="cert_watch.siem")

    router = _HECRouter(status=500)
    with allow_loopback_transport(monkeypatch), http_server(router) as srv:
        url = server_url(srv, path="/services/collector/event")
        monkeypatch.setenv("CERT_WATCH_HEC_URL", url)
        monkeypatch.setenv("CERT_WATCH_HEC_TOKEN", "test-token")
        exporter = SiemExporter()
        # Should not raise.
        exporter._to_hec({"action": "test"})

    assert len(router.events) == 1
    assert "HEC export failed" in caplog.text or "non-2xx" in caplog.text
