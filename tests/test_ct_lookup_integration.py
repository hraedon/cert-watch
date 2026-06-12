"""Integration tests for the CT-log lookup path.

``query_ct_log`` hardcodes ``allow_private=False`` so a local CT log is blocked
by the SSRF policy. This file documents that limitation; a success path would
require a code change to plumb ``allow_private`` through to ``ssrf_safe_urlopen``.
"""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler

from cert_watch.ct_lookup import query_ct_log
from tests._integration_servers import http_server


def _ct_router(handler: BaseHTTPRequestHandler) -> None:
    """Serve a mocked crt.sh JSON response."""
    now = datetime.now(UTC)
    entries = [
        {
            "issuer_ca_id": 1,
            "issuer_name": "Test CA",
            "common_name": "example.com",
            "name_value": "example.com",
            "serial_number": "010203",
            "not_before": (now - timedelta(days=1)).isoformat(),
            "not_after": (now + timedelta(days=30)).isoformat(),
        },
    ]
    body = json.dumps(entries).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def test_query_ct_log_local_server_blocked_by_ssrf(monkeypatch):
    """Local CT log targets are blocked because query_ct_log never passes allow_private."""
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "ct.local":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    router = _ct_router
    with http_server(router) as srv:
        port = srv.server_address[1]
        monkeypatch.setattr(
            "cert_watch.ct_lookup._ct_log_url",
            lambda: f"http://ct.local:{port}",
        )
        # _ct_log_url() caches its value, so also reset the cache for determinism.
        from cert_watch import ct_lookup as _ct_lookup_module

        _ct_lookup_module._ct_log_url_cache = None

        result = query_ct_log("example.com")
        assert isinstance(result, str)
        assert "blocked by SSRF policy" in result
