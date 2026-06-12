"""Integration tests for SSRF-safe HTTP fetching.

These tests exercise ``cert_watch.http_client.ssrf_safe_urlopen`` against real
local threaded HTTP/HTTPS servers (no mocks, no external network).
"""

from __future__ import annotations

import json
import socket
import ssl
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

import pytest

from cert_watch.http_client import SSRFBlockedError, ssrf_safe_urlopen
from tests._integration_servers import (
    allow_loopback_transport,
    free_port,
    http_server,
    https_server,
    server_url,
)

# ---------------------------------------------------------------------------
# TLS certificate material
# ---------------------------------------------------------------------------


def _write_self_signed_server_material(
    tmp_path: Path,
    hostname: str = "test.example.com",
) -> tuple[Path, Path]:
    """Create a self-signed server cert for *hostname* and return cert/key paths."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "server.pem"
    cert_path.write_bytes(cert.public_bytes(Encoding.PEM))

    key_path = tmp_path / "server.key"
    key_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    )
    return cert_path, key_path


def _trusted_context_factory(ca_path: Path):
    """Return a factory that trusts the test CA for both ssl context entrypoints."""

    def _factory(*args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=str(ca_path))
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    return _factory


# ---------------------------------------------------------------------------
# HTTP SSRF
# ---------------------------------------------------------------------------


def test_allowed_loopback_transport(monkeypatch):
    """Loopback is reachable when the transport test override is active."""

    def route(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Content-Type", "text/plain")
        handler.end_headers()
        handler.wfile.write(b"hello")

    with (
        allow_loopback_transport(monkeypatch),
        http_server(route) as srv,
        ssrf_safe_urlopen(server_url(srv), allow_private=True) as resp,
    ):
        assert resp.status == 200
        assert resp.read() == b"hello"


def test_blocked_without_allow_private():
    """Loopback is always blocked by the SSRF policy (127.0.0.0/8 ∈ ALWAYS_BLOCKED)."""

    def route(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.end_headers()

    with http_server(route) as srv, pytest.raises(SSRFBlockedError):
        ssrf_safe_urlopen(server_url(srv))


def test_post_body_and_headers_round_trip(monkeypatch):
    """POST data and custom headers reach the server intact."""

    def route(handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(length)
        payload = {
            "method": handler.command,
            "body": body.decode("utf-8"),
            "x_custom": handler.headers.get("X-Custom"),
            "content_type": handler.headers.get("Content-Type"),
        }
        response = json.dumps(payload).encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(response)))
        handler.end_headers()
        handler.wfile.write(response)

    with allow_loopback_transport(monkeypatch), http_server(route) as srv:
        data = b"request-payload"
        with ssrf_safe_urlopen(
            server_url(srv, path="/echo"),
            data=data,
            method="POST",
            headers={"X-Custom": "yes", "Content-Type": "text/plain"},
            allow_private=True,
        ) as resp:
            assert resp.status == 200
            received = json.loads(resp.read().decode("utf-8"))
            assert received["method"] == "POST"
            assert received["body"] == "request-payload"
            assert received["x_custom"] == "yes"
            assert received["content_type"] == "text/plain"


def test_redirect_blocked_on_second_hop(monkeypatch):
    """A redirect to a private IP is blocked when allow_private is off."""

    second_port = free_port()

    def route(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(302)
        handler.send_header("Location", f"http://second.example:{second_port}/done")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "first.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", second_port))]
        if host == "second.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", second_port))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with allow_loopback_transport(monkeypatch), http_server(route) as srv:
        url = server_url(srv, path="/redirect").replace("127.0.0.1", "first.example")
        parsed = urlparse(url)
        url = f"http://first.example:{parsed.port}/redirect"
        with pytest.raises(SSRFBlockedError, match="10.0.0.5"):
            ssrf_safe_urlopen(
                url,
                allow_private=False,
            )


def test_redirect_allowed_within_loopback_transport(monkeypatch):
    """A redirect to another loopback host works with the transport override."""

    def route(handler: BaseHTTPRequestHandler) -> None:
        if handler.path == "/done":
            handler.send_response(200)
            handler.send_header("Content-Type", "text/plain")
            handler.send_header("Content-Length", "4")
            handler.end_headers()
            handler.wfile.write(b"done")
            return
        host, port = handler.server.server_address
        handler.send_response(302)
        handler.send_header("Location", f"http://second.example:{port}/done")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host in ("first.example", "second.example"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with allow_loopback_transport(monkeypatch), http_server(route) as srv:
        parsed = urlparse(server_url(srv, path="/redirect"))
        url = f"http://first.example:{parsed.port}/redirect"
        with ssrf_safe_urlopen(
            url,
            allow_private=True,
        ) as resp:
            assert resp.status == 200
            assert resp.read() == b"done"


# ---------------------------------------------------------------------------
# HTTPS SSRF
# ---------------------------------------------------------------------------


def test_https_with_hostname_pinning_and_sni(tmp_path, monkeypatch):
    """HTTPS connects to the pinned IP with the original hostname as SNI."""

    hostname = "test.example.com"
    cert_path, key_path = _write_self_signed_server_material(tmp_path, hostname)

    def route(handler: BaseHTTPRequestHandler) -> None:
        body = f"HOST:{handler.headers.get('Host')}".encode()
        handler.send_response(200)
        handler.send_header("Content-Type", "text/plain")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    with allow_loopback_transport(monkeypatch), https_server(route, cert_path, key_path) as srv:
        ctx_factory = _trusted_context_factory(cert_path)
        monkeypatch.setattr("ssl.create_default_context", ctx_factory)
        monkeypatch.setattr("ssl._create_default_https_context", ctx_factory)
        host, port = srv.server_address
        real_getaddrinfo = socket.getaddrinfo

        def _fake_getaddrinfo(h, *a, **kw):
            if h == hostname:
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (host, port))]
            return real_getaddrinfo(h, *a, **kw)

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

        url = f"https://{hostname}:{port}/"
        with ssrf_safe_urlopen(url, allow_private=True) as resp:
            assert resp.status == 200
            assert b"HOST:test.example.com" in resp.read()


def test_https_non_standard_port_host_header(tmp_path, monkeypatch):
    """Non-standard HTTPS port is preserved in the Host header."""

    hostname = "test.example.com"
    cert_path, key_path = _write_self_signed_server_material(tmp_path, hostname)

    def route(handler: BaseHTTPRequestHandler) -> None:
        body = f"HOST:{handler.headers.get('Host')}".encode()
        handler.send_response(200)
        handler.send_header("Content-Type", "text/plain")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    with allow_loopback_transport(monkeypatch), https_server(route, cert_path, key_path) as srv:
        ctx_factory = _trusted_context_factory(cert_path)
        monkeypatch.setattr("ssl.create_default_context", ctx_factory)
        monkeypatch.setattr("ssl._create_default_https_context", ctx_factory)
        host, port = srv.server_address
        real_getaddrinfo = socket.getaddrinfo

        def _fake_getaddrinfo(h, *a, **kw):
            if h == hostname:
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (host, port))]
            return real_getaddrinfo(h, *a, **kw)

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

        url = f"https://{hostname}:{port}/"
        with ssrf_safe_urlopen(url, allow_private=True) as resp:
            assert resp.status == 200
            host_header = resp.read().decode("utf-8")
            assert host_header == f"HOST:{hostname}:{port}"


# ---------------------------------------------------------------------------
# Scheme / literal blocking
# ---------------------------------------------------------------------------


def test_disallowed_scheme():
    """file:// is rejected before any network access."""
    with pytest.raises(SSRFBlockedError, match="disallowed scheme"):
        ssrf_safe_urlopen("file:///etc/passwd", allow_private=True)


def test_ipv6_loopback_literal_blocked():
    """IPv6 loopback literal is always blocked."""
    port = free_port()
    with pytest.raises(SSRFBlockedError):
        ssrf_safe_urlopen(f"http://[::1]:{port}/", allow_private=True)


def test_ipv4_loopback_literal_blocked():
    """IPv4 loopback literal is always blocked (even with allow_private=True)."""
    port = free_port()
    with pytest.raises(SSRFBlockedError):
        ssrf_safe_urlopen(f"http://127.0.0.1:{port}/", allow_private=True)
