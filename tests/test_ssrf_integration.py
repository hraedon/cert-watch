"""Real-socket SSRF integration tests for the HTTP client / webhook boundary.

These tests start local threaded HTTP(S) servers and exercise
``cert_watch.http_client.ssrf_safe_urlopen`` and ``validate_webhook_url`` with
actual DNS resolution and TCP connections — no mocked urllib handlers.

They are opt-in via ``pytest -m integration`` because they bind real sockets.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from cert_watch.http_client import SSRFBlockedError, ssrf_safe_urlopen, validate_webhook_url
from cert_watch.scan_resolver import (
    _ALWAYS_BLOCKED_NETWORKS,
    _PRIVATE_NETWORKS,
)
from tests._integration_servers import allow_loopback_transport, http_server, server_url

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Local server helpers
# ---------------------------------------------------------------------------


class _QuietHandler(BaseHTTPRequestHandler):
    """Suppress request-log noise during test runs."""

    def log_message(self, fmt: str, *args) -> None:  # noqa: ARG002
        pass


class _StaticOKHandler(_QuietHandler):
    """Responds ``200 OK`` with a small plain-text body."""

    def do_GET(self) -> None:
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _IPv6HTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6


@contextlib.contextmanager
def _http_server_at(addr: tuple[str, int]):
    """Run a threaded HTTP server bound to a specific address."""
    srv = ThreadingHTTPServer(addr, _StaticOKHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        t.join(timeout=3)


@contextlib.contextmanager
def _http_server_ipv6():
    """Run a threaded HTTP server bound to ::1, skipping if IPv6 is unavailable."""
    try:
        srv = _IPv6HTTPServer(("::1", 0), _StaticOKHandler)
    except OSError as exc:
        pytest.skip(f"cannot bind IPv6 loopback server: {exc}")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        t.join(timeout=3)


def _server_url(host: str, port: int, path: str = "/") -> str:
    """Build an HTTP URL, bracketing IPv6 addresses."""
    ip_host = f"[{host}]" if ":" in host else host
    return f"http://{ip_host}:{port}{path}"


def _local_rfc1918_address() -> str | None:
    """Return a non-loopback RFC 1918 / ULA address for this host, if any."""
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    for _fam, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        check = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
        if any(check in net for net in _ALWAYS_BLOCKED_NETWORKS):
            continue
        if any(check in net for net in _PRIVATE_NETWORKS):
            return ip_str
    return None


def _host_prefix(host: str) -> str:
    """Return a /32 for IPv4 or /128 for IPv6 for use in allowed_subnets."""
    return f"{host}/128" if ":" in host else f"{host}/32"


# ---------------------------------------------------------------------------
# SSRF: loopback
# ---------------------------------------------------------------------------


def _ok_route(handler: BaseHTTPRequestHandler) -> None:
    body = b"hello"
    handler.send_response(200)
    handler.send_header("Content-Type", "text/plain")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def test_loopback_ipv4_literal_blocked_with_real_server():
    """A live server on 127.0.0.1 is unreachable because the IPv4 loopback
    range is always blocked, independent of ``allow_private``."""
    with http_server(_ok_route) as srv, pytest.raises(SSRFBlockedError, match="127.0.0.1"):
        ssrf_safe_urlopen(server_url(srv))


@pytest.mark.skipif(not socket.has_ipv6, reason="IPv6 not available")
def test_loopback_ipv6_literal_blocked_with_real_server():
    """A live server on ::1 is unreachable because IPv6 loopback is always
    blocked, independent of ``allow_private``."""
    with _http_server_ipv6() as srv:  # noqa: SIM117
        host, port = srv.server_address[:2]
        url = _server_url(host, port)
        with pytest.raises(SSRFBlockedError, match="::1"):
            ssrf_safe_urlopen(url)


def test_loopback_hostname_resolved_blocked():
    """``localhost`` resolves to loopback through the real resolver; the
    request is blocked before any TCP handshake."""
    with pytest.raises(SSRFBlockedError, match="127.0.0.1"):
        ssrf_safe_urlopen("http://localhost:12345/")


# ---------------------------------------------------------------------------
# SSRF: link-local / cloud metadata
# ---------------------------------------------------------------------------


def test_link_local_literal_blocked():
    """Literal link-local metadata IPs are blocked before any connection."""
    with pytest.raises(SSRFBlockedError, match="169.254.169.254"):
        ssrf_safe_urlopen("http://169.254.169.254/")


def test_link_local_resolved_blocked(monkeypatch: pytest.MonkeyPatch):
    """A hostname that resolves to a link-local IP is blocked at validation
    time, even when ``allow_private=True``."""
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "link.local":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.1.1", 80))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(SSRFBlockedError, match="169.254.1.1"):
        ssrf_safe_urlopen("http://link.local/", allow_private=True)


# ---------------------------------------------------------------------------
# SSRF: RFC 1918 allowlist
# ---------------------------------------------------------------------------


def test_rfc1918_allowed_with_allowed_subnets_real_socket():
    """A live server on a non-loopback private IP is reachable when that IP is
    listed in ``allowed_subnets``."""
    host = _local_rfc1918_address()
    if host is None:
        pytest.skip("no non-loopback RFC1918/ULA interface available")

    try:
        with _http_server_at((host, 0)) as srv:
            bound_host, port = srv.server_address[:2]
            url = _server_url(bound_host, port)
            with ssrf_safe_urlopen(
                url,
                allow_private=True,
                allowed_subnets=(_host_prefix(bound_host),),
            ) as resp:
                assert resp.status == 200
                assert resp.read() == b"hello"
    except OSError as exc:
        pytest.skip(f"cannot bind server to local private address {host}: {exc}")


def test_rfc1918_blocked_without_allow_private_real_socket():
    """A live server on a non-loopback private IP is blocked when
    ``allow_private=False`` and no ``allowed_subnets`` cover it."""
    host = _local_rfc1918_address()
    if host is None:
        pytest.skip("no non-loopback RFC1918/ULA interface available")

    try:
        with _http_server_at((host, 0)) as srv:
            bound_host, port = srv.server_address[:2]
            url = _server_url(bound_host, port)
            with pytest.raises(SSRFBlockedError, match=str(bound_host)):
                ssrf_safe_urlopen(url, allow_private=False)
    except OSError as exc:
        pytest.skip(f"cannot bind server to local private address {host}: {exc}")


# ---------------------------------------------------------------------------
# SSRF: redirect target validation
# ---------------------------------------------------------------------------


def test_redirect_to_blocked_private_ip_caught(monkeypatch: pytest.MonkeyPatch):
    """The redirect handler resolves and validates each hop; a redirect to a
    blocked private IP is rejected before the second TCP connection."""
    second_port = 0

    def route(handler: BaseHTTPRequestHandler) -> None:
        nonlocal second_port
        if handler.path == "/done":
            handler.send_response(200)
            handler.send_header("Content-Length", "4")
            handler.end_headers()
            handler.wfile.write(b"done")
            return
        handler.send_response(302)
        handler.send_header("Location", f"http://second.example:{second_port}/done")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "first.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]
        if host == "second.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", second_port))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with allow_loopback_transport(monkeypatch), http_server(route) as srv:
        _, first_port = srv.server_address
        second_port = first_port
        url = f"http://first.example:{first_port}/redirect"
        with pytest.raises(SSRFBlockedError, match="10.0.0.5"):
            ssrf_safe_urlopen(url, allow_private=False)


# ---------------------------------------------------------------------------
# Webhook URL validator
# ---------------------------------------------------------------------------


def test_validate_webhook_url_blocks_loopback_literal():
    """Literal loopback URLs are rejected by the webhook validator."""
    err = validate_webhook_url("http://127.0.0.1:8080/webhook")
    assert err is not None
    assert "blocked IP" in err


def test_validate_webhook_url_blocks_link_local_literal():
    """Literal link-local URLs are rejected by the webhook validator."""
    err = validate_webhook_url("http://169.254.169.254/metadata")
    assert err is not None
    assert "blocked IP" in err


def test_validate_webhook_url_blocks_loopback_hostname():
    """The validator resolves ``localhost`` through the real resolver and
    rejects the resulting loopback IP."""
    err = validate_webhook_url("http://localhost:8080/webhook")
    assert err is not None
    assert "127.0.0.1" in err


def test_validate_webhook_url_allows_rfc1918_with_subnet():
    """A literal RFC 1918 URL is valid when covered by ``allowed_subnets``.

    No TCP handshake is performed by the validator; this exercises the same
    resolution/validation path used for webhook configuration checks.
    """
    host = _local_rfc1918_address()
    if host is None:
        pytest.skip("no non-loopback RFC1918/ULA interface available")

    err = validate_webhook_url(
        f"http://{host}:8080/webhook",
        allow_private=True,
        allowed_subnets=(_host_prefix(host),),
    )
    assert err is None
