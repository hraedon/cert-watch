"""Tiny local HTTP/HTTPS server helpers for the integration test suite.

These servers are used by tests that need real sockets + TLS handshakes while
staying deterministic and fully local (127.0.0.1:0). They are kept separate
from ``conftest.py`` because only the integration test modules need them.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import ssl
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def free_port() -> int:
    """Return an ephemeral port bound to 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _QuietHandler(BaseHTTPRequestHandler):
    """Suppress request-log noise during test runs."""

    def log_message(self, fmt: str, *args) -> None:  # noqa: ARG002
        pass


class _RouterHandler(_QuietHandler):
    def do_GET(self) -> None:
        self.server._route(self)  # type: ignore[attr-defined]

    def do_POST(self) -> None:
        self.server._route(self)

    def do_HEAD(self) -> None:
        self.server._route(self)


class HTTPTestServer(ThreadingHTTPServer):
    def __init__(self, router: Callable[[BaseHTTPRequestHandler], None]) -> None:
        super().__init__(("127.0.0.1", 0), _RouterHandler)
        self._route = router


def server_url(srv: ThreadingHTTPServer, scheme: str = "http", path: str = "/") -> str:
    host, port = srv.server_address
    return f"{scheme}://{host}:{port}{path}"


@contextlib.contextmanager
def http_server(router: Callable[[BaseHTTPRequestHandler], None]):
    """Run a local threaded HTTP server for the duration of the context."""
    srv = HTTPTestServer(router)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        t.join(timeout=3)


def make_https_server(
    router: Callable[[BaseHTTPRequestHandler], None],
    cert_chain_path: Path,
    key_path: Path,
) -> HTTPTestServer:
    """Return an HTTPTestServer wrapped in TLS with the supplied key/cert chain."""
    srv = HTTPTestServer(router)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_chain_path), keyfile=str(key_path))
    # Allow TLS 1.2 clients (Python's default client context negotiates 1.2+).
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


@contextlib.contextmanager
def https_server(
    router: Callable[[BaseHTTPRequestHandler], None],
    cert_chain_path: Path,
    key_path: Path,
):
    """Run a local threaded HTTPS server for the duration of the context."""
    srv = make_https_server(router, cert_chain_path, key_path)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        t.join(timeout=3)


# ---------------------------------------------------------------------------
# Loopback transport override for integration tests
# ---------------------------------------------------------------------------

_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")

# Modules that import ``_is_blocked_ip`` and must be patched so loopback IPs
# are treated as transport-allowed (only for integration-test success paths).
_IS_BLOCKED_IP_PATCH_TARGETS = [
    "cert_watch.scan._is_blocked_ip",
    "cert_watch.scan_resolver._is_blocked_ip",
    "cert_watch.scan_conn._is_blocked_ip",
    "cert_watch.http_client._is_blocked_ip",
    "cert_watch.routes.settings.auth._is_blocked_ip",
    "cert_watch.routes.settings.ca_probe._is_blocked_ip",
    "cert_watch.routes.settings.smtp._is_blocked_ip",
]


def _make_loopback_allowed(original_fn):
    """Return a wrapper that treats IPv4 loopback as not-blocked, delegating
    everything else to *original_fn*."""

    def _loopback_allowed(ip, *, allow_private=True, allowed_subnets=()):
        # IPv4-mapped loopback (e.g. ::ffff:127.0.0.1) — check the mapped addr.
        check_ip = (
            ip.ipv4_mapped
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped
            else ip
        )
        if isinstance(check_ip, ipaddress.IPv4Address) and check_ip in _LOOPBACK_V4:
            return False
        return original_fn(ip, allow_private=allow_private, allowed_subnets=allowed_subnets)

    return _loopback_allowed


@contextlib.contextmanager
def allow_loopback_transport(monkeypatch):
    """Context manager that monkeypatches ``_is_blocked_ip`` in every module
    that imports it so that IPv4 loopback addresses (127.0.0.0/8) are treated
    as allowed **only for the transport-under-test** (connecting to the local
    threaded server). All other IPs still use the real ``_is_blocked_ip``
    behaviour.

    This exists because the security model blocks 127.0.0.0/8 unconditionally
    (``_ALWAYS_BLOCKED_NETWORKS``), which is correct for production but
    prevents integration tests from reaching their own local servers.
    """
    from cert_watch.scan_resolver import _is_blocked_ip as original

    wrapped = _make_loopback_allowed(original)
    for target in _IS_BLOCKED_IP_PATCH_TARGETS:
        # Some modules (e.g. settings.auth/core/smtp) import _is_blocked_ip
        # lazily inside functions, so the attribute may not exist yet on the
        # module. Skip those — the lazy import will resolve at call time and
        # pick up the already-patched source module.
        with contextlib.suppress(AttributeError):
            monkeypatch.setattr(target, wrapped)
    yield
