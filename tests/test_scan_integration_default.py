"""Integration tests for the scanner's TLS path without openssl.

These tests use a local threaded TLS server so they run in the default unit
suite; they do not depend on the ``openssl`` binary.
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from cert_watch.scan_conn import _get_chain_der, _open_tls_connection, _probe_hsts
from tests._integration_servers import allow_loopback_transport, https_server


def _hsts_router(handler: BaseHTTPRequestHandler) -> None:
    handler.send_response(200)
    handler.send_header("Strict-Transport-Security", "max-age=31536000")
    handler.send_header("Content-Type", "text/plain")
    handler.send_header("Content-Length", "2")
    handler.end_headers()
    handler.wfile.write(b"ok")


def _write_chain_server_material(tmp_path: Path, chain_triplet: dict) -> tuple[Path, Path]:
    """Write leaf+intermediate PEM and key for the TLS server."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    cert_path = tmp_path / "server_chain.pem"
    cert_path.write_bytes(chain_triplet["leaf"].pem + chain_triplet["intermediate"].pem)

    key_path = tmp_path / "server.key"
    key_path.write_bytes(
        chain_triplet["leaf"].key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
    )
    return cert_path, key_path


@pytest.fixture
def local_tls_server(chain_triplet, tmp_path):
    cert_path, key_path = _write_chain_server_material(tmp_path, chain_triplet)
    with https_server(_hsts_router, cert_path, key_path) as srv:
        yield srv


def test_open_tls_connection_pinned_loopback_returns_cert(local_tls_server, monkeypatch):
    """A pinned loopback TLS connection returns a non-empty peer certificate
    when the transport override is active."""
    host, port = local_tls_server.server_address

    def _trust_ctx(*args, **kwargs):
        import ssl as _ssl

        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        return ctx

    monkeypatch.setattr("ssl._create_default_https_context", _trust_ctx)
    monkeypatch.setattr("ssl.create_default_context", _trust_ctx)

    with allow_loopback_transport(monkeypatch):
        ssl_sock = _open_tls_connection(
            "chain-leaf.example.com",
            port,
            timeout=5.0,
            verify=False,
            pinned_ip="127.0.0.1",
            allow_private=True,
        )
    try:
        cert = ssl_sock.getpeercert(binary_form=True)
        assert cert
        assert len(cert) > 0
    finally:
        ssl_sock.close()


def test_open_tls_connection_pinned_loopback_always_blocked():
    """Pinned loopback is always blocked (127.0.0.0/8 ∈ ALWAYS_BLOCKED)."""
    with pytest.raises(OSError, match="blocked"):
        _open_tls_connection(
            "chain-leaf.example.com",
            443,
            timeout=5.0,
            verify=False,
            pinned_ip="127.0.0.1",
            allow_private=True,
        )


@pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="SSLSocket.get_unverified_chain requires Python 3.13+",
)
def test_get_chain_der_native_returns_full_chain(local_tls_server, monkeypatch):
    """On Python 3.13+, the peer's full presented chain is returned."""
    host, port = local_tls_server.server_address

    def _trust_ctx(*args, **kwargs):
        import ssl as _ssl

        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        return ctx

    monkeypatch.setattr("ssl._create_default_https_context", _trust_ctx)
    monkeypatch.setattr("ssl.create_default_context", _trust_ctx)

    with allow_loopback_transport(monkeypatch):
        ssl_sock = _open_tls_connection(
            "chain-leaf.example.com",
            port,
            timeout=5.0,
            verify=False,
            pinned_ip="127.0.0.1",
            allow_private=True,
        )
    try:
        chain = _get_chain_der(ssl_sock, "chain-leaf.example.com")
        # leaf + intermediate
        assert len(chain) >= 2
    finally:
        ssl_sock.close()


def test_probe_hsts_true_when_header_present(local_tls_server, monkeypatch):
    """_probe_hsts detects the HSTS header served by the local TLS server."""
    import ssl as _ssl_module

    host, port = local_tls_server.server_address

    def _trust_ctx(*args, **kwargs):
        ctx = _ssl_module.SSLContext(_ssl_module.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl_module.CERT_NONE
        return ctx

    monkeypatch.setattr("ssl._create_default_https_context", _trust_ctx)
    monkeypatch.setattr("ssl.create_default_context", _trust_ctx)

    result = _probe_hsts(
        "chain-leaf.example.com", port, pinned_ip="127.0.0.1", require_443=False
    )
    assert result is True
