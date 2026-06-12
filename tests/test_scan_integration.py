"""Integration tests for the openssl s_client scan path (BC-036).

These tests start a real TLS server and invoke the actual openssl binary.
They require openssl on PATH and are skipped if it is unavailable.
"""

from __future__ import annotations

import contextlib
import shutil
import socket
import ssl
import threading
from pathlib import Path

import pytest

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.scan import ScanError, ScannedEntry, scan_host
from tests._integration_servers import allow_loopback_transport

pytestmark = pytest.mark.integration


def _openssl_available() -> bool:
    return shutil.which("openssl") is not None


requires_openssl = pytest.mark.skipif(
    not _openssl_available(),
    reason="openssl not found on PATH",
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_tls_server(
    port: int,
    certfile: Path,
    keyfile: Path,
    shutdown_event: threading.Event,
) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)
    sock.settimeout(0.5)

    while not shutdown_event.is_set():
        try:
            conn, _ = sock.accept()
        except TimeoutError:
            continue
        try:
            ssl_conn = ctx.wrap_socket(conn, server_side=True)
            with contextlib.suppress(Exception):
                ssl_conn.recv(1024)
            ssl_conn.close()
        except Exception:
            with contextlib.suppress(Exception):
                conn.close()
    sock.close()


def _write_key_pem(key, path: Path) -> None:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )
    path.write_bytes(
        key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
    )


@pytest.fixture()
def tls_server_chain(chain_triplet, tmp_path):
    certfile = tmp_path / "server_chain.pem"
    certfile.write_bytes(chain_triplet["leaf"].pem + chain_triplet["intermediate"].pem)
    keyfile = tmp_path / "server.key"
    _write_key_pem(chain_triplet["leaf"].key, keyfile)

    port = _free_port()
    shutdown = threading.Event()
    t = threading.Thread(
        target=_start_tls_server,
        args=(port, certfile, keyfile, shutdown),
        daemon=True,
    )
    t.start()
    yield port, chain_triplet
    shutdown.set()
    t.join(timeout=3)


@pytest.fixture()
def tls_server_self_signed(self_signed_leaf, tmp_path):
    certfile = tmp_path / "server_self.pem"
    certfile.write_bytes(self_signed_leaf.pem)
    keyfile = tmp_path / "server.key"
    _write_key_pem(self_signed_leaf.key, keyfile)

    port = _free_port()
    shutdown = threading.Event()
    t = threading.Thread(
        target=_start_tls_server,
        args=(port, certfile, keyfile, shutdown),
        daemon=True,
    )
    t.start()
    yield port, self_signed_leaf
    shutdown.set()
    t.join(timeout=3)


@requires_openssl
def test_openssl_chain_extraction(monkeypatch, tls_server_chain):
    """Real openssl s_client extracts leaf + intermediate from local TLS server."""
    port, triplet = tls_server_chain

    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda hostname, p, *, allow_private=True, allowed_subnets=(), dns_servers=(): (
            socket.AF_INET, ("127.0.0.1", p)
        ),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    with allow_loopback_transport(monkeypatch):
        result = scan_host("localhost", port, timeout=5, allow_private=True)
    assert isinstance(result, ScannedEntry), f"expected ScannedEntry, got {result}"
    assert result.host == "localhost"
    assert result.port == port

    expected_leaf = parse_certificate(triplet["leaf"].der)
    assert isinstance(expected_leaf, Certificate)
    assert result.leaf.fingerprint_sha256 == expected_leaf.fingerprint_sha256

    assert len(result.chain) >= 1
    expected_inter = parse_certificate(triplet["intermediate"].der)
    assert isinstance(expected_inter, Certificate)
    assert result.chain[0].fingerprint_sha256 == expected_inter.fingerprint_sha256


@requires_openssl
def test_openssl_self_signed_leaf_only(monkeypatch, tls_server_self_signed):
    """Real openssl s_client extracts a self-signed leaf with no chain."""
    port, leaf_cert = tls_server_self_signed

    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda hostname, p, *, allow_private=True, allowed_subnets=(), dns_servers=(): (
            socket.AF_INET, ("127.0.0.1", p)
        ),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    with allow_loopback_transport(monkeypatch):
        result = scan_host("localhost", port, timeout=5, allow_private=True)
    assert isinstance(result, ScannedEntry), f"expected ScannedEntry, got {result}"

    expected_leaf = parse_certificate(leaf_cert.der)
    assert isinstance(expected_leaf, Certificate)
    assert result.leaf.fingerprint_sha256 == expected_leaf.fingerprint_sha256


@requires_openssl
def test_openssl_connection_refused(monkeypatch):
    """Real openssl s_client returns ScanError when nothing is listening."""
    port = _free_port()

    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda hostname, p, *, allow_private=True, allowed_subnets=(), dns_servers=(): (
            socket.AF_INET, ("127.0.0.1", p)
        ),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    with allow_loopback_transport(monkeypatch):
        result = scan_host("localhost", port, timeout=3, allow_private=True)
    assert isinstance(result, ScanError)
