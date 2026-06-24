"""Integration tests for OCSP/CRL endpoint reachability checks.

These tests build a certificate with local OCSP/CRL URLs and start a real HTTP
server to act as the responder.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    NameOID,
)

from cert_watch.posture import (
    _check_endpoint_reachable,
    _extract_crl_urls,
    _extract_ocsp_url,
)
from tests._integration_servers import allow_loopback_transport, http_server, server_url


def _make_cert_with_ocsp_crl(ocsp_url: str, crl_url: str) -> bytes:
    """Build a self-signed cert carrying AIA OCSP and CRLDP URLs, return DER."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "posture.test")])
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
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url),
                ),
            ]),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                ),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def _ocsp_crl_router(handler: BaseHTTPRequestHandler) -> None:
    body = b"ok"
    handler.send_response(200)
    handler.send_header("Content-Type", "application/octet-stream")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def test_ocsp_and_crl_reachable_with_transport_override(monkeypatch):
    """OCSP/CRL checks succeed with loopback transport override active."""
    router = _ocsp_crl_router
    with allow_loopback_transport(monkeypatch), http_server(router) as srv:
        ocsp_url = server_url(srv, path="/ocsp")
        crl_url = server_url(srv, path="/crl")
        cert_der = _make_cert_with_ocsp_crl(ocsp_url, crl_url)
        assert _extract_ocsp_url(cert_der) == ocsp_url
        assert crl_url in _extract_crl_urls(cert_der)

        reachable, msg = _check_endpoint_reachable(
            ocsp_url, method="HEAD", timeout=5, allow_private=True,
        )
        assert reachable is True
        assert msg == ""

        reachable, msg = _check_endpoint_reachable(
            crl_url, method="GET", timeout=5, allow_private=True,
        )
        assert reachable is True
        assert msg == ""


def test_ocsp_and_crl_blocked_because_loopback_always_blocked():
    """OCSP/CRL checks to loopback are blocked (127.0.0.0/8 ∈ ALWAYS_BLOCKED)."""
    router = _ocsp_crl_router
    with http_server(router) as srv:
        ocsp_url = server_url(srv, path="/ocsp")
        crl_url = server_url(srv, path="/crl")
        cert_der = _make_cert_with_ocsp_crl(ocsp_url, crl_url)
        assert _extract_ocsp_url(cert_der) == ocsp_url
        assert crl_url in _extract_crl_urls(cert_der)

        reachable, msg = _check_endpoint_reachable(
            ocsp_url, method="HEAD", timeout=5, allow_private=True,
        )
        assert reachable is False
        assert "blocked by SSRF policy" in msg

        reachable, msg = _check_endpoint_reachable(
            crl_url, method="GET", timeout=5, allow_private=True,
        )
        assert reachable is False
        assert "blocked by SSRF policy" in msg
