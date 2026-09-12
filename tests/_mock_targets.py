"""Capturing, loopback-only delivery targets for Plan 050 integration tests.

SMTP uses actual smtplib/TLS/AUTH traffic. Only the destination socket address
is redirected from the configured 587/465 to an OS-assigned ephemeral port.
The synthetic CA is trusted through SSL_CERT_FILE, keeping certificate and
hostname verification enabled in the production transport.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import threading
import warnings
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Literal

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, AuthResult, Envelope, LoginPassword, Session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests._integration_servers import HTTPTestServer, server_url


@dataclass(frozen=True)
class HTTPReceipt:
    path: str
    method: str
    headers: dict[str, str]
    body: bytes


@dataclass
class HTTPTarget:
    paths: frozenset[str]
    statuses: Mapping[str, int]
    requests: list[HTTPReceipt] = field(default_factory=list)
    server: HTTPTestServer | None = field(default=None, repr=False)

    def url(self, path: str) -> str:
        assert self.server is not None
        return server_url(self.server, path=path)

    def received(self, path: str) -> list[HTTPReceipt]:
        return [request for request in self.requests if request.path == path]

    def __call__(self, handler: BaseHTTPRequestHandler) -> None:
        self.requests.append(HTTPReceipt(
            path=handler.path,
            method=handler.command,
            headers=dict(handler.headers),
            body=handler.rfile.read(int(handler.headers.get("Content-Length", "0"))),
        ))
        default = 200 if not self.paths or handler.path in self.paths else 404
        handler.send_response(self.statuses.get(handler.path, default))
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", "2")
        handler.end_headers()
        handler.wfile.write(b"{}")


@contextmanager
def capturing_http_target(
    *paths: str, statuses: Mapping[str, int] | None = None,
) -> Iterator[HTTPTarget]:
    """Capture every request, including unexpected paths and rejected deliveries."""
    target = HTTPTarget(frozenset(paths), dict(statuses or {}))
    server = HTTPTestServer(target)
    target.server = server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield target
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive(), "HTTP target failed to stop"


@dataclass(frozen=True)
class SMTPReceipt:
    mail_from: str
    recipients: tuple[str, ...]
    data: bytes
    tls: bool
    authenticated: bool

    @property
    def message(self) -> EmailMessage:
        return BytesParser(policy=policy.default).parsebytes(self.data)


@dataclass(frozen=True)
class SMTPAuthAttempt:
    mechanism: str
    username: str
    success: bool
    tls: bool


@dataclass
class SMTPTarget:
    port: int
    username: str
    password: str = field(repr=False)
    host: str = "127.0.0.1"
    listening_port: int = 0
    messages: list[SMTPReceipt] = field(default_factory=list)
    auth_attempts: list[SMTPAuthAttempt] = field(default_factory=list)
    connection_addresses: list[tuple[str, int]] = field(default_factory=list)

    @staticmethod
    def _tls_active(server: SMTP) -> bool:
        return server.transport.get_extra_info("ssl_object") is not None

    def authenticate(
        self, server: SMTP, session: Session, envelope: Envelope,
        mechanism: str, auth_data: LoginPassword,
    ) -> AuthResult:
        tls = self._tls_active(server)
        success = (
            tls
            and isinstance(auth_data, LoginPassword)
            and auth_data.login == self.username.encode()
            and auth_data.password == self.password.encode()
        )
        username = auth_data.login.decode("utf-8", errors="replace")
        self.auth_attempts.append(SMTPAuthAttempt(mechanism, username, success, tls))
        # handled=False asks aiosmtpd to send its normal 535 failure response.
        return AuthResult(success=success, handled=False)

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        self.messages.append(SMTPReceipt(
            mail_from=envelope.mail_from,
            recipients=tuple(envelope.rcpt_tos),
            data=envelope.original_content,
            tls=self._tls_active(server),
            authenticated=bool(session.authenticated),
        ))
        return "250 message captured"


class _EphemeralController(Controller):
    async def _create_server(self) -> asyncio.Server:
        server = await super()._create_server()
        # Controller's readiness probe otherwise tries to connect to port 0.
        # Record the bound port before the thread signals its ready event.
        self.port = server.sockets[0].getsockname()[1]
        return server


def _certificate_builder(
    subject: x509.Name, issuer: x509.Name, public_key: ec.EllipticCurvePublicKey,
) -> x509.CertificateBuilder:
    # Long fixed validity makes these synthetic local certificates independent
    # of freeze-time fixtures used for the estate's expiry thresholds.
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2000, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2100, 1, 1, tzinfo=UTC))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )


def _make_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Routing test CA")])
    cert = (
        _certificate_builder(name, name, key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None,
        ), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _tls_material(
    directory: Path, *, trusted: bool, valid_hostname: bool,
) -> tuple[ssl.SSLContext, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = _make_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Routing SMTP target")])
    san = (
        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        if valid_hostname else x509.DNSName("wrong-host.invalid")
    )
    cert = (
        _certificate_builder(name, ca_cert.subject, key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=None, decipher_only=None,
        ), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path, key_path, ca_path = (directory / name for name in ("cert.pem", "key.pem", "ca.pem"))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    trust_cert = ca_cert if trusted else _make_ca()[1]
    ca_path.write_bytes(trust_cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    return context, ca_path


@contextmanager
def smtp_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: Literal["starttls", "implicit", "plaintext"] = "starttls",
    username: str = "routing-user",
    password: str = "routing-password",
    trusted: bool = True,
    valid_hostname: bool = True,
) -> Iterator[SMTPTarget]:
    """Run a TLS/AUTH receiver; caller separately permits loopback SSRF transport.

    ``plaintext`` exists only to verify that production refuses to send
    credentials when STARTTLS is unavailable. The receiver never accepts
    unauthenticated messages or authenticates credentials over plaintext.
    """
    if mode not in {"starttls", "implicit", "plaintext"}:
        raise ValueError(f"Unknown SMTP target mode: {mode}")
    target = SMTPTarget(465 if mode == "implicit" else 587, username, password)
    tls_context, ca_path = _tls_material(
        tmp_path / "smtp-target", trusted=trusted, valid_hostname=valid_hostname,
    )
    # aiosmtpd's auth_require_tls flag recognizes STARTTLS, not an already
    # wrapped implicit TLS listener. The latter is encrypted by the controller,
    # and authenticate() independently verifies the actual transport's SSL object.
    with warnings.catch_warnings():
        if mode == "implicit":
            warnings.filterwarnings(
                "ignore", message="Requiring AUTH while not requiring TLS.*", category=UserWarning,
            )
        controller = _EphemeralController(
            target, hostname=target.host, port=0,
            ssl_context=tls_context if mode == "implicit" else None,
            tls_context=tls_context if mode == "starttls" else None,
            require_starttls=mode == "starttls",
            auth_required=True,
            auth_require_tls=mode != "implicit",
            authenticator=target.authenticate,
            server_hostname="routing-target.invalid",
            ready_timeout=5,
        )
        try:
            controller.start()
            target.listening_port = controller.port
            real_create_connection = socket.create_connection

            def create_connection(address, *args, **kwargs):
                if address == (target.host, target.port):
                    target.connection_addresses.append(address)
                    address = (target.host, target.listening_port)
                return real_create_connection(address, *args, **kwargs)

            with monkeypatch.context() as scoped:
                scoped.setenv("SSL_CERT_FILE", str(ca_path))
                scoped.setattr(socket, "create_connection", create_connection)
                yield target
        finally:
            controller.stop(no_assert=True)
