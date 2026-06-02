"""Shared fixtures: cryptographic certificates generated at test time."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    pkcs7,
    pkcs12,
)
from cryptography.x509.oid import NameOID


@dataclass
class GeneratedCert:
    der: bytes
    pem: bytes
    key: rsa.RSAPrivateKey
    cert: x509.Certificate
    subject_cn: str


def _make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_cert(
    subject_cn: str,
    *,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
    key: rsa.RSAPrivateKey | None = None,
    days_valid: int = 365,
    san_dns: list[str] | None = None,
) -> GeneratedCert:
    key = key or _make_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = issuer_cert.subject if issuer_cert else subject
    sign_key = issuer_key or key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=days_valid))
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san_dns]),
            critical=False,
        )
    cert = builder.sign(sign_key, hashes.SHA256())
    return GeneratedCert(
        der=cert.public_bytes(Encoding.DER),
        pem=cert.public_bytes(Encoding.PEM),
        key=key,
        cert=cert,
        subject_cn=subject_cn,
    )


@pytest.fixture(scope="session")
def self_signed_leaf() -> GeneratedCert:
    return _make_cert("leaf.example.com", days_valid=365, san_dns=["leaf.example.com"])


@pytest.fixture(scope="session")
def expiring_soon_leaf() -> GeneratedCert:
    return _make_cert("expiring.example.com", days_valid=5, san_dns=["expiring.example.com"])


@pytest.fixture(scope="session")
def chain_triplet() -> dict[str, GeneratedCert]:
    """root -> intermediate -> leaf, all signed correctly."""
    root = _make_cert("Test Root CA", days_valid=3650)
    intermediate = _make_cert(
        "Test Intermediate CA",
        issuer_cert=root.cert,
        issuer_key=root.key,
        days_valid=1825,
    )
    leaf = _make_cert(
        "chain-leaf.example.com",
        issuer_cert=intermediate.cert,
        issuer_key=intermediate.key,
        days_valid=90,
        san_dns=["chain-leaf.example.com"],
    )
    return {"root": root, "intermediate": intermediate, "leaf": leaf}


@pytest.fixture(scope="session")
def chain_pem_bytes(chain_triplet) -> bytes:
    """Concatenated PEM with leaf first, then intermediate, then root."""
    return (
        chain_triplet["leaf"].pem
        + chain_triplet["intermediate"].pem
        + chain_triplet["root"].pem
    )


@pytest.fixture
def chain_pem_file(tmp_path: Path, chain_pem_bytes: bytes) -> Path:
    p = tmp_path / "chain.pem"
    p.write_bytes(chain_pem_bytes)
    return p


@pytest.fixture
def leaf_pem_file(tmp_path: Path, self_signed_leaf: GeneratedCert) -> Path:
    p = tmp_path / "leaf.pem"
    p.write_bytes(self_signed_leaf.pem)
    return p


@pytest.fixture
def leaf_der_file(tmp_path: Path, self_signed_leaf: GeneratedCert) -> Path:
    p = tmp_path / "leaf.der"
    p.write_bytes(self_signed_leaf.der)
    return p


def _pfx_bytes(chain_triplet, password: bytes | None) -> bytes:
    encryption = BestAvailableEncryption(password) if password else NoEncryption()
    return pkcs12.serialize_key_and_certificates(
        name=b"cert-watch-test",
        key=chain_triplet["leaf"].key,
        cert=chain_triplet["leaf"].cert,
        cas=[chain_triplet["intermediate"].cert, chain_triplet["root"].cert],
        encryption_algorithm=encryption,
    )


@pytest.fixture
def pfx_file_no_password(tmp_path: Path, chain_triplet) -> Path:
    p = tmp_path / "bundle.pfx"
    p.write_bytes(_pfx_bytes(chain_triplet, password=None))
    return p


@pytest.fixture
def pfx_file_with_password(tmp_path: Path, chain_triplet) -> tuple[Path, bytes]:
    pw = b"hunter2"
    p = tmp_path / "bundle-pw.pfx"
    p.write_bytes(_pfx_bytes(chain_triplet, password=pw))
    return p, pw


def _p7b_der_bytes(chain_triplet) -> bytes:
    certs = [
        chain_triplet["leaf"].cert,
        chain_triplet["intermediate"].cert,
        chain_triplet["root"].cert,
    ]
    return pkcs7.serialize_certificates(certs, Encoding.DER)


def _p7b_pem_bytes(chain_triplet) -> bytes:
    certs = [
        chain_triplet["leaf"].cert,
        chain_triplet["intermediate"].cert,
        chain_triplet["root"].cert,
    ]
    return pkcs7.serialize_certificates(certs, Encoding.PEM)


@pytest.fixture
def p7b_der_file(tmp_path: Path, chain_triplet) -> Path:
    p = tmp_path / "chain.p7b"
    p.write_bytes(_p7b_der_bytes(chain_triplet))
    return p


@pytest.fixture
def p7c_pem_file(tmp_path: Path, chain_triplet) -> Path:
    p = tmp_path / "chain.p7c"
    p.write_bytes(_p7b_pem_bytes(chain_triplet))
    return p


@pytest.fixture
def malformed_blob(tmp_path: Path) -> Path:
    p = tmp_path / "bad.der"
    p.write_bytes(b"this is definitely not a certificate")
    return p


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    """Point CERT_WATCH_DATA_DIR at a per-test tmp dir so tests don't collide.

    No module reloading (Plan 018 B1): config reads env live, and apps are built
    via ``create_app`` whose lifespan resolves a SecurityContext from these env
    vars. The module-level signing/CSRF globals are still seeded with
    deterministic test values for direct-call unit tests (e.g. session/CSRF
    round-trip helpers and OAuth state signing) that don't go through a request.
    """
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "test-auth-secret-for-tests")

    from cert_watch.auth import set_signing_key
    from cert_watch.middleware import set_csrf_secret

    set_signing_key("test-auth-secret-for-tests")
    set_csrf_secret("test-csrf-secret-for-tests")
    yield


@pytest.fixture
def reload_app(monkeypatch, tmp_path):
    """Build a fresh app via ``create_app()`` — no module reloading (Plan 018 B1).

    Returns a shim exposing ``.app`` (kept for call-site compatibility:
    ``app_mod = reload_app(); TestClient(app_mod.app)``). Env kwargs configure
    the build, e.g. ``reload_app(AUTH_PROVIDER="ldap", ...)``; ``Settings`` and
    the auth provider are then resolved from that environment and injected into
    ``create_app``, so the app's lifespan uses them without reloading modules.

    The ``monkeypatch`` fixture ensures env vars are restored after the test.
    """
    from types import SimpleNamespace

    def _build(**env):
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        from cert_watch.app import create_app
        from cert_watch.config import Settings

        application = create_app(settings=Settings.from_env())
        return SimpleNamespace(app=application)

    return _build


# Also export the private builder for tests that want a custom expiry.
__all__ = ["GeneratedCert", "_make_cert"]
