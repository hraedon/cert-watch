"""Tests for the fleet crypto inventory & agility lens (crypto_posture.py)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.crypto_posture import (
    analyze_fleet_crypto,
    classify_cert_crypto,
    crypto_posture_to_dict,
)


def _mint(key, *, sig_hash=None, cn="c.example.com", sign_key=None) -> bytes:
    """Build a self-signed DER cert with the given key and signature hash."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
    )
    # Ed25519/Ed448 sign with algorithm=None; RSA/EC take a hash.
    cert = builder.sign(sign_key or key, sig_hash)
    return cert.public_bytes(serialization.Encoding.DER)


def _rsa(bits: int):
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _ec(curve):
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(curve)


# ---------- classify_cert_crypto ----------


def test_classify_rsa_2048_sha256():
    from cryptography.hazmat.primitives import hashes
    info = classify_cert_crypto(_mint(_rsa(2048), sig_hash=hashes.SHA256()))
    assert info.key_family == "RSA"
    assert info.key_label == "RSA-2048"
    assert info.sig_hash == "SHA-256"
    assert not info.is_weak


def test_classify_weak_rsa_1024_flagged():
    from cryptography.hazmat.primitives import hashes
    info = classify_cert_crypto(_mint(_rsa(1024), sig_hash=hashes.SHA256()))
    assert info.is_weak
    assert "1024" in info.weak_reason


def test_classify_ec_p256():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    info = classify_cert_crypto(_mint(_ec(ec.SECP256R1()), sig_hash=hashes.SHA256()))
    assert info.key_family == "EC"
    assert info.key_label == "EC-P-256"
    assert not info.is_weak


def test_classify_weak_curve_flagged():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    info = classify_cert_crypto(_mint(_ec(ec.SECP224R1()), sig_hash=hashes.SHA256()))
    assert info.is_weak
    assert "curve" in info.weak_reason


# A real sha1WithRSAEncryption self-signed cert (DER, base64). Modern
# cryptography refuses to *sign* with SHA-1 but parses it fine, so this is the
# only way to exercise the SHA-1 detection path end to end. Minted with
# `openssl req -x509 -sha1`.
_SHA1_CERT_B64 = (
    "MIIDFzCCAf+gAwIBAgIUT9fXMHayZVgw+Q8nLsG0sLEj7m0wDQYJKoZIhvcNAQEFBQAwGzEZ"
    "MBcGA1UEAwwQc2hhMS5leGFtcGxlLmNvbTAeFw0yNjA2MjAxNjU5MjlaFw0yNjA2MjIxNjU5"
    "MjlaMBsxGTAXBgNVBAMMEHNoYTEuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB"
    "DwAwggEKAoIBAQC14K0z+Dr6Sb4MYsJSSXzR3rGtH3PqYfndaKWySJEBQLUrL65X9jY5f2gw"
    "FHagUrQi6XXDMQ1Q0ggiDJQXRpyttty7Kyrlgk6te/nOEllV37a2hi5mL6NVVg/g4fdOlB9e"
    "C1PglCaxb9a+FDIdat8YUJsGnST6esKXCGmjYu1BRQ/S1gGPj7HWquNApbJ2bhOpIpcDwQ3i"
    "w5FkpXGwb9wLbpOlk8MgWGyKoSihD3T/vMIdD5PJgp/KNFH5AWxN2Xxdp55pXWOKjGobq7QD"
    "oJdr88PPnFYGu5XFApPWOs/oqpB1Ehoy91At72PdHDyn0VCmqE1fppIZGHUi3+hY4owTAgMB"
    "AAGjUzBRMB0GA1UdDgQWBBSJK3f6RwK8WTW8pgW2oo8m7eNGgzAfBgNVHSMEGDAWgBSJK3f6"
    "RwK8WTW8pgW2oo8m7eNGgzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQCV"
    "ONz6Zk/I6QUUMBgzdFmaqOZNbnZledKO2+yR+DNGOBmpbF5f5ZfaIXRWYIf74DjsLUDVeKRo"
    "ZY+8jA2m+DoI6rY7PIx9G/b701uO05dlvvOf0xXqLQ5TTAmU9SNAXK/BuooLlxbUHsWf7yEQ"
    "x5j5qXdvjYesGRMJsZ7JSP8QjD61hHDhvieF3iY0lt5QSZ106khXK9TzoCI0gPbod9Yd4GNP"
    "7VpIoKsYXAjQUdcmm/jEQWsoZHV3IrZf+AOgeddaA1Iwv1KnSaFBPTLuiE3oL/9uyqc3TtGB"
    "55SoZQB2csnGYPDPUJNr778ep2sXkVkJLiOZQ6uvr/c+wqA4vhXE"
)


def _sha1_cert_der() -> bytes:
    import base64
    return base64.b64decode(_SHA1_CERT_B64)


def test_classify_sha1_signature_flagged():
    info = classify_cert_crypto(_sha1_cert_der())
    assert info.sig_hash == "SHA-1"
    assert info.is_weak
    assert "SHA-1" in info.weak_reason


def test_classify_ed25519():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    info = classify_cert_crypto(_mint(key, sig_hash=None))
    assert info.key_family == "EdDSA"
    assert info.key_label == "Ed25519"
    assert not info.is_weak


def test_classify_bad_der_returns_none():
    assert classify_cert_crypto(b"not a cert") is None
    assert classify_cert_crypto(b"") is None


# ---------- analyze_fleet_crypto ----------


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    from cert_watch.database import init_schema
    db = tmp_path / "crypto.sqlite3"
    init_schema(db)
    return db


def _store_leaf(db: Path, raw_der: bytes, hostname: str, subject: str) -> None:
    """Store a leaf cert via the real repository (handles every column)."""
    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository

    repo = SqliteCertificateRepository(db, hostname=hostname, port=443)
    repo.add(Certificate(
        subject=subject,
        issuer="CN=issuer",
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=datetime.now(UTC) + timedelta(days=90),
        san_dns_names=[hostname],
        fingerprint_sha256=subject.encode().hex().ljust(64, "0")[:64],
        raw_der=raw_der,
        is_leaf=True,
    ))


def test_fleet_aggregates_distribution(db_path: Path):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    _store_leaf(db_path, _mint(_rsa(2048), sig_hash=hashes.SHA256()), "a", "CN=a")
    _store_leaf(db_path, _mint(_rsa(2048), sig_hash=hashes.SHA256()), "b", "CN=b")
    _store_leaf(db_path, _mint(_ec(ec.SECP256R1()), sig_hash=hashes.SHA256()), "c", "CN=c")

    p = analyze_fleet_crypto(db_path)
    assert p.total == 3
    assert p.key_algorithms["RSA-2048"] == 2
    assert p.key_algorithms["EC-P-256"] == 1
    assert p.families["RSA"] == 2
    assert p.families["EC"] == 1
    assert p.weak_count == 0


def test_fleet_collects_weak_offenders(db_path: Path):
    from cryptography.hazmat.primitives import hashes
    _store_leaf(db_path, _mint(_rsa(2048), sig_hash=hashes.SHA256()), "ok", "CN=ok")
    _store_leaf(db_path, _mint(_rsa(1024), sig_hash=hashes.SHA256()), "weak", "CN=weak")
    _store_leaf(db_path, _sha1_cert_der(), "sha1", "CN=sha1")

    p = analyze_fleet_crypto(db_path)
    assert p.weak_count == 2
    hosts = {c["hostname"] for c in p.weak_certs}
    assert hosts == {"weak", "sha1"}


def test_fleet_empty_is_safe(db_path: Path):
    p = analyze_fleet_crypto(db_path)
    assert p.total == 0
    assert p.weak_count == 0
    assert "post-quantum" in p.pqc_note.lower()


def test_to_dict_orders_by_count_desc(db_path: Path):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    _store_leaf(db_path, _mint(_ec(ec.SECP256R1()), sig_hash=hashes.SHA256()), "c", "CN=c")
    _store_leaf(db_path, _mint(_rsa(2048), sig_hash=hashes.SHA256()), "a", "CN=a")
    _store_leaf(db_path, _mint(_rsa(2048), sig_hash=hashes.SHA256()), "b", "CN=b")

    d = crypto_posture_to_dict(analyze_fleet_crypto(db_path))
    # RSA-2048 (2) ranks before EC-P-256 (1)
    assert d["key_algorithms"][0]["label"] == "RSA-2048"
    assert d["key_algorithms"][0]["count"] == 2


# ---------- /crypto route ----------


class TestCryptoRoute:
    def test_crypto_page_renders_empty(self, reload_app):
        from starlette.testclient import TestClient
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/crypto")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "Crypto Inventory" in r.text

    def test_crypto_page_shows_weak_offender(self, tmp_path, reload_app):
        from cryptography.hazmat.primitives import hashes
        from starlette.testclient import TestClient

        from cert_watch.database import init_schema
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)
        _store_leaf(db, _mint(_rsa(2048), sig_hash=hashes.SHA256()), "good.example.com", "CN=good")
        _store_leaf(db, _sha1_cert_der(), "legacy.example.com", "CN=legacy")
        with TestClient(app_mod.app) as client:
            r = client.get("/crypto")
        assert r.status_code == 200
        assert "legacy.example.com" in r.text
        assert "RSA-2048" in r.text

    def test_crypto_page_auth_gated(self, reload_app):
        from starlette.testclient import TestClient
        app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
        with TestClient(app_mod.app) as client:
            r = client.get("/crypto", follow_redirects=False)
        assert r.status_code in (302, 303, 401)
