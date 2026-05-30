"""Tests for posture evaluation and storage (Plan 006 Phase 1)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import get_posture_for_cert, init_schema, store_scan_posture
from cert_watch.posture import Finding, evaluate_posture


def _make_cert(
    subject: str = "CN=test.example.com",
    issuer: str = "CN=Test CA",
    days_remaining: int = 90,
    san_dns_names: list[str] | None = None,
    fingerprint_sha256: str = "",
    raw_der: bytes = b"",
    is_leaf: bool = True,
) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=subject,
        issuer=issuer,
        not_before=now - timedelta(days=90),
        not_after=now + timedelta(days=days_remaining),
        san_dns_names=san_dns_names or ["test.example.com"],
        fingerprint_sha256=fingerprint_sha256 or "AA" * 32,
        raw_der=raw_der,
        is_leaf=is_leaf,
    )


def _self_signed_cert_der() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "self-signed.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _weak_rsa_cert_der(key_size: int = 1024) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "weak-rsa.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _long_validity_cert_der(days: int = 400) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "long-validity.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _ca_signed_cert_der() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "good.example.com"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Good CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _cert_from_der(der: bytes, fingerprint: str = "") -> Certificate:
    from cryptography import x509
    x509_cert = x509.load_der_x509_certificate(der)
    fp_hex = fingerprint or x509_cert.fingerprint(
        __import__("cryptography").hazmat.primitives.hashes.SHA256()
    ).hex()
    san = []
    try:
        san_ext = x509_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    return Certificate(
        subject=str(x509_cert.subject),
        issuer=str(x509_cert.issuer),
        not_before=x509_cert.not_valid_before_utc,
        not_after=x509_cert.not_valid_after_utc,
        san_dns_names=san,
        fingerprint_sha256=fp_hex,
        raw_der=der,
    )


class TestPostureEvaluation:
    """Tests for evaluate_posture() policy lint logic."""

    def test_grade_a_no_issues(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, chain_status="public")
        assert result.grade == "A"
        assert any(f.check == "rsa_key_size" and f.status == "pass" for f in result.findings)
        assert any(f.check == "sha1_signature" and f.status == "pass" for f in result.findings)
        assert any(f.check == "self_signed" and f.status == "pass" for f in result.findings)
        assert any(f.check == "chain_completeness" and f.status == "pass" for f in result.findings)

    def test_self_signed_warn(self):
        der = _self_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert)
        assert result.grade == "A"
        self_signed = [f for f in result.findings if f.check == "self_signed"]
        assert len(self_signed) == 1
        assert self_signed[0].status == "warn"

    def test_weak_rsa_drops_to_c(self):
        der = _weak_rsa_cert_der(1024)
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert)
        assert result.grade == "C"
        key = [f for f in result.findings if f.check == "rsa_key_size"]
        assert len(key) == 1
        assert key[0].status == "fail"

    def test_incomplete_chain_drops_to_b(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, chain_status="incomplete")
        assert result.grade == "B"

    def test_invalid_chain_drops_to_c(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, chain_status="invalid")
        assert result.grade == "C"

    def test_tls_10_drops_to_b(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, protocol_version="TLSv1.0")
        assert result.grade == "B"
        tls = [f for f in result.findings if f.check == "tls_version"]
        assert len(tls) == 1
        assert tls[0].status == "warn"

    def test_tls_11_drops_to_b(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, protocol_version="TLSv1.1")
        assert result.grade == "B"

    def test_tls_12_no_penalty(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, protocol_version="TLSv1.2")
        assert result.grade == "A"
        tls = [f for f in result.findings if f.check == "tls_version"]
        assert len(tls) == 1
        assert tls[0].status == "pass"

    def test_long_validity_warns(self):
        der = _long_validity_cert_der(400)
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert)
        assert result.grade == "A"
        validity = [f for f in result.findings if f.check == "long_validity"]
        assert len(validity) == 1
        assert validity[0].status == "warn"

    def test_unparseable_cert_returns_f(self):
        cert = Certificate(
            subject="CN=bad",
            issuer="CN=bad",
            not_before=datetime.now(UTC) - timedelta(days=90),
            not_after=datetime.now(UTC) + timedelta(days=90),
            san_dns_names=[],
            fingerprint_sha256="33" * 32,
            raw_der=b"not-valid-der",
        )
        result = evaluate_posture(cert=cert)
        assert result.grade == "F"
        assert any(f.check == "parse" and f.status == "fail" for f in result.findings)

    def test_hsts_informational(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, hsts=False)
        hsts = [f for f in result.findings if f.check == "hsts"]
        assert len(hsts) == 1
        assert hsts[0].status == "pass"

    def test_hsts_present(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, hsts=True)
        hsts = [f for f in result.findings if f.check == "hsts"]
        assert len(hsts) == 1
        assert hsts[0].status == "pass"

    def test_multiple_penalties_worst_wins(self):
        der = _weak_rsa_cert_der(1024)
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, chain_status="invalid", protocol_version="TLSv1.0")
        assert result.grade == "C"
        severities = {"tls_version": 1, "chain_completeness": 2, "rsa_key_size": 2}
        worst = max(severities.values())
        assert worst == 2

    def test_must_staple_not_required_is_info(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, ocsp_stapling=False)
        must_staple = [f for f in result.findings if f.check == "ocsp_must_staple"]
        assert len(must_staple) == 1
        assert must_staple[0].status == "info"

    def test_protocol_version_stored(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, protocol_version="TLSv1.3")
        assert result.protocol_version == "TLSv1.3"

    def test_a_plus_grade_for_tls13_hsts(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(
            cert=cert, protocol_version="TLSv1.3",
            hsts=True, chain_status="public",
        )
        assert result.grade == "A+"

    def test_a_grade_without_hsts(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(
            cert=cert, protocol_version="TLSv1.3",
            hsts=False, chain_status="public",
        )
        assert result.grade == "A"

    def test_a_grade_without_tls13(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(
            cert=cert, protocol_version="TLSv1.2",
            hsts=True, chain_status="public",
        )
        assert result.grade == "A"


class TestPostureStorage:
    """Tests for storing and retrieving posture data from the database."""

    def test_store_and_retrieve_posture(self, tmp_path):
        db = str(tmp_path / "test.db")
        init_schema(db)
        findings = [
            {"check": "rsa_key_size", "status": "pass", "message": "RSA 2048 bits"},
            {"check": "sha1_signature", "status": "pass", "message": "No SHA-1"},
        ]
        posture_id = store_scan_posture(
            db_path=db,
            cert_id="cert-001",
            hostname="example.com",
            port=443,
            grade="A",
            findings=findings,
            protocol_version="TLSv1.3",
            ocsp_stapling=True,
            hsts=True,
            must_staple=False,
        )
        assert posture_id

        result = get_posture_for_cert(db, "cert-001")
        assert result is not None
        assert result["cert_id"] == "cert-001"
        assert result["grade"] == "A"
        assert result["protocol_version"] == "TLSv1.3"
        assert result["ocsp_stapling"] == 1
        assert result["hsts"] == 1
        assert result["must_staple"] == 0
        assert len(result["findings"]) == 2

    def test_get_posture_nonexistent(self, tmp_path):
        db = str(tmp_path / "test.db")
        init_schema(db)
        result = get_posture_for_cert(db, "nonexistent")
        assert result is None

    def test_posture_with_finding_objects(self, tmp_path):
        db = str(tmp_path / "test.db")
        init_schema(db)
        findings = [
            Finding(check="chain_completeness", status="warn", message="Incomplete chain"),
        ]
        posture_id = store_scan_posture(
            db_path=db,
            cert_id="cert-002",
            hostname="example.com",
            port=443,
            grade="B",
            findings=findings,
        )
        assert posture_id

        result = get_posture_for_cert(db, "cert-002")
        assert result["grade"] == "B"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["check"] == "chain_completeness"

    def test_get_posture_grades_for_certs(self, tmp_path):
        from cert_watch.database import get_posture_grades_for_certs
        db = str(tmp_path / "test.db")
        init_schema(db)
        store_scan_posture(
            db, "c1", "h1", 443, "A",
            [{"check": "x", "status": "pass", "message": "ok"}],
        )
        store_scan_posture(
            db, "c2", "h2", 443, "B",
            [{"check": "x", "status": "warn", "message": "meh"}],
        )
        grades = get_posture_grades_for_certs(db, ["c1", "c2", "c3"])
        assert grades["c1"] == "A"
        assert grades["c2"] == "B"
        assert "c3" not in grades


class TestScanProtocolVersion:
    """Test that ScannedEntry carries protocol_version."""

    def test_scanned_entry_has_protocol_version(self):
        from cert_watch.scan import ScannedEntry

        cert = _make_cert()
        entry = ScannedEntry(
            host="example.com",
            port=443,
            leaf=cert,
            chain=[],
            scanned_at=datetime.now(UTC),
            protocol_version="TLSv1.3",
        )
        assert entry.protocol_version == "TLSv1.3"

    def test_scanned_entry_default_protocol_version(self):
        from cert_watch.scan import ScannedEntry

        cert = _make_cert()
        entry = ScannedEntry(
            host="example.com",
            port=443,
            leaf=cert,
            chain=[],
            scanned_at=datetime.now(UTC),
        )
        assert entry.protocol_version == ""

    def test_openssl_protocol_regex(self):
        from cert_watch.scan import _PROTOCOL_RE
        assert _PROTOCOL_RE.search(b"Protocol  : TLSv1.3").group(1) == b"TLSv1.3"
        assert _PROTOCOL_RE.search(b"Protocol  : TLSv1.2").group(1) == b"TLSv1.2"
        assert _PROTOCOL_RE.search(b"Protocol  : TLSv1.0").group(1) == b"TLSv1.0"
        assert _PROTOCOL_RE.search(b"no protocol") is None