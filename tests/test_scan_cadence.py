"""Tests for scan-cadence guidance finding (WI-3.2 / Plan 048)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.posture import evaluate_posture


def _cert_der(validity_days: int = 90) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _make_cert(validity_days: int = 90) -> Certificate:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    der = _cert_der(validity_days)
    x509_cert = x509.load_der_x509_certificate(der)
    fp = x509_cert.fingerprint(hashes.SHA256()).hex()
    san = []
    try:
        ext = x509_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    return Certificate(
        subject=str(x509_cert.subject),
        issuer=str(x509_cert.issuer),
        not_before=x509_cert.not_valid_before_utc,
        not_after=x509_cert.not_valid_after_utc,
        san_dns_names=san,
        fingerprint_sha256=fp,
        raw_der=der,
        is_leaf=True,
    )


def test_scan_interval_none_no_finding():
    cert = _make_cert(validity_days=90)
    result = evaluate_posture(cert=cert, scan_interval_days=None)
    cadence = [f for f in result.findings if f.check == "scan_cadence"]
    assert len(cadence) == 0


def test_scan_interval_zero_no_finding():
    cert = _make_cert(validity_days=90)
    result = evaluate_posture(cert=cert, scan_interval_days=0)
    cadence = [f for f in result.findings if f.check == "scan_cadence"]
    assert len(cadence) == 0


def test_daily_interval_never_triggers():
    cert = _make_cert(validity_days=47)
    result = evaluate_posture(cert=cert, scan_interval_days=1)
    cadence = [f for f in result.findings if f.check == "scan_cadence"]
    assert len(cadence) == 0


def test_7_day_interval_47_day_cert_triggers():
    cert = _make_cert(validity_days=47)
    result = evaluate_posture(cert=cert, scan_interval_days=7)
    cadence = [f for f in result.findings if f.check == "scan_cadence"]
    assert len(cadence) == 1
    assert cadence[0].status == "warn"
    assert "7" in cadence[0].message
    assert "certificate lifetime" in cadence[0].message


def test_interval_exactly_at_threshold_no_finding():
    cert = _make_cert(validity_days=100)
    result = evaluate_posture(cert=cert, scan_interval_days=10)
    cadence = [f for f in result.findings if f.check == "scan_cadence"]
    assert len(cadence) == 0


def test_interval_just_above_threshold_triggers():
    cert = _make_cert(validity_days=100)
    result = evaluate_posture(cert=cert, scan_interval_days=11)
    cadence = [f for f in result.findings if f.check == "scan_cadence"]
    assert len(cadence) == 1
    assert cadence[0].status == "warn"


def test_long_validity_no_trigger():
    cert = _make_cert(validity_days=365)
    result = evaluate_posture(cert=cert, scan_interval_days=30)
    cadence = [f for f in result.findings if f.check == "scan_cadence"]
    assert len(cadence) == 0


def test_short_validity_triggers():
    cert = _make_cert(validity_days=30)
    result = evaluate_posture(cert=cert, scan_interval_days=5)
    cadence = [f for f in result.findings if f.check == "scan_cadence"]
    assert len(cadence) == 1
    assert cadence[0].status == "warn"


def test_cadence_finding_no_grade_penalty():
    cert = _make_cert(validity_days=47)
    result = evaluate_posture(cert=cert, scan_interval_days=7)
    assert result.grade == "A"
