"""Tests for BC-121 — store CAA per scan for compliance report."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_watch.certificate_model import Certificate
from cert_watch.compliance import build_compliance_report
from cert_watch.database import init_schema, replace_scanned, store_scan_posture
from cert_watch.database.posture import get_posture_for_cert
from cert_watch.database.schema import ensure_base
from cert_watch.posture import evaluate_posture


def _valid_cert_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
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


def test_migration_0017_adds_caa_columns(tmp_path):
    db = tmp_path / "test.db"
    ensure_base(db)
    with sqlite3.connect(str(db)) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_posture)").fetchall()}
    assert "caa_present" in cols
    assert "caa_records" in cols


def test_store_scan_posture_persists_caa_data(tmp_path):
    db = tmp_path / "test.db"
    init_schema(db)
    cert_id = "cert-001"
    store_scan_posture(
        db_path=db,
        cert_id=cert_id,
        hostname="example.com",
        port=443,
        grade="A",
        findings=[],
        caa_present=True,
        caa_records=["issue letsencrypt.org", "issuewild ;"],
    )
    posture = get_posture_for_cert(db, cert_id)
    assert posture is not None
    assert posture["caa_present"] is True
    assert posture["caa_records"] == ["issue letsencrypt.org", "issuewild ;"]


def test_evaluate_posture_includes_caa_finding():
    now = datetime.now(UTC)
    cert = Certificate(
        subject="example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["example.com"],
        fingerprint_sha256="a" * 64,
        raw_der=_valid_cert_der(),
    )
    result = evaluate_posture(
        cert=cert,
        caa_present=True,
        caa_records=["issue letsencrypt.org"],
    )
    caa_findings = [f for f in result.findings if f.check == "caa"]
    assert len(caa_findings) == 1
    assert caa_findings[0].status == "pass"
    assert "letsencrypt.org" in caa_findings[0].message


def test_evaluate_posture_caa_absent():
    now = datetime.now(UTC)
    cert = Certificate(
        subject="example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["example.com"],
        fingerprint_sha256="a" * 64,
        raw_der=_valid_cert_der(),
    )
    result = evaluate_posture(
        cert=cert,
        caa_present=False,
    )
    caa_findings = [f for f in result.findings if f.check == "caa"]
    assert len(caa_findings) == 1
    assert caa_findings[0].status == "info"


def test_evaluate_posture_caa_not_collected():
    now = datetime.now(UTC)
    cert = Certificate(
        subject="example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["example.com"],
        fingerprint_sha256="a" * 64,
        raw_der=_valid_cert_der(),
    )
    result = evaluate_posture(
        cert=cert,
        caa_present=None,
    )
    caa_findings = [f for f in result.findings if f.check == "caa"]
    assert len(caa_findings) == 0


def test_compliance_report_caa_metric_collected(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    now = datetime.now(UTC)
    cert = Certificate(
        subject="example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["example.com"],
        fingerprint_sha256="a" * 64,
        raw_der=_valid_cert_der(),
    )
    leaf_id, _ = replace_scanned(db, "example.com", 443, cert, [], True)
    store_scan_posture(
        db_path=db,
        cert_id=leaf_id,
        hostname="example.com",
        port=443,
        grade="A",
        findings=[],
        caa_present=True,
        caa_records=["issue letsencrypt.org"],
    )

    report = build_compliance_report(
        db,
        version="0.7.0",
        commit="abc123",
        signing_key="test-key",
    )
    caa_metric = next(m for m in report.compliance_metrics if m.label == "CAA present for domain")
    assert caa_metric.collected is True
    assert caa_metric.passing == 1
    assert caa_metric.total == 1
    assert caa_metric.pct == 100.0


def test_compliance_report_caa_metric_not_collected_when_empty(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    now = datetime.now(UTC)
    cert = Certificate(
        subject="example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["example.com"],
        fingerprint_sha256="a" * 64,
        raw_der=_valid_cert_der(),
    )
    leaf_id, _ = replace_scanned(db, "example.com", 443, cert, [], True)
    store_scan_posture(
        db_path=db,
        cert_id=leaf_id,
        hostname="example.com",
        port=443,
        grade="A",
        findings=[],
        caa_present=None,
    )

    report = build_compliance_report(
        db,
        version="0.7.0",
        commit="abc123",
        signing_key="test-key",
    )
    caa_metric = next(m for m in report.compliance_metrics if m.label == "CAA present for domain")
    assert caa_metric.collected is False
    assert caa_metric.display == "Not collected"
