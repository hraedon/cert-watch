from unittest.mock import MagicMock, patch

from cert_watch.caa_check import CAAResult, check_caa


def test_check_caa_resolver_failure_surfaces_error(monkeypatch):
    """A resolver failure (SERVFAIL/no nameservers) is surfaced as an error,
    not raised. dnspython is a core dependency, so the lookup path is live."""
    import dns.resolver

    def _boom(domain, rdtype):
        raise dns.exception.DNSException("nameserver unreachable")

    monkeypatch.setattr(dns.resolver, "resolve", _boom)
    result = check_caa("example.com")
    assert isinstance(result, CAAResult)
    assert result.domain == "example.com"
    assert "DNS lookup failed" in result.error


def test_check_caa_with_mocked_dns():
    """Mock dnspython to return actual CAA records."""
    mock_answer = MagicMock()
    mock_answer.__iter__ = MagicMock(return_value=iter([
        "0 issue \"letsencrypt.org\"",
        "0 issuewild \";\"",
    ]))

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = mock_answer

    mock_rdata = MagicMock()
    mock_rdata.CAA = 257

    with patch.dict("sys.modules", {"dns.resolver": mock_resolver, "dns.rdatatype": mock_rdata}):
        import cert_watch.caa_check as caa_mod
        original_query = caa_mod._query_caa_records
        try:
            def _fake_query(domain):
                return ["0 issue \"letsencrypt.org\"", "0 issuewild \";\""]
            caa_mod._query_caa_records = _fake_query
            result = check_caa("example.com")
            assert result.domain == "example.com"
            assert result.issue_allowed is True
            assert result.issuewild_allowed is False
            assert 'issue "letsencrypt.org"' in result.records
        finally:
            caa_mod._query_caa_records = original_query


def test_check_caa_no_caa_records():
    """No CAA records means unrestricted issuance."""
    import cert_watch.caa_check as caa_mod
    original_query = caa_mod._query_caa_records
    try:
        def _fake_query(domain):
            return []
        caa_mod._query_caa_records = _fake_query
        result = check_caa("example.com")
        assert result.error == ""
        assert result.issue_allowed is True
        assert result.issuewild_allowed is True
        assert result.records == []
    finally:
        caa_mod._query_caa_records = original_query


def test_check_caa_blocked_issue():
    """Empty issue tag (';') blocks issuance."""
    import cert_watch.caa_check as caa_mod
    original_query = caa_mod._query_caa_records
    try:
        def _fake_query(domain):
            return ["0 issue \";\""]
        caa_mod._query_caa_records = _fake_query
        result = check_caa("example.com")
        assert result.issue_allowed is False
        assert result.issuewild_allowed is True  # no issuewild explicitly set
    finally:
        caa_mod._query_caa_records = original_query


# ── CAA per-scan persistence and posture (BC-121) ──────────────────────────


def _caa_valid_cert_der() -> bytes:
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

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


def _caa_insert_certificate(db, cert_id: str) -> None:
    from cert_watch.database.connection import _connect

    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO certificates (id, subject, issuer, not_before, not_after, "
            "san_dns_names, fingerprint_sha256, raw_der, source, hostname, port, is_leaf, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (cert_id, "CN=test", "CN=CA", "2026-01-01T00:00:00+00:00",
             "2027-01-01T00:00:00+00:00", "[]", f"fp-{cert_id}", b"", "scanned",
             "test", 443, 1, "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()


def test_store_scan_posture_persists_caa_data(tmp_path):
    from cert_watch.database import init_schema, store_scan_posture
    from cert_watch.database.posture import get_posture_for_cert

    db = tmp_path / "test.db"
    init_schema(db)
    cert_id = "cert-001"
    _caa_insert_certificate(db, cert_id)
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
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.posture import evaluate_posture

    now = datetime.now(UTC)
    cert = Certificate(
        subject="example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["example.com"],
        fingerprint_sha256="a" * 64,
        raw_der=_caa_valid_cert_der(),
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
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.posture import evaluate_posture

    now = datetime.now(UTC)
    cert = Certificate(
        subject="example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["example.com"],
        fingerprint_sha256="a" * 64,
        raw_der=_caa_valid_cert_der(),
    )
    result = evaluate_posture(
        cert=cert,
        caa_present=False,
    )
    caa_findings = [f for f in result.findings if f.check == "caa"]
    assert len(caa_findings) == 1
    assert caa_findings[0].status == "info"


def test_evaluate_posture_caa_not_collected():
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.posture import evaluate_posture

    now = datetime.now(UTC)
    cert = Certificate(
        subject="example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["example.com"],
        fingerprint_sha256="a" * 64,
        raw_der=_caa_valid_cert_der(),
    )
    result = evaluate_posture(
        cert=cert,
        caa_present=None,
    )
    caa_findings = [f for f in result.findings if f.check == "caa"]
    assert len(caa_findings) == 0


def test_compliance_report_caa_metric_collected(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.compliance import build_compliance_report
    from cert_watch.database import init_schema, replace_scanned, store_scan_posture

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
        raw_der=_caa_valid_cert_der(),
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
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.compliance import build_compliance_report
    from cert_watch.database import init_schema, replace_scanned, store_scan_posture

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
        raw_der=_caa_valid_cert_der(),
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
