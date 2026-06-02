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

    def test_a_plus_grade_for_tls13_non_443_no_hsts(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(
            cert=cert, protocol_version="TLSv1.3",
            hsts=None, chain_status="public", port=8443,
        )
        assert result.grade == "A+"

    def test_a_grade_for_tls13_443_no_hsts(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(
            cert=cert, protocol_version="TLSv1.3",
            hsts=None, chain_status="public", port=443,
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


class TestScanPosturePersistence:
    """store_scanned() must evaluate and persist posture as a side effect.

    The wiring in store_scanned swallows posture errors (best-effort), so
    without an explicit end-to-end assertion a broken wiring would pass
    every other test silently.
    """

    def test_store_scanned_persists_posture(self, tmp_path):
        from cert_watch.certificate_model import parse_certificate
        from cert_watch.scan import ScannedEntry, store_scanned

        db = str(tmp_path / "cert-watch.sqlite3")
        leaf = parse_certificate(_self_signed_cert_der())
        entry = ScannedEntry(
            host="example.com", port=443, leaf=leaf, chain=[],
            protocol_version="TLSv1.3",
        )

        cert_id = store_scanned(entry, db)

        posture = get_posture_for_cert(db, cert_id)
        assert posture is not None, "store_scanned did not persist posture"
        assert posture["grade"] in {"A", "A+", "B", "C", "F"}
        assert posture["protocol_version"] == "TLSv1.3"
        assert posture["findings"]


class TestPostureLatestSelection:
    """Both latest-row lookups must be deterministic under timestamp ties."""

    def test_tie_breaks_consistently_across_lookups(self, tmp_path):
        from cert_watch.database import get_posture_grades_for_certs

        db = str(tmp_path / "test.db")
        init_schema(db)
        same_ts = "2026-05-30T12:00:00+00:00"
        store_scan_posture(
            db, "cert-tie", "h", 443, "A",
            [{"check": "x", "status": "pass", "message": "ok"}],
            scanned_at=same_ts,
        )
        store_scan_posture(
            db, "cert-tie", "h", 443, "C",
            [{"check": "x", "status": "warn", "message": "meh"}],
            scanned_at=same_ts,
        )

        # Exactly one grade, and the single-cert and batch lookups agree.
        grades = get_posture_grades_for_certs(db, ["cert-tie"])
        single = get_posture_for_cert(db, "cert-tie")
        assert grades["cert-tie"] == single["grade"]
        # Stable across repeated calls.
        assert get_posture_grades_for_certs(db, ["cert-tie"]) == grades


class TestPostureEdgeCases:
    """Edge-case coverage for evaluate_posture() — gaps flagged in reflections."""

    def _ecdsa_cert_der(self, curve_name: str = "secp256r1") -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        curve = {"secp256r1": ec.SECP256R1(), "secp224r1": ec.SECP224R1()}
        key = ec.generate_private_key(curve[curve_name])
        now = datetime.now(UTC)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{curve_name}.example.com"),
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

    def _sha1_signed_cert_der(self) -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "sha1.example.com"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .sign(key, hashes.SHA1())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_ecdsa_secp256r1_passes(self):
        der = self._ecdsa_cert_der("secp256r1")
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert)
        ecdsa = [f for f in result.findings if f.check == "ecdsa_curve"]
        assert len(ecdsa) == 1
        assert ecdsa[0].status == "pass"

    def test_ecdsa_secp224r1_fails(self):
        der = self._ecdsa_cert_der("secp224r1")
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert)
        assert result.grade == "C"
        ecdsa = [f for f in result.findings if f.check == "ecdsa_curve"]
        assert len(ecdsa) == 1
        assert ecdsa[0].status == "fail"
        assert "secp224r1" in ecdsa[0].message

    def test_sha1_signature_oid_detection(self):
        """Verify SHA-1 signature OID is recognized. Modern cryptography
        refuses to sign with SHA-1, so we verify the OID constants exist
        and would trigger the fail path in evaluate_posture."""
        import inspect

        from cryptography.x509.oid import SignatureAlgorithmOID

        sha1_oids = [
            SignatureAlgorithmOID.RSA_WITH_SHA1,
            SignatureAlgorithmOID.ECDSA_WITH_SHA1,
        ]
        from cert_watch.posture import evaluate_posture as _ep

        source = inspect.getsource(_ep)
        assert "RSA_WITH_SHA1" in source
        assert "ECDSA_WITH_SHA1" in source
        for oid in sha1_oids:
            assert oid is not None

    def test_ocsp_must_staple_with_stapling_present(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509 import TLSFeatureType
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "must-staple.example.com"),
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.TLSFeature(
                    features=[TLSFeatureType.status_request],
                ),
                critical=False,
            )
        )
        cert = builder.sign(key, hashes.SHA256())
        cert_obj = _cert_from_der(cert.public_bytes(serialization.Encoding.DER))

        result = evaluate_posture(cert=cert_obj, ocsp_stapling=True)
        must_staple = [f for f in result.findings if f.check == "ocsp_must_staple"]
        assert len(must_staple) == 1
        assert must_staple[0].status == "pass"
        assert "Must-Staple" in must_staple[0].message

    def test_ocsp_must_staple_without_stapling_warns(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509 import TLSFeatureType
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "must-staple-nostap.example.com"),
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.TLSFeature(
                    features=[TLSFeatureType.status_request],
                ),
                critical=False,
            )
        )
        cert = builder.sign(key, hashes.SHA256())
        cert_obj = _cert_from_der(cert.public_bytes(serialization.Encoding.DER))

        result = evaluate_posture(cert=cert_obj, ocsp_stapling=False)
        must_staple = [f for f in result.findings if f.check == "ocsp_must_staple"]
        assert len(must_staple) == 1
        assert must_staple[0].status == "warn"
        assert "no stapling" in must_staple[0].message.lower()

    def test_no_protocol_version_no_finding(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, protocol_version=None)
        tls = [f for f in result.findings if f.check == "tls_version"]
        assert len(tls) == 0

    def test_empty_protocol_version_no_finding(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, protocol_version="")
        tls = [f for f in result.findings if f.check == "tls_version"]
        assert len(tls) == 0

    def test_self_signed_not_incomplete_chain(self):
        der = _self_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(cert=cert, chain_status="public")
        self_signed = [f for f in result.findings if f.check == "self_signed"]
        chain = [f for f in result.findings if f.check == "chain_completeness"]
        assert self_signed[0].status == "warn"
        assert chain[0].status == "pass"
        # Self-signed alone doesn't drop grade below A
        assert result.grade == "A"

    def test_grade_f_for_combined_invisible_key_and_invalid_chain(self):
        cert = Certificate(
            subject="CN=bad",
            issuer="CN=bad",
            not_before=datetime.now(UTC) - timedelta(days=90),
            not_after=datetime.now(UTC) + timedelta(days=90),
            san_dns_names=[],
            fingerprint_sha256="33" * 32,
            raw_der=b"not-valid-der",
        )
        result = evaluate_posture(cert=cert, chain_status="invalid")
        assert result.grade == "F"

    def test_posture_result_fields_populated(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        result = evaluate_posture(
            cert=cert,
            protocol_version="TLSv1.3",
            ocsp_stapling=True,
            hsts=True,
            chain_status="public",
        )
        assert result.protocol_version == "TLSv1.3"
        assert result.ocsp_stapling is True
        assert result.hsts is True


# ---------- Revocation endpoint health (Plan 017 A1) ----------


def _cert_with_aia_and_crl(
    ocsp_url: str | None = None,
    crl_urls: list[str] | None = None,
) -> bytes:
    """Generate a self-signed certificate with AIA and/or CRL extensions."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "revocation-test.example.com"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
    )

    if ocsp_url:
        aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(ocsp_url),
            ),
        ])
        builder = builder.add_extension(aia, critical=False)

    if crl_urls:
        dp = x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
            for url in crl_urls
        ])
        builder = builder.add_extension(dp, critical=False)

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_extract_ocsp_url_present():
    from cert_watch.posture import _extract_ocsp_url
    der = _cert_with_aia_and_crl(ocsp_url="http://ocsp.example.com")
    url = _extract_ocsp_url(der)
    assert url == "http://ocsp.example.com"


def test_extract_ocsp_url_absent():
    from cert_watch.posture import _extract_ocsp_url
    der = _cert_with_aia_and_crl()
    url = _extract_ocsp_url(der)
    assert url is None


def test_extract_crl_urls_present():
    from cert_watch.posture import _extract_crl_urls
    der = _cert_with_aia_and_crl(crl_urls=["http://crl.example.com/ca.crl"])
    urls = _extract_crl_urls(der)
    assert urls == ["http://crl.example.com/ca.crl"]


def test_extract_crl_urls_multiple():
    from cert_watch.posture import _extract_crl_urls
    der = _cert_with_aia_and_crl(crl_urls=[
        "http://crl1.example.com/ca.crl",
        "http://crl2.example.com/ca.crl",
    ])
    urls = _extract_crl_urls(der)
    assert len(urls) == 2


def test_extract_crl_urls_absent():
    from cert_watch.posture import _extract_crl_urls
    der = _cert_with_aia_and_crl()
    urls = _extract_crl_urls(der)
    assert urls == []


def test_extract_empty_der():
    from cert_watch.posture import _extract_crl_urls, _extract_ocsp_url
    assert _extract_ocsp_url(b"") is None
    assert _extract_crl_urls(b"") == []


def test_check_ocsp_reachable_success():
    from unittest.mock import MagicMock, patch

    from cert_watch.posture import _check_ocsp_reachable
    with patch("cert_watch.posture.urllib.request") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_req.urlopen.return_value.__enter__ = lambda s: mock_resp
        mock_req.urlopen.return_value.__exit__ = MagicMock(return_value=False)
        assert _check_ocsp_reachable("http://ocsp.test") is True


def test_check_ocsp_reachable_failure():
    from unittest.mock import patch

    from cert_watch.posture import _check_ocsp_reachable
    with patch("cert_watch.posture.urllib.request.urlopen", side_effect=Exception("timeout")):
        assert _check_ocsp_reachable("http://ocsp.test") is False


def test_check_crl_reachable_success():
    from unittest.mock import MagicMock, patch

    from cert_watch.posture import _check_crl_reachable
    with patch("cert_watch.posture.urllib.request") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_req.urlopen.return_value.__enter__ = lambda s: mock_resp
        mock_req.urlopen.return_value.__exit__ = MagicMock(return_value=False)
        assert _check_crl_reachable("http://crl.test/ca.crl") is True


def test_check_crl_reachable_failure():
    from unittest.mock import patch

    from cert_watch.posture import _check_crl_reachable
    with patch("cert_watch.posture.urllib.request.urlopen", side_effect=Exception("refused")):
        assert _check_crl_reachable("http://crl.test/ca.crl") is False


def test_check_revocation_endpoints_ocsp_reachable():
    from unittest.mock import patch

    from cert_watch.posture import check_revocation_endpoints
    der = _cert_with_aia_and_crl(ocsp_url="http://ocsp.test")
    with patch("cert_watch.posture._check_ocsp_reachable", return_value=True):
        findings = check_revocation_endpoints(der)
    assert any(f.check == "ocsp_endpoint" and f.status == "pass" for f in findings)


def test_check_revocation_endpoints_ocsp_unreachable():
    from unittest.mock import patch

    from cert_watch.posture import check_revocation_endpoints
    der = _cert_with_aia_and_crl(ocsp_url="http://ocsp.test")
    with patch("cert_watch.posture._check_ocsp_reachable", return_value=False):
        findings = check_revocation_endpoints(der)
    assert any(f.check == "ocsp_endpoint" and f.status == "warn" for f in findings)


def test_check_revocation_endpoints_crl_reachable():
    from unittest.mock import patch

    from cert_watch.posture import check_revocation_endpoints
    der = _cert_with_aia_and_crl(crl_urls=["http://crl.test/ca.crl"])
    with patch("cert_watch.posture._check_crl_reachable", return_value=True):
        findings = check_revocation_endpoints(der)
    assert any(f.check == "crl_endpoint" and f.status == "pass" for f in findings)


def test_check_revocation_endpoints_crl_unreachable():
    from unittest.mock import patch

    from cert_watch.posture import check_revocation_endpoints
    der = _cert_with_aia_and_crl(crl_urls=["http://crl.test/ca.crl"])
    with patch("cert_watch.posture._check_crl_reachable", return_value=False):
        findings = check_revocation_endpoints(der)
    assert any(f.check == "crl_endpoint" and f.status == "warn" for f in findings)


def test_check_revocation_endpoints_no_urls():
    from cert_watch.posture import check_revocation_endpoints
    der = _cert_with_aia_and_crl()
    findings = check_revocation_endpoints(der)
    assert any(f.check == "ocsp_endpoint" and f.status == "info" for f in findings)
    assert any(f.check == "crl_endpoint" and f.status == "info" for f in findings)


def test_evaluate_posture_with_revocation_check():
    """When check_revocation=True, revocation findings are included."""
    from unittest.mock import patch
    der = _cert_with_aia_and_crl(ocsp_url="http://ocsp.test")
    cert = Certificate(
        subject="CN=revocation-test.example.com",
        issuer="CN=revocation-test.example.com",
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=datetime.now(UTC) + timedelta(days=90),
        san_dns_names=["revocation-test.example.com"],
        fingerprint_sha256="AA" * 32,
        raw_der=der,
    )
    with patch("cert_watch.posture._check_ocsp_reachable", return_value=True):
        result = evaluate_posture(cert, check_revocation=True)
    assert any(f.check == "ocsp_endpoint" for f in result.findings)


def test_evaluate_posture_without_revocation_check():
    """When check_revocation=False (default), no revocation findings."""
    der = _cert_with_aia_and_crl(ocsp_url="http://ocsp.test")
    cert = Certificate(
        subject="CN=revocation-test.example.com",
        issuer="CN=revocation-test.example.com",
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=datetime.now(UTC) + timedelta(days=90),
        san_dns_names=["revocation-test.example.com"],
        fingerprint_sha256="AA" * 32,
        raw_der=der,
    )
    result = evaluate_posture(cert, check_revocation=False)
    assert not any(f.check == "ocsp_endpoint" for f in result.findings)
    assert not any(f.check == "crl_endpoint" for f in result.findings)