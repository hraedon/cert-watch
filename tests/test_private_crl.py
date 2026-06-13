"""Tests for private-trust CRL freshness checking (WI-042)."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from cert_watch.certificate_model import Certificate
from cert_watch.posture import (
    check_private_crl_freshness,
    evaluate_posture,
)


def _make_cert_der_with_cdp(cdp_url: str = "http://crl.example.com/ca.crl") -> bytes:
    """Build a minimal self-signed cert DER with a CRL distribution point."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-leaf.example.com"),
    ])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(cdp_url)],
                    relative_name=None, reasons=None, crl_issuer=None,
                ),
            ]),
            critical=False,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(Encoding.DER)


def _make_crl_der(
    *,
    next_update_days: int = 30,
    this_update_days_ago: int = 1,
    issuer_cn: str = "test-leaf.example.com",
    signing_key=None,
) -> bytes:
    """Build a minimal CRL DER. If signing_key is provided, use it; else generate one."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = signing_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    now = datetime.now(UTC)
    # Ensure this_update < next_update for the cryptography library
    this_update_offset = max(this_update_days_ago, abs(next_update_days) + 1)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - timedelta(days=this_update_offset))
        .next_update(now + timedelta(days=next_update_days))
    )
    crl = builder.sign(key, hashes.SHA256())
    return crl.public_bytes(Encoding.DER)


def _make_issuer_cert_der(cn: str = "test-leaf.example.com") -> tuple[bytes, object]:
    """Build a self-signed cert and return (DER, key) for CRL signing."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(Encoding.DER), key


class TestCheckPrivateCRLFreshness:
    def test_no_cdp_returns_warning(self):
        """Private cert without CDP should warn that CRL can't be checked."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-cdp.example.com")])
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        der = cert.public_bytes(Encoding.DER)
        findings = check_private_crl_freshness(der)
        assert len(findings) == 1
        assert findings[0].status == "warn"
        assert "no CRL distribution points" in findings[0].message

    def test_fresh_crl_passes(self):
        """CRL with future nextUpdate should produce a pass finding."""
        cert_der = _make_cert_der_with_cdp()
        crl_der = _make_crl_der(next_update_days=30)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = crl_der

        with patch("cert_watch.posture.ssrf_safe_urlopen", return_value=mock_resp):
            findings = check_private_crl_freshness(cert_der)
        statuses = {f.status for f in findings}
        assert "pass" in statuses
        assert all("expired" not in f.message for f in findings if f.status == "warn")

    def test_expired_crl_warns(self):
        """CRL past nextUpdate should produce a warning."""
        cert_der = _make_cert_der_with_cdp()
        crl_der = _make_crl_der(next_update_days=-5)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = crl_der

        with patch("cert_watch.posture.ssrf_safe_urlopen", return_value=mock_resp):
            findings = check_private_crl_freshness(cert_der)
        assert any("expired" in f.message and f.status == "warn" for f in findings)

    def test_stale_publication_warns(self):
        """CRL with thisUpdate > 30 days ago should warn about stale publication."""
        cert_der = _make_cert_der_with_cdp()
        crl_der = _make_crl_der(
            next_update_days=30, this_update_days_ago=45,
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = crl_der

        with patch("cert_watch.posture.ssrf_safe_urlopen", return_value=mock_resp):
            findings = check_private_crl_freshness(cert_der)
        assert any("not published" in f.message and f.status == "warn" for f in findings)

    def test_unreachable_crl_endpoint_warns(self):
        """Unreachable CRL endpoint should produce a warning."""
        cert_der = _make_cert_der_with_cdp()

        with patch("cert_watch.posture.ssrf_safe_urlopen", side_effect=Exception("timeout")):
            findings = check_private_crl_freshness(cert_der)
        assert any("unreachable" in f.message for f in findings)

    def test_ssrf_blocked_warns(self):
        """SSRF-blocked CRL endpoint should produce a clear warning."""
        from cert_watch.http_client import SSRFBlockedError

        cert_der = _make_cert_der_with_cdp()

        with patch(
            "cert_watch.posture.ssrf_safe_urlopen",
            side_effect=SSRFBlockedError("blocked IP: 127.0.0.1"),
        ):
            findings = check_private_crl_freshness(cert_der)
        assert any("SSRF" in f.message for f in findings)

    def test_signature_valid_with_matching_issuer(self):
        """CRL signed by the matching issuer key → no signature warning."""
        cert_der = _make_cert_der_with_cdp()
        issuer_der, issuer_key = _make_issuer_cert_der()
        crl_der = _make_crl_der(next_update_days=30, signing_key=issuer_key)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = crl_der

        with patch("cert_watch.posture.ssrf_safe_urlopen", return_value=mock_resp):
            findings = check_private_crl_freshness(cert_der, issuer_der=issuer_der)
        assert not any("signature does not match" in f.message for f in findings)

    def test_signature_mismatch_with_wrong_issuer(self):
        """CRL signed by a different key than the issuer → signature warning."""
        cert_der = _make_cert_der_with_cdp()
        # issuer cert has a different key than the one that signed the CRL
        issuer_der, _ = _make_issuer_cert_der(cn="different-ca")
        crl_der = _make_crl_der(next_update_days=30, issuer_cn="actual-ca")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = crl_der

        with patch("cert_watch.posture.ssrf_safe_urlopen", return_value=mock_resp):
            findings = check_private_crl_freshness(cert_der, issuer_der=issuer_der)
        assert any("signature does not match" in f.message for f in findings)


class TestEvaluatePosturePrivateCRL:
    def test_private_chain_triggers_crl_check(self):
        """evaluate_posture with chain_status='private' auto-checks CRL."""
        cert_der = _make_cert_der_with_cdp()
        cert = Certificate(
            subject="CN=test-leaf",
            issuer="CN=test-leaf.example.com",
            not_before=datetime.now(UTC) - timedelta(days=1),
            not_after=datetime.now(UTC) + timedelta(days=365),
            san_dns_names=[],
            fingerprint_sha256="abc",
            raw_der=cert_der,
        )
        crl_der = _make_crl_der(next_update_days=30)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = crl_der

        with patch("cert_watch.posture.ssrf_safe_urlopen", return_value=mock_resp):
            result = evaluate_posture(cert, chain_status="private")

        crl_findings = [f for f in result.findings if f.check == "private_crl"]
        assert len(crl_findings) > 0
        assert any(f.status == "pass" for f in crl_findings)

    def test_public_chain_does_not_trigger_crl_check(self):
        """evaluate_posture with chain_status='public' does NOT check CRL."""
        cert_der = _make_cert_der_with_cdp()
        cert = Certificate(
            subject="CN=test-leaf",
            issuer="CN=test-ca",
            not_before=datetime.now(UTC) - timedelta(days=1),
            not_after=datetime.now(UTC) + timedelta(days=365),
            san_dns_names=[],
            fingerprint_sha256="abc",
            raw_der=cert_der,
        )

        with patch("cert_watch.posture.ssrf_safe_urlopen") as mock:
            result = evaluate_posture(cert, chain_status="public")

        mock.assert_not_called()
        crl_findings = [f for f in result.findings if f.check == "private_crl"]
        assert len(crl_findings) == 0
