"""Test configuration and fixtures for cert-watch.

This module provides comprehensive fixtures for all FR-01, FR-02, FR-03 tests.
"""

import tempfile
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from cert_watch.core.config import Settings

# Import models
from cert_watch.models.alert import Alert, AlertStatus, AlertType
from cert_watch.models.certificate import Certificate, CertificateSource, CertificateType
from cert_watch.models.scan_history import ScanHistory, ScanStatus
from cert_watch.repositories.base import (
    AlertRepository,
    CertificateRepository,
    ScanHistoryRepository,
)
from cert_watch.repositories.sqlite import (
    SQLiteAlertRepository,
    SQLiteCertificateRepository,
    SQLiteConnectionPool,
    SQLiteScanHistoryRepository,
)
from cert_watch.web.app_factory import create_app

# =============================================================================
# Settings Fixtures
# =============================================================================


@pytest.fixture
def settings():
    """Create test settings with temporary database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        yield Settings(
            database_url=f"sqlite:///{db_path}",
            debug=True,
            smtp_host="localhost",
            smtp_port=1025,
            smtp_user="test@test.com",
            smtp_password="testpass",
            smtp_from_addr="alerts@test.com",
            alert_recipients=["admin@test.com", "ops@test.com"],
        )


# =============================================================================
# Database and Repository Fixtures (Real SQLite)
# =============================================================================


@pytest_asyncio.fixture
async def db_pool(settings) -> AsyncGenerator[SQLiteConnectionPool, None]:
    """Create a real SQLite connection pool for testing.

    This fixture provides a REAL database connection pool using aiosqlite.
    Tests using this fixture perform actual database operations.
    """
    pool = SQLiteConnectionPool(settings.database_path)
    yield pool
    # Cleanup - close any connections


@pytest_asyncio.fixture
async def cert_repo(db_pool) -> AsyncGenerator[CertificateRepository, None]:
    """Create a real CertificateRepository using SQLite.

    This fixture provides the ACTUAL repository implementation,
    not a mock. Tests using this verify real database behavior.
    """
    repo = SQLiteCertificateRepository(db_pool)
    yield repo


@pytest_asyncio.fixture
async def alert_repo(db_pool) -> AsyncGenerator[AlertRepository, None]:
    """Create a real AlertRepository using SQLite."""
    repo = SQLiteAlertRepository(db_pool)
    yield repo


@pytest_asyncio.fixture
async def scan_repo(db_pool) -> AsyncGenerator[ScanHistoryRepository, None]:
    """Create a real ScanHistoryRepository using SQLite."""
    repo = SQLiteScanHistoryRepository(db_pool)
    yield repo


# =============================================================================
# Certificate Fixtures (Real X.509 Certificates)
# =============================================================================


def _generate_test_certificate(
    subject_cn: str,
    issuer_cn: str,
    not_before: datetime,
    not_after: datetime,
    is_ca: bool = False,
    serial_number: int = None,
) -> x509.Certificate:
    """Generate a test X.509 certificate using cryptography library."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Build subject and issuer
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
        ]
    )

    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    builder = builder.serial_number(serial_number or int(not_before.timestamp()))
    builder = builder.public_key(private_key.public_key())

    # Add basic constraints
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None),
        critical=True,
    )

    # Self-sign (for test purposes)
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    return certificate


@pytest.fixture
def test_certificates():
    """Generate a set of test X.509 certificates with various expiry dates.

    Returns a dict with:
        - expired: Certificate expired 10 days ago
        - critical: Expires in 3 days (red status)
        - warning: Expires in 15 days (yellow status)
        - good: Expires in 60 days (green status)
        - root_ca: Root CA certificate
        - intermediate: Intermediate CA certificate
    """
    now = datetime.utcnow()

    certs = {}

    # Expired certificate (10 days ago)
    certs["expired"] = _generate_test_certificate(
        subject_cn="expired.example.com",
        issuer_cn="Test CA",
        not_before=now - timedelta(days=365),
        not_after=now - timedelta(days=10),
    )

    # Critical - expires in 3 days (red)
    certs["critical"] = _generate_test_certificate(
        subject_cn="critical.example.com",
        issuer_cn="Test CA",
        not_before=now - timedelta(days=90),
        not_after=now + timedelta(days=3),
    )

    # Warning - expires in 15 days (yellow)
    certs["warning"] = _generate_test_certificate(
        subject_cn="warning.example.com",
        issuer_cn="Test CA",
        not_before=now - timedelta(days=90),
        not_after=now + timedelta(days=15),
    )

    # Good - expires in 60 days (green)
    certs["good"] = _generate_test_certificate(
        subject_cn="good.example.com",
        issuer_cn="Test CA",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=60),
    )

    # Borderline - expires in 7 days (red boundary)
    certs["red_boundary"] = _generate_test_certificate(
        subject_cn="red-boundary.example.com",
        issuer_cn="Test CA",
        not_before=now - timedelta(days=90),
        not_after=now + timedelta(days=7),
    )

    # Borderline - expires in 30 days (yellow boundary)
    certs["yellow_boundary"] = _generate_test_certificate(
        subject_cn="yellow-boundary.example.com",
        issuer_cn="Test CA",
        not_before=now - timedelta(days=90),
        not_after=now + timedelta(days=30),
    )

    # Root CA
    certs["root_ca"] = _generate_test_certificate(
        subject_cn="Test Root CA",
        issuer_cn="Test Root CA",
        not_before=now - timedelta(days=3650),
        not_after=now + timedelta(days=3650),
        is_ca=True,
        serial_number=1,
    )

    # Intermediate CA
    certs["intermediate"] = _generate_test_certificate(
        subject_cn="Test Intermediate CA",
        issuer_cn="Test Root CA",
        not_before=now - timedelta(days=1825),
        not_after=now + timedelta(days=1825),
        is_ca=True,
        serial_number=2,
    )

    return certs


@pytest.fixture
def test_certificate_files(test_certificates, tmp_path) -> dict:
    """Create certificate files in various formats.

    Returns a dict with file paths for:
        - pem: PEM-encoded certificate
        - cer: DER-encoded certificate (.cer)
        - crt: PEM-encoded certificate (.crt)
        - pem_with_chain: PEM file with certificate + chain
    """
    files = {}

    # Single certificate PEM
    pem_path = tmp_path / "test.pem"
    pem_path.write_bytes(test_certificates["good"].public_bytes(serialization.Encoding.PEM))
    files["pem"] = str(pem_path)

    # DER format (.cer)
    cer_path = tmp_path / "test.cer"
    cer_path.write_bytes(test_certificates["good"].public_bytes(serialization.Encoding.DER))
    files["cer"] = str(cer_path)

    # .crt file (PEM)
    crt_path = tmp_path / "test.crt"
    crt_path.write_bytes(test_certificates["good"].public_bytes(serialization.Encoding.PEM))
    files["crt"] = str(crt_path)

    # Certificate with chain
    chain_path = tmp_path / "chain.pem"
    chain_data = b""
    chain_data += test_certificates["good"].public_bytes(serialization.Encoding.PEM)
    chain_data += test_certificates["intermediate"].public_bytes(serialization.Encoding.PEM)
    chain_data += test_certificates["root_ca"].public_bytes(serialization.Encoding.PEM)
    chain_path.write_bytes(chain_data)
    files["pem_with_chain"] = str(chain_path)

    # Invalid file
    invalid_path = tmp_path / "invalid.txt"
    invalid_path.write_text("This is not a certificate")
    files["invalid"] = str(invalid_path)

    return files


# =============================================================================
# Model Instance Fixtures
# =============================================================================


@pytest.fixture
def sample_certificate():
    """Create a sample Certificate model instance."""
    now = datetime.utcnow()
    return Certificate(
        id=1,
        certificate_type=CertificateType.LEAF,
        source=CertificateSource.SCANNED,
        hostname="test.example.com",
        port=443,
        label="Test Certificate",
        subject="CN=test.example.com,O=Test Org",
        issuer="CN=Test CA,O=Test CA Org",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=60),
        fingerprint="aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd",
        serial_number="1234567890",
        chain_position=0,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def sample_chain_certificate():
    """Create a sample chain Certificate model instance."""
    now = datetime.utcnow()
    return Certificate(
        id=2,
        certificate_type=CertificateType.INTERMEDIATE,
        source=CertificateSource.SCANNED,
        hostname=None,
        port=None,
        label=None,
        subject="CN=Test Intermediate CA,O=Test CA",
        issuer="CN=Test Root CA,O=Test Root",
        not_before=now - timedelta(days=1825),
        not_after=now + timedelta(days=1825),
        fingerprint="11223344aabbccdd55667788990011223344aabbccdd55667788990011223344",
        serial_number="987654321",
        chain_fingerprint="aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd",
        chain_position=1,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def sample_alert():
    """Create a sample Alert model instance."""
    return Alert(
        id=1,
        certificate_id=1,
        alert_type=AlertType.EXPIRY_WARNING,
        days_remaining=5,
        status=AlertStatus.PENDING,
        recipient="admin@test.com",
        subject="Certificate Expiry Warning",
        body="Certificate expires in 5 days",
    )


@pytest.fixture
def sample_scan_history():
    """Create a sample ScanHistory model instance."""
    now = datetime.utcnow()
    return ScanHistory(
        id=1,
        started_at=now,
        completed_at=now + timedelta(seconds=10),
        status=ScanStatus.SUCCESS,
        total_hosts=5,
        successful_hosts=5,
        failed_hosts=0,
        updated_certificates=5,
    )


# =============================================================================
# Application Fixtures
# =============================================================================


@pytest.fixture
def app(settings):
    """Create test FastAPI application."""
    return create_app(settings)


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@pytest_asyncio.fixture
async def async_client(app):
    """Create async test client for async route testing."""
    from httpx import AsyncClient

    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


# =============================================================================
# Mock Fixtures for External Dependencies
# =============================================================================


@pytest.fixture
def mock_smtp():
    """Mock SMTP connection for email tests."""
    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_instance = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_instance)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)
        yield mock_instance


@pytest.fixture
def mock_tls_connection():
    """Mock TLS connection for scanning tests.

    Yields a context manager that patches ssl.create_connection and
    ssl.SSLContext.wrap_socket to return mock certificates.
    """
    with (
        patch("ssl.create_connection") as mock_create_conn,
        patch("ssl.SSLContext.wrap_socket") as mock_wrap,
    ):
        mock_sock = MagicMock()
        mock_create_conn.return_value = mock_sock

        mock_ssl_sock = MagicMock()
        mock_wrap.return_value = mock_ssl_sock
        mock_ssl_sock.getpeercert.return_value = {
            "subject": (("commonName", "test.example.com"),),
            "issuer": (("commonName", "Test CA"),),
            "notBefore": "Jan 1 00:00:00 2024 GMT",
            "notAfter": "Jan 1 00:00:00 2025 GMT",
            "serialNumber": "1234567890",
        }
        mock_ssl_sock.getpeercertchain.return_value = [
            mock_ssl_sock.getpeercert.return_value,
            {
                "subject": (("commonName", "Test CA"),),
                "issuer": (("commonName", "Test Root CA"),),
                "notBefore": "Jan 1 00:00:00 2020 GMT",
                "notAfter": "Jan 1 00:00:00 2030 GMT",
                "serialNumber": "987654321",
            },
        ]

        yield {
            "create_connection": mock_create_conn,
            "wrap_socket": mock_wrap,
            "sock": mock_sock,
            "ssl_sock": mock_ssl_sock,
        }


# =============================================================================
# Helper Functions
# =============================================================================


def cert_to_model(cert: x509.Certificate, **kwargs) -> Certificate:
    """Convert an X.509 certificate to a Certificate model."""
    from cert_watch.core.formatters import compute_thumbprint, format_issuer, format_subject

    now = datetime.utcnow()
    return Certificate(
        subject=format_subject(cert),
        issuer=format_issuer(cert),
        not_before=cert.not_valid_before,
        not_after=cert.not_valid_after,
        fingerprint=compute_thumbprint(cert),
        serial_number=str(cert.serial_number),
        pem_data=cert.public_bytes(serialization.Encoding.PEM),
        created_at=now,
        updated_at=now,
        **kwargs,
    )


@pytest.fixture
def populated_repo(cert_repo, test_certificates):
    """Create a certificate repository populated with test data.

    Returns the repository with several certificates already inserted.
    """

    async def _populate():
        # Add various certificates
        for name in ["critical", "warning", "good", "expired"]:
            cert = test_certificates[name]
            model = cert_to_model(
                cert,
                certificate_type=CertificateType.LEAF,
                source=CertificateSource.SCANNED,
                hostname=f"{name}.example.com",
                port=443,
            )
            await cert_repo.create(model)
        return cert_repo

    # Return a coroutine that the test can await
    return _populate
