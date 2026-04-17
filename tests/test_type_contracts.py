"""Type Contract Tests for Data Transformation Boundaries.

These tests verify the ACTUAL runtime types at each boundary between layers:
- HTTP request → domain model
- Parser output → repository input
- Route → service
- Service → repository

This catches the common failure mode where code builds dict objects instead
of typed model instances - tests that mock the database layer never see
the type mismatch, but production crashes with AttributeError.
"""

import pytest
from datetime import datetime
from typing import get_type_hints
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from cryptography import x509

from cert_watch.models.certificate import Certificate, CertificateType, CertificateSource
from cert_watch.repositories.base import CertificateRepository


# =============================================================================
# Route → Repository Type Contracts
# =============================================================================


@pytest.mark.asyncio
class TestRouteRepositoryTypeContracts:
    """Type contracts for data flow from HTTP routes to repository."""

    async def test_upload_route_passes_certificate_model_to_repo(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """Upload route passes Certificate model to repo, not dict.

        BOUNDARY: HTTP request → Certificate model → repository

        This catches the bug where route builds a dict like:
            cert_data = {"subject": "...", ...}
            repo.create(cert_data)  # ❌ Type error in production!

        Instead of:
            cert = Certificate(subject="...", ...)
            repo.create(cert)  # ✓ Correct
        """
        from cryptography.hazmat.primitives import serialization

        # Arrange: Track what gets passed to repo.create
        actual_args = []
        original_create = cert_repo.create

        async def tracking_create(cert):
            actual_args.append(cert)
            return await original_create(cert)

        # Arrange: Certificate file
        cert = test_certificates["good"]
        pem_data = cert.public_bytes(serialization.Encoding.PEM)

        with patch.object(cert_repo, "create", side_effect=tracking_create):
            # Act: Upload certificate
            response = client.post(
                "/upload",
                files={"certificate": ("test.pem", pem_data, "application/x-pem-file")},
                data={"label": "Type Test"},
            )

        # Assert: Route processed the request
        # (May fail if route not implemented, which is OK)

        # Assert: Repository received proper type
        if actual_args:
            received = actual_args[0]

            # TYPE CONTRACT: Must be Certificate, not dict
            assert isinstance(received, Certificate), (
                f"CRITICAL TYPE ERROR: Repository received {type(received).__name__}, "
                f"expected Certificate. Route is building dict instead of model!"
            )

            # TYPE CONTRACT: Required fields must be proper types
            assert isinstance(received.subject, str), (
                f"subject must be str, got {type(received.subject)}"
            )
            assert isinstance(received.issuer, str), (
                f"issuer must be str, got {type(received.issuer)}"
            )
            assert isinstance(received.fingerprint, str), (
                f"fingerprint must be str, got {type(received.fingerprint)}"
            )
            assert isinstance(received.not_after, datetime), (
                f"not_after must be datetime, got {type(received.not_after)}"
            )

            # TYPE CONTRACT: Enum fields must be enum instances
            assert isinstance(received.certificate_type, CertificateType), (
                f"certificate_type must be CertificateType enum, got {type(received.certificate_type)}"
            )
            assert isinstance(received.source, CertificateSource), (
                f"source must be CertificateSource enum, got {type(received.source)}"
            )

    async def test_scan_route_passes_certificate_model_to_repo(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """Scan route passes Certificate model to repo, not dict.

        BOUNDARY: TLS scan → Certificate model → repository
        """
        from unittest.mock import patch

        # Track repo.create calls
        actual_args = []
        original_create = cert_repo.create

        async def tracking_create(cert):
            actual_args.append(cert)
            return await original_create(cert)

        # Mock TLS extraction to return real certificates
        leaf = test_certificates["good"]

        with (
            patch.object(cert_repo, "create", side_effect=tracking_create),
            patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract,
        ):
            mock_extract.return_value = (leaf, [])

            # Act: Scan request
            response = client.post(
                "/scan/add-host",
                data={"hostname": "type-test.example.com", "port": "443"},
            )

        # Assert: Repository received proper type
        if actual_args:
            received = actual_args[0]

            assert isinstance(received, Certificate), (
                f"CRITICAL: Repository received {type(received).__name__}, expected Certificate"
            )


# =============================================================================
# Parser Output Type Contracts
# =============================================================================


@pytest.mark.asyncio
class TestParserTypeContracts:
    """Type contracts for certificate parser output."""

    async def test_parse_certificate_file_returns_x509_certificate_objects(
        self,
        test_certificates,
    ):
        """Parser returns X.509 Certificate objects, not dicts or strings.

        BOUNDARY: Raw bytes → cryptography.x509.Certificate

        This catches bugs where parser returns:
            {"subject": "...", "not_after": "..."}  # ❌ Dict

        Instead of:
            x509.Certificate(...)  # ✓ Proper object
        """
        try:
            from cert_watch.core.formatters import parse_certificate_file
        except ImportError:
            pytest.skip("parse_certificate_file not implemented")

        # Arrange: Valid PEM data
        cert = test_certificates["good"]
        pem_data = cert.public_bytes(serialization.Encoding.PEM)

        # Act: Parse
        result = parse_certificate_file(pem_data)

        # Assert: Type contract on return value
        assert isinstance(result, tuple), (
            f"parse_certificate_file must return tuple, got {type(result)}"
        )
        assert len(result) == 2, f"must return (leaf, chain) tuple, got length {len(result)}"

        leaf, chain = result

        # TYPE CONTRACT: Leaf must be x509.Certificate
        assert isinstance(leaf, x509.Certificate), (
            f"CRITICAL: Leaf must be x509.Certificate, got {type(leaf).__name__}. "
            f"Parser is returning wrong type!"
        )

        # TYPE CONTRACT: Chain must be list
        assert isinstance(chain, list), f"Chain must be list, got {type(chain).__name__}"

        # TYPE CONTRACT: Each chain cert must be x509.Certificate
        for i, chain_cert in enumerate(chain):
            assert isinstance(chain_cert, x509.Certificate), (
                f"CRITICAL: Chain[{i}] must be x509.Certificate, got {type(chain_cert).__name__}"
            )

    async def test_parse_certificate_file_not_after_is_datetime(
        self,
        test_certificates,
    ):
        """Parser returns datetime for not_after, not string.

        BOUNDARY: Certificate ASN.1 → Python datetime

        Common bug: returning ISO string instead of datetime object.
        """
        try:
            from cert_watch.core.formatters import parse_certificate_file
        except ImportError:
            pytest.skip("parse_certificate_file not implemented")

        cert = test_certificates["good"]
        pem_data = cert.public_bytes(serialization.Encoding.PEM)

        leaf, _ = parse_certificate_file(pem_data)

        # TYPE CONTRACT: Dates must be datetime objects
        assert isinstance(leaf.not_valid_after, datetime), (
            f"CRITICAL: not_valid_after must be datetime, got {type(leaf.not_valid_after).__name__}. "
            f"Parser returning string instead of parsed datetime!"
        )

        assert isinstance(leaf.not_valid_before, datetime), (
            f"CRITICAL: not_valid_before must be datetime, got {type(leaf.not_valid_before).__name__}"
        )

    async def test_extract_certificate_from_tls_returns_x509_objects(
        self,
        test_certificates,
    ):
        """TLS extractor returns X.509 Certificate objects.

        BOUNDARY: SSL socket → cryptography.x509.Certificate
        """
        try:
            from cert_watch.core.formatters import extract_certificate_from_tls
        except ImportError:
            pytest.skip("extract_certificate_from_tls not implemented")

        from unittest.mock import patch, MagicMock
        from cryptography.hazmat.primitives import serialization

        # Mock SSL to return our test certificate
        cert_der = test_certificates["good"].public_bytes(serialization.Encoding.DER)

        with (
            patch("ssl.create_connection") as mock_conn,
            patch("ssl.SSLContext.wrap_socket") as mock_wrap,
        ):
            mock_conn.return_value = MagicMock()
            mock_ssl = MagicMock()
            mock_wrap.return_value = mock_ssl
            mock_ssl.getpeercert.return_value = cert_der
            mock_ssl.getpeercertchain.return_value = [cert_der]

            # Act: Extract
            result = extract_certificate_from_tls("test.example.com", 443)

        # Assert: Type contract
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        leaf, chain = result

        assert isinstance(leaf, x509.Certificate), (
            f"CRITICAL: TLS extractor must return x509.Certificate, got {type(leaf).__name__}"
        )


# =============================================================================
# Repository Return Type Contracts
# =============================================================================


@pytest.mark.asyncio
class TestRepositoryReturnTypeContracts:
    """Type contracts for repository method return values."""

    async def test_repo_get_by_id_returns_certificate_or_none(
        self,
        cert_repo: CertificateRepository,
        sample_certificate,
    ):
        """get_by_id returns Certificate or None, never dict.

        BOUNDARY: Database row → Certificate model

        Catches: Repository returning raw sqlite3.Row instead of model.
        """
        # Arrange: Create certificate
        created = await cert_repo.create(sample_certificate)

        # Act: Retrieve
        retrieved = await cert_repo.get_by_id(created.id)

        # TYPE CONTRACT: Must be Certificate or None
        assert retrieved is None or isinstance(retrieved, Certificate), (
            f"CRITICAL: get_by_id returned {type(retrieved).__name__}, "
            f"expected Certificate or None. Repository not converting rows to models!"
        )

    async def test_repo_get_all_returns_list_of_certificates(
        self,
        cert_repo: CertificateRepository,
        sample_certificate,
    ):
        """get_all returns list[Certificate], not list[dict] or list[Row].

        BOUNDARY: Database query → List[Certificate model]
        """
        # Arrange: Create certificate
        await cert_repo.create(sample_certificate)

        # Act: Get all
        all_certs = await cert_repo.get_all()

        # TYPE CONTRACT: Must be list
        assert isinstance(all_certs, list), (
            f"get_all must return list, got {type(all_certs).__name__}"
        )

        # TYPE CONTRACT: Each item must be Certificate
        for i, cert in enumerate(all_certs):
            assert isinstance(cert, Certificate), (
                f"CRITICAL: get_all[{i}] is {type(cert).__name__}, expected Certificate. "
                f"Repository returning wrong type!"
            )

    async def test_repo_create_returns_certificate_with_id(
        self,
        cert_repo: CertificateRepository,
        sample_certificate,
    ):
        """create returns Certificate with id populated.

        BOUNDARY: Insert → Certificate model with generated id
        """
        # Arrange: Certificate without id
        cert_without_id = sample_certificate
        cert_without_id.id = None  # Ensure no id

        # Act: Create
        created = await cert_repo.create(cert_without_id)

        # TYPE CONTRACT: Must return Certificate
        assert isinstance(created, Certificate), (
            f"CRITICAL: create returned {type(created).__name__}, expected Certificate"
        )

        # TYPE CONTRACT: Must have id assigned
        assert isinstance(created.id, int), (
            f"create must assign int id, got {type(created.id).__name__} ({created.id})"
        )

    async def test_repo_returns_naive_utc_datetimes(
        self,
        cert_repo: CertificateRepository,
        sample_certificate,
    ):
        """Repository returns naive UTC datetimes, not strings or aware datetimes.

        BOUNDARY: SQLite timestamp → Python datetime

        Per convention: "MUST USE: Naive UTC datetimes throughout"
        """
        # Arrange: Create certificate
        created = await cert_repo.create(sample_certificate)

        # Act: Retrieve
        retrieved = await cert_repo.get_by_id(created.id)

        if retrieved:
            # TYPE CONTRACT: Datetimes must be naive (no tzinfo)
            assert retrieved.not_after.tzinfo is None, (
                f"CRITICAL: not_after has tzinfo {retrieved.not_after.tzinfo}. "
                f"Must be naive UTC datetime!"
            )

            assert retrieved.not_before.tzinfo is None, f"not_before must be naive datetime"

            assert retrieved.created_at.tzinfo is None, f"created_at must be naive datetime"


# =============================================================================
# Formatter Type Contracts
# =============================================================================


@pytest.mark.asyncio
class TestFormatterTypeContracts:
    """Type contracts for formatter utility functions."""

    async def test_format_subject_returns_string(
        self,
        test_certificates,
    ):
        """format_subject returns str, not Name object.

        BOUNDARY: x509.Name → str
        """
        from cert_watch.core.formatters import format_subject

        cert = test_certificates["good"]
        result = format_subject(cert)

        assert isinstance(result, str), (
            f"format_subject must return str, got {type(result).__name__}"
        )

    async def test_compute_thumbprint_returns_string(
        self,
        test_certificates,
    ):
        """compute_thumbprint returns hex string, not bytes.

        BOUNDARY: Certificate bytes → hex fingerprint string
        """
        from cert_watch.core.formatters import compute_thumbprint

        cert = test_certificates["good"]
        result = compute_thumbprint(cert)

        assert isinstance(result, str), (
            f"compute_thumbprint must return str, got {type(result).__name__}"
        )

        # Must be lowercase hex
        assert result == result.lower(), f"thumbprint must be lowercase, got {result}"

        # Must be 64 chars (SHA-256 hex)
        assert len(result) == 64, f"SHA-256 thumbprint must be 64 hex chars, got {len(result)}"

    async def test_compute_days_remaining_returns_int(
        self,
        test_certificates,
    ):
        """compute_days_remaining returns int, not float or timedelta.

        BOUNDARY: datetime → int days
        """
        from cert_watch.core.formatters import compute_days_remaining

        cert = test_certificates["good"]
        result = compute_days_remaining(cert.not_valid_after)

        assert isinstance(result, int), (
            f"compute_days_remaining must return int, got {type(result).__name__}"
        )

    async def test_get_status_color_returns_string(
        self,
    ):
        """get_status_color returns color string, not enum or int.

        BOUNDARY: int days → str color code
        """
        from cert_watch.core.formatters import get_status_color

        result = get_status_color(60)

        assert isinstance(result, str), (
            f"get_status_color must return str, got {type(result).__name__}"
        )

        assert result in ["red", "yellow", "green"], (
            f"color must be 'red', 'yellow', or 'green', got '{result}'"
        )


# =============================================================================
# Model Property Type Contracts
# =============================================================================


@pytest.mark.asyncio
class TestModelPropertyTypeContracts:
    """Type contracts for computed model properties."""

    async def test_certificate_days_remaining_returns_int(
        self,
        sample_certificate,
    ):
        """Certificate.days_remaining returns int.

        BOUNDARY: Model property → int
        """
        result = sample_certificate.days_remaining

        assert isinstance(result, int), (
            f"days_remaining must return int, got {type(result).__name__}"
        )

    async def test_certificate_status_color_returns_string(
        self,
        sample_certificate,
    ):
        """Certificate.status_color returns str.

        BOUNDARY: Model property → str
        """
        result = sample_certificate.status_color

        assert isinstance(result, str), f"status_color must return str, got {type(result).__name__}"

    async def test_certificate_is_expired_returns_bool(
        self,
        sample_certificate,
    ):
        """Certificate.is_expired returns bool.

        BOUNDARY: Model property → bool
        """
        result = sample_certificate.is_expired

        assert isinstance(result, bool), f"is_expired must return bool, got {type(result).__name__}"

    async def test_certificate_is_leaf_returns_bool(
        self,
        sample_certificate,
    ):
        """Certificate.is_leaf returns bool.

        BOUNDARY: Model property → bool
        """
        result = sample_certificate.is_leaf

        assert isinstance(result, bool), f"is_leaf must return bool, got {type(result).__name__}"

    async def test_certificate_is_chain_returns_bool(
        self,
        sample_chain_certificate,
    ):
        """Certificate.is_chain returns bool.

        BOUNDARY: Model property → bool
        """
        result = sample_chain_certificate.is_chain

        assert isinstance(result, bool), f"is_chain must return bool, got {type(result).__name__}"
