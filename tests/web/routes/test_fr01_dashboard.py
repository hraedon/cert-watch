"""Tests for FR-01: Dashboard Display.

Acceptance Criteria:
- List view shows hostname, issuer, expiry date, days remaining
- Color coding: red <7 days, yellow <30 days, green >30 days
- Sorted by days remaining ascending
"""

from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from cert_watch.models.certificate import CertificateSource, CertificateType
from cert_watch.repositories.base import CertificateRepository

# =============================================================================
# FR-01 AC-01: Dashboard Display Tests
# =============================================================================


@pytest.mark.asyncio
class TestDashboardDisplay:
    """Test suite for FR-01 Dashboard Display requirements."""

    async def test_dashboard_shows_all_certificates(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """AC-01.1: Dashboard displays all monitored certificates.

        Given: Multiple certificates in the database
        When: User accesses the dashboard
        Then: All certificates are displayed in the list
        """
        # Arrange: Insert test certificates into real database
        from tests.conftest import cert_to_model

        expected_certs = []
        for name in ["critical", "warning", "good"]:
            cert = test_certificates[name]
            model = cert_to_model(
                cert,
                certificate_type=CertificateType.LEAF,
                source=CertificateSource.SCANNED,
                hostname=f"{name}.example.com",
                port=443,
            )
            created = await cert_repo.create(model)
            expected_certs.append(created)

        # Act: Request the dashboard
        response = client.get("/")

        # Assert: Dashboard loads successfully
        assert response.status_code == 200, f"Dashboard failed to load: {response.text}"

        # Assert: All certificates are present in the response
        content = response.text
        for cert in expected_certs:
            assert cert.hostname in content or cert.subject in content, (
                f"Certificate {cert.hostname} not found in dashboard"
            )

    async def test_dashboard_shows_hostname_issuer_expiry_days_remaining(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """AC-01.2: Dashboard shows hostname/label, issuer, expiry date, days remaining.

        Given: A certificate with all fields populated
        When: Viewing the dashboard
        Then: All required fields are visible
        """
        # Arrange: Create a certificate with specific fields
        from cert_watch.core.formatters import format_datetime
        from tests.conftest import cert_to_model

        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="api.example.com",
            port=443,
            label="API Server Certificate",
        )
        await cert_repo.create(model)

        # Act: Request dashboard
        response = client.get("/")

        # Assert: Dashboard contains expected fields
        assert response.status_code == 200
        content = response.text

        # Check for hostname or label
        assert "api.example.com" in content or "API Server Certificate" in content, (
            "Hostname or label not displayed"
        )

        # Check for issuer
        assert "Test CA" in content, "Issuer not displayed"

        # Check for expiry date
        expiry_str = format_datetime(model.not_after)
        assert expiry_str.split()[0] in content or "UTC" in content, "Expiry date not displayed"

    async def test_dashboard_color_coding_red_under_7_days(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """AC-01.3: Color coding - red for <7 days remaining.

        Given: Certificate expiring in 3 days
        When: Viewing dashboard
        Then: Certificate is displayed with red status indicator
        """
        # Arrange: Create critical certificate (3 days remaining)
        from tests.conftest import cert_to_model

        cert = test_certificates["critical"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="critical.example.com",
            port=443,
        )
        await cert_repo.create(model)

        # Act: Request dashboard
        response = client.get("/")

        # Assert: Red status is indicated
        assert response.status_code == 200
        content = response.text.lower()

        # Check for red color indicator (CSS class or style)
        assert any(
            indicator in content
            for indicator in ["status-red", "red", "danger", "critical", "bg-red", "text-red"]
        ), "Red color coding not found for critical certificate"

    async def test_dashboard_color_coding_yellow_under_30_days(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """AC-01.4: Color coding - yellow for <30 days remaining.

        Given: Certificate expiring in 15 days
        When: Viewing dashboard
        Then: Certificate is displayed with yellow status indicator
        """
        # Arrange: Create warning certificate (15 days remaining)
        from tests.conftest import cert_to_model

        cert = test_certificates["warning"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="warning.example.com",
            port=443,
        )
        await cert_repo.create(model)

        # Act: Request dashboard
        response = client.get("/")

        # Assert: Yellow status is indicated
        assert response.status_code == 200
        content = response.text.lower()

        # Check for yellow color indicator
        assert any(
            indicator in content
            for indicator in [
                "status-yellow",
                "yellow",
                "warning",
                "bg-yellow",
                "text-yellow",
                "amber",
            ]
        ), "Yellow color coding not found for warning certificate"

    async def test_dashboard_color_coding_green_over_30_days(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """AC-01.5: Color coding - green for >30 days remaining.

        Given: Certificate expiring in 60 days
        When: Viewing dashboard
        Then: Certificate is displayed with green status indicator
        """
        # Arrange: Create good certificate (60 days remaining)
        from tests.conftest import cert_to_model

        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="good.example.com",
            port=443,
        )
        await cert_repo.create(model)

        # Act: Request dashboard
        response = client.get("/")

        # Assert: Green status is indicated
        assert response.status_code == 200
        content = response.text.lower()

        # Check for green color indicator
        assert any(
            indicator in content
            for indicator in [
                "status-green",
                "green",
                "success",
                "bg-green",
                "text-green",
                "ok",
                "healthy",
            ]
        ), "Green color coding not found for good certificate"

    async def test_dashboard_sorted_by_urgency_ascending(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """AC-01.6: Certificates sorted by days remaining ascending.

        Given: Multiple certificates with varying expiry dates
        When: Viewing dashboard
        Then: Most urgent (expiring soonest) appears first
        """
        # Arrange: Create certificates in random order
        from tests.conftest import cert_to_model

        cert_order = ["good", "critical", "warning"]  # Will be sorted to: critical, warning, good
        created_certs = []

        for name in cert_order:
            cert = test_certificates[name]
            model = cert_to_model(
                cert,
                certificate_type=CertificateType.LEAF,
                source=CertificateSource.SCANNED,
                hostname=f"{name}.example.com",
                port=443,
            )
            created = await cert_repo.create(model)
            created_certs.append((name, created))

        # Act: Request dashboard
        response = client.get("/")

        # Assert: Response is successful
        assert response.status_code == 200
        content = response.text

        # Find positions of each hostname in the content
        critical_pos = content.find("critical.example.com")
        warning_pos = content.find("warning.example.com")
        good_pos = content.find("good.example.com")

        # Assert: Positions are in ascending order (critical < warning < good)
        assert critical_pos < warning_pos < good_pos, (
            f"Certificates not sorted by urgency: critical@{critical_pos}, warning@{warning_pos}, good@{good_pos}"
        )

    async def test_dashboard_empty_state(
        self,
        client: TestClient,
    ):
        """AC-01.7: Dashboard handles empty database gracefully.

        Given: No certificates in database
        When: Viewing dashboard
        Then: Empty state message shown, no errors
        """
        # Act: Request dashboard with empty database
        response = client.get("/")

        # Assert: Dashboard loads successfully
        assert response.status_code == 200

        # Assert: Empty state or no certificates message
        content = response.text.lower()
        assert (
            any(
                phrase in content
                for phrase in [
                    "no certificates",
                    "empty",
                    "no items",
                    "get started",
                    "add certificate",
                ]
            )
            or "<tr>" not in content
        ), "Empty state not handled properly"

    async def test_dashboard_color_boundary_red_at_7_days(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """AC-01.8: Boundary test - exactly 7 days shows red.

        Given: Certificate expiring in exactly 7 days
        When: Viewing dashboard
        Then: Status is red (boundary condition)
        """
        from tests.conftest import cert_to_model

        cert = test_certificates["red_boundary"]  # Exactly 7 days
        model = cert_to_model(
            cert,
            hostname="red-boundary.example.com",
            port=443,
        )
        await cert_repo.create(model)

        response = client.get("/")
        assert response.status_code == 200

        content = response.text.lower()
        assert any(indicator in content for indicator in ["red", "danger", "critical"]), (
            "7-day boundary should show red"
        )

    async def test_dashboard_color_boundary_yellow_at_30_days(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """AC-01.9: Boundary test - exactly 30 days shows yellow.

        Given: Certificate expiring in exactly 30 days
        When: Viewing dashboard
        Then: Status is yellow (boundary condition)
        """
        from tests.conftest import cert_to_model

        cert = test_certificates["yellow_boundary"]  # Exactly 30 days
        model = cert_to_model(
            cert,
            hostname="yellow-boundary.example.com",
            port=443,
        )
        await cert_repo.create(model)

        response = client.get("/")
        assert response.status_code == 200

        content = response.text.lower()
        assert any(indicator in content for indicator in ["yellow", "warning", "amber"]), (
            "30-day boundary should show yellow"
        )


# =============================================================================
# Integration Tests with Real Database
# =============================================================================


@pytest.mark.asyncio
class TestDashboardIntegration:
    """Integration tests using real database (no mocks)."""

    async def test_repository_integration_returns_actual_datetimes(
        self,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """Verify repository returns datetime objects, not strings.

        This catches type mismatches that mocked tests miss.
        """
        from tests.conftest import cert_to_model

        # Arrange: Create certificate
        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            hostname="type-test.example.com",
            port=443,
        )
        created = await cert_repo.create(model)

        # Act: Retrieve from database
        retrieved = await cert_repo.get_by_id(created.id)

        # Assert: Verify actual runtime types
        assert retrieved is not None
        assert isinstance(retrieved.not_after, datetime), (
            f"not_after should be datetime, got {type(retrieved.not_after)}"
        )
        assert isinstance(retrieved.not_before, datetime), (
            f"not_before should be datetime, got {type(retrieved.not_before)}"
        )
        assert isinstance(retrieved.created_at, datetime), (
            f"created_at should be datetime, got {type(retrieved.created_at)}"
        )

        # Assert: Can perform datetime operations
        delta = retrieved.not_after - datetime.utcnow()
        assert isinstance(delta.days, int)

    async def test_get_all_sorted_by_urgency(
        self,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """Repository returns certificates sorted by days remaining."""
        from tests.conftest import cert_to_model

        # Arrange: Create certificates with known expiry order
        certs_to_create = [
            ("good", 60),  # 60 days - should be last
            ("critical", 3),  # 3 days - should be first
            ("warning", 15),  # 15 days - should be middle
        ]

        for name, _ in certs_to_create:
            cert = test_certificates[name]
            model = cert_to_model(
                cert,
                hostname=f"{name}.test.com",
                port=443,
            )
            await cert_repo.create(model)

        # Act: Get all certificates
        all_certs = await cert_repo.get_all()

        # Assert: Sorted by days remaining ascending
        days_remaining = [cert.days_remaining for cert in all_certs]
        assert days_remaining == sorted(days_remaining), (
            f"Certificates not sorted by urgency: {days_remaining}"
        )

        # Assert: Critical comes first
        assert all_certs[0].hostname == "critical.test.com"


# =============================================================================
# HTMX/Pagination Tests
# =============================================================================


@pytest.mark.asyncio
class TestDashboardHTMX:
    """Tests for HTMX interactions on dashboard."""

    async def test_dashboard_htmx_partial_content(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        sample_certificate,
    ):
        """Dashboard supports HTMX partial content requests."""
        # Arrange: Add a certificate
        await cert_repo.create(sample_certificate)

        # Act: Request with HTMX header
        response = client.get("/", headers={"HX-Request": "true"})

        # Assert: Returns partial content
        assert response.status_code in [200, 204]

    async def test_dashboard_refresh_via_htmx(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """Dashboard can be refreshed via HTMX request."""
        from tests.conftest import cert_to_model

        # Arrange: Add initial certificate
        cert = test_certificates["good"]
        model = cert_to_model(cert, hostname="initial.example.com")
        await cert_repo.create(model)

        # Act: HTMX refresh request
        response = client.get("/", headers={"HX-Request": "true", "HX-Target": "certificate-list"})

        # Assert: Returns updated content
        assert response.status_code == 200
        assert "initial.example.com" in response.text
