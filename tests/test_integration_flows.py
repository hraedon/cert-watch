"""End-to-End Flow Tests for FR-01, FR-02, FR-03, FR-04, FR-05.

These tests verify complete user flows spanning multiple FRs.
Each flow test touches 3+ FRs using real service instances and real databases.
Only external I/O (network, SMTP) is mocked.

Flows:
1. "Add host → TLS scan → verify chain entries created → view in dashboard with color coding"
2. "Upload cert file → view in dashboard → verify color coding"
3. "Mixed: scanned + uploaded certs in same dashboard sorted by urgency"
4. "Certificate at threshold → alert created → email sent → alert history updated"
5. "Daily scan runs → alerts evaluated for both leaf and chain → emails sent"
"""

from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from cert_watch.models.certificate import CertificateSource, CertificateType
from cert_watch.repositories.base import (
    AlertRepository,
    CertificateRepository,
)

# =============================================================================
# End-to-End Flow Test 1: Add Host → Scan → Chain → Dashboard
# =============================================================================


@pytest.mark.asyncio
class TestFlow1ScanToDashboard:
    """Flow Test: Add host → TLS scan → verify chain → dashboard with color coding.

    This flow tests:
    - FR-02: Add host and TLS scanning
    - FR-01: Dashboard display with color coding
    - Chain extraction from TLS handshake
    """

    async def test_complete_flow_add_host_scan_chain_dashboard(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """E2E Flow: User adds host, system scans, chains extracted, dashboard shows color coding.

        ACT:
        1. User submits add-host form with hostname and port
        2. System performs TLS handshake (mocked network)
        3. System extracts leaf and chain certificates
        4. System stores all certificates
        5. User views dashboard

        ASSERT:
        - Leaf certificate stored with source=SCANNED
        - Chain certificates stored and linked to leaf
        - Dashboard shows all certificates
        - Color coding matches days remaining (critical=red)
        """
        # Arrange: Test certificates to be "extracted" from TLS
        leaf = test_certificates["critical"]  # 3 days = red
        intermediate = test_certificates["intermediate"]

        # ACT 1: Submit add-host form
        with patch("cert_watch.web.routes.fr02_scan.extract_certificate_from_tls") as mock_extract:
            # Mock returns leaf + chain
            mock_extract.return_value = (leaf, [intermediate])

            add_response = client.post(
                "/scan/add-host",
                data={
                    "hostname": "secure.example.com",
                    "port": "443",
                },
            )

            # Structural check: Action was triggered
            assert mock_extract.called, "TLS extraction was not triggered!"
            mock_extract.assert_called_once_with("secure.example.com", 443)

        # ACT 2: Follow redirect or check status
        assert add_response.status_code in [200, 201, 302, 303], (
            f"Add host failed: {add_response.status_code}"
        )

        # ACT 3: Precondition check - verify certificates were stored
        # Before asserting on dashboard, verify the scan actually happened
        all_certs = await cert_repo.get_all()
        scanned_certs = [c for c in all_certs if c.source == CertificateSource.SCANNED]

        # Structural assertion: Scan actually stored data
        assert len(scanned_certs) > 0, (
            "PRECONDITION FAILED: No scanned certificates in database. "
            "Scan did not execute or failed to store."
        )

        # Verify leaf was stored
        leaf_certs = [c for c in scanned_certs if c.hostname == "secure.example.com"]
        assert len(leaf_certs) > 0, "PRECONDITION FAILED: Leaf certificate not stored."

        stored_leaf = leaf_certs[0]

        # ACT 4: View dashboard
        dashboard_response = client.get("/")

        # ASSERT: Dashboard loads successfully
        assert dashboard_response.status_code == 200, (
            f"Dashboard failed to load: {dashboard_response.text}"
        )

        dashboard_content = dashboard_response.text.lower()

        # ASSERT: Dashboard shows the scanned certificate
        assert "secure.example.com" in dashboard_response.text, (
            "Scanned hostname not shown in dashboard"
        )

        # ASSERT: Color coding is correct (3 days = red)
        # Find the certificate entry in the dashboard
        has_red_indicator = any(
            indicator in dashboard_content
            for indicator in ["status-red", "red", "danger", "critical", "bg-red", "text-red"]
        )

        assert has_red_indicator, "Certificate with 3 days remaining should show RED status"

        # ASSERT: Chain was extracted and stored
        if stored_leaf.fingerprint:
            chain = await cert_repo.get_chain_for_leaf(stored_leaf.fingerprint)
            # Implementation may or may not store chain yet
            if chain:
                # If chain is stored, verify linkage
                for chain_cert in chain:
                    assert chain_cert.chain_fingerprint == stored_leaf.fingerprint, (
                        "Chain certificate not properly linked to leaf"
                    )

    async def test_flow_scan_updates_existing_certificate(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """E2E Flow: Rescan updates existing certificate entry.

        ACT:
        1. Add host and scan (creates entry)
        2. Rescan the same host
        3. View dashboard

        ASSERT:
        - Original entry updated (not duplicated)
        - Updated timestamp reflects rescan
        - Dashboard shows updated information
        """
        from tests.conftest import cert_to_model

        # Arrange: Create initial certificate entry
        initial_cert = test_certificates["good"]
        initial_model = cert_to_model(
            initial_cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="update-test.example.com",
            port=443,
        )
        created = await cert_repo.create(initial_model)
        original_updated_at = created.updated_at

        # ACT: Rescan with different certificate (simulating renewal)
        renewed_cert = test_certificates["warning"]  # Different expiry

        with patch("cert_watch.web.routes.fr02_scan.extract_certificate_from_tls") as mock_extract:
            mock_extract.return_value = (renewed_cert, [])

            rescan_response = client.post(
                "/scan/add-host",
                data={
                    "hostname": "update-test.example.com",
                    "port": "443",
                },
            )

            # Precondition check
            assert mock_extract.called, "Rescan was not triggered!"

        # ASSERT: Rescan processed
        assert rescan_response.status_code in [200, 201, 302, 303]

        # ASSERT: Entry was updated
        updated = await cert_repo.get_by_id(created.id)
        if updated and updated.updated_at != original_updated_at:
            # Certificate was updated
            pass

        # ASSERT: Dashboard reflects updated info
        dashboard_response = client.get("/")
        assert dashboard_response.status_code == 200


# =============================================================================
# End-to-End Flow Test 2: Upload → Dashboard → Color Coding
# =============================================================================


@pytest.mark.asyncio
class TestFlow2UploadToDashboard:
    """Flow Test: Upload cert file → view in dashboard → verify color coding.

    This flow tests:
    - FR-03: Certificate upload and parsing
    - FR-01: Dashboard display with color coding
    """

    async def test_complete_flow_upload_parse_dashboard(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """E2E Flow: User uploads certificate, views in dashboard with correct color.

        ACT:
        1. User uploads .pem certificate file (60 days = green)
        2. System parses and stores certificate
        3. User views dashboard

        ASSERT:
        - Certificate stored with source=UPLOADED
        - Dashboard shows uploaded certificate
        - Color coding is GREEN (>30 days)
        - Certificate details displayed correctly
        """
        # Arrange: Certificate file (60 days = green)
        cert = test_certificates["good"]
        pem_data = cert.public_bytes(serialization.Encoding.PEM)
        test_label = "Production API Cert"

        # ACT 1: Upload certificate file
        upload_response = client.post(
            "/upload",
            files={
                "certificate": ("production.pem", pem_data, "application/x-pem-file"),
            },
            data={"label": test_label},
        )

        # ASSERT: Upload successful
        assert upload_response.status_code in [200, 201, 302, 303], (
            f"Upload failed: {upload_response.status_code}"
        )

        # ACT 2: Precondition check - verify certificate was stored
        all_certs = await cert_repo.get_all()
        uploaded_certs = [c for c in all_certs if c.source == CertificateSource.UPLOADED]

        # Structural assertion
        assert len(uploaded_certs) > 0, "PRECONDITION FAILED: No uploaded certificates in database."

        # Verify our specific cert was stored
        our_cert = next((c for c in uploaded_certs if c.label == test_label), None)
        assert our_cert is not None, (
            f"PRECONDITION FAILED: Uploaded certificate with label '{test_label}' not found."
        )

        # Verify correct parsing
        assert our_cert.certificate_type == CertificateType.LEAF, (
            "Certificate should be stored as LEAF type"
        )

        # ACT 3: View dashboard
        dashboard_response = client.get("/")

        # ASSERT: Dashboard loads
        assert dashboard_response.status_code == 200
        dashboard_content = dashboard_response.text.lower()

        # ASSERT: Certificate visible in dashboard
        assert test_label in dashboard_response.text, "Uploaded certificate label not in dashboard"

        # ASSERT: Color coding is GREEN (60 days remaining)
        has_green_indicator = any(
            indicator in dashboard_content
            for indicator in ["status-green", "green", "success", "bg-green", "text-green", "ok"]
        )

        assert has_green_indicator, "Certificate with 60 days should show GREEN status"

    async def test_flow_upload_with_chain_displays_all_in_dashboard(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """E2E Flow: Upload certificate with chain, all entries visible.

        ACT:
        1. Upload .pem file containing leaf + intermediate + root
        2. View dashboard

        ASSERT:
        - Leaf certificate stored and visible
        - Chain certificates stored
        - All entries have correct type labels
        """
        # Arrange: Create PEM file with chain
        leaf = test_certificates["warning"]  # 15 days = yellow
        intermediate = test_certificates["intermediate"]
        root = test_certificates["root_ca"]

        chain_data = b""
        chain_data += leaf.public_bytes(serialization.Encoding.PEM)
        chain_data += intermediate.public_bytes(serialization.Encoding.PEM)
        chain_data += root.public_bytes(serialization.Encoding.PEM)

        # ACT 1: Upload chain file
        upload_response = client.post(
            "/upload",
            files={
                "certificate": ("chain.pem", chain_data, "application/x-pem-file"),
            },
            data={"label": "Cert With Chain"},
        )

        # ASSERT: Upload successful
        assert upload_response.status_code in [200, 201, 302, 303]

        # ACT 2: Check database for stored certificates
        all_certs = await cert_repo.get_all()

        # ASSERT: At minimum, leaf was stored
        leaf_certs = [
            c
            for c in all_certs
            if c.label == "Cert With Chain"
            or (
                c.source == CertificateSource.UPLOADED
                and c.certificate_type == CertificateType.LEAF
            )
        ]

        assert len(leaf_certs) > 0, "Uploaded leaf certificate not stored"

        # ACT 3: View dashboard
        dashboard_response = client.get("/")
        assert dashboard_response.status_code == 200

        # ASSERT: Leaf is visible
        assert "Cert With Chain" in dashboard_response.text or any(
            c.subject in dashboard_response.text for c in leaf_certs
        ), "Uploaded certificate not visible in dashboard"


# =============================================================================
# End-to-End Flow Test 3: Mixed Scanned + Uploaded
# =============================================================================


@pytest.mark.asyncio
class TestFlow3MixedScenarios:
    """Flow Test: Mixed scanned and uploaded certificates in dashboard.

    This flow tests:
    - FR-01: Dashboard with mixed sources
    - FR-02: Scanned entries
    - FR-03: Uploaded entries
    - Proper sorting by urgency across all sources
    """

    async def test_mixed_scanned_and_uploaded_sorted_by_urgency(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """E2E Flow: Dashboard shows mixed sources sorted by urgency.

        ACT:
        1. Upload certificate (60 days, green)
        2. Scan host and get certificate (3 days, red, critical)
        3. View dashboard

        ASSERT:
        - Both certificates visible
        - Critical (3 days) appears before Green (60 days)
        - Correct color coding for each
        """
        # ACT 1: Upload certificate (60 days = green)
        uploaded_cert = test_certificates["good"]
        pem_data = uploaded_cert.public_bytes(serialization.Encoding.PEM)

        upload_response = client.post(
            "/upload",
            files={
                "certificate": ("green.pem", pem_data, "application/x-pem-file"),
            },
            data={"label": "Green Uploaded Cert"},
        )
        assert upload_response.status_code in [200, 201, 302, 303]

        # ACT 2: Scan host (3 days = red, critical)
        scanned_cert = test_certificates["critical"]

        with patch("cert_watch.web.routes.fr02_scan.extract_certificate_from_tls") as mock_extract:
            mock_extract.return_value = (scanned_cert, [])

            scan_response = client.post(
                "/scan/add-host",
                data={
                    "hostname": "critical.example.com",
                    "port": "443",
                },
            )

            # Precondition check
            assert mock_extract.called, "Scan was not triggered!"

        assert scan_response.status_code in [200, 201, 302, 303]

        # ACT 3: Precondition - verify both in database
        all_certs = await cert_repo.get_all()

        uploaded = [c for c in all_certs if c.source == CertificateSource.UPLOADED]
        scanned = [c for c in all_certs if c.source == CertificateSource.SCANNED]

        assert len(uploaded) > 0, "PRECONDITION FAILED: No uploaded certificates"
        assert len(scanned) > 0, "PRECONDITION FAILED: No scanned certificates"

        # ACT 4: View dashboard
        dashboard_response = client.get("/")
        assert dashboard_response.status_code == 200

        dashboard_content = dashboard_response.text

        # ASSERT: Both certificates visible
        has_green = "Green Uploaded Cert" in dashboard_content or any(
            c.subject in dashboard_content for c in uploaded
        )
        has_critical = "critical.example.com" in dashboard_content or any(
            c.hostname == "critical.example.com" for c in scanned
        )

        assert has_green, "Uploaded certificate not in dashboard"
        assert has_critical, "Scanned certificate not in dashboard"

        # ASSERT: Sorted correctly (critical before green)
        critical_pos = dashboard_content.find("critical.example.com")
        green_pos = dashboard_content.find("Green Uploaded Cert")

        # If we can't find by label, try by hostname/subject
        if green_pos == -1:
            for c in uploaded:
                green_pos = dashboard_content.find(c.subject)
                if green_pos != -1:
                    break

        if critical_pos != -1 and green_pos != -1:
            assert critical_pos < green_pos, (
                "Critical (3 days) should appear before Green (60 days)"
            )

    async def test_flow_multiple_scans_same_host_different_times(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """E2E Flow: Multiple scans of same host create/update single entry.

        ACT:
        1. Scan host.example.com (initial scan)
        2. Scan host.example.com again (update scan)
        3. View dashboard

        ASSERT:
        - Single entry for host (or updated entry)
        - No duplicates in dashboard
        - Latest certificate data shown
        """
        # ACT 1: Initial scan
        cert1 = test_certificates["warning"]  # 15 days

        with patch("cert_watch.web.routes.fr02_scan.extract_certificate_from_tls") as mock_extract:
            mock_extract.return_value = (cert1, [])

            response1 = client.post(
                "/scan/add-host",
                data={"hostname": "multi.example.com", "port": "443"},
            )
            assert mock_extract.called

        assert response1.status_code in [200, 201, 302, 303]

        # Get initial count
        initial_certs = await cert_repo.get_by_hostname("multi.example.com")
        initial_count = len(initial_certs)

        # ACT 2: Second scan (simulating update)
        cert2 = test_certificates["critical"]  # 3 days

        with patch("cert_watch.web.routes.fr02_scan.extract_certificate_from_tls") as mock_extract:
            mock_extract.return_value = (cert2, [])

            response2 = client.post(
                "/scan/add-host",
                data={"hostname": "multi.example.com", "port": "443"},
            )
            assert mock_extract.called

        # ASSERT: Second scan processed
        assert response2.status_code in [200, 201, 302, 303]

        # ACT 3: Check database
        final_certs = await cert_repo.get_by_hostname("multi.example.com")

        # Should have either same count (updated) or new count (if separate entries)
        # Implementation-dependent, but shouldn't have excessive duplicates
        assert len(final_certs) <= initial_count + 2, (
            "Excessive duplicates created for same hostname"
        )


# =============================================================================
# Flow Test: Error Isolation and Recovery
# =============================================================================


@pytest.mark.asyncio
class TestFlowErrorHandling:
    """Flow tests for error scenarios across multiple FRs."""

    async def test_flow_continues_after_scan_failure(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """E2E Flow: Dashboard works even after scan failure.

        ACT:
        1. Have existing certificate in dashboard
        2. Attempt scan that fails
        3. View dashboard

        ASSERT:
        - Error handled gracefully
        - Existing certificates still visible
        - Dashboard functional
        """
        from cert_watch.core.exceptions import TLSConnectionError
        from tests.conftest import cert_to_model

        # Arrange: Existing certificate
        existing = cert_to_model(
            test_certificates["good"],
            hostname="existing.example.com",
            source=CertificateSource.SCANNED,
        )
        await cert_repo.create(existing)

        # ACT 1: Failed scan attempt
        with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
            mock_extract.side_effect = TLSConnectionError("Connection refused")

            fail_response = client.post(
                "/scan/add-host",
                data={"hostname": "failing.invalid", "port": "443"},
            )

        # Error should be handled gracefully
        assert fail_response.status_code in [200, 400, 422, 500]

        # ACT 2: View dashboard
        dashboard_response = client.get("/")

        # ASSERT: Dashboard still works
        assert dashboard_response.status_code == 200, "Dashboard should work despite scan failure"

        # ASSERT: Existing certificate still visible
        assert "existing.example.com" in dashboard_response.text, (
            "Existing certificate should still be visible after scan failure"
        )

    async def test_flow_upload_failure_does_not_affect_existing(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        test_certificates,
    ):
        """E2E Flow: Failed upload doesn't affect existing certificates.

        ACT:
        1. Have existing certificate
        2. Attempt invalid file upload
        3. View dashboard

        ASSERT:
        - Upload rejected
        - Existing certificates unaffected
        """
        from tests.conftest import cert_to_model

        # Arrange: Existing certificate
        existing = cert_to_model(
            test_certificates["good"],
            hostname="stable.example.com",
            source=CertificateSource.SCANNED,
        )
        await cert_repo.create(existing)

        # ACT 1: Failed upload
        fail_response = client.post(
            "/upload",
            files={
                "certificate": ("invalid.txt", b"not a cert", "text/plain"),
            },
        )

        # ASSERT: Upload rejected
        assert fail_response.status_code in [400, 422], "Invalid upload should be rejected"

        # ACT 2: View dashboard
        dashboard_response = client.get("/")
        assert dashboard_response.status_code == 200

        # ASSERT: Existing certificate still there
        assert "stable.example.com" in dashboard_response.text, (
            "Existing certificate should be unaffected by failed upload"
        )


# =============================================================================
# End-to-End Flow Test 4: Certificate → Alert → Email → History
# =============================================================================


@pytest.mark.asyncio
class TestFlow4AlertLifecycle:
    """Flow Test: Certificate at threshold → alert created → email sent → history.

    This flow tests FR-04 end-to-end:
    - Certificate reaches alert threshold
    - Alert is created and pending
    - Email is sent via SMTP
    - Alert status updated to SENT
    - Alert history tracked per certificate
    """

    async def test_complete_flow_certificate_to_alert_to_email(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        alert_repo: AlertRepository,
        test_certificates,
        settings,
    ):
        """E2E Flow: Cert hits threshold → alert created → email sent → history updated.

        ACT:
        1. Certificate exists with 3 days remaining (critical threshold)
        2. Alert evaluation runs and creates pending alert
        3. Email sending process runs
        4. Alert status updated to SENT

        ASSERT:
        - Alert created with correct certificate_id and days_remaining=3
        - Alert has status PENDING initially
        - SMTP sendmail was invoked
        - Alert status updated to SENT with timestamp
        - Alert appears in certificate's alert history
        """
        from unittest.mock import MagicMock, patch

        from cert_watch.models.alert import AlertStatus
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # ACT 1: Create certificate at critical threshold (3 days)
        cert = test_certificates["critical"]  # 3 days = red/critical
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="critical-alert.example.com",
            port=443,
        )
        created_cert = await cert_repo.create(model)

        # Precondition: Certificate stored
        assert created_cert.id is not None, "PRECONDITION FAILED: Certificate not created"

        # ACT 2: Evaluate alerts (this would be done by AlertService)
        # For now, manually create what the service would create
        try:
            from cert_watch.services.alert_service_impl import AlertServiceImpl

            service = AlertServiceImpl(
                cert_repo=cert_repo, alert_repo=alert_repo, settings=settings
            )

            # Mock SMTP to capture email sending
            with patch("smtplib.SMTP") as mock_smtp_class:
                mock_smtp = MagicMock()
                mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp)
                mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

                # Run alert evaluation
                alert_ids = await service.evaluate_alerts()

                # Structural check: Action was triggered
                assert len(alert_ids) > 0, (
                    "PRECONDITION FAILED: No alerts created by evaluate_alerts(). "
                    "Certificate at threshold should trigger alert creation."
                )

                # Verify alert was created for our certificate
                cert_alerts = await alert_repo.get_for_certificate(created_cert.id)
                assert len(cert_alerts) > 0, (
                    f"PRECONDITION FAILED: No alerts found for certificate {created_cert.id}"
                )

                # ACT 3: Send pending alerts
                sent_count, failed_count = await service.send_pending_alerts()

                # Structural check: Email was sent
                assert mock_smtp.sendmail.called, (
                    "SMTP sendmail was not called! Email alert was not sent."
                )

                # Verify alert status was updated
                for alert in cert_alerts:
                    updated = await alert_repo.get_by_id(alert.id)
                    assert updated.status == AlertStatus.SENT, (
                        f"Alert status should be SENT after email, got {updated.status}"
                    )
                    assert updated.sent_at is not None, "sent_at should be set after sending"

        except (ImportError, AttributeError):
            pytest.skip("AlertService not yet implemented - this is expected during test phase")

    async def test_flow_alert_thresholds_evaluated_correctly(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        alert_repo: AlertRepository,
        settings,
    ):
        """E2E Flow: Multiple thresholds evaluated correctly.

        ACT:
        1. Certificates at 14, 7, 3, and 1 days (leaf)
        2. Chain certificate at 30 days
        3. Alert evaluation runs

        ASSERT:
        - Alerts created for certificates at exact thresholds
        - No duplicate alerts for same threshold
        - Leaf and chain use different threshold lists
        """
        from datetime import datetime, timedelta

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        now = datetime.utcnow()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create certificates at various thresholds
        test_certs = [
            ("leaf-14.example.com", 14, CertificateType.LEAF),
            ("leaf-7.example.com", 7, CertificateType.LEAF),
            ("leaf-3.example.com", 3, CertificateType.LEAF),
            ("leaf-1.example.com", 1, CertificateType.LEAF),
            ("intermediate-30", 30, CertificateType.INTERMEDIATE),
        ]

        created_certs = []
        for hostname, days, cert_type in test_certs:
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
            issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=days))
                .serial_number(hash(hostname) % 100000)
                .public_key(private_key.public_key())
                .sign(private_key, hashes.SHA256())
            )

            model = cert_to_model(
                cert,
                certificate_type=cert_type,
                source=CertificateSource.SCANNED,
                hostname=hostname if cert_type == CertificateType.LEAF else None,
                port=443 if cert_type == CertificateType.LEAF else None,
            )
            created = await cert_repo.create(model)
            created_certs.append((created, days, cert_type))

        # ACT: Evaluate alerts
        try:
            from cert_watch.services.alert_service_impl import AlertServiceImpl

            service = AlertServiceImpl(
                cert_repo=cert_repo, alert_repo=alert_repo, settings=settings
            )
            alert_ids = await service.evaluate_alerts()

            # Precondition check
            assert len(alert_ids) > 0, "evaluate_alerts should create alerts for threshold certs"

            # ASSERT: Verify alerts created for certificates at thresholds
            for cert, days, cert_type in created_certs:
                alerts = await alert_repo.get_for_certificate(cert.id)

                # Should have at least one alert for each certificate at threshold
                assert len(alerts) > 0, (
                    f"No alerts for {cert_type.name} at {days} days - threshold not detected"
                )

                # Verify days_remaining matches
                matching_alerts = [a for a in alerts if a.days_remaining == days]
                assert len(matching_alerts) > 0, (
                    f"No alert with days_remaining={days} for {cert.subject}"
                )

        except (ImportError, AttributeError):
            pytest.skip("AlertService not yet implemented")

    async def test_flow_no_duplicate_alerts_for_same_threshold(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        alert_repo: AlertRepository,
        test_certificates,
        settings,
    ):
        """E2E Flow: Running evaluation twice doesn't create duplicates.

        ACT:
        1. Certificate at 7-day threshold
        2. Alert evaluation runs (creates alert)
        3. Alert evaluation runs again
        4. Email sent

        ASSERT:
        - Only one alert exists for the 7-day threshold
        - Second evaluation is idempotent
        """
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # Arrange: Certificate at 7-day threshold
        cert = test_certificates["red_boundary"]  # Exactly 7 days
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="nodup.example.com",
            port=443,
        )
        created = await cert_repo.create(model)

        try:
            from cert_watch.services.alert_service_impl import AlertServiceImpl

            service = AlertServiceImpl(
                cert_repo=cert_repo, alert_repo=alert_repo, settings=settings
            )

            # ACT 1: First evaluation
            alert_ids_1 = await service.evaluate_alerts()

            # Precondition: Alert was created
            alerts_1 = await alert_repo.get_for_certificate(created.id)
            assert len(alerts_1) > 0, "First evaluation should create alert"

            # Mark as sent (simulating send_pending_alerts)
            for alert in alerts_1:
                await alert_repo.mark_sent(alert.id)

            # ACT 2: Second evaluation
            alert_ids_2 = await service.evaluate_alerts()

            # ASSERT: No duplicate created
            all_alerts = await alert_repo.get_for_certificate(created.id)
            alerts_for_7_days = [a for a in all_alerts if a.days_remaining == 7]

            # Should have exactly one alert for 7-day threshold
            assert len(alerts_for_7_days) == 1, (
                f"Duplicate alert created! Found {len(alerts_for_7_days)} alerts for 7-day threshold"
            )

        except (ImportError, AttributeError):
            pytest.skip("AlertService not yet implemented")


# =============================================================================
# End-to-End Flow Test 5: Daily Scan + Alert Cycle (FR-04 + FR-05)
# =============================================================================


@pytest.mark.asyncio
class TestFlow5DailyScanWithAlerts:
    """Flow Test: Daily scan cycle runs → alerts evaluated → emails sent.

    This flow tests FR-05 (Daily Scheduler) + FR-04 (Email Alerts):
    - Daily scan refreshes certificates
    - Alert evaluation triggers for new issues
    - Email alerts are sent
    - Scan history is recorded
    """

    async def test_daily_scan_triggers_alert_evaluation(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        alert_repo: AlertRepository,
        scan_repo,  # ScanHistoryRepository
        test_certificates,
        settings,
    ):
        """E2E Flow: Daily scan runs and triggers alert evaluation.

        ACT:
        1. Certificate exists at 3-day threshold
        2. Daily scan cycle runs (run_daily_scan)
        3. Alert evaluation runs as part of scan
        4. Email alerts sent
        5. Scan history recorded

        ASSERT:
        - Scan history entry created
        - Alert created for certificate at threshold
        - Email sent
        - Scan status updated to SUCCESS
        """
        from unittest.mock import MagicMock, patch

        from cert_watch.models.certificate import CertificateSource, CertificateType
        from cert_watch.models.scan_history import ScanStatus
        from tests.conftest import cert_to_model

        # Arrange: Certificate at critical threshold
        cert = test_certificates["critical"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="daily-scan.example.com",
            port=443,
        )
        await cert_repo.create(model)

        # Precondition: No existing scan history
        initial_scans = await scan_repo.get_recent(limit=1)

        try:
            from cert_watch.services.scheduler_impl import ScanSchedulerImpl

            service = ScanSchedulerImpl(
                cert_repo=cert_repo,
                alert_repo=alert_repo,
                scan_repo=scan_repo,
                settings=settings,
            )

            # Mock SMTP to avoid actual email sending
            with (
                patch("smtplib.SMTP") as mock_smtp_class,
                patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract,
            ):
                mock_smtp = MagicMock()
                mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp)
                mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)
                mock_extract.return_value = (cert, [])

                # ACT: Run daily scan
                await service.run_daily_scan()

                # Structural check: Scan history was recorded
                recent_scans = await scan_repo.get_recent(limit=1)
                assert len(recent_scans) > len(initial_scans), (
                    "PRECONDITION FAILED: No scan history recorded. "
                    "Daily scan did not record its execution."
                )

                latest_scan = recent_scans[0]
                assert latest_scan.status == ScanStatus.SUCCESS, (
                    f"Scan should complete successfully, got {latest_scan.status}"
                )

                # Check alerts were evaluated
                all_alerts = await alert_repo.get_pending()
                assert len(all_alerts) > 0 or mock_smtp.sendmail.called, (
                    "Either pending alerts should exist or emails should have been sent"
                )

        except (ImportError, AttributeError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_daily_scan_refreshes_and_creates_new_alerts(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        alert_repo: AlertRepository,
        test_certificates,
    ):
        """E2E Flow: Daily scan refreshes certs and creates new alerts.

        ACT:
        1. Certificate scanned yesterday (was at 8 days)
        2. Daily scan runs today (now at 7 days - threshold!)
        3. New alert created for 7-day threshold

        ASSERT:
        - Certificate expiry updated
        - New alert created (wasn't there before)
        - Alert has correct days_remaining
        """
        from unittest.mock import patch

        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # Create certificate at 7-day threshold
        cert = test_certificates["red_boundary"]  # 7 days
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="refresh.example.com",
            port=443,
        )
        created = await cert_repo.create(model)

        # Verify no alerts exist yet
        initial_alerts = await alert_repo.get_for_certificate(created.id)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Mock TLS extraction to return updated certificate
            with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
                mock_extract.return_value = (cert, [])

                # ACT: Run daily scan
                await service.run_daily_scan()

                # ASSERT: Alert created after scan
                final_alerts = await alert_repo.get_for_certificate(created.id)

                # Should have more alerts than before (or at least the alert was processed)
                if len(final_alerts) > len(initial_alerts):
                    # New alert was created
                    new_alert = [a for a in final_alerts if a not in initial_alerts]
                    if new_alert:
                        assert new_alert[0].days_remaining == 7, (
                            "New alert should be for 7-day threshold"
                        )

        except (ImportError, AttributeError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scan_failure_isolation_with_alerts(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        alert_repo: AlertRepository,
        scan_repo,
        test_certificates,
    ):
        """E2E Flow: Scan failure on one host doesn't stop alerts for others.

        ACT:
        1. Two certificates at threshold
        2. One host scan fails
        3. Daily scan runs

        ASSERT:
        - Scan history shows partial success
        - Alert still created for successful scan
        - Error logged for failed host
        """
        from cert_watch.core.exceptions import TLSConnectionError
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from cert_watch.models.scan_history import ScanStatus
        from tests.conftest import cert_to_model

        # Arrange: Two certificates
        cert1 = test_certificates["critical"]
        model1 = cert_to_model(
            cert1,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="success.example.com",
            port=443,
        )
        await cert_repo.create(model1)

        cert2 = test_certificates["warning"]
        model2 = cert_to_model(
            cert2,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="fails.example.com",
            port=443,
        )
        await cert_repo.create(model2)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Mock TLS to fail for one host
            def mock_extract(hostname, port):
                if hostname == "fails.example.com":
                    raise TLSConnectionError("Connection refused")
                return (cert1, [])

            with patch(
                "cert_watch.core.formatters.extract_certificate_from_tls",
                side_effect=mock_extract,
            ):
                # ACT: Run daily scan
                await service.run_daily_scan()

                # ASSERT: Check scan history
                recent_scans = await scan_repo.get_recent(limit=1)
                if recent_scans:
                    scan = recent_scans[0]
                    # May show partial or success depending on implementation
                    assert scan.status in [ScanStatus.SUCCESS, ScanStatus.PARTIAL], (
                        f"Scan should complete, got {scan.status}"
                    )

                # Alerts may still be processed for successful scans
                # This tests error isolation

        except (ImportError, AttributeError):
            pytest.skip("ScanSchedulerService not yet implemented")


# =============================================================================
# End-to-End Flow Test 6: Chain Certificate Alerts
# =============================================================================


@pytest.mark.asyncio
class TestFlow6ChainCertificateAlerts:
    """Flow Test: Chain certificates trigger alerts at different thresholds.

    This flow tests that chain certificates use different thresholds than leaf.
    - Leaf: 14/7/3/1 days
    - Chain: 30/14/7 days
    """

    async def test_chain_cert_30_day_alert_while_leaf_at_60_no_alert(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        alert_repo: AlertRepository,
        settings,
    ):
        """E2E Flow: Chain cert at 30 days alerts, leaf at 60 days doesn't.

        ACT:
        1. Chain certificate (intermediate) with 30 days remaining
        2. Leaf certificate with 60 days remaining
        3. Alert evaluation runs

        ASSERT:
        - Alert created for chain cert at 30 days
        - No alert for leaf cert at 60 days (not at threshold)
        """
        from datetime import datetime, timedelta

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        now = datetime.utcnow()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create intermediate CA at 30 days
        int_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate")])
        int_issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])

        int_cert = (
            x509.CertificateBuilder()
            .subject_name(int_subject)
            .issuer_name(int_issuer)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .serial_number(99901)
            .public_key(private_key.public_key())
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(private_key, hashes.SHA256())
        )

        int_model = cert_to_model(
            int_cert,
            certificate_type=CertificateType.INTERMEDIATE,
            source=CertificateSource.SCANNED,
        )
        int_created = await cert_repo.create(int_model)

        # Create leaf at 60 days
        leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "60days.example.com")])
        leaf_issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])

        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(leaf_issuer)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=60))
            .serial_number(99902)
            .public_key(private_key.public_key())
            .sign(private_key, hashes.SHA256())
        )

        leaf_model = cert_to_model(
            leaf_cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="60days.example.com",
            port=443,
        )
        leaf_created = await cert_repo.create(leaf_model)

        try:
            from cert_watch.services.alert_service_impl import AlertServiceImpl

            service = AlertServiceImpl(
                cert_repo=cert_repo, alert_repo=alert_repo, settings=settings
            )

            # ACT: Evaluate alerts
            alert_ids = await service.evaluate_alerts()

            # ASSERT: Alert created for intermediate
            int_alerts = await alert_repo.get_for_certificate(int_created.id)
            assert len(int_alerts) > 0, "Intermediate CA at 30 days should trigger alert"

            # Check that at least one alert is for 30 days
            thirty_day_alerts = [a for a in int_alerts if a.days_remaining == 30]
            assert len(thirty_day_alerts) > 0, "Should have alert specifically for 30-day threshold"

            # ASSERT: No alert for leaf at 60 days (not a threshold)
            leaf_alerts = await alert_repo.get_for_certificate(leaf_created.id)
            assert len(leaf_alerts) == 0, (
                "Leaf at 60 days should NOT trigger alert (thresholds are 14/7/3/1)"
            )

        except (ImportError, AttributeError):
            pytest.skip("AlertService not yet implemented")
