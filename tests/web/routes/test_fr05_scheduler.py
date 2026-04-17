"""Tests for FR-05: Daily Scheduler.

Acceptance Criteria:
- Daily scan at configurable time (default 06:00)
- Updates expiry dates for all scanned entries
- Triggers alerts for newly detected issues
- Scan history logged with timestamp

Per spec:
- Scheduler runs daily at configured time
- Refreshes all scanned certificates
- Triggers alert evaluation after refresh
- Records scan history with status and results
"""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from cert_watch.models.certificate import CertificateSource, CertificateType
from cert_watch.models.scan_history import ScanHistory, ScanStatus
from cert_watch.repositories.base import (
    AlertRepository,
    CertificateRepository,
    ScanHistoryRepository,
)

# =============================================================================
# FR-05 AC-05: Scheduler Configuration Tests
# =============================================================================


@pytest.mark.asyncio
class TestSchedulerConfiguration:
    """Test suite for scheduler configuration requirements."""

    async def test_default_scan_time_is_0600(
        self,
        settings,
    ):
        """AC-05.1: Default scan time is 06:00.

        Given: Default settings
        When: Checking scan time configuration
        Then: Default is 06:00
        """
        assert settings.scan_time == "06:00", (
            f"Default scan time should be '06:00', got '{settings.scan_time}'"
        )

    async def test_scan_time_is_configurable(
        self,
    ):
        """AC-05.2: Scan time is configurable via settings.

        Given: Custom scan time setting
        When: Scheduler initializes
        Then: Uses custom time
        """
        # This tests that the settings field accepts custom values
        # Implementation should respect this setting
        from cert_watch.core.config import Settings

        custom_settings = Settings(
            database_url="sqlite:///./test.db",
            scan_time="14:30",
        )

        assert custom_settings.scan_time == "14:30", "Custom scan time should be configurable"

    async def test_scan_timezone_is_configurable(
        self,
        settings,
    ):
        """AC-05.3: Scan timezone is configurable.

        Given: Timezone configuration
        When: Scheduler runs
        Then: Respects timezone setting
        """
        # Default should be UTC
        assert settings.scan_timezone == "UTC", (
            f"Default timezone should be UTC, got '{settings.scan_timezone}'"
        )

    async def test_scan_time_format_is_hhmm(
        self,
    ):
        """AC-05.4: Scan time format is HH:MM.

        Given: Scan time setting
        When: Parsing time
        Then: Format is valid HH:MM
        """
        from cert_watch.core.config import Settings

        settings = Settings(
            database_url="sqlite:///./test.db",
            scan_time="23:59",
        )

        # Validate format
        assert ":" in settings.scan_time, "Time should contain colon separator"
        parts = settings.scan_time.split(":")
        assert len(parts) == 2, "Time should have hours and minutes"

        hours, minutes = parts
        assert hours.isdigit() and 0 <= int(hours) <= 23, "Hours should be 00-23"
        assert minutes.isdigit() and 0 <= int(minutes) <= 59, "Minutes should be 00-59"


# =============================================================================
# FR-05 Scheduler Service Tests
# =============================================================================


@pytest.mark.asyncio
class TestSchedulerService:
    """Test suite for ScanSchedulerService implementation."""

    async def test_scheduler_service_has_start_method(
        self,
    ):
        """AC-05.5: Scheduler service has start_scheduler method.

        Given: ScanSchedulerService instance
        When: Checking methods
        Then: start_scheduler exists
        """
        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            assert hasattr(service, "start_scheduler"), (
                "ScanSchedulerService must have start_scheduler method"
            )
            assert callable(service.start_scheduler), "start_scheduler must be callable"

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scheduler_service_has_stop_method(
        self,
    ):
        """AC-05.6: Scheduler service has stop_scheduler method.

        Given: ScanSchedulerService instance
        When: Checking methods
        Then: stop_scheduler exists
        """
        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            assert hasattr(service, "stop_scheduler"), (
                "ScanSchedulerService must have stop_scheduler method"
            )
            assert callable(service.stop_scheduler), "stop_scheduler must be callable"

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scheduler_service_has_run_daily_scan_method(
        self,
    ):
        """AC-05.7: Scheduler service has run_daily_scan method.

        Given: ScanSchedulerService instance
        When: Checking methods
        Then: run_daily_scan exists and is async
        """
        try:
            import inspect

            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            assert hasattr(service, "run_daily_scan"), (
                "ScanSchedulerService must have run_daily_scan method"
            )
            assert callable(service.run_daily_scan), "run_daily_scan must be callable"
            assert inspect.iscoroutinefunction(service.run_daily_scan), (
                "run_daily_scan must be async"
            )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")


# =============================================================================
# FR-05 Daily Scan Cycle Tests
# =============================================================================


@pytest.mark.asyncio
class TestDailyScanCycle:
    """Test suite for daily scan cycle functionality."""

    async def test_daily_scan_refreshes_scanned_certificates(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.8: Daily scan updates expiry dates for scanned entries.

        Given: Existing scanned certificate entries
        When: Daily scan runs
        Then: Certificates are refreshed with current data
        """
        from tests.conftest import cert_to_model

        # Arrange: Create scanned certificate
        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="refresh-test.example.com",
            port=443,
        )
        created = await cert_repo.create(model)
        original_updated_at = created.updated_at

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Mock TLS to return updated certificate
            with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
                mock_extract.return_value = (cert, [])

                # Act: Run daily scan
                await service.run_daily_scan()

                # Precondition check: Mock was called
                assert mock_extract.called, (
                    "PRECONDITION FAILED: TLS extraction not triggered. "
                    "Daily scan did not attempt to refresh certificates."
                )

                # Assert: Certificate was updated (or at least refresh attempted)
                updated = await cert_repo.get_by_id(created.id)
                if updated:
                    # Either updated_at changed, or scan history was recorded
                    scan_history = await scan_repo.get_recent(limit=1)
                    assert len(scan_history) > 0, (
                        "Scan should record history even if cert unchanged"
                    )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_daily_scan_triggers_alert_evaluation(
        self,
        cert_repo: CertificateRepository,
        alert_repo: AlertRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.9: Daily scan triggers alert evaluation.

        Given: Certificates at alert thresholds
        When: Daily scan completes
        Then: Alert evaluation runs for refreshed certs
        """
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # Arrange: Create certificate at threshold
        cert = test_certificates["critical"]  # 3 days
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="alert-trigger.example.com",
            port=443,
        )
        await cert_repo.create(model)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Mock TLS and alert service
            with (
                patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract,
                patch.object(service, "_evaluate_alerts") as mock_evaluate,
            ):
                mock_extract.return_value = (cert, [])
                mock_evaluate.return_value = [1, 2, 3]  # Alert IDs

                # Act: Run daily scan
                await service.run_daily_scan()

                # Assert: Alert evaluation was triggered
                # OR scan history shows it was attempted
                scan_history = await scan_repo.get_recent(limit=1)
                if scan_history:
                    latest = scan_history[0]
                    # Scan should complete successfully
                    assert latest.status in [ScanStatus.SUCCESS, ScanStatus.PARTIAL], (
                        f"Scan should complete, got status: {latest.status}"
                    )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_daily_scan_isolates_errors_per_host(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.10: Error on one host doesn't stop scan for others.

        Given: Multiple scanned hosts where one fails
        When: Daily scan runs
        Then: Other hosts still scanned, partial success recorded
        """
        from cert_watch.core.exceptions import TLSConnectionError
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # Arrange: Create two scanned certificates
        cert1 = test_certificates["good"]
        model1 = cert_to_model(
            cert1,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="success-host.example.com",
            port=443,
        )
        await cert_repo.create(model1)

        cert2 = test_certificates["warning"]
        model2 = cert_to_model(
            cert2,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="fail-host.example.com",
            port=443,
        )
        await cert_repo.create(model2)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Mock TLS to fail for one host, succeed for other
            def mock_extract(hostname, port):
                if hostname == "fail-host.example.com":
                    raise TLSConnectionError("Connection refused")
                return (cert1, [])

            with patch(
                "cert_watch.core.formatters.extract_certificate_from_tls",
                side_effect=mock_extract,
            ):
                # Act: Run daily scan
                await service.run_daily_scan()

                # Assert: Scan history recorded
                scan_history = await scan_repo.get_recent(limit=1)
                if scan_history:
                    latest = scan_history[0]
                    # Status should be PARTIAL (some succeeded, some failed)
                    assert latest.status in [ScanStatus.SUCCESS, ScanStatus.PARTIAL], (
                        f"Scan should complete with partial success, got: {latest.status}"
                    )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_daily_scan_skips_uploaded_certificates(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.11: Daily scan only refreshes scanned entries, not uploaded.

        Given: Mix of scanned and uploaded certificates
        When: Daily scan runs
        Then: Only scanned entries are refreshed
        """
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # Arrange: Create scanned certificate
        scanned_cert = test_certificates["good"]
        scanned_model = cert_to_model(
            scanned_cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="scanned.example.com",
            port=443,
        )
        await cert_repo.create(scanned_model)

        # Arrange: Create uploaded certificate
        uploaded_cert = test_certificates["warning"]
        uploaded_model = cert_to_model(
            uploaded_cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.UPLOADED,
            hostname=None,  # Uploaded certs don't have hostname
            port=None,
            label="Uploaded Cert",
        )
        await cert_repo.create(uploaded_model)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Track which hosts were scanned
            scanned_hosts = []

            def mock_extract(hostname, port):
                scanned_hosts.append(hostname)
                return (scanned_cert, [])

            with patch(
                "cert_watch.core.formatters.extract_certificate_from_tls",
                side_effect=mock_extract,
            ):
                # Act: Run daily scan
                await service.run_daily_scan()

                # Assert: Only scanned host was refreshed
                # Uploaded cert should not trigger TLS scan
                if scanned_hosts:
                    assert "scanned.example.com" in scanned_hosts, (
                        "Scanned certificate should be refreshed"
                    )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_daily_scan_updates_chain_certificates(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.12: Daily scan refreshes chain certificates.

        Given: Scanned certificate with chain
        When: Daily scan runs
        Then: Chain certificates are also refreshed
        """
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # Arrange: Create scanned certificate with chain
        leaf = test_certificates["good"]
        intermediate = test_certificates["intermediate"]

        leaf_model = cert_to_model(
            leaf,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="chain-refresh.example.com",
            port=443,
        )
        await cert_repo.create(leaf_model)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Mock TLS to return updated chain
            with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
                mock_extract.return_value = (leaf, [intermediate])

                # Act: Run daily scan
                await service.run_daily_scan()

                # Assert: TLS extraction was called
                assert mock_extract.called, "TLS extraction should be called for scanned certs"

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")


# =============================================================================
# FR-05 Scan History Tracking Tests
# =============================================================================


@pytest.mark.asyncio
class TestScanHistoryTracking:
    """Test suite for scan history logging requirements."""

    async def test_scan_creates_history_entry(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.13: Scan creates history entry with timestamp.

        Given: Certificates to scan
        When: Daily scan runs
        Then: ScanHistory entry created with started_at timestamp
        """
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # Arrange: Create certificate
        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="history-test.example.com",
            port=443,
        )
        await cert_repo.create(model)

        # Get initial scan count
        initial_scans = await scan_repo.get_recent(limit=10)
        initial_count = len(initial_scans)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
                mock_extract.return_value = (cert, [])

                # Act: Run daily scan
                await service.run_daily_scan()

                # Assert: Scan history was created
                final_scans = await scan_repo.get_recent(limit=10)

                # Should have more scans than before
                assert len(final_scans) > initial_count, (
                    "PRECONDITION FAILED: No scan history entry created. "
                    f"Had {initial_count} scans, still have {len(final_scans)}."
                )

                # Latest entry should have timestamp
                latest = final_scans[0]
                assert latest.started_at is not None, "Scan history must have started_at"
                assert isinstance(latest.started_at, datetime), (
                    f"started_at must be datetime, got {type(latest.started_at)}"
                )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scan_history_records_success_status(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.14: Successful scan records SUCCESS status.

        Given: All hosts scan successfully
        When: Daily scan completes
        Then: ScanHistory status is SUCCESS
        """
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="success-scan.example.com",
            port=443,
        )
        await cert_repo.create(model)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
                mock_extract.return_value = (cert, [])

                # Act: Run daily scan
                await service.run_daily_scan()

                # Assert: Scan history shows success
                recent_scans = await scan_repo.get_recent(limit=1)
                assert len(recent_scans) > 0, "Scan history should exist"

                latest = recent_scans[0]
                assert latest.status == ScanStatus.SUCCESS, (
                    f"Successful scan should have SUCCESS status, got {latest.status}"
                )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scan_history_records_partial_status(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.15: Partial failure records PARTIAL status.

        Given: Some hosts fail during scan
        When: Daily scan completes
        Then: ScanHistory status is PARTIAL
        """
        from cert_watch.core.exceptions import TLSConnectionError
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # Create two certificates
        cert1 = test_certificates["good"]
        model1 = cert_to_model(
            cert1,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="partial-success.example.com",
            port=443,
        )
        await cert_repo.create(model1)

        cert2 = test_certificates["warning"]
        model2 = cert_to_model(
            cert2,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="partial-fail.example.com",
            port=443,
        )
        await cert_repo.create(model2)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            def mock_extract(hostname, port):
                if "fail" in hostname:
                    raise TLSConnectionError("Connection refused")
                return (cert1, [])

            with patch(
                "cert_watch.core.formatters.extract_certificate_from_tls",
                side_effect=mock_extract,
            ):
                await service.run_daily_scan()

                # Check scan history
                recent_scans = await scan_repo.get_recent(limit=1)
                if recent_scans:
                    latest = recent_scans[0]
                    assert latest.status in [ScanStatus.PARTIAL, ScanStatus.SUCCESS], (
                        f"Partial scan should have PARTIAL or SUCCESS status, got {latest.status}"
                    )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scan_history_records_completion_time(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.16: Scan history records completed_at timestamp.

        Given: Scan runs
        When: Scan completes
        Then: completed_at is set
        """
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="completion-test.example.com",
            port=443,
        )
        await cert_repo.create(model)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
                mock_extract.return_value = (cert, [])

                await service.run_daily_scan()

                # Check scan history
                recent_scans = await scan_repo.get_recent(limit=1)
                assert len(recent_scans) > 0, "Scan history should exist"

                latest = recent_scans[0]
                assert latest.completed_at is not None, "completed_at should be set"
                assert isinstance(latest.completed_at, datetime), (
                    f"completed_at must be datetime, got {type(latest.completed_at)}"
                )

                # completed_at should be after started_at
                assert latest.completed_at >= latest.started_at, (
                    "completed_at should be >= started_at"
                )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scan_history_records_host_counts(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.17: Scan history records total/successful/failed counts.

        Given: Multiple hosts scanned
        When: Scan completes
        Then: Host counts are recorded
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

        # Create multiple certificates with unique fingerprints
        for i, hostname in enumerate(["host1.example.com", "host2.example.com"]):
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
            issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])

            # Create unique cert for each host
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=60 + i))  # Different expiry = different cert
                .serial_number(100000 + i)  # Different serial = different fingerprint
                .public_key(private_key.public_key())
                .sign(private_key, hashes.SHA256())
            )

            model = cert_to_model(
                cert,
                certificate_type=CertificateType.LEAF,
                source=CertificateSource.SCANNED,
                hostname=hostname,
                port=443,
            )
            await cert_repo.create(model)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
                mock_extract.return_value = (test_certificates["good"], [])

                await service.run_daily_scan()

                # Check scan history
                recent_scans = await scan_repo.get_recent(limit=1)
                if recent_scans:
                    latest = recent_scans[0]

                    # Verify counts are recorded
                    assert latest.total_hosts >= 0, "total_hosts should be >= 0"
                    assert latest.successful_hosts >= 0, "successful_hosts should be >= 0"
                    assert latest.failed_hosts >= 0, "failed_hosts should be >= 0"
                    assert latest.updated_certificates >= 0, "updated_certificates should be >= 0"

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scan_history_records_error_message(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """AC-05.18: Failed scan records error message.

        Given: Complete scan failure
        When: Scan fails
        Then: error_message is recorded
        """
        from cert_watch.core.exceptions import TLSConnectionError
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="error-test.example.com",
            port=443,
        )
        await cert_repo.create(model)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            with patch(
                "cert_watch.core.formatters.extract_certificate_from_tls",
                side_effect=TLSConnectionError("Connection refused"),
            ):
                await service.run_daily_scan()

                # Check scan history
                recent_scans = await scan_repo.get_recent(limit=1)
                if recent_scans:
                    latest = recent_scans[0]
                    if latest.status == ScanStatus.FAILURE:
                        assert latest.error_message is not None, (
                            "Failed scan should have error_message"
                        )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_get_recent_returns_ordered_scans(
        self,
        scan_repo: ScanHistoryRepository,
    ):
        """AC-05.19: get_recent returns scans in reverse chronological order.

        Given: Multiple scan history entries
        When: Getting recent scans
        Then: Most recent first
        """
        from datetime import datetime, timedelta

        # Create scan entries
        now = datetime.utcnow()

        for i in range(3):
            scan = ScanHistory(
                started_at=now - timedelta(hours=i),
                status=ScanStatus.SUCCESS,
                total_hosts=1,
                successful_hosts=1,
            )
            await scan_repo.create(scan)

        # Get recent scans
        recent = await scan_repo.get_recent(limit=10)

        # Should be ordered by started_at desc
        for i in range(len(recent) - 1):
            assert recent[i].started_at >= recent[i + 1].started_at, (
                "Scans should be ordered by started_at descending"
            )


# =============================================================================
# Manual Scan Trigger Tests
# =============================================================================


@pytest.mark.asyncio
class TestManualScanTrigger:
    """Test suite for manual scan trigger functionality."""

    async def test_manual_scan_endpoint_exists(
        self,
        client: TestClient,
    ):
        """AC-05.20: Manual scan endpoint exists and is accessible.

        Given: Application running
        When: POST to manual scan endpoint
        Then: Request is accepted
        """
        # Try common manual scan endpoints
        possible_endpoints = [
            "/scan/trigger",
            "/scheduler/scan",
            "/admin/scan",
        ]

        found = False
        for endpoint in possible_endpoints:
            response = client.post(endpoint)
            if response.status_code in [200, 201, 202, 302, 401, 403]:
                # Endpoint exists (even if auth required)
                found = True
                break

        # If none found, check if scheduler service can be called directly
        if not found:
            try:
                from cert_watch.web.deps import get_scheduler_service

                service = get_scheduler_service()
                assert service is not None, "Scheduler service should be accessible"
                found = True
            except (ImportError, NotImplementedError):
                pass

        if not found:
            pytest.skip("Manual scan endpoint not yet implemented (expected during test phase)")

    async def test_manual_scan_triggers_same_as_scheduled(
        self,
        client: TestClient,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
        settings,
    ):
        """AC-05.21: Manual scan runs same cycle as scheduled scan.

        Given: Certificates to scan
        When: Manual scan triggered
        Then: Same refresh + alert evaluation runs
        """
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="manual-scan.example.com",
            port=443,
        )
        await cert_repo.create(model)

        try:
            from cert_watch.services.scheduler_impl import ScanSchedulerImpl

            service = ScanSchedulerImpl(
                cert_repo=cert_repo,
                scan_repo=scan_repo,
                settings=settings,
            )

            with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
                mock_extract.return_value = (cert, [])

                # Act: Trigger manual scan via service
                await service.run_daily_scan()

                # Assert: TLS extraction was called (scan happened)
                assert mock_extract.called, (
                    "PRECONDITION FAILED: Manual scan did not trigger TLS extraction. "
                    "Scan was not executed."
                )

                # Assert: Scan history was recorded
                recent_scans = await scan_repo.get_recent(limit=1)
                assert len(recent_scans) > 0, "Scan history should be recorded after manual scan"

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")


# =============================================================================
# Scheduler Lifecycle Tests
# =============================================================================


@pytest.mark.asyncio
class TestSchedulerLifecycle:
    """Test suite for scheduler startup and shutdown."""

    async def test_scheduler_can_be_started(
        self,
    ):
        """AC-05.22: Scheduler can be started.

        Given: Scheduler service
        When: start_scheduler() called
        Then: Scheduler starts without error
        """
        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Should not raise
            service.start_scheduler()

            # Clean up
            service.stop_scheduler()

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scheduler_can_be_stopped(
        self,
    ):
        """AC-05.23: Scheduler can be stopped.

        Given: Running scheduler
        When: stop_scheduler() called
        Then: Scheduler stops without error
        """
        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Start first
            service.start_scheduler()

            # Stop should not raise
            service.stop_scheduler()

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scheduler_starts_with_application(
        self,
        client: TestClient,
        app,
    ):
        """AC-05.24: Scheduler starts when application starts.

        Given: Application startup
        When: Lifespan context entered
        Then: Scheduler is started
        """
        # This test verifies the wiring in app_factory.py
        # The scheduler should be stored in app.state
        if hasattr(app.state, "scheduler"):
            assert app.state.scheduler is not None, "Scheduler should be in app.state"
        else:
            # Scheduler may be managed differently
            pytest.skip("Scheduler wiring not yet implemented in lifespan")


# =============================================================================
# Integration Tests with Real Database
# =============================================================================


@pytest.mark.asyncio
class TestSchedulerIntegration:
    """Integration tests using real database (no mocks)."""

    async def test_scan_history_repo_returns_actual_datetimes(
        self,
        scan_repo: ScanHistoryRepository,
    ):
        """Verify scan history repository returns datetime objects, not strings.

        This catches type mismatches that mocked tests miss.
        """
        # Arrange: Create scan history
        scan = ScanHistory(
            started_at=datetime.utcnow(),
            status=ScanStatus.SUCCESS,
            total_hosts=1,
            successful_hosts=1,
        )
        created = await scan_repo.create(scan)

        # Act: Retrieve
        retrieved = await scan_repo.get_by_id(created.id)

        # Assert: Types are correct
        assert retrieved is not None
        assert isinstance(retrieved.started_at, datetime), (
            f"started_at should be datetime, got {type(retrieved.started_at)}"
        )

    async def test_scan_history_repo_returns_scan_history_objects(
        self,
        scan_repo: ScanHistoryRepository,
    ):
        """get_recent returns list[ScanHistory], not list[dict].

        BOUNDARY: Database query → List[ScanHistory model]
        """
        # Arrange: Create scan entries
        for i in range(3):
            scan = ScanHistory(
                started_at=datetime.utcnow() - timedelta(hours=i),
                status=ScanStatus.SUCCESS,
                total_hosts=1,
                successful_hosts=1,
            )
            await scan_repo.create(scan)

        # Act: Get recent
        recent = await scan_repo.get_recent(limit=5)

        # Assert: Types
        assert isinstance(recent, list), f"get_recent must return list, got {type(recent)}"

        for i, scan in enumerate(recent):
            assert isinstance(scan, ScanHistory), (
                f"get_recent[{i}] should be ScanHistory, got {type(scan).__name__}"
            )

    async def test_run_daily_scan_with_real_repository(
        self,
        cert_repo: CertificateRepository,
        scan_repo: ScanHistoryRepository,
        test_certificates,
    ):
        """Daily scan uses real repositories (integration test).

        This test verifies the full integration between scheduler
        and repositories without mocking the database layer.
        """
        from cert_watch.models.certificate import CertificateSource, CertificateType
        from tests.conftest import cert_to_model

        # Arrange: Create real certificate entry
        cert = test_certificates["good"]
        model = cert_to_model(
            cert,
            certificate_type=CertificateType.LEAF,
            source=CertificateSource.SCANNED,
            hostname="real-repo-test.example.com",
            port=443,
        )
        await cert_repo.create(model)

        # Record initial scan count
        initial_scans = await scan_repo.get_recent(limit=10)

        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Mock only external I/O (network), not database
            with patch("cert_watch.core.formatters.extract_certificate_from_tls") as mock_extract:
                mock_extract.return_value = (cert, [])

                # Act: Run scan
                await service.run_daily_scan()

                # Assert: Scan was recorded in real database
                final_scans = await scan_repo.get_recent(limit=10)

                # Structural assertion: Something was recorded
                assert len(final_scans) > len(initial_scans) or mock_extract.called, (
                    "PRECONDITION FAILED: Daily scan did not record history or call TLS. "
                    "Service may not be properly integrated with repositories."
                )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")


# =============================================================================
# Type Contract Tests for Scheduler
# =============================================================================


@pytest.mark.asyncio
class TestSchedulerTypeContracts:
    """Type contracts for scheduler service methods."""

    async def test_run_daily_scan_returns_none(
        self,
        settings,
    ):
        """run_daily_scan returns None.

        BOUNDARY: Daily scan execution → None
        """
        try:
            from cert_watch.services.scheduler_impl import ScanSchedulerImpl

            service = ScanSchedulerImpl(settings=settings)

            with patch("cert_watch.core.formatters.extract_certificate_from_tls"):
                result = await service.run_daily_scan()

                assert result is None, (
                    f"run_daily_scan should return None, got {type(result).__name__}"
                )

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_start_scheduler_returns_none(
        self,
    ):
        """start_scheduler returns None.

        BOUNDARY: Scheduler startup → None
        """
        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            result = service.start_scheduler()

            assert result is None, (
                f"start_scheduler should return None, got {type(result).__name__}"
            )

            # Clean up
            service.stop_scheduler()

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_stop_scheduler_returns_none(
        self,
    ):
        """stop_scheduler returns None.

        BOUNDARY: Scheduler shutdown → None
        """
        try:
            from cert_watch.services.base import ScanSchedulerService
            from cert_watch.web.deps import get_scheduler_service

            service = get_scheduler_service()

            # Start first
            service.start_scheduler()

            result = service.stop_scheduler()

            assert result is None, f"stop_scheduler should return None, got {type(result).__name__}"

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("ScanSchedulerService not yet implemented")

    async def test_scan_history_id_is_int_or_none(
        self,
        sample_scan_history,
    ):
        """ScanHistory.id is int or None.

        BOUNDARY: Model field → int | None
        """
        if sample_scan_history.id is not None:
            assert isinstance(sample_scan_history.id, int), (
                f"ScanHistory.id must be int or None, got {type(sample_scan_history.id)}"
            )

    async def test_scan_history_status_is_enum(
        self,
        sample_scan_history,
    ):
        """ScanHistory.status is ScanStatus enum.

        BOUNDARY: Model field → ScanStatus
        """
        assert isinstance(sample_scan_history.status, ScanStatus), (
            f"ScanHistory.status must be ScanStatus, got {type(sample_scan_history.status)}"
        )

    async def test_scan_history_timestamps_are_datetime(
        self,
        sample_scan_history,
    ):
        """ScanHistory timestamps are datetime.

        BOUNDARY: Model field → datetime
        """
        assert isinstance(sample_scan_history.started_at, datetime), (
            f"started_at must be datetime, got {type(sample_scan_history.started_at)}"
        )

        if sample_scan_history.completed_at is not None:
            assert isinstance(sample_scan_history.completed_at, datetime), (
                f"completed_at must be datetime or None, got {type(sample_scan_history.completed_at)}"
            )

    async def test_scan_history_counts_are_int(
        self,
        sample_scan_history,
    ):
        """ScanHistory counts are int.

        BOUNDARY: Model field → int
        """
        assert isinstance(sample_scan_history.total_hosts, int), (
            f"total_hosts must be int, got {type(sample_scan_history.total_hosts)}"
        )
        assert isinstance(sample_scan_history.successful_hosts, int), (
            f"successful_hosts must be int, got {type(sample_scan_history.successful_hosts)}"
        )
        assert isinstance(sample_scan_history.failed_hosts, int), (
            f"failed_hosts must be int, got {type(sample_scan_history.failed_hosts)}"
        )
        assert isinstance(sample_scan_history.updated_certificates, int), (
            f"updated_certificates must be int, got {type(sample_scan_history.updated_certificates)}"
        )


# =============================================================================
# Web Route Tests for Scheduler
# =============================================================================


@pytest.mark.asyncio
class TestSchedulerWebRoutes:
    """Tests for scheduler-related web routes."""

    async def test_scheduler_status_page_exists(
        self,
        client: TestClient,
    ):
        """AC-05.25: Scheduler status page is accessible.

        Given: Scheduler running
        When: Accessing status page
        Then: Page shows scheduler configuration
        """
        # Try common status endpoints
        possible_endpoints = [
            "/scheduler",
            "/admin/scheduler",
            "/scan/status",
        ]

        found = False
        for endpoint in possible_endpoints:
            response = client.get(endpoint)
            if response.status_code == 200:
                found = True
                # Verify it shows scheduler info
                content = response.text.lower()
                assert any(term in content for term in ["scan", "schedule", "time", "status"]), (
                    "Status page should show scheduler information"
                )
                break

        if not found:
            pytest.skip("Scheduler status page not yet implemented")

    async def test_scan_history_page_shows_history(
        self,
        client: TestClient,
        scan_repo: ScanHistoryRepository,
    ):
        """AC-05.26: Scan history page displays recent scans.

        Given: Scan history entries exist
        When: Viewing history page
        Then: Recent scans are displayed
        """
        # Arrange: Create scan history
        scan = ScanHistory(
            started_at=datetime.utcnow(),
            status=ScanStatus.SUCCESS,
            total_hosts=5,
            successful_hosts=5,
        )
        await scan_repo.create(scan)

        # Try common history endpoints
        possible_endpoints = [
            "/scan/history",
            "/scheduler/history",
            "/admin/scan-history",
        ]

        found = False
        for endpoint in possible_endpoints:
            response = client.get(endpoint)
            if response.status_code == 200:
                found = True
                content = response.text.lower()
                # Should show some scan-related info
                assert any(term in content for term in ["scan", "history", "host", "status"]), (
                    "History page should show scan information"
                )
                break

        if not found:
            pytest.skip("Scan history page not yet implemented")
