"""Scheduler service implementation for FR-05.

Provides business logic for daily scan cycles with APScheduler.
"""

import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from cert_watch.core import formatters
from cert_watch.core.config import Settings
from cert_watch.core.exceptions import TLSConnectionError, TLSHandshakeError
from cert_watch.models.certificate import Certificate, CertificateSource, CertificateType
from cert_watch.models.scan_history import ScanHistory, ScanStatus
from cert_watch.repositories.base import (
    AlertRepository,
    CertificateRepository,
    ScanHistoryRepository,
)
from cert_watch.services.base import AlertService, ScanSchedulerService

logger = logging.getLogger(__name__)


class ScanSchedulerImpl(ScanSchedulerService):
    """Service for scheduled scanning using APScheduler."""

    def __init__(
        self,
        cert_repo: CertificateRepository | None = None,
        alert_repo: AlertRepository | None = None,
        scan_repo: ScanHistoryRepository | None = None,
        alert_service: AlertService | None = None,
        settings: Settings | None = None,
    ):
        """Initialize the scheduler service.

        Args:
            cert_repo: Certificate repository. If None, creates from settings.
            alert_repo: Alert repository. If None, creates from settings.
            scan_repo: Scan history repository. If None, creates from settings.
            alert_service: Alert service for evaluating alerts. If None, creates from settings.
            settings: Application settings. If None, uses Settings.get().
        """
        self._settings = settings or Settings.get()
        self._cert_repo = cert_repo
        self._alert_repo = alert_repo
        self._scan_repo = scan_repo
        self._alert_service = alert_service
        self._scheduler: AsyncIOScheduler | None = None

    def _get_cert_repo(self) -> CertificateRepository:
        """Get certificate repository, creating if needed."""
        if self._cert_repo is None:
            from cert_watch.repositories.sqlite import SQLiteCertificateRepository
            from cert_watch.web.deps import _get_connection_pool

            pool = _get_connection_pool(str(self._settings.database_path))
            self._cert_repo = SQLiteCertificateRepository(pool)
        return self._cert_repo

    def _get_alert_repo(self) -> AlertRepository:
        """Get alert repository, creating if needed."""
        if self._alert_repo is None:
            from cert_watch.repositories.sqlite import SQLiteAlertRepository
            from cert_watch.web.deps import _get_connection_pool

            pool = _get_connection_pool(str(self._settings.database_path))
            self._alert_repo = SQLiteAlertRepository(pool)
        return self._alert_repo

    def _get_scan_repo(self) -> ScanHistoryRepository:
        """Get scan history repository, creating if needed."""
        if self._scan_repo is None:
            from cert_watch.repositories.sqlite import SQLiteScanHistoryRepository
            from cert_watch.web.deps import _get_connection_pool

            pool = _get_connection_pool(str(self._settings.database_path))
            self._scan_repo = SQLiteScanHistoryRepository(pool)
        return self._scan_repo

    def _get_alert_service(self) -> AlertService:
        """Get alert service, creating if needed."""
        if self._alert_service is None:
            try:
                from cert_watch.services.alert_service_impl import AlertServiceImpl

                self._alert_service = AlertServiceImpl(
                    cert_repo=self._get_cert_repo(),
                    alert_repo=self._get_alert_repo(),
                    settings=self._settings,
                )
            except ImportError:
                # Fallback to base class if not implemented yet
                from cert_watch.services.base import AlertServiceStub

                self._alert_service = AlertServiceStub()
        return self._alert_service

    def start_scheduler(self) -> None:
        """Start the background scheduler.

        Configures the scheduler to run the daily scan at the configured time.
        """
        if self._scheduler is not None and self._scheduler.running:
            logger.warning("Scheduler is already running")
            return

        self._scheduler = AsyncIOScheduler()

        # Parse scan time (HH:MM format)
        scan_time = self._settings.scan_time
        try:
            hour, minute = map(int, scan_time.split(":"))
        except ValueError:
            logger.error(f"Invalid scan_time format: {scan_time}, using default 06:00")
            hour, minute = 6, 0

        # Schedule daily scan
        trigger = CronTrigger(hour=hour, minute=minute)
        self._scheduler.add_job(
            self._scheduled_scan_wrapper,
            trigger=trigger,
            id="daily_scan",
            replace_existing=True,
        )

        self._scheduler.start()
        logger.info(f"Scheduler started. Daily scan scheduled for {hour:02d}:{minute:02d}")

    def stop_scheduler(self) -> None:
        """Stop the background scheduler."""
        if self._scheduler is not None and self._scheduler.running:
            self._scheduler.shutdown()
            logger.info("Scheduler stopped")
        self._scheduler = None

    async def _scheduled_scan_wrapper(self) -> None:
        """Wrapper for scheduled scan that handles exceptions."""
        try:
            await self.run_daily_scan()
        except Exception as e:
            logger.exception(f"Scheduled daily scan failed: {e}")

    async def run_daily_scan(self) -> None:
        """Run the daily scan cycle.

        This method:
        1. Gets all SCANNED certificates from the database
        2. For each scanned certificate, performs TLS handshake to refresh data
        3. Updates certificate entries with current data
        4. Records scan history with status and counts
        5. Triggers alert evaluation for refreshed certificates
        """
        cert_repo = self._get_cert_repo()
        scan_repo = self._get_scan_repo()

        # Create scan history entry
        scan_history = ScanHistory(
            started_at=datetime.utcnow(),
            status=ScanStatus.SUCCESS,
            total_hosts=0,
            successful_hosts=0,
            failed_hosts=0,
            updated_certificates=0,
        )
        scan_history = await scan_repo.create(scan_history)

        try:
            # Get all certificates (we'll filter for scanned ones)
            all_certs = await cert_repo.get_all(limit=10000)

            # Filter to only SCANNED certificates with hostname
            scanned_certs = [
                cert
                for cert in all_certs
                if cert.source == CertificateSource.SCANNED and cert.hostname is not None
            ]

            total_hosts = len(scanned_certs)
            successful_hosts = 0
            failed_hosts = 0
            updated_certs = 0

            # Track if any failures occurred
            has_failures = False
            has_successes = False

            # Refresh each scanned certificate
            for cert in scanned_certs:
                try:
                    # Perform TLS handshake to get current certificate
                    port = cert.port or 443
                    leaf_cert, chain_certs = await formatters.extract_certificate_from_tls(
                        cert.hostname, port
                    )

                    # Update the certificate entry
                    await self._update_certificate_from_scan(cert, leaf_cert, chain_certs)
                    updated_certs += 1
                    successful_hosts += 1
                    has_successes = True

                except (TLSConnectionError, TLSHandshakeError) as e:
                    logger.warning(f"Failed to scan {cert.hostname}:{cert.port}: {e}")
                    failed_hosts += 1
                    has_failures = True
                except Exception as e:
                    logger.exception(f"Unexpected error scanning {cert.hostname}:{cert.port}: {e}")
                    failed_hosts += 1
                    has_failures = True

            # Determine scan status
            if has_failures and has_successes:
                status = ScanStatus.PARTIAL
            elif has_failures:
                status = ScanStatus.FAILURE
            else:
                status = ScanStatus.SUCCESS

            # Build error message for failure cases
            error_message = None
            if status == ScanStatus.FAILURE and failed_hosts > 0:
                error_message = f"All {failed_hosts} host(s) failed to scan"

            # Complete scan history
            await scan_repo.complete(
                scan_history.id,
                status=status,
                total_hosts=total_hosts,
                successful_hosts=successful_hosts,
                failed_hosts=failed_hosts,
                updated_certificates=updated_certs,
                error_message=error_message,
            )

            logger.info(
                f"Daily scan completed: {successful_hosts}/{total_hosts} hosts successful, "
                f"{updated_certs} certificates updated"
            )

            # Trigger alert evaluation
            try:
                alert_service = self._get_alert_service()
                await alert_service.evaluate_alerts()
                logger.info("Alert evaluation completed after daily scan")
            except Exception as e:
                logger.exception(f"Alert evaluation failed after daily scan: {e}")

        except Exception as e:
            # Complete scan history with failure
            await scan_repo.complete(
                scan_history.id,
                status=ScanStatus.FAILURE,
                total_hosts=0,
                successful_hosts=0,
                failed_hosts=0,
                updated_certificates=0,
                error_message=str(e),
            )
            logger.exception(f"Daily scan failed: {e}")

    async def _update_certificate_from_scan(
        self,
        existing_cert: Certificate,
        leaf_cert,
        chain_certs: list,
    ) -> None:
        """Update a certificate entry from TLS scan results.

        Args:
            existing_cert: The existing certificate entry
            leaf_cert: The leaf certificate from TLS handshake
            chain_certs: List of chain certificates from TLS handshake
        """
        cert_repo = self._get_cert_repo()

        # Compute new fingerprint
        new_fingerprint = formatters.compute_thumbprint(leaf_cert)

        # Update certificate fields
        existing_cert.subject = formatters.format_subject(leaf_cert)
        existing_cert.issuer = formatters.format_issuer(leaf_cert)
        existing_cert.not_before = leaf_cert.not_valid_before
        existing_cert.not_after = leaf_cert.not_valid_after
        existing_cert.fingerprint = new_fingerprint
        existing_cert.serial_number = str(leaf_cert.serial_number)
        existing_cert.pem_data = formatters.serialize_certificate(leaf_cert)
        existing_cert.updated_at = datetime.utcnow()
        existing_cert.last_scanned_at = datetime.utcnow()

        # Save updated certificate
        await cert_repo.update(existing_cert)

        # Update chain certificates if present
        if chain_certs:
            await self._update_chain_certificates(existing_cert, chain_certs)

    async def _update_chain_certificates(
        self,
        leaf_cert: Certificate,
        chain_certs: list,
    ) -> None:
        """Update chain certificates for a leaf certificate.

        Args:
            leaf_cert: The leaf certificate entry
            chain_certs: List of chain certificates from TLS handshake
        """
        cert_repo = self._get_cert_repo()

        # Get existing chain
        existing_chain = await cert_repo.get_chain_for_leaf(leaf_cert.fingerprint)

        # For simplicity, we'll create/update chain certificates
        for i, chain_cert in enumerate(chain_certs):
            fingerprint = formatters.compute_thumbprint(chain_cert)

            # Check if this chain cert already exists
            existing = await cert_repo.get_by_fingerprint(fingerprint)

            if existing:
                # Update existing chain cert
                existing.subject = formatters.format_subject(chain_cert)
                existing.issuer = formatters.format_issuer(chain_cert)
                existing.not_before = chain_cert.not_valid_before
                existing.not_after = chain_cert.not_valid_after
                existing.serial_number = str(chain_cert.serial_number)
                existing.pem_data = formatters.serialize_certificate(chain_cert)
                existing.updated_at = datetime.utcnow()
                existing.last_scanned_at = datetime.utcnow()
                existing.source_hostname = leaf_cert.hostname
                existing.source_port = leaf_cert.port
                await cert_repo.update(existing)
            else:
                # Create new chain cert entry
                cert_type = (
                    CertificateType.ROOT
                    if i == len(chain_certs) - 1
                    else CertificateType.INTERMEDIATE
                )
                new_chain_cert = Certificate(
                    certificate_type=cert_type,
                    source=CertificateSource.SCANNED,
                    subject=formatters.format_subject(chain_cert),
                    issuer=formatters.format_issuer(chain_cert),
                    not_before=chain_cert.not_valid_before,
                    not_after=chain_cert.not_valid_after,
                    fingerprint=fingerprint,
                    serial_number=str(chain_cert.serial_number),
                    chain_fingerprint=leaf_cert.fingerprint,
                    chain_position=i + 1,
                    pem_data=formatters.serialize_certificate(chain_cert),
                    source_hostname=leaf_cert.hostname,
                    source_port=leaf_cert.port,
                )
                await cert_repo.create(new_chain_cert)
